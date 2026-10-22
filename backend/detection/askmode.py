"""
Snitch — interactive ask-on-first-connect (Linux NFQUEUE) / demande
interactive à la première connexion (NFQUEUE Linux).

EN: The honest user-mode slice of "ask before letting a new outbound flow
    out" — no kernel driver needed on Linux thanks to NFQUEUE: packets
    matching an iptables rule are handed to a user-space verdict socket
    that can ACCEPT or DROP them. We divert the FIRST outbound packet of
    each unseen (remote_ip, remote_port, proto) flow into queue 7, hold it
    pending the analyst's decision via the API, then apply the verdict.
    Decisions persist per flow-key for the session, so only the first
    packet of each flow ever waits.

      * opt-in only: enable via settings ask_enabled=1 — needs Linux,
        root (CAP_NET_ADMIN) and iptables; the NFQUEUE client is the
        PURE-PYTHON `nfqueue.py` in this package, so there is nothing
        else to install
      * iptables rule installed: `OUTPUT -j NFQUEUE --queue-num 7` minus
        exemptions for loopback/LAN (the API itself must stay reachable)
      * timeout policy `ask_timeout`: after N seconds with no verdict the
        packet is dropped (secure default) or accepted (ask_failopen=1)
      * each held packet waits on its own waiter thread, so a stalled
        flow never blocks the verdict loop for other connections
      * flows the user already ruled on go straight through — this is
        ask-on-first-connect, not ask-every-packet

    This is REAL verdict power (Little-Snitch-style): the connection is
    genuinely suspended until you answer. Platform scope: Linux only;
    Windows/macOS need the kernel callout / NetworkExtension tracks
    (contrib/) — reported honestly by available().

FR: La tranche user-mode honnête du « demander avant de laisser sortir un
    nouveau flux » — sans driver noyau sous Linux grâce à NFQUEUE : les
    paquets matchés par iptables sont remis à un socket de verdict
    user-space qui les ACCEPTe ou les DROPpe. On détourne le PREMIER
    paquet sortant de chaque flux (ip, port, proto) inconnu vers la file 7
    via `nfqueue.py` (pur Python, rien à installer), on le gèle en
    attendant le verdict de l'analyste via l'API, puis on applique.
    Opt-in uniquement (Linux + root + iptables). Politique de timeout :
    drop par défaut (ask_failopen=1 pour accepter). Chaque paquet retenu
    a son propre thread d'attente — un flux gelé ne bloque pas les autres.
    Linux seulement — Windows/macOS passent par les pistes noyau
    (contrib/).
"""

from __future__ import annotations

import logging
import os
import platform
import threading
import time
from typing import Callable, Optional

logger = logging.getLogger(__name__)

_QUEUE_NUM = 7
_MAX_PENDING = 512
# EN: Cap on remembered verdicts — long-running hosts see endless fresh
#     (ip, port) pairs via ephemeral ports, so keep only the most recent
#     decisions (dict order = insertion order).
# FR: Borne des verdicts retenus — un hôte longue durée voit défiler des
#     paires (ip, port) sans fin via les ports éphémères ; on ne garde que
#     les décisions récentes (ordre du dict = ordre d'insertion).
_MAX_DECIDED = 65_536
_DEFAULT_TIMEOUT = 15.0


def available() -> tuple[bool, str]:
    """EN: Linux + root + iptables — the NFQUEUE client is pure Python
    (nfqueue.py) so no extra package is needed anymore.
    FR: Linux + root + iptables — le client NFQUEUE est en pur Python
    (nfqueue.py), aucun paquet supplémentaire requis."""
    if platform.system().lower() != "linux":
        return False, "NFQUEUE is linux-only (windows/macOS need kernel " \
                      "callouts — see contrib/)"
    if os.geteuid() != 0:
        return False, "needs root (CAP_NET_ADMIN) for iptables + NFQUEUE"
    import shutil
    if shutil.which("iptables") is None:
        return False, "iptables binary not found"
    return True, ""


class AskMode:
    """EN: Owns the NFQUEUE verdict loop + pending-flow table.
    FR: Gère la boucle de verdict NFQUEUE + la table des flux en attente."""

    def __init__(self, on_ask: Callable[[dict], None],
                 timeout: float = _DEFAULT_TIMEOUT,
                 failopen: bool = False):
        self._on_ask = on_ask                # EN: emit ASK_VERDICT alert / FR: émet l'alerte
        self._timeout = max(3.0, min(float(timeout), 120.0))
        self._failopen = failopen
        self._nfq = None                     # EN: NfqSocket / FR: NfqSocket
        self._thread: Optional[threading.Thread] = None
        self._running = False
        # EN: flow-key → [event, packet_id, ts] pending verdict;
        #     decided flow-key → allow verdict
        # FR: clé de flux → [event, id du paquet, ts] en attente ;
        #     clé décidée → verdict
        self._pending: dict[tuple, list] = {}
        self._decided: dict[tuple, bool] = {}
        self._lock = threading.Lock()
        self._rule_installed = False
        # EN: Rules planted by the last successful start() — needed so
        #     stop() can remove the complete set, not just the queue jump.
        # FR: Règles posées par le dernier start() réussi — nécessaire pour
        #     que stop() retire l'ensemble complet, pas seulement le saut.
        self._installed: list[list[str]] = []
        # EN: IPs exempted from diversion at start (whitelist — "allow
        #     always" verdicts). Bounded; their delete-mirrors ride in
        #     _installed like every other rule.
        # FR: IPs exemptées du détournement au start (whitelist — verdicts
        #     « autoriser toujours »). Bornées ; leurs suppressions miroir
        #     voyagent dans _installed comme les autres règles.
        self._exempt: list[str] = []

    # ── lifecycle / cycle de vie ──────────────────────────────────────────

    def configure(self, timeout: Optional[float] = None,
                  failopen: Optional[bool] = None) -> None:
        """EN: Live-update timeout / fail-open policy from settings — takes
            effect on the next pending flow (no restart needed).
        FR: Met à jour à chaud timeout / fail-open depuis les réglages —
            effet au prochain flux en attente (pas de redémarrage)."""
        if timeout is not None:
            try:
                self._timeout = max(3.0, min(float(timeout), 120.0))
            except (TypeError, ValueError):
                pass
        if failopen is not None:
            self._failopen = bool(failopen)

    def start(self, exempt_ips: Optional[list] = None) -> tuple[bool, str]:
        """EN: `exempt_ips` get iptables RETURN rules before the NFQUEUE
        jump so "allow always" verdicts survive restarts — bounded to 64.
        FR: `exempt_ips` reçoivent des règles RETURN avant le saut NFQUEUE
        — les verdicts « autoriser toujours » survivent au redémarrage."""
        ok, why = available()
        if not ok:
            return False, why
        # EN: Exempt IPs end up as `iptables -d <value>` argv — even
        #     without a shell, a crafted value could smuggle extra
        #     iptables flags. Only literal addresses/prefixes pass.
        # FR: Les IP exemptées deviennent `iptables -d <valeur>` — même
        #     sans shell, une valeur forgée pourrait injecter des options
        #     iptables. Seules des adresses/préfixes littéraux passent.
        import ipaddress
        self._exempt = []
        for ip in (exempt_ips or [])[:64]:
            try:
                # EN: store the PARSER-PRODUCED form — the argv value is a
                #     normalized CIDR literal, not the raw input string.
                # FR: on stocke la forme NORMALISÉE par le parseur — la
                #     valeur argv est un littéral CIDR, pas l'entrée brute.
                self._exempt.append(
                    str(ipaddress.ip_network(str(ip), strict=False)))
            except ValueError:
                continue
        import subprocess
        from .nfqueue import NfqSocket                        # noqa: PLC0415
        try:
            self._nfq = NfqSocket(_QUEUE_NUM)
            self._nfq.open()
            self._nfq.bind_queue()
        except Exception as e:                     # noqa: BLE001
            try:
                if self._nfq is not None:
                    self._nfq.close()
            finally:
                self._nfq = None
            return False, f"nfqueue bind failed: {e}"
        # EN: Divert outbound SYN/non-established flows into queue 7 —
        #     private ranges exempt so the LAN/UI never stalls.
        # FR: Détourne les flux sortants non établis vers la file 7 —
        #     plages privées exemptées pour ne pas geler le LAN/l'UI.
        cmds = [
            ["iptables", "-w", "-I", "OUTPUT", "-o", "lo", "-j", "RETURN"],
            ["iptables", "-w", "-I", "OUTPUT", "-m", "conntrack",
             "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN"],
            ["iptables", "-w", "-I", "OUTPUT", "-d", "127.0.0.0/8",
             "-j", "RETURN"],
            ["iptables", "-w", "-I", "OUTPUT", "-d", "10.0.0.0/8",
             "-j", "RETURN"],
            ["iptables", "-w", "-I", "OUTPUT", "-d", "172.16.0.0/12",
             "-j", "RETURN"],
            ["iptables", "-w", "-I", "OUTPUT", "-d", "192.168.0.0/16",
             "-j", "RETURN"],
            ["iptables", "-w", "-I", "OUTPUT", "-j", "NFQUEUE",
             "--queue-num", str(_QUEUE_NUM)],
        ]
        # EN: Per-IP exemptions ride BEFORE the queue jump — they keep the
        #     LAN/UI exemption insertion order intact.
        # FR: Les exemptions par IP précèdent le saut — l'ordre d'insertion
        #     des exemptions LAN/UI est préservé.
        for ip in self._exempt:
            cmds.insert(len(cmds) - 1,
                        ["iptables", "-w", "-I", "OUTPUT", "-d", ip,
                         "-j", "RETURN"])
        # EN: Rules land one at a time — track each inserted rule so a
        #     mid-sequence failure rolls back EVERYTHING it already
        #     planted (a stranded NFQUEUE jump would wedge the host's
        #     outbound traffic until reboot).
        # FR: Les règles atterrissent une à une — suivre chaque insertion
        #     pour qu'un échec à mi-parcours annule TOUT ce qui a été posé
        #     (un saut NFQUEUE orphelin bloquerait le trafic sortant de
        #     l'hôte jusqu'au reboot).
        inserted: list[list[str]] = []
        for c in cmds:
            try:
                subprocess.run(c, timeout=10, check=False,
                               capture_output=True)
                inserted.append(c)
            except OSError as e:
                self._rollback_rules(inserted)
                try:
                    if self._nfq is not None:
                        self._nfq.close()
                finally:
                    self._nfq = None
                return False, f"iptables failed: {e}"
        # EN: Remember EVERY rule planted — stop() removes the full set,
        #     not just the queue jump + exemptions (repeated start/stop
        #     cycles used to stack stale RETURN rules on OUTPUT).
        # FR: Retenir CHAQUE règle posée — stop() retire l'ensemble
        #     complet, pas seulement le saut + exemptions (les cycles
        #     start/stop empilaient des règles RETURN périmées sur OUTPUT).
        self._installed = inserted
        self._rule_installed = True
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="snitch-askmode")
        self._thread.start()
        return True, ""

    def _run(self) -> None:
        try:
            while self._running:
                # EN: 0.5 s timeout keeps the loop interruptible; each
                #     packet is handled inline (fast) or handed to a
                #     per-flow waiter thread for the async verdict.
                # FR: Timeout 0,5 s pour une boucle interruptible ;
                #     chaque paquet est traité directement ou remis à un
                #     thread d'attente dédié.
                for pid, payload in self._nfq.recv_packets(0.5):
                    self._handle(pid, payload)
        except Exception as e:                     # noqa: BLE001
            logger.warning("askmode nfqueue loop ended: %s", e)
        finally:
            self._running = False

    @staticmethod
    def _rollback_rules(inserted: list[list[str]]) -> None:
        """EN: Undo partial rule installation — every `-I` insert becomes
            the mirror `-D` delete, applied in reverse order so dependant
            entries unwind cleanly. Best-effort, never raises.
        FR: Annuler une installation partielle — chaque `-I` devient le
            `-D` miroir, appliqué en ordre inverse. Au mieux, ne lève jamais."""
        import subprocess
        for c in reversed(inserted):
            rm = ["-D" if a == "-I" else a for a in c]
            try:
                subprocess.run(rm, timeout=10, check=False,
                               capture_output=True)
            except OSError:
                pass

    def stop(self) -> None:
        self._running = False
        with self._lock:
            pending = list(self._pending.values())
            self._pending.clear()
            self._decided.clear()
        # EN: Verdict every held packet BEFORE closing — an unverdicted
        #     packet dies with the socket; apply the fail-open policy so
        #     shutdown semantics stay explicit.
        # FR: Verdicter chaque paquet retenu AVANT de fermer — sans verdict
        #     il meurt avec le socket ; on applique la politique fail-open.
        for ent in pending:
            try:
                if self._nfq is not None:
                    self._nfq.verdict(ent[1], self._failopen)
            except Exception:                      # noqa: BLE001
                pass
            ent[0].set()
        try:
            if self._nfq is not None:
                self._nfq.close()
        except Exception:                          # noqa: BLE001
            pass
        if self._rule_installed:
            # EN: Mirror-delete every rule start() planted — jump AND all
            #     the RETURN exemptions, in reverse insertion order.
            # FR: Suppression miroir de toutes les règles posées par
            #     start() — saut ET toutes les exemptions RETURN, en
            #     ordre inverse d'insertion.
            self._rollback_rules(self._installed)
            self._installed = []
            self._rule_installed = False

    # ── verdict path / chemin du verdict ─────────────────────────────────

    @staticmethod
    def _flow_key(payload: bytes) -> Optional[tuple]:
        """EN: Extract (remote_ip, remote_port, proto) from the raw IPv4/6
        packet payload NFQUEUE hands us — only TCP/UDP outbound matters.
        FR: Extrait (ip, port, proto) du paquet brut NFQUEUE — TCP/UDP
        sortants seulement."""
        try:
            ver = payload[0] >> 4
            if ver == 4:
                ihl = (payload[0] & 0x0F) * 4
                proto = payload[9]
                dst = ".".join(str(b) for b in payload[16:20])
                l4 = payload[ihl:]
            elif ver == 6:
                proto = payload[6]
                dst = ":".join(f"{payload[24+i]:02x}{payload[25+i]:02x}"
                               for i in range(0, 16, 2))
                l4 = payload[40:]
            else:
                return None
            if proto == 6:
                dport = int.from_bytes(l4[2:4], "big")
                # EN: only SYN (first) packets get asked; the rest of the
                #     handshake rides the stored decision.
                # FR: seuls les SYN (premiers paquets) interrogent ; le
                #     reste du handshake suit la décision stockée.
                if len(l4) > 13 and not (l4[13] & 0x02):
                    return None
                return (dst, dport, "TCP")
            if proto == 17:
                dport = int.from_bytes(l4[2:4], "big")
                return (dst, dport, "UDP")
        except (IndexError, ValueError):
            return None
        return None

    def _handle(self, pid: int, payload: bytes) -> None:
        """EN: One diverted packet: apply the stored verdict, accept when
        not askable, or park it on a per-flow waiter thread.
        FR: Un paquet détourné : applique le verdict stocké, accepte s'il
        n'est pas interrogable, ou le gare sur un thread d'attente."""
        try:
            key = self._flow_key(payload)
            if key is None:
                self._nfq.verdict(pid, True)
                return
            with self._lock:
                verdict = self._decided.get(key)
                if verdict is None:
                    # EN: Pending table bounded — overflow accepts
                    #     (fail-open on capacity, documented).
                    # FR: Table bornée — débordement accepte.
                    if len(self._pending) >= _MAX_PENDING:
                        verdict = True
                    else:
                        ev = threading.Event()
                        self._pending[key] = [ev, pid,
                                              time.monotonic()]
            if verdict is not None:
                self._nfq.verdict(pid, verdict)
                return
            self._on_ask({"type": "ASK_VERDICT", "remote_ip": key[0],
                          "remote_port": key[1], "proto": key[2],
                          "timeout_s": int(self._timeout)})
            threading.Thread(target=self._waiter, args=(key, ev),
                             daemon=True,
                             name="snitch-ask-waiter").start()
        except Exception:                          # noqa: BLE001
            try:
                self._nfq.verdict(pid, True)       # EN: never wedge host
            except Exception:                      # noqa: BLE001
                pass

    def _remember(self, key: tuple, allow: bool) -> None:
        """EN: Record a verdict under the lock, evicting the oldest
            quarter once the cache overflows.
        FR: Mémoriser un verdict sous le verrou, en évinçant le quart le
            plus ancien une fois le cache plein. Caller holds _lock."""
        self._decided[key] = allow
        if len(self._decided) > _MAX_DECIDED:
            for k in list(self._decided)[:_MAX_DECIDED // 4]:
                del self._decided[k]

    def _verdict(self, pkt_id: int, allow: bool) -> None:
        """EN: Emit an NFQUEUE verdict, swallowing the races a concurrent
            stop() creates by closing the socket mid-verdict.
        FR: Émettre un verdict NFQUEUE en absorbant les courses créées par
            un stop() concurrent qui ferme le socket en plein verdict."""
        try:
            if self._nfq is not None:
                self._nfq.verdict(pkt_id, allow)
        except Exception:                          # noqa: BLE001 — stop() raced
            pass

    def _waiter(self, key: tuple, ev: threading.Event) -> None:
        """EN: Holds one packet until decide() or the timeout; the recv
        loop keeps serving other flows meanwhile.
        FR: Retient un paquet jusqu'à decide() ou timeout ; la boucle de
        réception sert les autres flux pendant ce temps."""
        if ev.wait(self._timeout):
            return                                 # EN: decide() applied it
        with self._lock:
            ent = self._pending.pop(key, None)
            self._remember(key, self._failopen)
        if ent is not None:
            self._verdict(ent[1], self._failopen)

    def decide(self, remote_ip: str, remote_port: int, proto: str,
               allow: bool) -> bool:
        """EN: API entry — verdict for a pending flow; returns False if the
        flow already timed out. / FR: Entrée API — verdict pour un flux en
        attente ; False si le flux a déjà expiré."""
        key = (remote_ip, int(remote_port), (proto or "TCP").upper())
        with self._lock:
            ent = self._pending.pop(key, None)
            self._remember(key, bool(allow))
        if ent is None:
            return False
        self._verdict(ent[1], bool(allow))
        ent[0].set()
        return True

    def status(self) -> dict:
        with self._lock:
            return {"running": self._running,
                    "queue": _QUEUE_NUM if self._rule_installed else None,
                    "pending": len(self._pending),
                    "decided": len(self._decided),
                    "timeout_s": self._timeout,
                    "failopen": self._failopen}
