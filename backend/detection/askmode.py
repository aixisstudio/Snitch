"""
Snitch — interactive ask-on-first-connect (Linux NFQUEUE) / demande
interactive à la première connexion (NFQUEUE Linux).

EN: The honest user-mode slice of "ask before letting a new outbound flow
    out" — no kernel driver needed on Linux thanks to NFQUEUE: packets
    matching an iptables rule are handed to a user-space verdict callback
    that can ACCEPT or DROP them. We divert the FIRST outbound packet of
    each unseen (remote_ip, remote_port, proto) flow into queue 7, hold it
    pending the analyst's decision via the API, then apply the verdict.
    Decisions persist per flow-key for the session, so only the first
    packet of each flow ever waits.

      * opt-in only: enable via settings ask_enabled=1 (needs root +
        libnetfilter_queue — python package `NetfilterQueue`)
      * iptables rule installed: `OUTPUT -j NFQUEUE --queue-num 7` minus
        exemptions for loopback/LAN (the API itself must stay reachable)
      * timeout policy `ask_timeout`: after N seconds with no verdict the
        packet is dropped (secure default) or accepted (ask_failopen=1)
      * flows the user already ruled on go straight through — this is
        ask-on-first-connect, not ask-every-packet

    This is REAL verdict power (Little-Snitch-style): the connection is
    genuinely suspended until you answer. Platform scope: Linux only;
    Windows/macOS need the kernel callout / NetworkExtension tracks
    (contrib/) — reported honestly by available().

FR: La tranche user-mode honnête du « demander avant de laisser sortir un
    nouveau flux » — sans driver noyau sous Linux grâce à NFQUEUE : les
    paquets matchés par iptables sont remis à un callback user-space qui
    les ACCEPTe ou les DROPpe. On détourne le PREMIER paquet sortant de
    chaque flux (ip, port, proto) inconnu vers la file 7, on le gèle en
    attendant le verdict de l'analyste via l'API, puis on applique.
    Opt-in uniquement (root + libnetfilter_queue requis). Politique de
    timeout : drop par défaut (ask_failopen=1 pour accepter). Linux
    seulement — Windows/macOS passent par les pistes noyau (contrib/).
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
_DEFAULT_TIMEOUT = 15.0


def available() -> tuple[bool, str]:
    """EN: Linux + root + NetfilterQueue importable + libnetfilter_queue.
    FR: Linux + root + NetfilterQueue importable + libnetfilter_queue."""
    if platform.system().lower() != "linux":
        return False, "NFQUEUE is linux-only (windows/macOS need kernel " \
                      "callouts — see contrib/)"
    try:
        import netfilterqueue  # noqa: F401
    except ImportError:
        return False, "python package `NetfilterQueue` + libnetfilter_queue " \
                      "required (pip install NetfilterQueue, apt install " \
                      "libnetfilter-queue1)"
    if os.geteuid() != 0:
        return False, "needs root (CAP_NET_ADMIN) for iptables + NFQUEUE"
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
        self._nfq = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        # EN: flow-key → (event, pkt, ts) pending verdict; decided → verdict
        # FR: clé de flux → (event, pkt, ts) en attente ; décidé → verdict
        self._pending: dict[tuple, list] = {}
        self._decided: dict[tuple, bool] = {}
        self._lock = threading.Lock()
        self._rule_installed = False

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

    def start(self) -> tuple[bool, str]:
        ok, why = available()
        if not ok:
            return False, why
        import subprocess
        try:
            from netfilterqueue import NetfilterQueue
        except ImportError as e:                   # pragma: no cover
            return False, str(e)
        try:
            self._nfq = NetfilterQueue()
            self._nfq.bind(_QUEUE_NUM, self._verdict_cb)
        except Exception as e:                     # noqa: BLE001
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
        for c in cmds:
            try:
                subprocess.run(c, timeout=10, check=False,
                               capture_output=True)
            except OSError as e:
                self.stop()
                return False, f"iptables failed: {e}"
        self._rule_installed = True
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="snitch-askmode")
        self._thread.start()
        return True, ""

    def _run(self) -> None:
        try:
            self._nfq.run()
        except Exception as e:                     # noqa: BLE001
            logger.warning("askmode nfqueue loop ended: %s", e)
        finally:
            self._running = False

    def stop(self) -> None:
        self._running = False
        try:
            if self._nfq is not None:
                self._nfq.unbind()
        except Exception:                          # noqa: BLE001
            pass
        if self._rule_installed:
            import subprocess
            subprocess.run(["iptables", "-w", "-D", "OUTPUT", "-j",
                            "NFQUEUE", "--queue-num", str(_QUEUE_NUM)],
                           timeout=10, check=False, capture_output=True)
            self._rule_installed = False
        with self._lock:
            self._pending.clear()
            self._decided.clear()

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

    def _verdict_cb(self, pkt) -> None:
        try:
            payload = pkt.get_payload()
            key = self._flow_key(payload)
            if key is None:
                pkt.accept()
                return
            with self._lock:
                verdict = self._decided.get(key)
            if verdict is not None:
                (pkt.accept if verdict else pkt.drop)()
                return
            # EN: Pending table bounded — overflow accepts (fail-open on
            #     capacity, documented; timeout policy is separate).
            # FR: Table bornée — débordement accepte (fail-open capacitaire,
            #     documenté ; la politique de timeout est à part).
            with self._lock:
                if len(self._pending) >= _MAX_PENDING:
                    pkt.accept()
                    return
                ev = threading.Event()
                self._pending[key] = [ev, pkt, time.monotonic()]
            self._on_ask({"type": "ASK_VERDICT", "remote_ip": key[0],
                          "remote_port": key[1], "proto": key[2],
                          "timeout_s": int(self._timeout)})
            if not ev.wait(self._timeout):
                with self._lock:
                    self._pending.pop(key, None)
                    self._decided[key] = self._failopen
                (pkt.accept if self._failopen else pkt.drop)()
        except Exception:                          # noqa: BLE001
            try:
                pkt.accept()                       # EN: never wedge the host
            except Exception:                      # noqa: BLE001
                pass

    def decide(self, remote_ip: str, remote_port: int, proto: str,
               allow: bool) -> bool:
        """EN: API entry — verdict for a pending flow; returns False if the
        flow already timed out. / FR: Entrée API — verdict pour un flux en
        attente ; False si le flux a déjà expiré."""
        key = (remote_ip, int(remote_port), (proto or "TCP").upper())
        with self._lock:
            ent = self._pending.pop(key, None)
            self._decided[key] = bool(allow)
        if ent is None:
            return False
        ev, pkt, _ = ent
        try:
            (pkt.accept if allow else pkt.drop)()
        except Exception:                          # noqa: BLE001
            pass
        ev.set()
        return True

    def status(self) -> dict:
        with self._lock:
            return {"running": self._running,
                    "queue": _QUEUE_NUM if self._rule_installed else None,
                    "pending": len(self._pending),
                    "decided": len(self._decided),
                    "timeout_s": self._timeout,
                    "failopen": self._failopen}
