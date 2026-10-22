"""
EN: Cryptomining detection — three orthogonal signals, escalating severity
    as they combine. No single signal is enough to accuse a process:

      1. STRATUM PROTOCOL — the cleartext JSON-RPC dialect miners speak to
         pools ("mining.subscribe", "mining.authorize", "mining.notify",
         "mining.set_difficulty", ethash "mining.submit"). Seen in the
         first payload bytes (parser's bounded app_head) → near-certain,
         critical. Encrypted stratum (TLS) is invisible to this, honestly.
      2. POOL PORTS — outbound TCP to well-known mining ports (3333, 5555,
         7777, 14444, 45700…) only raises suspicion when combined with
         sustained high CPU from the same process — alone it false-
         positives on IRC/game traffic.
      3. SUSTAINED CPU — psutil cpu_percent sampled per flagged PID over a
         drain window; a process burning >70% while talking to a pool port
         gets MINING_SUSPECT.

    The optional perf probe (detection/perfprobe.py) adds hardware
    counters (instructions/cycle anomalies) when the kernel allows it.

FR: Détection de cryptominage — trois signaux orthogonaux dont la sévérité
    monte quand ils se combinent. Aucun signal seul n'accuse :

      1. PROTOCOLE STRATUM — le dialecte JSON-RPC en clair des mineurs
         (« mining.subscribe », « mining.authorize », « mining.notify »…)
         vu dans les premiers octets du payload → quasi-certain, critique.
         Le stratum chiffré (TLS) est invisible — honnêtement.
      2. PORTS DE POOLS — TCP sortant vers des ports de minage connus ne
         devient suspect que combiné à une CPU élevée soutenue — seul, il
         faussement positif sur IRC/jeux.
      3. CPU SOUTENUE — cpu_percent psutil échantillonné par PID flagué ;
         >70 % + port de pool = MINING_SUSPECT.
"""

from __future__ import annotations

import threading
import time

# EN: Stratum cleartext markers searched in the first payload bytes —
#     JSON-RPC method names the mining protocol can't hide (cleartext only).
# FR: Marqueurs stratum en clair cherchés dans les premiers octets —
#     noms de méthodes JSON-RPC que le protocole ne peut masquer.
_STRATUM_MARKERS = (
    b'"mining.subscribe"', b'"mining.authorize"', b'"mining.notify"',
    b'"mining.set_difficulty"', b'"mining.submit"', b'"mining.ping"',
    b'mining.subscribe', b'login', b'"blob"', b'"job"', b'"target"',
)

# EN: Strong markers — presence alone is conclusive (the generic ones
#     above like "login"/"job" only count with a mining.* context word).
# FR: Marqueurs forts — concluants seuls (les génériques ne comptent
#     qu'avec un contexte mining.*).
_STRONG = (b'mining.', b'"blob"', b'"job_id"', b'"seed_hash"')

# EN: Well-known stratum/pool TCP ports (xmrig defaults, nanopool,
#     supportxmr, minergate, 2miners…). Port alone never alerts.
# FR: Ports stratum/pool connus (défauts xmrig, nanopool, supportxmr,
#     minergate, 2miners…). Le port seul n'alerte jamais.
_POOL_PORTS = {3333, 4444, 5555, 7777, 8333, 9999, 14433, 14444,
               45560, 45700}

_CPU_THRESHOLD = 70.0        # EN: sustained % to corroborate / FR: % soutenu corroborant
_CPU_WINDOW_S = 30.0         # EN: min observation before accusing / FR: observation min avant accusation
_COOLDOWN = 600.0            # EN: per-process alert cooldown / FR: cooldown par processus
# EN: Bound on the suspect map — corroboration drains 32 per tick, so a
#     flood of distinct (pid, remote) pairs is capped well above the
#     plausible legitimate rate but far below memory concern.
# FR: Borne de la map de suspects — la corroboration draine 32 par tick ;
#     un flot de paires (pid, remote) est borné au-dessus du rythme
#     légitime mais loin de tout souci mémoire.
_MAX_SUSPECTS = 4096


class MinerDetector:
    """EN: Combines stratum signatures, pool ports and sustained CPU into
    MINING_* findings. analyze_packet() is the per-packet entry point;
    cpu_corroborate() is polled from the drain loop for flagged PIDs.
    FR: Combine signatures stratum, ports de pool et CPU soutenue en
    constats MINING_*. analyze_packet() est le point d'entrée par paquet ;
    cpu_corroborate() est appelé depuis la boucle de vidage."""

    def __init__(self):
        self._lock = threading.Lock()
        # EN: (pid, remote) → first-seen ts — pool-port suspects under
        #     observation before CPU corroboration.
        # FR: (pid, remote) → premier ts vu — suspects port-pool en
        #     observation avant corroboration CPU.
        self._suspects: dict[tuple, float] = {}
        self._last_alert: dict[tuple, float] = {}

    def _cooldown_ok(self, key: tuple) -> bool:
        now = time.time()
        with self._lock:
            if now - self._last_alert.get(key, 0) < _COOLDOWN:
                return False
            self._last_alert[key] = now
            return True

    def analyze_packet(self, pkt) -> list[dict]:
        """EN: Per-packet checks — stratum signature in cleartext head,
        pool-port marking for later CPU corroboration.
        FR: Contrôles par paquet — signature stratum dans la tête en clair,
        marquage port-pool pour corroboration CPU ultérieure."""
        out: list[dict] = []
        direction = getattr(pkt, "direction", "out")
        if direction != "out" or pkt.protocol != "TCP":
            return out
        remote = pkt.dst_ip
        proc = pkt.process_name or "unknown"
        pid = pkt.pid

        # EN: Signal 1 — cleartext stratum. Two generic markers OR one
        #     strong mining.* marker → conclusive.
        # FR: Signal 1 — stratum en clair. Deux marqueurs génériques OU un
        #     marqueur mining.* fort → concluant.
        head = getattr(pkt, "app_head", b"") or b""
        if head:
            strong = any(m in head for m in _STRONG)
            generic = sum(1 for m in _STRATUM_MARKERS if m in head)
            if strong or generic >= 2:
                key = ("stratum", pid, remote)
                if self._cooldown_ok(key):
                    out.append({
                        "type": "MINING_STRATUM",
                        "severity": "critical",
                        "process": proc, "pid": pid, "ip": remote,
                        "port": pkt.dst_port,
                        "detail": "cleartext stratum mining protocol "
                                  "observed in payload",
                    })
                return out                       # EN: no need to suspect further

        # EN: Signal 2 — pool port: mark for CPU corroboration, never
        #     enough alone. The suspect map is bounded — a process
        #     sweeping many remotes (scanner, busy proxy) must not grow
        #     it past the drain rate of 32 corroborations/tick.
        # FR: Signal 2 — port de pool : marqué pour corroboration CPU,
        #     jamais suffisant seul. La map est bornée — un processus
        #     balayant beaucoup d'hôtes (scanner, proxy chargé) ne doit
        #     pas la faire croître au-delà du rythme de 32/tick.
        if pkt.dst_port in _POOL_PORTS and pid:
            with self._lock:
                if len(self._suspects) >= _MAX_SUSPECTS:
                    # EN: evict the oldest quarter — stale suspects are
                    #     the least informative anyway.
                    # FR: évincer le quart le plus ancien — les suspects
                    #     périmés sont les moins informatifs.
                    stale = sorted(self._suspects.items(),
                                   key=lambda kv: kv[1])
                    for k, _ in stale[:_MAX_SUSPECTS // 4]:
                        self._suspects.pop(k, None)
                self._suspects.setdefault((pid, remote), time.time())
        return out

    def cpu_corroborate(self) -> list[dict]:
        """EN: Called each drain tick — suspects older than the window get
        a cpu_percent sample; sustained high CPU + pool port → MINING_SUSPECT.
        FR: Appelé à chaque tick — les suspects au-delà de la fenêtre sont
        échantillonnés ; CPU haute soutenue + port de pool → MINING_SUSPECT."""
        out: list[dict] = []
        now = time.time()
        with self._lock:
            due = [(k, ts) for k, ts in self._suspects.items()
                   if now - ts >= _CPU_WINDOW_S]
        try:
            import psutil
        except ImportError:
            return out
        for (pid, remote), _ts in due[:32]:
            with self._lock:
                self._suspects.pop((pid, remote), None)
            try:
                proc = psutil.Process(pid)
                cpu = proc.cpu_percent(interval=0.2)
                name = proc.name()
            except Exception:                        # noqa: BLE001 — process gone
                continue
            if cpu >= _CPU_THRESHOLD and self._cooldown_ok(("suspect", pid, remote)):
                out.append({
                    "type": "MINING_SUSPECT",
                    "severity": "warning",
                    "process": name, "pid": pid, "ip": remote,
                    "detail": f"sustained {cpu:.0f}% CPU while talking to "
                              f"a known mining-pool port",
                })
        return out
