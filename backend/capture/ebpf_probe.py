"""
EN: Optional eBPF connect probe (Linux only, opt-in). When the `bcc`
    package and root privileges are present, Snitch attaches kprobes to
    tcp_v4_connect / tcp_v6_connect — the kernel functions performing
    connect() — and streams (pid, comm, dst) events into a small ring.
    The sniffer consults that ring when its psutil socket-table lookup
    misses: short-lived processes (curl, malware droppers) vanish before
    psutil snapshots them, but the kprobe sees every connect() attempt,
    even the ones that fail.

    If bcc/kernel headers/root are missing, the probe reports
    available=False and the pipeline keeps working with psutil only —
    graceful, honest degradation. Nothing is simulated.

    Layout follows iovisor/bcc's tcpconnect.py (Apache-2.0): same kprobes,
    same perf-buffer mechanism, reduced to the fields Snitch needs.

FR: Sonde eBPF optionnelle pour connect() (Linux seulement, opt-in). Quand
    le paquet `bcc` et les droits root sont présents, Snitch attache des
    kprobes à tcp_v4_connect / tcp_v6_connect — les fonctions noyau qui
    réalisent connect() — et streame les événements (pid, comm, dst) vers
    un petit anneau. Le sniffer le consulte quand la table psutil rate :
    les processus courts disparaissent avant l'instantané psutil, mais la
    kprobe voit chaque tentative, même celles qui échouent.
"""

from __future__ import annotations

import ctypes
import ipaddress
import os
import platform
import threading
import time

# EN: Recent connect events keyed by (dst_ip, dst_port) — TTL-bounded.
# FR: Événements connect récents indexés (dst_ip, dst_port) — TTL borné.
_EVENT_TTL = 60.0

# EN: Minimal eBPF program — one kprobe per address family, emitting the
#     connect() destination. tcpconnect.py traces more fields; we need
#     only pid+comm+dst for attribution.
# FR: Programme eBPF minimal — une kprobe par famille, émettant la
#     destination du connect(). tcpconnect.py trace plus de champs ; seuls
#     pid+comm+dst servent à l'attribution.
_BPF_SRC = r"""
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct snitch_evt {
    u32 pid;
    char comm[16];
    u16 dport;
    u8  ipver;
    u8  daddr[16];
};

BPF_PERF_OUTPUT(events);

static int trace_connect(struct pt_regs *ctx, struct sock *sk, int v6) {
    struct snitch_evt ev = {};
    ev.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&ev.comm, sizeof(ev.comm));
    ev.dport = ntohs(sk->__sk_common.skc_dport);
    ev.ipver = v6;
    if (v6) {
        bpf_probe_read_kernel(&ev.daddr, 16,
            (void *)sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
    } else {
        bpf_probe_read_kernel(&ev.daddr, 4,
            (void *)&sk->__sk_common.skc_daddr);
    }
    events.perf_submit(ctx, &ev, sizeof(ev));
    return 0;
}

int kprobe__tcp_v4_connect(struct pt_regs *ctx, struct sock *sk) {
    return trace_connect(ctx, sk, 4);
}
int kprobe__tcp_v6_connect(struct pt_regs *ctx, struct sock *sk) {
    return trace_connect(ctx, sk, 6);
}
"""


class _Event(ctypes.Structure):
    """EN: ctypes mirror of struct snitch_evt for perf-buffer decoding.
    FR: Miroir ctypes de struct snitch_evt pour décoder le perf buffer."""
    _fields_ = [("pid", ctypes.c_uint32), ("comm", ctypes.c_char * 16),
                ("dport", ctypes.c_uint16), ("ipver", ctypes.c_uint8),
                ("daddr", ctypes.c_uint8 * 16)]


class EbpfProbe:
    """EN: Lifecycle + lookup for the connect probe. start() compiles the
    BPF program (needs kernel headers — that is the honest requirement) and
    spawns a poll thread; lookup(ip, port) returns (pid, comm) when a recent
    connect() event matches.
    FR: Cycle de vie + consultation de la sonde. start() compile le
    programme BPF (en-têtes noyau requis — c'est l'exigence honnête) et
    lance un thread de poll ; lookup(ip, port) renvoie (pid, comm) si un
    événement connect() récent correspond."""

    def __init__(self):
        self._bpf = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._events: dict[tuple[str, int], tuple[int, str, float]] = {}
        # EN: (ip,port) pairs seen from ≥2 distinct pids — attribution
        #     there would be a coin flip (any shared 443), so we refuse it.
        # FR: Paires (ip,port) vues depuis ≥2 pids — l'attribution y serait
        #     aléatoire (tout 443 partagé), on la refuse donc.
        self._ambiguous: set[tuple[str, int]] = set()
        self._lock = threading.Lock()
        self._err: str | None = None

    # ── availability / disponibilité ─────────────────────────────────────────

    @staticmethod
    def available() -> tuple[bool, str]:
        """EN: Honest capability check — Linux + root + bcc importable.
        FR: Vérification honnête — Linux + root + bcc importable."""
        if platform.system().lower() != "linux":
            return False, "linux only"
        if os.geteuid() != 0:
            return False, "requires root"
        try:
            import bcc  # noqa: F401
        except ImportError:
            return False, "python3-bcc not installed"
        return True, ""

    def status(self) -> dict:
        ok, why = self.available()
        with self._lock:
            n = len(self._events)
        return {"available": ok, "reason": None if ok else why,
                "active": self._bpf is not None, "events_buffered": n,
                "error": self._err}

    # ── lifecycle / cycle de vie ─────────────────────────────────────────────

    def start(self) -> bool:
        """EN: Compile + attach. Returns False with _err set when the kernel
        can't run the probe (no headers, lockdown, old kernel).
        FR: Compile + attache. False + _err si le noyau refuse (pas
        d'en-têtes, lockdown, noyau ancien)."""
        if self._bpf is not None:
            return True
        ok, why = self.available()
        if not ok:
            self._err = why
            return False
        try:
            from bcc import BPF
            self._bpf = BPF(text=_BPF_SRC)
            self._bpf["events"].open_perf_buffer(self._on_evt)
        except Exception as e:                       # noqa: BLE001
            self._err = str(e)[:200]
            self._bpf = None
            return False
        self._stop.clear()
        self._thread = threading.Thread(target=self._poll, daemon=True,
                                        name="snitch-ebpf")
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop.set()
        self._bpf = None

    def _poll(self) -> None:
        while not self._stop.is_set() and self._bpf is not None:
            try:
                self._bpf.perf_buffer_poll(timeout=500)
            except Exception:                        # noqa: BLE001
                time.sleep(1)

    # ── events / événements ──────────────────────────────────────────────────

    def _on_evt(self, cpu, data, size) -> None:
        ev = _Event.from_buffer_copy(
            ctypes.string_at(data, ctypes.sizeof(_Event)))
        ip = str(ipaddress.ip_address(
            bytes(ev.daddr[:4] if ev.ipver == 4 else ev.daddr)))
        comm = ev.comm.split(b"\x00", 1)[0].decode("utf-8", "replace")
        key = (ip, ev.dport)
        with self._lock:
            prev = self._events.get(key)
            if prev and prev[0] != ev.pid:
                # EN: Two different processes hit the same destination —
                #     never guess which one owns a later packet.
                # FR: Deux processus distincts vers la même destination —
                #     ne jamais deviner lequel émettra le paquet suivant.
                self._ambiguous.add(key)
                self._events.pop(key, None)
            elif key not in self._ambiguous:
                self._events[key] = (ev.pid, comm, time.time())
            # EN: Cheap bound — drop the oldest third past 4096 entries.
            # FR: Borne simple — on jette le tiers le plus vieux après 4096.
            if len(self._events) > 4096:
                items = sorted(self._events.items(), key=lambda kv: kv[1][2])
                self._events = dict(items[len(items) // 3:])
                self._ambiguous &= set(self._events)

    def lookup(self, ip: str, port: int | None) -> tuple[int | None, str | None]:
        """EN: (pid, comm) for a recent connect() to this destination —
        the attribution the socket table misses for short-lived processes.
        FR: (pid, comm) d'un connect() récent vers cette destination —
        l'attribution que la table des sockets rate pour les processus
        courts."""
        if port is None:
            return None, None
        key = (ip, int(port))
        with self._lock:
            if key in self._ambiguous:
                return None, None
            hit = self._events.get(key)
            if not hit:
                return None, None
            pid, comm, ts = hit
            if time.time() - ts > _EVENT_TTL:
                del self._events[key]
                return None, None
            return pid, comm
