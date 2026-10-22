"""
EN: Hardware performance counters — the user-mode, dependency-free slice
    of "PMU anomaly detection". perf_event_open(2) is a plain syscall:
    no kernel module, no perf binary needed. We attach per-PID counters
    (cycles, instructions, cache-misses, task-clock) for a bounded window
    and report the ratios.

    What it honestly buys us: a cryptominer running stratum shows a
    *sustained* high instructions-per-second rate with regular IPC — the
    perf numbers corroborate MINING_SUSPECT beyond a one-shot cpu_percent.
    Anything deeper (speculation anomalies, branch-miss forensics) stays
    research — documented as such.

    Honest gates: /proc/sys/kernel/perf_event_paranoid must allow per-
    process counting (≤2 for own processes, ≤1 for all processes); a
    refusal returns available=False, never a silent zero.

FR: Compteurs matériels — la tranche user-mode sans dépendance de la
    « détection d'anomalies PMU ». perf_event_open(2) est un simple
    syscall : ni module noyau, ni binaire perf. On attache des compteurs
    par PID (cycles, instructions, cache-misses, task-clock) pendant une
    fenêtre bornée et on rapporte les ratios.

    Ce que ça apporte honnêtement : un mineur stratum montre un débit
    d'instructions *soutenu* avec un IPC régulier — les chiffres perf
    corroborent MINING_SUSPECT au-delà d'un cpu_percent instantané. Tout
    le reste (anomalies de spéculation, forensique des branches) reste en
    recherche — documenté comme tel.
"""

from __future__ import annotations

import ctypes
import fcntl
import os
import platform
import struct
import time

_SYS_PERF_EVENT_OPEN = 298                    # EN: x86_64/aarch64 number / FR: numéro x86_64/aarch64
_IOC_ENABLE = 0x2400                          # EN: PERF_EVENT_IOC_ENABLE / FR: idem
_IOC_DISABLE = 0x2401                         # EN: PERF_EVENT_IOC_DISABLE / FR: idem

# EN: perf_event_attr — only the head fields matter; kernels pad/truncate
#     by attr.size. flags bit0 = disabled (counter starts paused).
# FR: perf_event_attr — seuls les champs de tête comptent ; le noyau
#     ajuste selon attr.size. flags bit0 = disabled (compteur en pause).
class _Attr(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint32), ("size", ctypes.c_uint32),
                ("config", ctypes.c_uint64), ("sample", ctypes.c_uint64),
                ("sample_type", ctypes.c_uint64),
                ("read_format", ctypes.c_uint64), ("flags", ctypes.c_uint64),
                ("wakeup", ctypes.c_uint32), ("bp_type", ctypes.c_uint32),
                ("bp_addr", ctypes.c_uint64), ("bp_len", ctypes.c_uint64),
                ("branch_sample_type", ctypes.c_uint64),
                ("sample_regs_user", ctypes.c_uint64),
                ("sample_stack_user", ctypes.c_uint32),
                ("clock", ctypes.c_int32),
                ("sample_regs_intr", ctypes.c_uint64),
                ("aux_watermark", ctypes.c_uint32),
                ("sample_max_stack", ctypes.c_uint16),
                ("reserved", ctypes.c_uint16)]

_TYPE_HW, _TYPE_SW = 0, 1
_CNT = {"cycles": (_TYPE_HW, 0), "instructions": (_TYPE_HW, 1),
        "cache_misses": (_TYPE_HW, 3), "task_clock_ms": (_TYPE_SW, 1)}

_libc = None


def _open(attr_type: int, config: int, pid: int) -> int:
    """EN: perf_event_open(type, config, pid, cpu=-1, group=-1, flags=0).
    FR: perf_event_open(type, config, pid, cpu=-1, groupe=-1, flags=0)."""
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(None, use_errno=True)
    attr = _Attr()
    attr.type = attr_type
    attr.size = ctypes.sizeof(_Attr)
    attr.config = config
    attr.flags = 1                             # EN: start disabled / FR: démarre en pause
    fd = _libc.syscall(_SYS_PERF_EVENT_OPEN, ctypes.byref(attr),
                     pid, -1, -1, 0)
    if fd < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return fd


def available() -> tuple[bool, str]:
    """EN: Honest gate — Linux + perf_event_paranoid permissive enough.
    FR: Verrou honnête — Linux + perf_event_paranoid assez permissif."""
    if platform.system().lower() != "linux":
        return False, "linux only"
    try:
        level = int(open("/proc/sys/kernel/perf_event_paranoid").read())
    except (OSError, ValueError):
        return True, ""                          # EN: can't read → try anyway / FR: illisible → on tente
    if level > 2:
        return False, f"perf_event_paranoid={level} blocks unprivileged use"
    if level > 1 and os.geteuid() != 0:
        return False, f"perf_event_paranoid={level} needs root for foreign PIDs"
    return True, ""


def sample(pid: int, seconds: float = 1.5) -> dict:
    """EN: Count cycles/instructions/cache-misses for `pid` over `seconds`.
    Returns {ok, ipc, instr_per_s, cache_miss_per_s, cpu_ms} — all rates
    normalized by elapsed task-clock ms so partial-window runs compare.
    FR: Compte cycles/instructions/cache-misses pour `pid` sur `seconds`.
    Renvoie {ok, ipc, instr_per_s, cache_miss_per_s, cpu_ms} — taux
    normalisés par task-clock pour comparer entre fenêtres."""
    ok, why = available()
    if not ok:
        return {"ok": False, "error": why}
    seconds = max(0.2, min(float(seconds), 10.0))
    fds: dict[str, int] = {}
    try:
        for name, (t, c) in _CNT.items():
            try:
                fds[name] = _open(t, c, pid)
            except OSError as e:
                if e.errno == 3:                 # EN: ESRCH — pid gone / FR: pid disparu
                    return {"ok": False, "error": "process exited"}
                raise
        for fd in fds.values():
            fcntl.ioctl(fd, _IOC_ENABLE)
        time.sleep(seconds)
        for fd in fds.values():
            fcntl.ioctl(fd, _IOC_DISABLE)
        vals = {n: struct.unpack("q", os.read(fd, 8))[0]
                for n, fd in fds.items()}
    except OSError as e:
        return {"ok": False, "error": str(e)[:120]}
    finally:
        for fd in fds.values():
            try:
                os.close(fd)
            except OSError:
                pass
    ms = max(vals["task_clock_ms"] / 1e6, 1.0)   # EN: task-clock is ns / FR: task-clock en ns
    cycles = vals["cycles"] or 1
    return {
        "ok": True, "pid": pid, "window_s": seconds,
        "instructions": vals["instructions"],
        "instr_per_s": round(vals["instructions"] / ms * 1000),
        "cache_miss_per_s": round(vals["cache_misses"] / ms * 1000),
        "ipc": round(vals["instructions"] / cycles, 3),
        "cpu_ms": round(ms, 1),
    }
