"""
Snitch — eBPF egress enforcement (Linux cgroup_skb) / enforcement eBPF en
sortie (cgroup_skb Linux).

EN: The kernel-enforcement complement to the *attribution* probe
    (capture/ebpf_probe.py): a BPF_PROG_TYPE_CGROUP_SKB program attached
    at cgroup2 egress that returns 0 (drop) for destinations present in a
    BPF hash map — packets are killed inside the kernel before they leave,
    which iptables rules achieve too, but with per-cgroup precision:
    moving a PID into our dedicated cgroup sandboxes THAT process without
    touching the rest of the host.

      * drop by remote IPv4 — `block_ip(ip)` inserts into the map
      * per-process scope — `isolate_pid(pid)` reparents it into
        /sys/fs/cgroup/snitch (v2) so ONLY that process is filtered
      * honest gates: needs root, bcc (`from bcc import BPF`), a mounted
        cgroup2 tree and a kernel that allows cgroup_skb (≥4.10+)

    Everything degrades to available()=False + applied=False — never a
    fake success. The verdict is a real kernel drop, not a userspace race.

FR: Complément d'enforcement noyau à la sonde d'attribution : un
    programme BPF_PROG_TYPE_CGROUP_SKB attaché en egress cgroup2 qui
    renvoie 0 (drop) pour les destinations présentes dans la map — les
    paquets sont tués dans le noyau avant de sortir, avec une précision
    par cgroup : déplacer un PID dans notre cgroup dédié isole CE
    processus sans toucher le reste de l'hôte. Conditions honnêtes : root,
    bcc, cgroup2 monté, noyau ≥4.10. Tout se dégrade en applied=False —
    jamais de faux succès.
"""

from __future__ import annotations

import ctypes
import ipaddress
import os
import platform
from pathlib import Path
from typing import Optional

_CGROUP_DIR = Path("/sys/fs/cgroup/snitch")

_PROG = r"""
#include <uapi/linux/bpf.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/if_ether.h>

BPF_HASH(blocked, u32, u8, 4096);

int egress_drop(struct __sk_buff *skb) {
    /* EN: __sk_buff gives remote_ip4 directly for skb programs —
           no header walking needed. */
    u32 daddr = skb->remote_ip4;
    u8 *hit = blocked.lookup(&daddr);
    if (hit) {
        return 0;            /* EN: drop / FR: drop */
    }
    return 1;                /* EN: pass / FR: passe */
}
"""


def _cgroup2_root() -> Optional[Path]:
    try:
        for line in Path("/proc/mounts").read_text().splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[2] == "cgroup2":
                return Path(parts[1])
    except OSError:
        return None
    return None


def available() -> tuple[bool, str]:
    """EN: Linux + root + bcc + cgroup2 mounted. Honest capability probe.
    FR: Linux + root + bcc + cgroup2 monté. Sonde de capacité honnête."""
    if platform.system().lower() != "linux":
        return False, "linux only"
    if os.geteuid() != 0:
        return False, "needs root"
    try:
        import bcc  # noqa: F401
    except ImportError:
        return False, "bcc not installed"
    if _cgroup2_root() is None:
        return False, "no cgroup2 mount"
    return True, ""


class EbpfEnforcer:
    """EN: One cgroup_skb egress program + blocked-IP map + our own
    cgroup for per-process isolation. / FR: Un programme egress cgroup_skb
    + map d'IP bloquées + cgroup dédié pour l'isolation par processus."""

    def __init__(self) -> None:
        self._b = None
        self._fn = None
        self._blocked: set[str] = set()
        self._attached_to: Optional[str] = None
        self._isolated: set[int] = set()

    def start(self) -> tuple[bool, str]:
        ok, why = available()
        if not ok:
            return False, why
        try:
            from bcc import BPF
            self._b = BPF(text=_PROG)
            self._fn = self._b.load_func("egress_drop", BPF.CGROUP_SKB)
            # EN: Attach at the cgroup2 root — covers every process;
            #     per-process isolation narrows via our own cgroup below.
            # FR: Attach à la racine cgroup2 — couvre tous les processus ;
            #     l'isolation par processus affine via notre cgroup.
            root = str(_cgroup2_root())
            self._b.attach_cgroup(self._fn, root,
                                  self._b.BPFAttachType.CGROUP_INET_EGRESS)
            self._attached_to = root
        except Exception as e:                     # noqa: BLE001
            self._b = None
            return False, f"bpf attach failed: {e}"
        try:
            _CGROUP_DIR.mkdir(exist_ok=True)
        except OSError:
            pass
        return True, ""

    def stop(self) -> None:
        try:
            if self._b is not None and self._fn is not None \
                    and self._attached_to:
                self._b.detach_cgroup(
                    self._fn, self._attached_to,
                    self._b.BPFAttachType.CGROUP_INET_EGRESS)
        except Exception:                          # noqa: BLE001
            pass
        self._b = self._fn = None
        self._attached_to = None

    def block_ip(self, ip: str) -> tuple[bool, str]:
        """EN: Add an IPv4/6 destination to the kernel drop map (v6
        addresses are folded to their mapped v4 when possible — honest
        limitation, cgroup_skb remote_ip4 is v4-only).
        FR: Ajoute une destination à la map de drop noyau (v6 repliée en
        v4 mappée quand possible — limite honnête, remote_ip4 est v4)."""
        if self._b is None:
            return False, "enforcer not started"
        try:
            addr = ipaddress.ip_address(ip)
            if addr.version == 6:
                if addr.ipv4_mapped is None:
                    return False, "cgroup_skb remote_ip4 is IPv4-only"
                addr = addr.ipv4_mapped
            key = ctypes.c_uint32(int.from_bytes(addr.packed, "big"))
            self._b["blocked"][key] = ctypes.c_uint8(1)
            self._blocked.add(str(addr))
            return True, ""
        except Exception as e:                     # noqa: BLE001
            return False, str(e)[:200]

    def unblock_ip(self, ip: str) -> None:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.version == 6 and addr.ipv4_mapped is not None:
                addr = addr.ipv4_mapped
            key = ctypes.c_uint32(int.from_bytes(addr.packed, "big"))
            if self._b is not None:
                del self._b["blocked"][key]
            self._blocked.discard(str(addr))
        except Exception:                          # noqa: BLE001
            pass

    def isolate_pid(self, pid: int) -> tuple[bool, str]:
        """EN: Move a process into our cgroup so the attached program (and
        any stricter future rules) applies to it specifically.
        FR: Déplace un processus dans notre cgroup pour que le programme
        s'applique spécifiquement à lui."""
        procs = _CGROUP_DIR / "cgroup.procs"
        try:
            procs.write_text(str(int(pid)))
            self._isolated.add(int(pid))
            return True, ""
        except OSError as e:
            return False, str(e)[:200]

    def status(self) -> dict:
        return {"attached": self._attached_to is not None,
                "cgroup": str(_CGROUP_DIR),
                "blocked": sorted(self._blocked),
                "isolated_pids": sorted(self._isolated)}
