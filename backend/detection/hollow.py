"""
Snitch — process-hollowing evidence check / vérification de hollowing.

EN: The missing disk↔memory half of integrity.py: read the FILE-BACKED
    executable pages straight out of /proc/<pid>/mem and compare their
    SHA-256 to the same ranges on disk. Legit processes are byte-identical
    there (.text is read-only file-mapped code — the kernel never rewrites
    it); a mismatch means the image was patched after load — process
    hollowing, hot-patch injection or manual code carving. Relocation
    noise lives in writable mappings which we deliberately skip (only
    r-xp/r--p file-backed regions of the exe itself are compared).

    Honest bounds:
      * Linux only — /proc/pid/mem requires ptrace-equivalent rights
        (root, or CAP_SYS_PTRACE; yama scope can block same-uid reads —
        reported honestly);
      * on-demand scan, never continuous — reading megabytes of foreign
        pages is expensive; the API endpoint triggers it per PID;
      * bounded: ≤64 MiB of compared bytes, first 4096 differing pages
        reported, always returns a dict, never raises.

FR: La moitié disque↔mémoire manquante d'integrity.py : lit les pages
    fichier-mappées de l'exécutable dans /proc/<pid>/mem et compare leur
    SHA-256 aux mêmes zones sur disque. Un processus légitime y est
    identique octet pour octet ; un écart = image patchée après chargement
    (hollowing, injection, carving). Le bruit de relocation vit dans les
    mappings accessibles en écriture — ignorés volontairement (on ne
    compare que les régions r-xp/r--p fichier de l'exe). Linux seulement,
    scan à la demande, borné, ne lève jamais.
"""

from __future__ import annotations

import hashlib
import os
import platform
from pathlib import Path
from typing import Optional

_MAX_BYTES = 64 << 20
_MAX_DIFFS = 4096


def available() -> tuple[bool, str]:
    if platform.system().lower() != "linux":
        return False, "/proc/<pid>/mem is linux-only"
    return True, ""


def _exe_regions(pid: int, exe: str) -> list[tuple[int, int]]:
    """EN: File-backed read/exec regions of the exe itself from maps —
    returns [(start, end)] virtual ranges. Only the exe's own mappings:
    library files are checked separately by the Merkle watcher.
    FR: Régions fichier read/exec de l'exe lui-même — plages virtuelles
    [(début, fin)]. Seules les mappings de l'exe : les bibliothèques sont
    couvertes par la veille Merkle."""
    regions = []
    maps = Path(f"/proc/{pid}/maps")
    try:
        for line in maps.read_text(errors="replace").splitlines():
            parts = line.split()
            if len(parts) < 6 or parts[5] != exe:
                continue
            perms = parts[1]
            if "w" in perms:                       # EN: writable → skip
                continue                           # FR: writable → ignoré
            if "r" not in perms:
                continue
            start, end = (int(x, 16) for x in parts[0].split("-"))
            regions.append((start, end))
    except OSError:
        pass
    return regions


def _read_mem(pid: int, start: int, length: int) -> Optional[bytes]:
    try:
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as m:
            m.seek(start)
            return m.read(length)
    except OSError:
        return None


def _read_file_range(path: str, off: int, length: int) -> Optional[bytes]:
    try:
        with open(path, "rb") as f:
            f.seek(off)
            return f.read(length)
    except OSError:
        return None


def hollow_check(pid: int) -> dict:
    """EN: Compare the exe's file-backed memory pages with their disk
    bytes. Returns {ok, matched_bytes, mismatches[], error?}. A mismatch
    lists {vaddr, file_off, size} — where memory ≠ disk.
    FR: Compare les pages mémoire fichier-mappées de l'exe aux octets
    disque. Renvoie {ok, matched_bytes, mismatches[], error?}."""
    ok, why = available()
    if not ok:
        return {"ok": False, "error": why}
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError as e:
        return {"ok": False, "error": f"cannot resolve exe: {e}"}
    regions = _exe_regions(pid, exe)
    if not regions:
        return {"ok": False, "error": "no file-backed exe regions "
                                      "(process gone or mem unreadable)",
                "exe": exe}
    # EN: Map file offsets — /proc/pid/maps column 3 is the file offset.
    # FR: Offsets fichier — la colonne 3 de /proc/pid/maps est l'offset.
    offsets: dict[tuple[int, int], int] = {}
    try:
        for line in Path(f"/proc/{pid}/maps").read_text(
                errors="replace").splitlines():
            parts = line.split()
            if len(parts) < 6 or parts[5] != exe or "w" in parts[1]:
                continue
            s, e = (int(x, 16) for x in parts[0].split("-"))
            offsets[(s, e)] = int(parts[2], 16)
    except OSError:
        pass

    mismatches: list[dict] = []
    compared = 0
    for start, end in regions:
        length = end - start
        if length <= 0 or compared >= _MAX_BYTES:
            continue
        step = min(length, _MAX_BYTES - compared, 1 << 20)
        mem = _read_mem(pid, start, step)
        if mem is None:
            return {"ok": False, "exe": exe,
                    "error": "cannot read process memory (yama/ptrace "
                             "restrictions or process exited)"}
        disk = _read_file_range(exe, offsets.get((start, end), 0), step)
        if disk is not None and len(mem) == len(disk):
            compared += len(mem)
            if hashlib.sha256(mem).digest() != \
                    hashlib.sha256(disk).digest():
                # EN: Narrow to the first differing 4 KiB page.
                # FR: Restreindre à la première page de 4 Kio différente.
                for off in range(0, len(mem), 4096):
                    mseg, dseg = mem[off:off + 4096], disk[off:off + 4096]
                    if mseg != dseg:
                        mismatches.append({
                            "vaddr": hex(start + off),
                            "file_off": hex(
                                offsets.get((start, end), 0) + off),
                            "size": len(mseg)})
                        if len(mismatches) >= _MAX_DIFFS:
                            break
    return {
        "ok": True, "pid": pid, "exe": exe,
        "regions": len(regions), "compared_bytes": compared,
        "clean": not mismatches,
        "mismatches": mismatches,
        "verdict": ("executable memory differs from disk — hollowing or "
                    "in-memory patching suspected")
                   if mismatches else
                   "memory matches disk image",
    }
