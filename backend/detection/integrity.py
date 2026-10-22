"""
EN: Process integrity watch — the user-space slice of "is this process
    what it claims to be?" that is actually implementable without a
    kernel driver:

      1. EXE HASH WATCH — SHA-256 of the executable backing each PID that
         shows network activity. The first hash seen for a path becomes
         the baseline (persisted); a different hash later means the file
         was replaced/patched on disk → BINARY_CHANGED.
      2. NAME/EXE MISMATCH — a process whose display name does not match
         its executable's basename is classic masquerading (malware named
         "svchost" living in %TEMP%) → NAME_MISMATCH.
      3. RWX MEMORY SCAN (Linux only) — anonymous or file-backed regions
         mapped rwxp in /proc/<pid>/maps are the signature of injected
         shellcode / reflective loading → MEM_RWX. Bounded: max 10
         regions reported, known-JIT processes (browsers, node, java,
         electron) are reported at "info" severity instead of warning —
         RWX pages are legitimate there.

    Honest limits, documented to the user:
      * The hash compares FILE-ON-DISK states across launches — detecting
        true in-memory tampering (process hollowing, DLL injection that
        never touches the file) needs driver/memory-forensics tooling,
        which stays on the research roadmap.
      * /proc/<pid>/maps needs ptrace-level privileges — usually the same
        ones packet capture already requires. Access-denied degrades to
        `rwx: None`, never to a crash.
      * Everything is read-only local inspection: no process is modified,
        killed or debugged by this module.

FR: Veille d'intégrité des processus — la partie user-space implémentable
    de « ce processus est-il ce qu'il prétend ? » sans driver noyau :

      1. SURVEILLANCE DU HASH DE L'EXE — SHA-256 de l'exécutable derrière
         chaque PID avec activité réseau. Le premier hash vu pour un
         chemin devient la baseline (persistée) ; un hash différent plus
         tard = fichier remplacé/patché sur disque → BINARY_CHANGED.
      2. MISMATCH NOM/EXE — un processus dont le nom affiché ne correspond
         pas au basename de son exécutable = masquage classique →
         NAME_MISMATCH.
      3. SCAN MÉMOIRE RWX (Linux seulement) — régions rwxp dans
         /proc/<pid>/maps = signature d'injection de shellcode → MEM_RWX.
         Borné : max 10 régions ; les processus à JIT connus (navigateurs,
         node, java, electron) sont signalés en « info » et non
         « warning » — leurs pages RWX sont légitimes.

    Limites honnêtes :
      * Le hash compare les ÉTATS SUR DISQUE entre lancements — détecter
        une altération en mémoire vive (hollowing, injection DLL sans
        toucher au fichier) exige un outil mémoire/noyau, qui reste à la
        roadmap recherche.
      * /proc/<pid>/maps exige des privilèges type ptrace — généralement
        ceux déjà requis par la capture. Un refus dégrade en `rwx: None`.
      * Inspection locale en lecture seule : ce module ne modifie, ne tue
        ni ne débogue aucun processus.
"""

from __future__ import annotations

import hashlib
import os
import platform
import re
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Optional

# EN: Bounded containers — a long-running session must not grow these
#     forever. / FR: Conteneurs bornés — une longue session ne doit pas
#     les faire grossir indéfiniment.
_MAX_CHECKED = 4_000          # (pid, create_time) pairs already inspected
_MAX_PATHS = 2_000            # exe paths with a hash baseline
_MAX_RWX_REGIONS = 10         # regions reported per MEM_RWX alert
_RWX_MIN_SIZE = 64 * 1024     # ignore tiny rwx pages (JIT stubs)

# EN: Processes whose RWX pages are EXPECTED (JIT engines). Reported at
#     "info" so they don't drown real findings — not silently skipped,
#     the user can still see them.
# FR: Processus dont les pages RWX sont ATTENDUES (moteurs JIT). Signalés
#     en « info » pour ne pas noyer les vrais constats — pas ignorés :
#     l'utilisateur peut toujours les voir.
_KNOWN_JIT = {
    "chrome", "chromium", "firefox", "msedge", "brave", "opera", "safari",
    "node", "deno", "bun", "java", "javaw", "dotnet", "electron",
    "code", "slack", "discord", "teams", "spotify", "obsidian",
}

# EN: Name→exe comparison tolerates these decorations so legit cases like
#     "python3" → /usr/bin/python3.11 don't fire.
# FR: La comparaison nom→exe tolère ces décorations pour que des cas
#     légitimes comme « python3 » → /usr/bin/python3.11 n'alertent pas.
_VERSION_SUFFIX = re.compile(r"[\d.\-]+$")


def _sha256_file(path: str, _bufsize: int = 1 << 20) -> Optional[str]:
    """EN: Streaming SHA-256 of a file — None on any failure.
    FR: SHA-256 en flux d'un fichier — None en cas d'échec."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(_bufsize), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def _names_match(name: str, exe_basename: str) -> bool:
    """EN: Loose equality — case-insensitive, strips .exe and trailing
    version numbers ("python3" vs "python3.11", "svchost" vs "svchost.exe").
    FR: Égalité souple — insensible à la casse, retire .exe et les suffixes
    de version (« python3 » vs « python3.11 »)."""
    def _norm(s: str) -> str:
        s = s.lower()
        if s.endswith(".exe"):
            s = s[:-4]
        return _VERSION_SUFFIX.sub("", s)
    return _norm(name) == _norm(exe_basename)


class IntegrityWatcher:
    """EN: Read-only per-process integrity checks, all state bounded.
    FR: Contrôles d'intégrité par processus en lecture seule, état borné."""

    def __init__(self):
        self._lock = threading.Lock()
        self._enabled = True
        self._platform = platform.system().lower()
        # EN: (pid, create_time) → checked — the same long-lived PID is
        #     only inspected once per backend run.
        # FR: (pid, create_time) → vérifié — un même PID durable n'est
        #     inspecté qu'une fois par exécution du backend.
        self._checked: OrderedDict[tuple, float] = OrderedDict()
        # EN: exe path → baseline sha256 persisted across restarts.
        # FR: chemin exe → sha256 de référence persisté entre redémarrages.
        self._baselines: OrderedDict[str, str] = OrderedDict()
        # EN: path → (mtime, sha256) — re-hash only when the file's mtime
        #     changed; hashing a 200 MB binary every packet would be silly.
        # FR: chemin → (mtime, sha256) — re-hash seulement si le mtime a
        #     changé ; hasher 200 Mo à chaque paquet serait absurde.
        self._hash_cache: OrderedDict[str, tuple[float, Optional[str]]] = OrderedDict()
        self._findings: OrderedDict[str, dict] = OrderedDict()   # key → finding

    # ── Config / Configuration ──────────────────────────────────────────────

    def configure(self, enabled: bool) -> None:
        with self._lock:
            self._enabled = bool(enabled)

    @property
    def enabled(self) -> bool:
        with self._lock:
            return self._enabled

    def load_baselines(self, data: dict) -> None:
        with self._lock:
            for path, sha in (data or {}).items():
                if isinstance(path, str) and isinstance(sha, str):
                    self._baselines[path] = sha
            while len(self._baselines) > _MAX_PATHS:
                self._baselines.popitem(last=False)

    def dump_baselines(self) -> dict:
        with self._lock:
            return dict(self._baselines)

    def status(self) -> dict:
        """EN: Capability + activity report for /security/integrity.
        FR: Rapport de capacité + activité pour /security/integrity."""
        with self._lock:
            return {
                "enabled": self._enabled,
                "platform": self._platform,
                "capabilities": {
                    # EN: Hash + name checks work everywhere; RWX maps scan
                    #     is Linux-only (needs /proc).
                    # FR: Hash + nom fonctionnent partout ; le scan RWX est
                    #     Linux seulement (besoin de /proc).
                    "exe_hash_watch": True,
                    "name_mismatch": True,
                    "rwx_scan": self._platform == "linux",
                },
                "checked": len(self._checked),
                "baselines": len(self._baselines),
                "findings": list(self._findings.values())[-50:],
            }

    # ── Per-process checks / Contrôles par processus ────────────────────────

    def check(self, pid: int, name: str = "") -> list[dict]:
        """EN: Run all three checks for one PID. Returns finding dicts
        (empty list when clean/already-checked/unavailable). Never raises.
        FR: Lancer les trois contrôles pour un PID. Retourne des constats
        (liste vide si sain/déjà vérifié/indisponible). Ne lève jamais."""
        if not self.enabled or pid <= 3 or pid == os.getpid():
            return []
        try:
            import psutil
            proc = psutil.Process(pid)
            create_time = proc.create_time()
            key = (pid, create_time)
            with self._lock:
                if key in self._checked:
                    return []
                self._checked[key] = time.time()
                while len(self._checked) > _MAX_CHECKED:
                    self._checked.popitem(last=False)
            name = name or proc.name() or ""
            exe = proc.exe() or ""
        except Exception:
            return []

        findings: list[dict] = []
        if exe:
            findings += self._check_name(name, exe, pid)
            findings += self._check_hash(name, exe, pid)
        if self._platform == "linux":
            findings += self._check_rwx(pid, name)
        for f in findings:
            self._record(f)
        return findings

    def check_many(self, items: list[tuple[int, str]]) -> list[dict]:
        """EN: Batch entry point — one call per drain tick with the new
        (pid, name) pairs seen. Bounded internally.
        FR: Point d'entrée par lot — un appel par tick de vidage avec les
        couples (pid, nom) nouveaux. Borné en interne."""
        out: list[dict] = []
        for pid, name in items[:256]:                 # EN: cap / FR: borne
            findings = self.check(pid, name)
            for f in findings:
                f.setdefault("process", name)
            out += findings
        return out

    # ── Check 1: name vs exe / Contrôle 1 : nom vs exe ─────────────────────

    def _check_name(self, name: str, exe: str, pid: int) -> list[dict]:
        base = Path(exe).name
        if not name or not base or _names_match(name, base):
            return []
        return [{
            "type": "NAME_MISMATCH",
            "severity": "warning",
            "pid": pid,
            "exe": exe,
            "detail": f"process name '{name}' but executable is '{base}'",
        }]

    # ── Check 2: on-disk hash baseline / Contrôle 2 : hash sur disque ──────

    def _hash_for(self, path: str) -> Optional[str]:
        try:
            mtime = os.stat(path).st_mtime
        except OSError:
            return None
        with self._lock:
            cached = self._hash_cache.get(path)
            if cached and cached[0] == mtime:
                return cached[1]
        sha = _sha256_file(path)
        with self._lock:
            self._hash_cache[path] = (mtime, sha)
            while len(self._hash_cache) > _MAX_PATHS:
                self._hash_cache.popitem(last=False)
        return sha

    def _check_hash(self, name: str, exe: str, pid: int) -> list[dict]:
        sha = self._hash_for(exe)
        if not sha:
            return []
        with self._lock:
            baseline = self._baselines.get(exe)
            if baseline is None:
                self._baselines[exe] = sha
                while len(self._baselines) > _MAX_PATHS:
                    self._baselines.popitem(last=False)
                return []
        if baseline == sha:
            return []
        return [{
            "type": "BINARY_CHANGED",
            "severity": "critical",
            "pid": pid,
            "exe": exe,
            "detail": "executable hash changed vs recorded baseline "
                      "(file replaced or patched on disk)",
            "expected": baseline, "actual": sha,
        }]

    # ── Check 3: RWX maps (Linux) / Contrôle 3 : maps RWX (Linux) ──────────

    def _check_rwx(self, pid: int, name: str) -> list[dict]:
        """EN: Scan /proc/<pid>/maps for rwxp regions — the cheap, honest
        subset of memory-injection detection that needs no driver.
        FR: Balayer /proc/<pid>/maps à la recherche de régions rwxp — le
        sous-ensemble honnête et sans driver de la détection d'injection."""
        maps_path = Path(f"/proc/{pid}/maps")
        try:
            lines = maps_path.read_text(errors="replace").splitlines()
        except (OSError, PermissionError):
            return []
        regions: list[dict] = []
        for line in lines:
            parts = line.split(None, 5)
            if len(parts) < 2 or "rwx" not in parts[1]:
                continue
            try:
                start_s, end_s = parts[0].split("-", 1)
                size = int(end_s, 16) - int(start_s, 16)
            except (ValueError, IndexError):
                continue
            if size < _RWX_MIN_SIZE:
                continue
            regions.append({"range": parts[0], "size": size,
                            "backing": (parts[5] if len(parts) > 5 else "anonymous")})
            if len(regions) >= _MAX_RWX_REGIONS:
                break
        if not regions:
            return []
        # EN: JIT processes get "info" — their RWX pages are by design.
        # FR: Les processus JIT reçoivent « info » — leurs pages RWX sont
        #     prévues par conception.
        sev = "info" if (name or "").lower() in _KNOWN_JIT else "warning"
        return [{
            "type": "MEM_RWX",
            "severity": sev,
            "pid": pid,
            "detail": f"{len(regions)} rwx memory region(s) "
                      f"({sum(r['size'] for r in regions) // 1024} KiB total)",
            "regions": regions,
        }]

    # ── Findings log / Journal des constats ────────────────────────────────

    def _record(self, finding: dict) -> None:
        finding = dict(finding)
        finding["ts"] = time.time()
        key = f"{finding['type']}:{finding.get('pid')}:{finding.get('exe','')}"
        with self._lock:
            self._findings[key] = finding
            while len(self._findings) > 200:
                self._findings.popitem(last=False)
