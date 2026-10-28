"""
EN: Process enrichment — cmdline + parent attribution for connections.
    Attribution gives us a pid; users writing rules need more than the
    16-char kernel `comm` to distinguish "node" running an MCP server
    from "node" running their editor. This module resolves, once per
    pid per TTL window:
        cmdline      — full command line (psutil .cmdline(), joined)
        ppid         — parent pid
        parent_name  — parent process name (comm), so a rule can key
                       on the *launcher* of an interpreter process.
    Everything is lazy + TTL-cached: the hot path never touches procfs
    twice per pid per window, and dead/foreign pids fail closed.
FR: Enrichissement processus — cmdline + attribution parente pour les
    connexions. L'attribution donne un pid ; pour écrire des règles il
    faut plus que le `comm` noyau de 16 caractères pour distinguer
    « node » lançant un serveur MCP de « node » lançant l'éditeur.
    Ce module résout, une fois par pid par fenêtre TTL :
        cmdline      — ligne de commande complète (psutil .cmdline())
        ppid         — pid parent
        parent_name  — nom du processus parent (comm), pour qu'une
                       règle puisse viser le *lanceur* d'un interpréteur.
    Tout est paresseux + cache TTL : le chemin chaud ne touche jamais
    procfs deux fois par pid par fenêtre, et les pid morts/étrangers
    échouent silencieusement.
"""

from __future__ import annotations

import threading
import time
from typing import Optional

import psutil

_ENRICH_TTL = 45.0  # seconds — process metadata rarely changes


class ProcEnricher:
    """EN: TTL-cached pid → (cmdline, ppid, parent_name) resolver.
    FR: Résolveur pid → (cmdline, ppid, parent_name) à cache TTL."""

    def __init__(self, ttl: float = _ENRICH_TTL):
        self.ttl = ttl
        self._cache: dict[int, tuple[float, Optional[str], Optional[int], Optional[str]]] = {}
        self._lock = threading.Lock()

    def _resolve(self, pid: int) -> tuple[Optional[str], Optional[int], Optional[str]]:
        cmdline = ppid = parent_name = None
        try:
            proc = psutil.Process(pid)
            try:
                cmdline = " ".join(proc.cmdline()) or None
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            try:
                ppid = proc.ppid()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            if ppid:
                try:
                    parent_name = psutil.Process(ppid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return cmdline, ppid, parent_name

    def enrich(self, pid: Optional[int]) -> tuple[Optional[str], Optional[int], Optional[str]]:
        """EN: (cmdline, ppid, parent_name) for pid, cached for `ttl`.
        FR: (cmdline, ppid, parent_name) du pid, mis en cache `ttl`."""
        if not pid:
            return None, None, None
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(pid)
            if hit and now - hit[0] < self.ttl:
                return hit[1], hit[2], hit[3]
            # EN: Bound the cache — pids churn, keep only live window.
            # FR: Borner le cache — les pid tournent, garder la fenêtre.
            if len(self._cache) > 4096:
                self._cache = {p: v for p, v in self._cache.items()
                               if now - v[0] < self.ttl}
        resolved = self._resolve(pid)
        with self._lock:
            self._cache[pid] = (now, *resolved)
        return resolved

    def parent_chain(self, pid: Optional[int], depth: int = 8) -> list[tuple[int, str]]:
        """EN: Walk up the parent chain → [(ppid, name), ...], root-first
            order is NOT guaranteed — listed nearest-parent first. Used
            by agent-audit views, not the packet hot path.
        FR: Remonte la chaîne des parents → [(ppid, nom), ...], du parent
            le plus proche vers la racine. Pour les vues d'audit agent,
            pas le chemin chaud."""
        chain: list[tuple[int, str]] = []
        seen: set[int] = set()
        cur = pid
        for _ in range(depth):
            if not cur or cur in seen:
                break
            seen.add(cur)
            try:
                proc = psutil.Process(cur)
                ppid = proc.ppid()
                if not ppid or ppid in seen:
                    break
                chain.append((ppid, psutil.Process(ppid).name()))
                cur = ppid
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
        return chain
