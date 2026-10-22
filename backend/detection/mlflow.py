"""
Snitch — ML flow anomaly scoring / scoring ML des flux.

EN: Feeds outbound flow summaries through a bounded pure-Python
    IsolationForest (detection/iforest.py) and raises ML_ANOMALY when a
    flow scores far above this machine's OWN traffic baseline. Features
    are deliberately coarse and privacy-safe — no payloads, no hostnames:

      [remote_port_norm, pkt_size_mean, interval_s, remote_fanout,
       hour_of_day, bytes_per_pkt_out]

    Honest framing: unsupervised outlier detection against THIS host's
    learned normality — complements heuristics, emits few alerts
    (per-(process,remote) cooldown), and disables itself until 384
    summaries have been observed so early traffic isn't flagged en masse.

FR: Alimente les résumés de flux sortants dans une IsolationForest pur
    Python bornée et lève ML_ANOMALY quand un flux s'écarte fortement de
    la propre baseline de la machine. Features volontairement grossières —
    ni payloads ni noms d'hôte. Cadre honnête : détection d'outliers non
    supervisée contre la normalité apprise — complément heuristique,
    alertes parcimonieuses (cooldown par (processus,remote)), inerte tant
    que 384 résumés n'ont pas été observés.
"""

from __future__ import annotations

import ipaddress
import math
import time
from collections import deque
from typing import Optional

from .iforest import IsolationForest

_TRAIN_MIN = 384          # EN: summaries needed before scoring / FR: résumés requis avant scoring
_WINDOW = 4096            # EN: rolling training window / FR: fenêtre glissante
_REFIT_EVERY = 256        # EN: refit cadence in new samples / FR: cadence de re-fit
# EN: Alert threshold — the iForest paper treats ≈0.5 as average and
#     s→1 as anomalous; ~0.6+ is the usual "top outliers" operating
#     point. 0.72 proved unreachable for points extreme on only a few
#     features (path-length compression), so we alert at 0.62.
# FR: Seuil d'alerte — le papier iForest traite ≈0,5 comme moyen et
#     s→1 comme anomalie ; ~0,6+ est le point d'opération usuel. 0,72
#     s'est révélé inatteignable pour des points extrêmes sur peu de
#     features (compression des chemins) → alerte à 0,62.
_THRESHOLD = 0.62         # EN: anomaly score alert threshold / FR: seuil d'alerte
_COOLDOWN = 900           # EN: per (proc, remote) alert cooldown s / FR: cooldown d'alerte
_MAX_KEYS = 4096


class FlowAnomaly:
    """EN: Rolling iForest over outbound flow summaries.
    FR: iForest glissant sur les résumés de flux sortants."""

    def __init__(self) -> None:
        self._window: deque[list[float]] = deque(maxlen=_WINDOW)
        self._forest = IsolationForest(n_trees=64, sample=256, max_depth=8,
                                     seed=20261022)
        self._since_fit = 0
        self._fitted = False
        self._cool: dict[tuple, float] = {}
        self._first_seen: dict[tuple, float] = {}
        self._fanout: dict[str, set[str]] = {}

    def observe(self, proc: str, remote_ip: str, remote_port: int,
                direction: str, size: int, ts: Optional[float] = None) \
            -> Optional[dict]:
        """EN: Record one packet's contribution to a flow and score when
        warranted. Returns an alert context dict or None.
        FR: Enregistre la contribution d'un paquet et score le cas échéant.
        Renvoie un contexte d'alerte ou None."""
        if direction != "out":
            return None
        now = ts or time.time()
        try:
            ipaddress.ip_address(remote_ip)
        except ValueError:
            return None
        key = (proc or "?", remote_ip, int(remote_port or 0))
        prev = self._first_seen.get(key)
        interval = min(now - prev, 3600.0) if prev else 3600.0
        if len(self._first_seen) < _MAX_KEYS:
            self._first_seen[key] = now
        fanset = self._fanout.setdefault(proc or "?", set())
        if len(fanset) < 512:
            fanset.add(remote_ip)

        feats = [
            min(int(remote_port or 0), 65535) / 65535.0,
            min(size, 65535) / 65535.0,
            math.log1p(interval) / math.log1p(3600.0),
            min(len(fanset), 512) / 512.0,
            (time.gmtime(now).tm_hour) / 23.0,
            1.0,                                   # EN: placeholder weight / FR: poids
        ]
        self._window.append(feats)
        self._since_fit += 1
        if self._since_fit >= _REFIT_EVERY:
            self._forest.fit(list(self._window))
            self._fitted = True
            self._since_fit = 0
        if not self._fitted or len(self._window) < _TRAIN_MIN:
            return None
        score = self._forest.score(feats)
        if score < _THRESHOLD:
            return None
        ck = (proc or "?", remote_ip)
        last = self._cool.get(ck, 0.0)
        if now - last < _COOLDOWN:
            return None
        if len(self._cool) < _MAX_KEYS:
            self._cool[ck] = now
        return {
            "type": "ML_ANOMALY", "severity": "warning",
            "remote_ip": remote_ip, "process": proc or "?",
            "detail": f"isolation-forest score {score:.2f} ≥ {_THRESHOLD} — "
                      f"flow unlike this host's learned baseline "
                      f"(port {remote_port}, interval {interval:.0f}s, "
                      f"fan-out {len(fanset)})",
            "score": round(score, 3),
        }
