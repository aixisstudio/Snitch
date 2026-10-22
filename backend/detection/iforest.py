"""
Snitch — embedded isolation forest / forêt d'isolation embarquée.

EN: A tiny pure-Python IsolationForest (Liu, Ting & Zhou 2008) — no numpy,
    no ONNX runtime, ~150 lines. Random trees split the training window on
    random feature/value pairs; anomalies isolate in few splits, so the
    score is s = 2^(-E(h)/c(n)) where c(n) is the expected path length of
    an unsuccessful BST search. Honest scope: this is UNSUPERVISED
    statistical outlier scoring on Snitch's own flow summaries — it
    complements the heuristic detectors, it does not replace them and it
    carries no learned notion of "malware" (there are no labels). High
    score = unusual vs this machine's own recent traffic.

    Bounds: n_trees=64, sub-sample 256, training window 4096 summaries,
    re-fit every 256 new samples — all constant-time/memory regardless of
    uptime.

FR: Petite IsolationForest en pur Python (Liu, Ting & Zhou 2008) — sans
    numpy ni ONNX. Des arbres aléatoires découpent la fenêtre d'entraînement
    sur des paires feature/valeur tirées au hasard ; les anomalies
    s'isolent en peu de splits → score s = 2^(-E(h)/c(n)). Portée honnête :
    score statistique non supervisé sur les flux de Snitch — complète les
    détecteurs heuristiques, ne les remplace pas, aucune notion apprise de
    « malware » (pas d'étiquettes). Score élevé = inhabituel vs le trafic
    récent de CETTE machine. Bornes constantes : 64 arbres, échantillon
    256, fenêtre 4096, re-fit tous les 256.
"""

from __future__ import annotations

import math
import random
from typing import Optional


def _c(n: int) -> float:
    """EN: Expected path length of an unsuccessful BST search on n points —
    the normalizer c(n) = 2H(n-1) - 2(n-1)/n.
    FR: Longueur de chemin attendue d'une recherche BST infructueuse sur n
    points — le normaliseur c(n)."""
    if n <= 1:
        return 1.0
    h = math.log(n - 1) + 0.5772156649          # EN: Euler–Mascheroni / FR: Euler–Mascheroni
    return 2.0 * h - 2.0 * (n - 1) / n


class _Node:
    __slots__ = ("feat", "split", "left", "right", "size")

    def __init__(self, size: int):
        self.feat = -1
        self.split = 0.0
        self.left: Optional[_Node] = None
        self.right: Optional[_Node] = None
        self.size = size


class IsolationForest:
    """EN: Bounded isolation forest — fit() on a list of feature vectors,
    score() a new vector to a 0..1 anomaly score (higher = more isolated).
    FR: Forêt d'isolation bornée — fit() sur des vecteurs, score() un
    nouveau vecteur vers un score 0..1 (plus haut = plus isolé)."""

    def __init__(self, n_trees: int = 64, sample: int = 256,
                 max_depth: int = 8, seed: Optional[int] = None):
        self.n_trees = n_trees
        self.sample = sample
        self.max_depth = max_depth
        self._rng = random.Random(seed)
        self._trees: list[_Node] = []

    def fit(self, data: list[list[float]]) -> int:
        """EN: Build the forest on `data`; returns number of trees fitted
        (0 when data is too small to say anything honest).
        FR: Construire la forêt ; nombre d'arbres (0 si données trop rares)."""
        self._trees = []
        if len(data) < 16:
            return 0
        for _ in range(self.n_trees):
            # EN: Fresh subsample per tree (paper-standard) — sharing one
            #     subsample correlated every tree and wasted diversity.
            # FR: Sous-échantillon frais par arbre (standard du papier) —
            #     partager un seul échantillon corrélait tous les arbres.
            sub = data if len(data) <= self.sample else \
                self._rng.sample(data, self.sample)
            self._trees.append(self._build(sub, 0))
        return len(self._trees)

    def _build(self, pts: list[list[float]], depth: int) -> _Node:
        node = _Node(len(pts))
        if len(pts) <= 1 or depth >= self.max_depth:
            return node
        nfeat = len(pts[0])
        # EN: Split only among features with actual variance in this subset.
        #     Constant columns (e.g. the direction placeholder, a fixed
        #     hour) can never separate points — picking them produced
        #     degenerate fat leaves that compressed every score toward 0.5.
        # FR: Ne splitter que sur les features à variance réelle. Les
        #     colonnes constantes ne séparent rien — elles produisaient des
        #     feuilles grasses qui compressaient tous les scores vers 0,5.
        cols = list(zip(*pts))
        cands = [f for f in range(nfeat)
                 if min(cols[f]) != max(cols[f])]
        if not cands:
            return node                            # EN: no split possible
        feat = self._rng.choice(cands)
        col = cols[feat]
        lo, hi = min(col), max(col)
        node.feat = feat
        node.split = self._rng.uniform(lo, hi)
        left = [p for p in pts if p[feat] < node.split]
        right = [p for p in pts if p[feat] >= node.split]
        if not left or not right:
            return node
        node.left = self._build(left, depth + 1)
        node.right = self._build(right, depth + 1)
        return node

    def _path(self, x: list[float], node: _Node, depth: float) -> float:
        """EN: Path length of x in one tree + expected remainder c(size).
        FR: Longueur de chemin de x dans un arbre + reste attendu c(size)."""
        if node.feat < 0 or node.left is None or node.right is None:
            return depth + _c(node.size)
        branch = node.left if x[node.feat] < node.split else node.right
        return self._path(x, branch, depth + 1.0)

    def score(self, x: list[float]) -> float:
        """EN: Anomaly score in [0,1] — s = 2^(-E(h)/c(n)). ~0.5 = average
        point, →1 = isolated outlier, →0 = deeply normal.
        FR: Score d'anomalie dans [0,1]. ~0,5 = point moyen, →1 = isolé."""
        if not self._trees:
            return 0.0
        e_h = sum(self._path(x, t, 0.0) for t in self._trees) / len(self._trees)
        return 2.0 ** (-e_h / _c(self.sample))
