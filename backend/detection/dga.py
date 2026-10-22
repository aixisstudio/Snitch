"""
Snitch — DGA / suspicious-domain heuristics (pure Python, local-only) /
heuristiques anti-DGA (pur Python, local).

EN: Domain-generation-algorithm detection without any external lookup —
    DNS names and TLS SNIs are scored on pure lexical features that
    separate human-chosen domains from algorithmically generated ones:

      * per-label Shannon entropy     — dictionary words sit ~2.3–3.1
        bits/char, random strings sit 3.8+
      * vowel ratio                   — pronounceable names keep 25–55 %
        vowels; random consonant soups don't
      * longest consonant run         — real words rarely stack 5+
      * digit ratio                   — mixed alnum noise trips it
      * label count + length          — DGA C2s favor deep, long names

    A name only flags when entropy AND shape agree, so `duckduckgo`,
    `amazonaws` or `akamaihd` stay quiet while `xj3kq9zw.example` and
    `qwxzjkvbtp` trip. Honest limits: this is a HEURISTIC — no WHOIS, no
    registration-age data, no online reputation. Fresh domains can't be
    dated locally; only the lexical smell is scored.

    Public surface: `score(name)` → {"score", "reasons", "label"} | None
    (None = input not usable — IP literal, single label, idna noise).

FR: Détection de domaines générés algorithmiquement sans aucune requête
    externe — les noms DNS et SNI TLS sont notés sur des caractéristiques
    lexicales pures (entropie, ratio de voyelles, suites de consonnes,
    chiffres, profondeur). Un nom ne déclenche que si l'entropie ET la
    forme concordent — les vrais services restent silencieux. Limites
    honnêtes : HEURISTIQUE locale, sans WHOIS ni âge d'enregistrement.
"""

from __future__ import annotations

import math
import re
from typing import Optional

_LABEL_RE = re.compile(r"^[a-z0-9-]+$")
_VOWELS = set("aeiou")
# EN: Public-suffix-ish second labels that legitimately carry random
#     left-hand labels — skip scoring the LEFT label for these parents.
# FR: Suffixes publics dont les labels à gauche sont légitimement
#     aléatoires (CDN/cloud) — on ne note pas le label gauche.
_SKIP_LEFT = {"amazonaws", "azure", "cloudfront", "akamaized", "akamai",
            "akamaihd", "fastly", "cloudflare", "googleusercontent",
            "fbcdn", "edgesuite", "edgekey", "azurewebsites"}


def _entropy(s: str) -> float:
    """EN: Shannon entropy in bits/char over the label alphabet.
    FR: Entropie de Shannon en bits/caractère sur le label."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _consonant_run(s: str) -> int:
    """EN: Longest run of consonants (digits count as consonants).
    FR: Plus longue suite de consonnes (chiffres comptés)."""
    best = run = 0
    for ch in s:
        if ch not in _VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def score(name: str) -> Optional[dict]:
    """EN: Score one hostname for DGA-ness. Returns a finding dict when
    suspicious enough to flag, None when clean or unscorable.

    Thresholds tuned for near-zero false positives on the top-1M shape:
    needs entropy ≥3.4 PLUS a shape anomaly (unpronounceable, stacked
    consonants, digit noise) or entropy ≥4.0 alone. Labels shorter than
    10 chars are ignored — short domains can't be judged lexically.

    FR: Note l'aspect DGA d'un nom. Renvoie un finding quand assez
    suspect, None sinon. Il faut entropie ≥3.4 ET une anomalie de forme,
    ou ≥4.0 seule. Labels <10 caractères ignorés."""
    if not name or "." not in name:
        return None
    name = name.rstrip(".").lower()
    if name.replace(".", "").isdigit() or ":" in name:
        return None                              # EN: IP literal / FR: IP
    labels = [l for l in name.split(".") if l]
    if len(labels) < 2:
        return None

    # EN: Score the deepest "interesting" label — usually the registrable
    #     part (labels[-2]); CDN parents get their LEFT label skipped.
    # FR: On note le label « intéressant » — en général le registrable ;
    #     les parents CDN sautent le label de gauche.
    idx = len(labels) - 2
    if labels[idx] in _SKIP_LEFT and len(labels) >= 3:
        idx = len(labels) - 3
    cand = labels[idx]
    if len(cand) < 10:
        return None

    ent = _entropy(cand)
    vowels = sum(1 for c in cand if c in _VOWELS) / len(cand)
    digits = sum(1 for c in cand if c.isdigit()) / len(cand)
    run = _consonant_run(cand)

    reasons: list[str] = []
    if vowels < 0.15:
        reasons.append("almost no vowels")
    if run >= 5:
        reasons.append(f"{run}-consonant run")
    if digits > 0.2:
        reasons.append("digit-heavy")
    if len(labels) >= 4:
        reasons.append("deeply nested")

    score = 0.0
    if ent >= 4.0:
        score = 1.0
        reasons.insert(0, f"entropy {ent:.1f} bits/char")
    elif ent >= 3.4 and reasons:
        score = 0.7
        reasons.insert(0, f"entropy {ent:.1f} bits/char")
    else:
        return None

    # EN: Extra weight when the name is also long and nested — classic
    #     C2 fingerprint. / FR: Poids supplémentaire si long + imbriqué.
    if len(cand) >= 20:
        score = min(1.0, score + 0.1)
    return {"score": round(score, 2),
            "entropy": round(ent, 2),
            "label": cand,
            "reasons": reasons}
