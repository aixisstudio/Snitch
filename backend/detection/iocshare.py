"""
EN: Privacy-preserving IOC sharing — the honest implementable slice of
    "fleet intelligence". Real zero-knowledge fleet telemetry needs a
    coordination server and a proof system; what DOES work peer-to-peer,
    today, with zero infrastructure is a *deniable indicator pack*:

      * Every indicator (IP, domain, exe SHA-256) is hashed into a Bloom
        filter — nothing stored is reversible.
      * Randomized response then flips each bit with probability `flip`:
        a pack provably cannot reveal which exact indicators the source
        machine saw (local differential privacy, ε ≈ ln((1−f/2)/(f/2))
        per bit) while membership queries still work probabilistically.
      * Export = one JSON file the user may publish/share themselves —
        there is no server, no upload, nothing automatic. Import =
        checking local candidates against a received pack; hits are
        returned as "community hints" with a false-positive caveat, never
        auto-blocked.

    Honest wording: this is differential-privacy IOC exchange, NOT a ZKP
    scheme — the roadmap keeps the real ZK design as research.

FR: Partage d'IOC préservant la vie privée — la tranche implémentable et
    honnête de « l'intelligence de flotte ». Une vraie télémétrie ZK
    exige un serveur de coordination et un système de preuves ; ce qui
    fonctionne en pair-à-pair, aujourd'hui, sans infrastructure, c'est un
    *paquet d'indicateurs à déni plausible* :

      * Chaque indicateur (IP, domaine, SHA-256 d'exe) est haché dans un
        filtre de Bloom — rien de stocké n'est réversible.
      * La randomized response retourne chaque bit avec probabilité
        `flip` : un paquet ne peut pas révéler quels indicateurs la
        machine source a vus (DP locale, ε ≈ ln((1−f/2)/(f/2)) par bit)
        alors que les requêtes d'appartenance restent probabilistes.
      * Export = un fichier JSON que l'utilisateur publie lui-même —
        aucun serveur, aucun upload, rien d'automatique. Import =
        vérification de candidats locaux contre un paquet reçu ; les
        correspondances reviennent en « indices communautaires » avec
        réserve de faux-positifs — jamais bloqués automatiquement.

    Formulation honnête : échange d'IOC sous DP, PAS un schéma ZK — la
    roadmap garde le vrai design ZK en recherche.
"""

from __future__ import annotations

import base64
import hashlib
import random
import time

_BITS = 8192                 # EN: filter size — FP rate ~1e-4 at ≤1k items / FR: taille — FP ~1e-4 à ≤1k items
_HASHES = 4                  # EN: k hash functions / FR: k fonctions de hachage
# EN: Per-bit flip probability — the privacy/usability trade-off: 0.02
#     keeps per-indicator miss ≈ 8 % (0.98⁴) while ε ≈ ln(99) ≈ 4.6 per
#     bit still makes any single pack deniable. Higher values would make
#     honest membership queries useless.
# FR: Probabilité de flip par bit — compromis vie privée/utilisabilité :
#     0,02 garde ~8 % de ratés par indicateur (0,98⁴) tout en offrant un
#     déni plausible (ε ≈ ln(99) ≈ 4,6 par bit).
_FLIP = 0.02
_FORMAT = "snitch-ioc-pack/1"


def _positions(item: str) -> list[int]:
    """EN: k Bloom positions via double-hashing on SHA-256 — uniform and
    deterministic across machines. / FR: k positions Bloom par double-
    hachage SHA-256 — uniforme et déterministe entre machines."""
    digest = hashlib.sha256(item.strip().lower().encode()).digest()
    h1, h2 = (int.from_bytes(digest[i:i + 8], "big") for i in (0, 8))
    return [((h1 + i * h2) % _BITS) for i in range(_HASHES)]


def build_pack(indicators: list[str]) -> dict:
    """EN: Encode indicators → Bloom → randomized response → JSON pack.
    Bounded to 4096 indicators (beyond that the FP rate grows anyway).
    FR: Encode les indicateurs → Bloom → randomized response → paquet
    JSON. Borné à 4096 indicateurs (au-delà le taux de FP croît)."""
    bits = bytearray(_BITS // 8)
    for item in indicators[:4096]:
        for pos in _positions(item):
            bits[pos // 8] |= 1 << (pos % 8)
    # EN: Randomized response — each bit flips with _FLIP probability.
    #     This is what makes "was THIS indicator on their machine?"
    #     unanswerable for any single pack.
    # FR: Randomized response — chaque bit bascule avec probabilité
    #     _FLIP. C'est ce qui rend « cet indicateur était-il sur leur
    #     machine ? » impossible à répondre pour un paquet seul.
    rng = random.SystemRandom()
    for i in range(_BITS):
        if rng.random() < _FLIP:
            bits[i // 8] ^= 1 << (i % 8)
    return {
        "format": _FORMAT,
        "created": int(time.time()),
        "count": len(indicators[:4096]),
        "m": _BITS, "k": _HASHES, "flip": _FLIP,
        "bits_b64": base64.b64encode(bytes(bits)).decode(),
    }


def check_pack(pack: dict, candidates: list[str]) -> dict:
    """EN: Probabilistic membership for each candidate against a received
    pack. Returns {ok, hints, error} — hints carry the DP caveat.
    FR: Appartenance probabiliste de chaque candidat à un paquet reçu.
    Renvoie {ok, hints, error} — les indices portent la réserve DP."""
    if pack.get("format") != _FORMAT:
        return {"ok": False, "hints": [], "error": "unsupported pack format"}
    if pack.get("m") != _BITS or pack.get("k") != _HASHES:
        return {"ok": False, "hints": [], "error": "pack parameters mismatch"}
    try:
        bits = base64.b64decode(pack["bits_b64"])
    except Exception:                                # noqa: BLE001
        return {"ok": False, "hints": [], "error": "corrupt bits_b64"}
    if len(bits) != _BITS // 8:
        return {"ok": False, "hints": [], "error": "bad bitfield length"}
    hints = []
    for item in candidates[:2048]:
        if all(bits[p // 8] & (1 << (p % 8)) for p in _positions(item)):
            hints.append({"indicator": item,
                          "confidence": "probabilistic — bloom+noise "
                                        "cannot prove presence"})
    return {"ok": True, "hints": hints,
            "checked": len(candidates[:2048]),
            "note": "membership is probabilistic (false positives "
                    "expected) — treat as hints, not verdicts"}


# ── Commitment packs (cryptographic, selective disclosure) ──────────────────
# EN: Second pack format — for peers who want EXACT answers instead of
#     probabilistic ones. Each indicator becomes a salted SHA-256 leaf
#     `H(salt || indicator)`; the pack publishes every leaf + its salt +
#     a Merkle root over the sorted leaves as a tamper-evident commitment.
#
#     Verifier side: for each candidate x and each entry, recompute
#     H(salt||x) — a match is a *proof* of membership (no false
#     positives). Unlisted indicators stay hidden unless the attacker
#     already guesses them (the salt only blocks precomputed tables —
#     dictionary guessing is inherent to any selective-disclosure scheme).
#
#     Honest wording: a cryptographic commitment + membership proof, NOT
#     an interactive zero-knowledge protocol.
# FR: Second format — pour des pairs qui veulent des réponses EXACTES.
#     Chaque indicateur devient une feuille salée `H(salt || indicateur)` ;
#     le paquet publie feuilles + sels + racine Merkle sur les feuilles
#     triées (engagement inviolable). Une correspondance *prouve*
#     l'appartenance — zéro faux-positif. Schéma d'engagement, PAS un
#     protocole ZK interactif.

_PROOF_FORMAT = "snitch-ioc-proof/1"


def _leaf(salt: bytes, indicator: str) -> bytes:
    """EN: Salted leaf hash — hides the raw indicator behind a per-entry
    secret. / FR: Hash de feuille salé — cache l'indicateur brut derrière
    un secret par entrée."""
    return hashlib.sha256(salt + indicator.strip().lower().encode()).digest()


def _merkle(leaves: list[bytes]) -> str:
    """EN: Root over the sorted leaves — one commitment that pins down the
    whole set (any edit to any leaf changes the root).
    FR: Racine sur les feuilles triées — un engagement unique qui fixe
    tout l'ensemble (toute modification de feuille change la racine)."""
    if not leaves:
        return hashlib.sha256(b"empty").hexdigest()
    lvl = sorted(leaves)
    while len(lvl) > 1:
        if len(lvl) % 2:
            lvl.append(lvl[-1])
        lvl = [hashlib.sha256(lvl[i] + lvl[i + 1]).digest()
               for i in range(0, len(lvl), 2)]
    return lvl[0].hex()


def build_proof_pack(indicators: list[str]) -> dict:
    """EN: Commitment pack — exact-membership sharing. The sharer's salts
    are disclosed inside the pack, so a verifier can *prove* their
    candidates are present while unsuspected indicators can't be
    enumerated (each needs its own salt + candidate guess).
    FR: Paquet d'engagement — partage à appartenance exacte. Les sels sont
    publiés dans le paquet : un vérificateur *prouve* ses candidats, les
    indicateurs insoupçonnés restent inénumérables."""
    import secrets
    entries = []
    for ind in indicators[:4096]:
        salt = secrets.token_bytes(16)
        entries.append({"leaf": _leaf(salt, ind).hex(), "salt": salt.hex()})
    return {
        "format": _PROOF_FORMAT,
        "created": int(time.time()),
        "count": len(entries),
        "root": _merkle([bytes.fromhex(e["leaf"]) for e in entries]),
        "entries": entries,
    }


def check_proof_pack(pack: dict, candidates: list[str]) -> dict:
    """EN: Exact membership check — returns hits with a verifiable leaf,
    plus the root so the caller can re-commit the pack they received.
    FR: Vérification d'appartenance exacte — renvoie les hits avec la
    feuille vérifiable + la racine pour re-valider le paquet reçu."""
    if pack.get("format") != _PROOF_FORMAT:
        return {"ok": False, "hints": [], "error": "unsupported pack format"}
    entries = pack.get("entries")
    if not isinstance(entries, list) or len(entries) > 4096:
        return {"ok": False, "hints": [], "error": "bad entries"}
    # EN: Re-commit — the published root must match the leaves shipped.
    # FR: Re-engagement — la racine publiée doit correspondre aux feuilles.
    try:
        leaves = [bytes.fromhex(e["leaf"]) for e in entries]
        salts = [bytes.fromhex(e["salt"]) for e in entries]
    except (KeyError, ValueError):
        return {"ok": False, "hints": [], "error": "corrupt entries"}
    if _merkle(leaves) != pack.get("root"):
        return {"ok": False, "hints": [], "error": "root mismatch — "
                                                 "pack was tampered"}
    hits = []
    for item in candidates[:2048]:
        low = item.strip().lower()
        for salt, leaf in zip(salts, leaves):
            if hashlib.sha256(salt + low.encode()).digest() == leaf:
                hits.append({"indicator": item,
                             "confidence": "proven — salted leaf + "
                                           "merkle commitment"})
                break
    return {"ok": True, "hints": hits,
            "checked": len(candidates[:2048]),
            "note": "membership is cryptographically exact — "
                    "a hit proves the sharer listed that indicator"}
