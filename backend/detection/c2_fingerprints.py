"""
EN: Passive TLS ClientHello C2 fingerprint lookup table (JA3/JA4).
    Matches observed ClientHello hashes against known Command & Control (C2)
    framework profiles (Cobalt Strike, Sliver, Havoc, Metasploit, Mythic, etc.).
    Local-only, strictly passive, zero network overhead.

FR: Table de correspondance passive d'empreintes C2 TLS ClientHello (JA3/JA4).
    Associe les empreintes ClientHello observées aux profils connus de frameworks
    de Command & Control (Cobalt Strike, Sliver, Havoc, Metasploit, Mythic, etc.).
    Purement local, strictement passif, aucune surcharge réseau.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("snitch.detection.c2_fingerprints")

_JA3_MAP: dict[str, dict[str, Any]] = {}
_JA4_MAP: dict[str, dict[str, Any]] = {}
_FINGERPRINTS: list[dict[str, Any]] = []
_LOADED = False


def _find_c2_file() -> Optional[Path]:
    """EN: Locate c2_fingerprints.json from data_dir, package, or repo root.
    FR: Localiser c2_fingerprints.json depuis data_dir, paquet ou racine du repo."""
    try:
        from paths import data_dir
        candidate = data_dir() / "c2_fingerprints.json"
        if candidate.is_file():
            return candidate
    except Exception:
        pass

    bundled = Path(__file__).parent / "c2_fingerprints.json"
    if bundled.is_file():
        return bundled

    repo_root = Path(__file__).resolve().parent.parent.parent / "c2_fingerprints.json"
    if repo_root.is_file():
        return repo_root

    return None


def reload_fingerprints() -> int:
    """EN: Reload C2 fingerprints from disk. Thread-safe copy-on-write swap.
    FR: Recharger les empreintes C2 depuis le disque. Échange atomique."""
    global _JA3_MAP, _JA4_MAP, _FINGERPRINTS, _LOADED
    p = _find_c2_file()
    if not p or not p.is_file():
        logger.debug("c2_fingerprints.json not found")
        _JA3_MAP = {}
        _JA4_MAP = {}
        _FINGERPRINTS = []
        _LOADED = True
        return 0

    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        items = data.get("fingerprints") if isinstance(data, dict) else data
        if not isinstance(items, list):
            items = []
    except Exception as exc:
        logger.warning("failed to parse %s: %s", p, exc)
        return 0

    new_ja3: dict[str, dict[str, Any]] = {}
    new_ja4: dict[str, dict[str, Any]] = {}
    valid_items: list[dict[str, Any]] = []

    for item in items:
        if not isinstance(item, dict):
            continue
        ja3 = str(item.get("ja3") or "").strip().lower()
        ja4 = str(item.get("ja4") or "").strip().lower()
        if not ja3 and not ja4:
            continue
        valid_items.append(item)
        if ja3:
            new_ja3[ja3] = item
        if ja4:
            new_ja4[ja4] = item

    _JA3_MAP = new_ja3
    _JA4_MAP = new_ja4
    _FINGERPRINTS = valid_items
    _LOADED = True
    logger.info("loaded %d C2 fingerprints (%d JA3, %d JA4) from %s",
                len(valid_items), len(new_ja3), len(new_ja4), p.name)
    return len(valid_items)


def _ensure_loaded() -> None:
    if not _LOADED:
        reload_fingerprints()


def lookup_c2(ja3: Optional[str] = None, ja4: Optional[str] = None) -> Optional[dict[str, Any]]:
    """EN: Match observed JA3 / JA4 hashes against known C2 profiles.
    Returns matched profile dict or None. O(1) dictionary hit.
    FR: Associer les empreintes JA3 / JA4 observées aux profils C2 connus.
    Renvoie le dict du profil matché ou None. Accès dictionnaire O(1)."""
    _ensure_loaded()
    if ja3:
        hit = _JA3_MAP.get(ja3.strip().lower())
        if hit:
            return hit
    if ja4:
        hit = _JA4_MAP.get(ja4.strip().lower())
        if hit:
            return hit
    return None


def list_fingerprints() -> list[dict[str, Any]]:
    """EN: List all registered C2 fingerprint profiles.
    FR: Lister tous les profils d'empreintes C2 enregistrés."""
    _ensure_loaded()
    return list(_FINGERPRINTS)
