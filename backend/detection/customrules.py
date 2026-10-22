"""
EN: User-defined alert rules — a deliberately SMALL matcher, not a
    signature language. A rule picks one packet field, one operator and
    one value; the first enabled rule matching a packet raises a
    CUSTOM_RULE alert carrying the rule name, so users can build their
    own detections ("warn me when curl touches port 4444", "flag any
    process talking to *.onion-ish hosts") without waiting for a Snitch
    release. Rules are persisted in the settings table and matched
    in-line in the packet path — they only ALERT, they never block
    (blocking stays the firewall's job).

    Supported fields  : remote_ip, host (SNI or DNS answer name),
                        process_name, remote_port, protocol, direction,
                        size.
    Supported ops     : eq, ne, contains, regex, gt, lt, cidr.
    Regex is bounded (pattern <= 200 chars, applied with a per-packet
    compiled cache of <= 64 patterns) so a bad rule cannot DoS the
    packet path; an invalid rule fails validation at creation.

FR: Règles d'alerte définies par l'utilisateur — un filtreur
    volontairement PETIT, pas un langage de signatures. Une règle choisit
    un champ de paquet, un opérateur et une valeur ; la première règle
    active qui matche lève une alerte CUSTOM_RULE portant son nom, pour
    construire ses propres détections sans attendre une release. Les
    règles sont persistées dans la table settings et évaluées en ligne
    dans le chemin paquet — elles ALERTENT seulement, jamais de blocage
    (c'est le travail du pare-feu). Regex bornée pour qu'une mauvaise
    règle ne puisse pas DoS le pipeline.
"""

from __future__ import annotations

import ipaddress
import re
import time
import uuid
from typing import Optional

_FIELDS = ("remote_ip", "host", "process_name", "remote_port",
           "protocol", "direction", "size")
_OPS = ("eq", "ne", "contains", "regex", "gt", "lt", "cidr")
_SEVERITIES = ("info", "warning", "critical")
_MAX_RULES = 256
_MAX_PATTERN = 200
_MAX_COMPILED = 64


class CustomRules:
    """EN: Ordered list of user rules with a bounded regex cache.
    FR: Liste ordonnée de règles utilisateur avec cache regex borné."""

    def __init__(self):
        self._rules: list[dict] = []
        self._compiled: dict[str, "re.Pattern"] = {}
        self._hits: dict[str, dict] = {}   # EN: rid → {count,last} / FR: rid → {count,last}

    # ── persistence / persistance ────────────────────────────────────────────

    def load(self, rules: list) -> None:
        """EN: Restore persisted rules (validated one by one; broken
        entries are dropped rather than killing startup).
        FR: Restaurer les règles persistées (validées une à une ; les
        entrées cassées sont ignorées plutôt que de tuer le démarrage)."""
        self._rules = []
        for r in rules or []:
            try:
                self._validate(r)
            except ValueError:
                continue
            self._rules.append(dict(r))
            self._rules[-1].setdefault("hits", 0)

    def serialized(self) -> list[dict]:
        return [dict(r) for r in self._rules]

    # ── CRUD ─────────────────────────────────────────────────────────────────

    def _validate(self, rule: dict) -> None:
        if rule.get("field") not in _FIELDS:
            raise ValueError(f"unknown field: {rule.get('field')}")
        if rule.get("op") not in _OPS:
            raise ValueError(f"unknown op: {rule.get('op')}")
        if rule.get("severity", "warning") not in _SEVERITIES:
            raise ValueError(f"unknown severity: {rule.get('severity')}")
        value = str(rule.get("value", ""))
        if not value:
            raise ValueError("empty value")
        if rule["op"] == "regex":
            if len(value) > _MAX_PATTERN:
                raise ValueError("pattern too long")
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"bad regex: {exc}") from exc
        if rule["op"] == "cidr":
            ipaddress.ip_network(value, strict=False)
        if rule["op"] in ("gt", "lt") and rule["field"] in ("remote_port", "size"):
            int(value)                               # EN: numeric ops need numbers / FR: ops numériques

    def add(self, name: str, field: str, op: str, value: str,
            severity: str = "warning") -> dict:
        if len(self._rules) >= _MAX_RULES:
            raise ValueError("rule limit reached")
        rule = {
            "id": uuid.uuid4().hex[:10],
            "name": (name or "").strip()[:120] or f"{field} {op} {value}",
            "field": field, "op": op, "value": str(value).strip(),
            "severity": severity, "enabled": True,
            "hits": 0, "created": time.time(),
        }
        self._validate(rule)
        self._rules.append(rule)
        return rule

    def remove(self, rule_id: str) -> bool:
        for i, r in enumerate(self._rules):
            if r["id"] == rule_id:
                self._rules.pop(i)
                self._hits.pop(rule_id, None)
                return True
        return False

    def toggle(self, rule_id: str, enabled: bool) -> Optional[dict]:
        for r in self._rules:
            if r["id"] == rule_id:
                r["enabled"] = bool(enabled)
                return r
        return None

    # ── matching / correspondance ────────────────────────────────────────────

    @staticmethod
    def _field_value(pkt, field: str):
        """EN: Extract the comparable value from a Packet.
        FR: Extraire la valeur comparable d'un Packet."""
        if field == "remote_ip":
            return pkt.dst_ip if pkt.direction == "out" else pkt.src_ip
        if field == "host":
            # EN: TLS SNI first, then any DNS answer name in the packet.
            # FR: SNI TLS d'abord, puis noms des réponses DNS du paquet.
            names = [pkt.sni] if pkt.sni else []
            names += [d[0] for d in (pkt.dns or []) if d and d[0]]
            return names
        if field == "process_name":
            return pkt.process_name or ""
        if field == "remote_port":
            return pkt.remote_port
        if field == "protocol":
            return pkt.protocol or ""
        if field == "direction":
            return pkt.direction or ""
        if field == "size":
            return pkt.size
        return None

    def _match_one(self, rule: dict, actual) -> bool:
        op, want = rule["op"], rule["value"]
        values = actual if isinstance(actual, list) else [actual]
        for v in values:
            if v is None:
                continue
            try:
                if op == "cidr":
                    if ipaddress.ip_address(str(v)) in \
                            ipaddress.ip_network(want, strict=False):
                        return True
                elif op in ("gt", "lt"):
                    num = float(v)
                    if (op == "gt" and num > float(want)) or \
                            (op == "lt" and num < float(want)):
                        return True
                else:
                    s = str(v)
                    wl = want.lower()
                    sl = s.lower()
                    if op == "eq" and sl == wl:
                        return True
                    if op == "ne" and sl != wl:
                        return True
                    if op == "contains" and wl in sl:
                        return True
                    if op == "regex":
                        pat = self._compiled.get(want)
                        if pat is None:
                            if len(self._compiled) >= _MAX_COMPILED:
                                self._compiled.pop(next(iter(self._compiled)))
                            pat = re.compile(want)
                            self._compiled[want] = pat
                        if pat.search(s):
                            return True
            except (ValueError, TypeError, re.error):
                continue
        return False

    def check(self, pkt) -> list[dict]:
        """EN: All enabled rules matching this packet (usually one per
        packet is emitted — callers may cap). Hit counters updated.
        FR: Toutes les règles actives qui matchent ce paquet (en pratique
        une alerte par paquet — l'appelant borne). Compteurs mis à jour."""
        out = []
        for r in self._rules:
            if not r.get("enabled"):
                continue
            if self._match_one(r, self._field_value(pkt, r["field"])):
                h = self._hits.setdefault(r["id"], {"count": 0, "last": 0.0})
                h["count"] += 1
                h["last"] = time.time()
                r["hits"] = h["count"]
                out.append({"rule": r, "count": h["count"]})
        return out
