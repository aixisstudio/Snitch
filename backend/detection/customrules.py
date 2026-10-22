"""
EN: User-defined alert rules — a deliberately SMALL matcher, not a
    signature language. A rule picks one packet field, one operator and
    one value; the first enabled rule matching a packet raises a
    CUSTOM_RULE alert carrying the rule name, so users can build their
    own detections ("warn me when curl touches port 4444", "flag any
    process talking to *.onion-ish hosts") without waiting for a Snitch
    release. Rules are persisted in the settings table and matched
    in-line in the packet path. The default action ALERTS only; a rule
    may opt into action="block" which additionally installs a real
    firewall rule on the matched remote host (deduped per rule+target).

    Supported fields  : remote_ip, host (SNI or DNS answer name),
                        process_name, remote_port, protocol, direction,
                        size, asn, country (from the local geo DB).
    Supported ops     : eq, ne, contains, regex, gt, lt, cidr.
    Actions           : alert (default) | block (firewall rule on the
                        matched remote_ip — the per-flow kill-switch).
    Regex is bounded (pattern <= 200 chars, nested quantifiers rejected
    at validation, compiled cache <= 64 patterns) so a bad rule cannot
    DoS the packet path; an invalid rule fails validation at creation.
    Residual: ambiguous alternation under a quantifier ((a|a)+) is a
    known unblocked shape — the matcher stays O(fields) worst-case.

FR: Règles d'alerte définies par l'utilisateur — un filtreur
    volontairement PETIT, pas un langage de signatures. Une règle choisit
    un champ de paquet, un opérateur et une valeur ; la première règle
    active qui matche lève une alerte CUSTOM_RULE portant son nom, pour
    construire ses propres détections sans attendre une release. Les
    règles sont persistées dans la table settings et évaluées en ligne
    dans le chemin paquet. L'action par défaut ALERTE seulement ; une
    règle peut opter pour action="block" qui installe de plus une vraie
    règle pare-feu sur l'hôte distant matché (dédupliquée par
    règle+cible). Regex bornée pour qu'une mauvaise règle ne puisse pas
    DoS le pipeline.
"""

from __future__ import annotations

import ipaddress
import re
import time
import uuid
from typing import Optional

_FIELDS = ("remote_ip", "host", "process_name", "remote_port",
           "protocol", "direction", "size", "asn", "country")
_OPS = ("eq", "ne", "contains", "regex", "gt", "lt", "cidr")
_SEVERITIES = ("info", "warning", "critical")
# EN: "alert" (default) emits CUSTOM_RULE only; "block" additionally
#     creates a real firewall rule for the matched target — the per-app
#     kill-switch / auto-block path the UI asks for.
# FR: « alert » (défaut) émet CUSTOM_RULE seulement ; « block » crée de
#     plus une vraie règle pare-feu sur la cible matchée — le kill-switch
#     par application demandé par l'UI.
_ACTIONS = ("alert", "block")
_MAX_RULES = 256
_MAX_PATTERN = 200
_MAX_COMPILED = 64
# EN: Nested-quantifier detector — the dominant catastrophic-backtracking
#     shape: a group that CONTAINS a quantifier is itself quantified
#     ((a+)+, (.*)*, ([a-z]+)+). Python's `re` has no match timeout, so
#     the only honest defence is rejecting the shape at validation time.
#     The scan skips escapes and char classes to avoid flagging
#     `[+*]` or `\+` as real quantifiers.
# FR: Détecteur de quantifieurs imbriqués — la forme dominante du
#     backtracking catastrophique : un groupe CONTENANT un quantifieur
#     est lui-même quantifié ((a+)+, (.*)*, ([a-z]+)+). Le `re` de Python
#     n'a pas de timeout de match ; la seule défense honnête est de
#     rejeter la forme à la validation. Le scan ignore les échappements
#     et les classes de caractères pour ne pas signaler `[+*]` ou `\+`.
def _brace_quant(pattern: str, i: int) -> int:
    """EN: Classify pattern[i] == '{' — 0 = not a quantifier (literal),
        1 = bounded ({n}, {n,m}, {,m}), 2 = unbounded ({n,}).
    FR: Classer pattern[i] == '{' — 0 = pas un quantifieur (littéral),
        1 = borné ({n}, {n,m}, {,m}), 2 = non borné ({n,})."""
    j = pattern.find("}", i + 1)
    if j == -1 or j - i > 8:
        return 0
    inner = pattern[i + 1:j]
    if not inner or not all(ch.isdigit() or ch == "," for ch in inner):
        return 0
    if inner.endswith(",") and inner[:-1].isdigit():
        return 2                            # EN: {n,} — open upper bound / FR: borne haute ouverte
    return 1


def _unbounded_quant(pattern: str, i: int) -> bool:
    """EN: True when pattern[i] opens an UNBOUNDED repetition — '+', '*'
        or '{n,}'. '?' and '{n,m}' are bounded and cannot produce
        exponential backtracking as the OUTER loop.
    FR: Vrai quand pattern[i] ouvre une répétition NON bornée — '+', '*'
        ou '{n,}'. '?' et '{n,m}' sont bornés et ne peuvent produire un
        backtracking exponentiel comme boucle EXTERNE."""
    c = pattern[i]
    if c in "+*":
        return True
    if c == "{":
        return _brace_quant(pattern, i) == 2
    return False


def _any_quant(pattern: str, i: int) -> bool:
    """EN: True when pattern[i] is ANY real quantifier — the INNER
        criterion. Even a bounded inner repetition under an unbounded
        outer one is catastrophic: (a{1,3})+ partitions the input
        exponentially many ways.
    FR: Vrai quand pattern[i] est un vrai quantifieur — le critère
        INTERNE. Même une répétition interne bornée sous une externe non
        bornée est catastrophique : (a{1,3})+ partitionne l'entrée de
        façon exponentielle."""
    c = pattern[i]
    if c in "+*?":
        return True
    if c == "{":
        return _brace_quant(pattern, i) != 0
    return False


def _has_nested_quantifier(pattern: str) -> bool:
    """EN: True when an unboundedly-quantified group itself contains any
        quantifier — the (a+)+ / (.*)* / (a?)+ catastrophic shapes.
    FR: Vrai quand un groupe quantifié sans borne contient un quantifieur
        — les formes catastrophiques (a+)+ / (.*)* / (a?)+."""
    stack: list[bool] = []          # EN: group → contains a quantifier / FR: groupe → contient un quantifieur
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            # EN: skip the whole char class (handles ]-first and escapes)
            # FR: sauter toute la classe (gère ]-premier et échappements)
            i += 1
            if i < n and pattern[i] == "^":
                i += 1
            if i < n and pattern[i] == "]":
                i += 1
            while i < n:
                if pattern[i] == "\\":
                    i += 2
                    continue
                if pattern[i] == "]":
                    break
                i += 1
            i += 1
            continue
        if c == "(":
            stack.append(False)
            i += 1
            # EN: (?: ?= ?! ?<= ?<! ?P<name> ?P= ?# (?flags — the '?' is a
            #     group-type marker, not a quantifier; skip the prefix so
            #     it never flags the group as quantified.
            # FR: (?: ?= ?! ?<= ?<! ?P<name> ?P= ?# (?flags — le '?' est
            #     un marqueur de type de groupe, pas un quantifieur ;
            #     sauter le préfixe pour ne pas marquer le groupe.
            if i < n and pattern[i] == "?":
                i += 1
                while i < n and pattern[i] in ":<>=!P#aiLmsux_":
                    i += 1
                if i >= 2 and pattern[i - 1] == "<":
                    # EN: (?P<name> — consume the name up to '>'
                    # FR: (?P<name> — consommer le nom jusqu'à '>'
                    while i < n and pattern[i] not in ")>":
                        i += 1
                    if i < n:
                        i += 1
            continue
        if c == ")":
            inner = stack.pop() if stack else False
            i += 1
            # EN: unbounded quantifier right after the group close?
            # FR: quantifieur non borné juste après la fermeture ?
            if i < n and _unbounded_quant(pattern, i) and inner:
                return True
            # EN: the parent "contains a quantifier" whenever the child
            #     carried one — (a+)b inside (...) + is dangerous too.
            # FR: le parent « contient un quantifieur » dès que l'enfant
            #     en portait un — (a+)b dans (...) + est dangereux aussi.
            if stack and inner:
                stack[-1] = True
            i += 1
            continue
        if c in "+*?{" and _any_quant(pattern, i) and stack:
            stack[-1] = True
        i += 1
    return False


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

    @staticmethod
    def _clauses(rule: dict) -> list[dict]:
        """EN: The rule's AND-clauses — `conds` (Sigma-style multi-field
        AND) when present, else the single top-level condition.
        FR: Les clauses AND de la règle — `conds` (multi-champ façon
        Sigma) si présentes, sinon la condition simple."""
        return rule.get("conds") or [rule]

    def _validate(self, rule: dict) -> None:
        clauses = self._clauses(rule)
        if not clauses or len(clauses) > 16:
            raise ValueError("a rule needs 1..16 clauses")
        first_field = clauses[0].get("field")
        for c in clauses:
            if c.get("field") not in _FIELDS:
                raise ValueError(f"unknown field: {c.get('field')}")
            if c.get("op") not in _OPS:
                raise ValueError(f"unknown op: {c.get('op')}")
            # EN: asn/country need the local geo DB — eq/ne/contains on
            #     the resolved value only.
            # FR: asn/country exigent la base geo — eq/ne/contains
            #     seulement sur la valeur résolue.
            if c.get("field") in ("asn", "country") and \
                    c.get("op") not in ("eq", "ne", "contains"):
                raise ValueError(f"op {c.get('op')} not meaningful for "
                                 f"{c.get('field')}")
            value = str(c.get("value", ""))
            if not value:
                raise ValueError("empty value")
            if c["op"] == "regex":
                if len(value) > _MAX_PATTERN:
                    raise ValueError("pattern too long")
                try:
                    re.compile(value)
                except re.error as exc:
                    raise ValueError(f"bad regex: {exc}") from exc
                if _has_nested_quantifier(value):
                    raise ValueError(
                        "nested quantifiers rejected (ReDoS risk) — "
                        "rewrite without (…+/…*)+" )
            if c["op"] == "cidr":
                ipaddress.ip_network(value, strict=False)
            if c["op"] in ("gt", "lt") and \
                    c["field"] in ("remote_port", "size"):
                int(value)                           # EN: numeric ops need numbers / FR: ops numériques
        if rule.get("severity", "warning") not in _SEVERITIES:
            raise ValueError(f"unknown severity: {rule.get('severity')}")
        if rule.get("action", "alert") not in _ACTIONS:
            raise ValueError(f"unknown action: {rule.get('action')}")
        if rule.get("action") == "block" and \
                first_field not in ("remote_ip", "host",
                                    "process_name", "asn", "country"):
            raise ValueError("block action needs a blockable field "
                             "(remote_ip/host/process_name/asn/country)")

    def add(self, name: str, field: str, op: str, value: str,
            severity: str = "warning", action: str = "alert",
            conds: Optional[list] = None) -> dict:
        if len(self._rules) >= _MAX_RULES:
            raise ValueError("rule limit reached")
        rule = {
            "id": uuid.uuid4().hex[:10],
            "name": (name or "").strip()[:120] or f"{field} {op} {value}",
            "severity": severity, "enabled": True,
            "action": action or "alert",
            "hits": 0, "created": time.time(),
        }
        if conds:
            # EN: Multi-clause AND rule (Sigma-style selection) — no
            #     top-level field/op/value. / FR: Règle AND multi-clauses
            #     (selection façon Sigma) — pas de field/op/value simple.
            rule["conds"] = [{"field": str(c.get("field", "")),
                              "op": str(c.get("op", "")),
                              "value": str(c.get("value", "")).strip()}
                             for c in conds]
        else:
            rule.update(field=field, op=op, value=str(value).strip())
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
    def _field_value(pkt, field: str, geo: Optional[dict] = None):
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
        if field == "asn":
            return str((geo or {}).get("asn") or "")
        if field == "country":
            g = geo or {}
            return g.get("country") or g.get("country_code") or ""
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

    def check(self, pkt, geo: Optional[dict] = None) -> list[dict]:
        """EN: All enabled rules matching this packet (usually one per
        packet is emitted — callers may cap). Hit counters updated.
        FR: Toutes les règles actives qui matchent ce paquet (en pratique
        une alerte par paquet — l'appelant borne). Compteurs mis à jour."""
        out = []
        for r in self._rules:
            if not r.get("enabled"):
                continue
            # EN: every clause of the rule must match (Sigma-style AND).
            # FR: chaque clause de la règle doit matcher (AND façon Sigma).
            if all(self._match_one(
                    c, self._field_value(pkt, c["field"], geo))
                    for c in self._clauses(r)):
                h = self._hits.setdefault(r["id"], {"count": 0, "last": 0.0})
                h["count"] += 1
                h["last"] = time.time()
                r["hits"] = h["count"]
                out.append({"rule": r, "count": h["count"]})
        return out
