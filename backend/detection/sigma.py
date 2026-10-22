"""
Snitch — Sigma rule import (bounded subset) / import de règles Sigma
(sous-ensemble borné).

EN: Converts a Sigma detection YAML into Snitch custom rules with an
    honest, documented subset of the spec:

      supported   — `detection` selections that are field→value maps
                    (implicit AND), `field|modifier` operators
                    (contains, startswith, endswith, re, cidr, gt, lt,
                    all), list values (OR inside a field → regex
                    alternation; `|all` → one clause per value), list
                    selections (OR → one rule per selection) and the
                    conditions `selection`, `1 of them`, `all of them`
      mapped      — level: critical→critical, high/medium→warning,
                    low/informational→info; title→name, id kept for
                    traceability
      NOT handled — count/near/aggregation conditions, timeframe,
                    Sigma backend pipelines, taxonomies outside the
                    mapped field list — skipped selections are reported
                    in `skipped`, never silently half-imported

    Sigma is an SIEM log language, so the field vocabulary is mapped to
    what a PACKET sensor can actually see (dst ip/port, process name,
    SNI/DNS host, protocol, ASN, country) — a Sigma rule referencing
    e.g. `CommandLine` is skipped rather than mistranslated.

FR: Convertit un YAML de détection Sigma en règles custom Snitch avec
    un sous-ensemble honnête et documenté de la spec : sélections
    champ→valeur (AND implicite), modificateurs contains/startswith/
    endswith/re/cidr/gt/lt/all, listes (OR intra-champ → regex,
    `|all` → une clause par valeur), sélections listées (OR → une
    règle par sélection), conditions `selection`, `1 of them`,
    `all of them`. Les aggrégations count/near, timeframe, pipelines
    backend et taxonomies hors champ mappé sont IGNORÉES et rapportées
    dans `skipped` — jamais de traduction à moitié silencieuse. Les
    champs sont mappés vers ce qu'un capteur de PAQUETS voit réellement.
"""

from __future__ import annotations

import re
from typing import Optional

_MAX_RULES = 64        # EN: per import / FR: par import
_MAX_VALUE = 200       # EN: chars per clause value / FR: caractères par valeur

# EN: Sigma (log) field names → Snitch packet fields, lowercased and
#     normalised (underscores/dots removed). / FR: Champs Sigma (logs) →
#     champs paquet Snitch, en minuscules et normalisés.
_FIELD_MAP = {
    "destinationip": "remote_ip", "dst_ip": "remote_ip",
    "dstip": "remote_ip", "destination_ip": "remote_ip",
    "destinationport": "remote_port", "dst_port": "remote_port",
    "dstport": "remote_port", "destination_port": "remote_port",
    "image": "process_name", "processname": "process_name",
    "process_name": "process_name", "originalfilename": "process_name",
    "destinationhostname": "host", "destination_host": "host",
    "destinationhost": "host", "domain": "host", "hostname": "host",
    "host": "host", "queryname": "host", "sni": "host",
    "tlsservername": "host", "dnsquery": "host",
    "protocol": "protocol", "ipprotocol": "protocol",
    "destinationasn": "asn", "asn": "asn",
    "destinationcountry": "country", "country": "country",
}

# EN: |modifier → (op, transform). startswith/endswith become anchored
#     regexes; plain field or |all use per-value ops below.
# FR: |modificateur → (op, transform). startswith/endswith deviennent
#     des regex ancrées ; champ nu ou |all utilisent les ops ci-dessous.
_MODS = {
    "contains": ("contains", str),
    "startswith": ("regex", lambda v: "^" + re.escape(str(v))),
    "endswith": ("regex", lambda v: re.escape(str(v)) + "$"),
    "re": ("regex", str),
    "cidr": ("cidr", str),
    "gt": ("gt", str),
    "lt": ("lt", str),
}

_LEVELS = {"critical": "critical", "high": "warning", "medium": "warning",
           "low": "info", "informational": "info"}


def _norm(name: str) -> str:
    return re.sub(r"[_.\- ]", "", name.lower())


def _clause(key: str, value) -> Optional[dict]:
    """EN: One `field|mod: value` pair → {field, op, value} or None when
    the field/modifier is outside the supported subset.
    FR: Une paire `champ|mod: valeur` → clause ou None si hors périmètre."""
    field_raw, _, mod = key.partition("|")
    field = _FIELD_MAP.get(_norm(field_raw))
    if not field:
        return None
    if not mod:
        op, xf = "eq", str
    elif mod.lower() == "all":
        op, xf = "eq", str            # EN: handled by caller (AND) / FR: géré par l'appelant (AND)
    else:
        found = _MODS.get(mod.lower())
        if not found:
            return None
        op, xf = found
    return {"field": field, "op": op, "xf": xf}


def _selection_to_conds(sel: dict) -> Optional[list[dict]]:
    """EN: One selection map → AND clause list, or None when any entry
    is unmapped (honest skip — a half-translated selection would widen
    the match). / FR: Une sélection → clauses AND, ou None si une entrée
    n'est pas mappée (skip honnête)."""
    conds: list[dict] = []
    for key, value in sel.items():
        key, _, all_mod = key.partition("|")
        is_all = all_mod.lower() == "all"
        values = value if isinstance(value, list) else [value]
        if not values:
            return None
        if is_all:
            # EN: field|all: [a,b] — every value must match → AND
            #     clauses, one per value. / FR: field|all: [a,b] —
            #     chaque valeur doit matcher → clauses AND.
            for v in values:
                c = _clause(key, v)
                if c is None:
                    return None
                conds.append({"field": c["field"], "op": c["op"],
                              "value": str(c["xf"](v))[:_MAX_VALUE]})
            continue
        built = []
        for v in values:
            c = _clause(f"{key}|{all_mod}" if all_mod else key, v)
            if c is None:
                return None
            built.append((c, v))
        if len(built) == 1:
            c, v = built[0]
            conds.append({"field": c["field"], "op": c["op"],
                          "value": str(c["xf"](v))[:_MAX_VALUE]})
        else:
            # EN: OR inside one field → regex alternation (escaped for
            #     eq/contains, verbatim for re). / FR: OR intra-champ →
            #     alternation regex (échappée pour eq/contains, verbatim
            #     pour re).
            c0 = built[0][0]
            if any(c["field"] != c0["field"] for c, _ in built):
                return None
            if all_mod.lower() in ("re",):
                alt = "|".join(f"(?:{v})" for _, v in built)
            else:
                alt = "|".join(re.escape(str(v)) for _, v in built)
                if all_mod.lower() == "startswith":
                    alt = "^(?:" + alt + ")"
                elif all_mod.lower() == "endswith":
                    alt = "(?:" + alt + ")$"
                elif not all_mod:
                    alt = f"^(?:{alt})$"
            conds.append({"field": c0["field"], "op": "regex",
                          "value": alt[:_MAX_VALUE]})
    return conds or None


def convert(yaml_text: str) -> dict:
    """EN: Sigma YAML → {"rules": [{name, conds, severity, sigma_id}],
    "skipped": [reasons]}. Raises ValueError on malformed input.
    FR: YAML Sigma → règles + motifs de skip. ValueError si invalide."""
    import yaml
    doc = yaml.safe_load(yaml_text)
    if not isinstance(doc, dict):
        raise ValueError("not a Sigma rule (expected a mapping)")
    # EN: Multi-document files — callers split with '---' themselves;
    #     safe_load only reads the first doc. / FR: Fichiers multi-doc —
    #     l'appelant sépare avec '---' ; safe_load ne lit que le premier.
    det = doc.get("detection") or {}
    if not isinstance(det, dict) or "condition" not in det:
        raise ValueError("no detection.condition")
    title = str(doc.get("title") or "Sigma rule")[:120]
    sid = str(doc.get("id") or "")
    severity = _LEVELS.get(str(doc.get("level") or "").lower(), "warning")
    cond_raw = str(det.get("condition") or "").strip()
    combine_all = cond_raw.lower().startswith("all of")
    sel_names = re.findall(r"[A-Za-z_][\w]*", cond_raw)
    sel_names = [n for n in sel_names
                 if n.lower() not in ("of", "them", "all", "and",
                                      "or", "not", "selection")]
    if not sel_names:
        sel_names = [k for k in det if k != "condition"]
    rules: list[dict] = []
    skipped: list[str] = []
    merged_conds: list[dict] = []
    for name in sel_names:
        sel = det.get(name)
        if sel is None:
            continue
        selections = sel if isinstance(sel, list) else [sel]
        for i, s in enumerate(selections):
            if not isinstance(s, dict):
                skipped.append(f"{name}[{i}]: not a map")
                continue
            conds = _selection_to_conds(s)
            if conds is None:
                skipped.append(f"{name}[{i}]: unmapped field/modifier")
                continue
            if combine_all:
                merged_conds += conds
            else:
                rules.append({"name": title, "conds": conds,
                              "severity": severity, "sigma_id": sid})
        if len(rules) >= _MAX_RULES:
            break
    if combine_all and merged_conds:
        rules = [{"name": title, "conds": merged_conds,
                  "severity": severity, "sigma_id": sid}]
    if not rules and not skipped:
        skipped.append("no selection matched the condition")
    return {"rules": rules[:_MAX_RULES], "skipped": skipped}
