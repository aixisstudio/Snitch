"""
Snitch — YARA-L 2.0 export / export YARA-L 2.0.

EN: Translates Snitch custom rules (single-condition or `conds:` AND
    rules, including Sigma-imported ones) into a YARA-L 2.0 file for
    Google SecOps/Chronicle UDM pipelines. Snitch stays the runtime —
    this is a one-way EXPORT, giving a Sigma→YARA-L path for free
    (Sigma YAML → snitch rules → YARA-L text).

    Field mapping (packet-sensor → UDM, honest approximations):

      remote_ip    → target.ip            (eq/ne =/!=, cidr → net.ip_in_range_cidr)
      remote_port  → target.port          (eq/ne/gt/lt)
      host         → network.tls.client.server_name OR'd with
                     network.dns.questions.name — SNI and DNS are both
                     "host" in Snitch; emitted as a ( … or … ) clause
      process_name → principal.process.file.full_path (contains → regex)
      protocol     → network.ip_protocol  (tcp/udp uppercased)
      direction    → network.direction    (OUTBOUND/INBOUND)
      asn          → network.asn          (eq/ne only)
      country      → target.location.country_or_region
      size         → network.sent_bytes   (gt/lt only — UDM byte fields
                     are numeric; eq stays numeric too)
      regex        → =~ /pattern/         (forwarded verbatim)

    Ops outside a field's row are dropped with a `// SKIPPED` comment —
    never mistranslated, same honesty contract as the Sigma importer.

FR: Traduit les règles custom Snitch (simples ou `conds:` AND, y
    compris les règles importées Sigma) en fichier YARA-L 2.0 pour
    pipelines UDM Google SecOps/Chronicle. Export unidirectionnel —
    donne un chemin Sigma→YARA-L gratuitement. Les ops hors ligne sont
    ignorées avec un commentaire `// SKIPPED`, jamais mal traduites.
"""

from __future__ import annotations

import re

_HEADER = """// Snitch — auto-generated YARA-L 2.0 rules
// Source: Snitch custom rules (single + Sigma-imported conds rules)
// Regenerate: GET /alerts/rules/yaral — do NOT edit by hand.
// Field mapping is packet-sensor → UDM; see detection/yaral.py.

"""

_SEV = {"critical": "CRITICAL", "warning": "HIGH", "info": "INFORMATIONAL"}

# EN: ops usable per field — None means "skip with a comment".
# FR: ops utilisables par champ — None = « skip avec commentaire ».
_FIELD: dict[str, dict] = {
    "remote_ip": {"lhs": "$e.target.ip",
                  "ops": ("eq", "ne", "cidr")},
    "remote_port": {"lhs": "$e.target.port",
                    "ops": ("eq", "ne", "gt", "lt")},
    "host": {"lhs": None,                  # EN: dual-field clause / FR: clause double
             "ops": ("eq", "ne", "contains", "regex")},
    "process_name": {"lhs": "$e.principal.process.file.full_path",
                     "ops": ("eq", "ne", "contains", "regex")},
    "protocol": {"lhs": "$e.network.ip_protocol",
                 "ops": ("eq", "ne"),
                 "xf": str.upper},
    "direction": {"lhs": "$e.network.direction",
                  "ops": ("eq", "ne"),
                  "xf": lambda v: "OUTBOUND" if v == "out" else "INBOUND"},
    "asn": {"lhs": "$e.network.asn", "ops": ("eq", "ne")},
    "country": {"lhs": "$e.target.location.country_or_region",
                "ops": ("eq", "ne", "contains")},
    "size": {"lhs": "$e.network.sent_bytes",
             "ops": ("eq", "ne", "gt", "lt")},
}


def _esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _clause(field: str, op: str, value: str) -> str | None:
    spec = _FIELD.get(field)
    if spec is None or op not in spec["ops"]:
        return None
    v = spec.get("xf", lambda x: x)(value)
    if field == "host":
        # EN: "host" covers SNI + DNS answers — emit the honest OR.
        # FR: « host » couvre SNI + réponses DNS — OR honnête émis.
        if op == "regex":
            pat = f"/{value}/"
            return (f"($e.network.tls.client.server_name =~ {pat} or "
                    f"$e.network.dns.questions.name =~ {pat})")
        cmp = "=" if op == "eq" else ("!=" if op == "ne" else None)
        if op == "contains":
            pat = f"/.*{re.escape(value)}.*/"
            return (f"($e.network.tls.client.server_name =~ {pat} or "
                    f"$e.network.dns.questions.name =~ {pat})")
        return (f"($e.network.tls.client.server_name {cmp} \"{_esc(v)}\" or "
                f"$e.network.dns.questions.name {cmp} \"{_esc(v)}\")")
    lhs = spec["lhs"]
    if op == "cidr":
        return f'net.ip_in_range_cidr({lhs}, "{_esc(v)}")'
    if op == "regex":
        return f"{lhs} =~ /{v}/"
    if op == "contains":
        return f"{lhs} =~ /.*{re.escape(v)}.*/"
    sym = {"eq": "=", "ne": "!=", "gt": ">", "lt": "<"}[op]
    # EN: numeric UDM fields stay unquoted. / FR: champs UDM numériques sans guillemets.
    val = v if field in ("remote_port", "size", "asn") else f'"{_esc(v)}"'
    return f"{lhs} {sym} {val}"


def export(rules: list[dict]) -> str:
    """EN: Serialized rules → a complete .yar file. Each rule's clauses
    are ANDed (same semantics as the packet matcher); rules with zero
    translatable clauses are emitted commented-out with a // SKIPPED
    note. / FR: Règles sérialisées → fichier .yar complet. Clauses ANDées
    ; les règles sans clause traduisible sont émises en commentaire."""
    out = [_HEADER]
    for r in rules:
        rid = re.sub(r"[^A-Za-z0-9_]", "_", str(r.get("id", "x")))
        name = str(r.get("name", "rule")).replace('"', "'")[:120]
        sev = _SEV.get(r.get("severity", "warning"), "MEDIUM")
        clauses = []
        skipped = []
        for c in (r.get("conds") or
                  [{"field": r.get("field"), "op": r.get("op"),
                    "value": r.get("value")}]):
            cl = _clause(str(c.get("field")), str(c.get("op")),
                         str(c.get("value", "")))
            (clauses if cl else skipped).append(
                cl or f"{c.get('field')} {c.get('op')} {c.get('value')}")
        if not clauses:
            out.append(f"// SKIPPED rule {name!r}: no translatable clause "
                       f"({', '.join(skipped)})")
            continue
        body = " and\n    ".join(clauses)
        note = ("\n    // skipped: " + "; ".join(skipped)) if skipped else ""
        out.append(
            f'rule snitch_{rid} {{\n'
            f'  meta:\n'
            f'    author = "Snitch"\n'
            f'    description = "{_esc(name)}"\n'
            f'    severity = "{sev}"\n'
            f'  events:\n'
            f'    {body}{note}\n'
            f'  condition:\n'
            f'    $e\n'
            f'}}\n')
    return "\n".join(out)
