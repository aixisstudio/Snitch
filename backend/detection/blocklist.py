"""
EN: Blocklist import — turn a hosts-file, plain domain/IP list, or
    ThreatFox C2 threat intelligence feed into firewall `domain` / `ip`
    rules. Sources:

      * LOCAL FILE — a path on this machine (StevenBlack/hosts exports,
        ThreatFox exports you downloaded yourself…). Purely local:
        nothing leaves the host.
      * REMOTE URL — an OPT-IN outbound HTTPS fetch. This is one of the
        few places Snitch can ever touch the network, so the code is
        honest about it: the URL is fetched verbatim (no telemetry, no
        referer), bounded to 4 MiB and 10 s, and the import reports
        exactly what it did.
      * PRESETS — curated public threat feeds (e.g. abuse.ch ThreatFox C2
        indicators, CC0 / Public Domain) with safe defaults.

    Entries are deduplicated against existing rules and capped
    (`max_entries`) because every rule costs memory and kernel lookup;
    giant lists belong in a resolver, not a per-rule firewall.

FR: Import de blocklist — transformer un fichier hosts, une liste
    simple domaine/IP ou un flux de renseignement sur les menaces C2
    ThreatFox en règles pare-feu `domain` / `ip`. Sources :

      * FICHIER LOCAL — un chemin sur la machine. Purement local.
      * URL DISTANTE — fetch HTTPS OPT-IN. Un des rares endroits où
        Snitch peut toucher le réseau : URL fetchée telle quelle, bornée
        à 4 Mio / 10 s, et l'import rapporte exactement ce qu'il a fait.
      * PRÉRÉGLAGES — flux publics sélectionnés (ex. indicateurs C2
        ThreatFox d'abuse.ch, CC0 / Domaine Public) avec valeurs sûres.

    Entrées dédupliquées et plafonnées (`max_entries`) pour préserver les
    ressources système.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from typing import Any
import urllib.parse
import urllib.request

_MAX_BYTES = 4 * 1024 * 1024          # EN: 4 MiB fetch cap / FR: plafond 4 Mio
_FETCH_TIMEOUT = 10.0
_DEFAULT_MAX = 500
_HARD_MAX = 5000

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def _clean_domain(candidate: str) -> str | None:
    """EN: Check if candidate is a valid, non-local domain name.
    FR: Vérifier si le candidat est un nom de domaine valide et non local."""
    d = candidate.strip().lower().rstrip(".")
    if (d in ("localhost", "localhost.localdomain", "local",
              "broadcasthost", "ip6-localhost", "ip6-loopback")
            or d.endswith(".localhost")
            or not _DOMAIN_RE.match(d)):
        return None
    return d


def _clean_ip(candidate: str) -> str | None:
    """EN: Check if candidate is a valid public IP (reject private/reserved/loopback).
    FR: Vérifier si le candidat est une IP publique valide (rejette privée/réservée/loopback)."""
    token = candidate.strip()
    try:
        ip = ipaddress.ip_address(token)
    except ValueError:
        return None
    if (ip.is_private or ip.is_reserved or ip.is_loopback
            or ip.is_link_local or ip.is_multicast
            or ip.is_unspecified):
        return None
    return str(ip)


def _extract_host_from_endpoint(val: str) -> str:
    """EN: Extract host portion from 'ip:port', '[ipv6]:port', 'domain:port', or raw value.
    FR: Extraire l'hôte depuis 'ip:port', '[ipv6]:port', 'domain:port' ou valeur brute."""
    s = val.strip().strip("'\"")
    if s.startswith("[") and "]" in s:
        return s.split("]")[0].lstrip("[")
    if s.count(":") == 1:
        part0, part1 = s.split(":", 1)
        if part1.isdigit():
            return part0
    return s


def parse_domains(text: str) -> list[str]:
    """EN: Extract unique valid domains from hosts-file / plain-list
    text. Skips comments, blank lines, the local host's own entries
    (localhost etc.) and anything that is not a syntactically valid
    domain. Order-preserving dedupe.
    FR: Extraire les domaines valides uniques d'un texte hosts/liste.
    Ignore commentaires, lignes vides, entrées locales (localhost…) et
    tout ce qui n'est pas un domaine syntaxiquement valide. Dédup en
    conservant l'ordre."""
    seen: set[str] = set()
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()          # EN: strip comments / FR: retirer commentaires
        if not line:
            continue
        parts = line.split()
        # EN: hosts format "0.0.0.0 domain [aliases…]" vs plain "domain".
        # FR: format hosts « 0.0.0.0 domaine [alias…] » vs « domaine » seul.
        if len(parts) > 1 and _looks_like_ip(parts[0]):
            candidates = parts[1:]
        else:
            candidates = parts[:1]
        for c in candidates:
            d = c.strip().lower().rstrip(".")
            if (d in seen or not _DOMAIN_RE.match(d)
                    or d == "localhost" or d.endswith(".localhost")
                    or d in ("localhost.localdomain", "local",
                             "broadcasthost", "ip6-localhost",
                             "ip6-loopback")):
                continue
            seen.add(d)
            out.append(d)
    return out


def parse_ips(text: str) -> list[str]:
    """EN: Extract unique PUBLIC IPs from IP-feed text — one-per-line
    lists (Blocklist.de, Feodo CSV `ip,port,...`), CIDR lines expanded
    only for /32-/64 hosts, hosts-format lines use their first token.
    Private/reserved/loopback addresses are skipped — an IP feed never
    rewrites your LAN into the firewall. Order-preserving dedupe.
    FR: Extraire les IP PUBLIQUES uniques d'un flux IP — listes une-par-
    ligne (Blocklist.de, CSV Feodo `ip,port,…`), CIDR limité aux hôtes
    /32-/64, format hosts = premier token. Les IP privées/réservées/
    loopback sont ignorées — un flux IP ne réécrit jamais le LAN dans
    le pare-feu. Dédup en conservant l'ordre."""
    seen: set[str] = set()
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        # EN: CSV feeds ("ip,port,...") or plain "ip" / "ip port"-style.
        # FR: Flux CSV (« ip,port,… ») ou « ip » / « ip port » simple.
        token = re.split(r"[,\s;]", line, maxsplit=1)[0].strip()
        if "/" in token:
            try:
                net = ipaddress.ip_network(token, strict=False)
            except ValueError:
                continue
            if net.num_addresses > 4096:
                continue                      # EN: refuse giant CIDRs / FR: refuser les gros CIDR
            for ip in net.hosts() if net.num_addresses > 2 else net:
                s = str(ip)
                if s not in seen and not ip.is_private \
                        and not ip.is_reserved and not ip.is_loopback \
                        and not ip.is_link_local and not ip.is_multicast:
                    seen.add(s)
                    out.append(s)
            continue
        try:
            ip = ipaddress.ip_address(token)
        except ValueError:
            continue
        if ip.is_private or ip.is_reserved or ip.is_loopback \
                or ip.is_link_local or ip.is_multicast \
                or ip.is_unspecified:
            continue
        s = str(ip)
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _looks_like_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def fetch_url(url: str) -> str:
    """EN: OPT-IN remote fetch — plain HTTPS GET, bounded. The caller is
    responsible for surfacing that this performs an outbound request.
    FR: Fetch distant OPT-IN — GET HTTPS simple, borné. L'appelant doit
    rendre visible que ceci émet une requête sortante."""
    if not url.lower().startswith(("https://", "http://")):
        raise ValueError("url must be http(s)")
    req = urllib.request.Request(url, headers={"User-Agent": "Snitch/1.3"})
    with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT) as r:
        data = r.read(_MAX_BYTES + 1)
    if len(data) > _MAX_BYTES:
        raise ValueError("blocklist too large (>4 MiB)")
    return data.decode("utf-8", errors="replace")


def clamp_max(n: int | None) -> int:
    """EN: Bound the caller's requested entry cap.
    FR: Borner le plafond demandé par l'appelant."""
    try:
        v = int(n) if n else _DEFAULT_MAX
    except (TypeError, ValueError):
        v = _DEFAULT_MAX
    return max(1, min(v, _HARD_MAX))


# ── ThreatFox C2 Threat-Feed Ingestion (abuse.ch, CC0) ───────────────────────

def parse_threatfox(
    text: str,
    kind: str = "both",
    malware: str | list[str] | None = None,
    min_confidence: int = 0,
    threat_type: str | None = None,
) -> tuple[list[str], list[str]]:
    """EN: Parse ThreatFox (abuse.ch) C2 threat intelligence export in CSV
    or JSON format. ThreatFox indicators are CC0 / Public Domain.
    Extracts unique public IPs and domains. Optional filtering by:
      - `kind`: "both" (default), "ip", or "domain"
      - `malware`: malware family name or tags (e.g. "cobalt_strike", "sliver")
      - `min_confidence`: minimum confidence level (0-100)
      - `threat_type`: threat classification (e.g. "botnet_cc", "payload_delivery")
    Order-preserving deduplication. Returns (ips, domains).

    FR: Analyse l'export C2 ThreatFox (abuse.ch) au format CSV ou JSON.
    Indicateurs ThreatFox sous CC0 / Domaine Public.
    Extrait les IP publiques et domaines uniques. Filtrage optionnel par :
      - `kind` : « both » (défaut), « ip » ou « domain »
      - `malware` : famille ou étiquette de malware (ex. « cobalt_strike »)
      - `min_confidence` : niveau de confiance minimal (0-100)
      - `threat_type` : type de menace (ex. « botnet_cc »)
    Déduplication conservant l'ordre. Renvoie (ips, domains)."""
    target_malware: list[str] = []
    if malware:
        if isinstance(malware, str):
            target_malware = [m.strip().lower() for m in malware.split(",") if m.strip()]
        elif isinstance(malware, (list, tuple, set)):
            target_malware = [str(m).strip().lower() for m in malware if str(m).strip()]

    target_threat = str(threat_type).strip().lower() if threat_type else None
    try:
        min_conf = int(min_confidence)
    except (TypeError, ValueError):
        min_conf = 0

    seen_ips: set[str] = set()
    ips: list[str] = []
    seen_domains: set[str] = set()
    domains: list[str] = []

    def _consider_ip(cand: str) -> None:
        if kind not in ("both", "ip"):
            return
        cleaned = _clean_ip(cand)
        if cleaned and cleaned not in seen_ips:
            seen_ips.add(cleaned)
            ips.append(cleaned)

    def _consider_domain(cand: str) -> None:
        if kind not in ("both", "domain"):
            return
        cleaned = _clean_domain(cand)
        if cleaned and cleaned not in seen_domains:
            seen_domains.add(cleaned)
            domains.append(cleaned)

    def _process_indicator(
        ioc_val: str,
        ioc_t: str,
        tt: str,
        mal_id: str,
        mal_print: str,
        tags: list[str],
        conf: int,
    ) -> None:
        if min_conf > 0 and conf < min_conf:
            return
        if target_threat and target_threat != tt.lower():
            return
        if target_malware:
            haystack = f"{mal_id.lower()} {mal_print.lower()} {' '.join(t.lower() for t in tags)}"
            if not any(tm in haystack for tm in target_malware):
                return

        ioc_val = ioc_val.strip()
        ioc_t = ioc_t.strip().lower()

        # Ignore hash types (file IOCs, not network rules)
        if "hash" in ioc_t or ioc_t in ("md5_hash", "sha1_hash", "sha256_hash"):
            return

        if ioc_t in ("ip:port", "ip"):
            host = _extract_host_from_endpoint(ioc_val)
            _consider_ip(host)
        elif ioc_t in ("domain:port", "domain"):
            host = _extract_host_from_endpoint(ioc_val)
            _consider_domain(host)
        elif ioc_t == "url" or ioc_val.lower().startswith(("http://", "https://")):
            try:
                parsed = urllib.parse.urlsplit(ioc_val)
                netloc = parsed.netloc.split("@")[-1]
                host = _extract_host_from_endpoint(netloc)
                if _looks_like_ip(host):
                    _consider_ip(host)
                else:
                    _consider_domain(host)
            except Exception:
                pass
        else:
            host = _extract_host_from_endpoint(ioc_val)
            if _looks_like_ip(host):
                _consider_ip(host)
            else:
                _consider_domain(host)

    trimmed = text.strip()
    if trimmed.startswith(("{", "[")):
        try:
            data = json.loads(trimmed)
        except Exception:
            data = None
        if data is not None:
            records: list[dict[str, Any]] = []
            if isinstance(data, dict):
                if isinstance(data.get("data"), list):
                    records = [r for r in data["data"] if isinstance(r, dict)]
                else:
                    records = [v for v in data.values() if isinstance(v, dict)]
            elif isinstance(data, list):
                records = [r for r in data if isinstance(r, dict)]

            for rec in records:
                ioc_val = str(rec.get("ioc") or rec.get("ioc_value") or "")
                if not ioc_val:
                    continue
                ioc_t = str(rec.get("ioc_type") or "")
                tt = str(rec.get("threat_type") or "")
                mal_id = str(rec.get("malware") or rec.get("fk_malware") or "")
                mal_print = str(rec.get("malware_printable") or "")
                tags_raw = rec.get("tags") or []
                if isinstance(tags_raw, str):
                    tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
                elif isinstance(tags_raw, (list, tuple, set)):
                    tags = [str(t).strip() for t in tags_raw if str(t).strip()]
                else:
                    tags = []
                try:
                    conf = int(rec.get("confidence_level", 100))
                except (TypeError, ValueError):
                    conf = 100
                _process_indicator(ioc_val, ioc_t, tt, mal_id, mal_print, tags, conf)
            return ips, domains

    # Parse as CSV
    reader = csv.reader(io.StringIO(text))
    col_map: dict[str, int] = {}
    for row in reader:
        if not row:
            continue
        first_cell = row[0].strip()
        if first_cell.startswith("#"):
            cleaned_row = [re.sub(r"^#+\s*", "", c).strip().strip("'\"").lower() for c in row]
            for idx, col_name in enumerate(cleaned_row):
                if col_name in ("ioc", "ioc_value"):
                    col_map["ioc"] = idx
                elif col_name in ("ioc_type", "type"):
                    col_map["ioc_type"] = idx
                elif col_name in ("threat_type",):
                    col_map["threat_type"] = idx
                elif col_name in ("fk_malware", "malware"):
                    col_map["malware"] = idx
                elif col_name in ("malware_printable", "malware_alias"):
                    col_map["malware_printable"] = idx
                elif col_name in ("confidence_level", "confidence"):
                    col_map["confidence"] = idx
                elif col_name in ("tags", "tag"):
                    col_map["tags"] = idx
            continue

        if not col_map:
            if len(row) >= 4 and any(t in str(row[2]).lower() for t in ("ip", "domain", "url", "hash", "botnet")):
                col_map = {
                    "ioc": 1,
                    "ioc_type": 2,
                    "threat_type": 3 if len(row) > 3 else -1,
                    "malware": 4 if len(row) > 4 else -1,
                    "malware_printable": 6 if len(row) > 6 else 4,
                    "confidence": 7 if len(row) > 7 else -1,
                }
            elif len(row) >= 5 and any(t in str(row[3]).lower() for t in ("ip", "domain", "url", "hash", "botnet")):
                col_map = {
                    "ioc": 2,
                    "ioc_type": 3,
                    "threat_type": 4,
                    "malware": 5,
                    "malware_printable": 7 if len(row) > 7 else 5,
                    "confidence": 9 if len(row) > 9 else -1,
                    "tags": 12 if len(row) > 12 else -1,
                }
            elif len(row) >= 2 and any(t in str(row[1]).lower() for t in ("ip", "domain", "url", "hash", "botnet")):
                col_map = {"ioc": 0, "ioc_type": 1}
            elif len(row) >= 5:
                col_map = {
                    "ioc": 2,
                    "ioc_type": 3,
                    "threat_type": 4,
                    "malware": 5,
                    "malware_printable": 7 if len(row) > 7 else 5,
                    "confidence": 9 if len(row) > 9 else -1,
                    "tags": 12 if len(row) > 12 else -1,
                }
            elif len(row) == 1:
                col_map = {"ioc": 0}
            elif len(row) >= 2:
                col_map = {"ioc": 0, "ioc_type": 1}

        ioc_idx = col_map.get("ioc", 0)
        if ioc_idx >= len(row):
            continue
        ioc_val = row[ioc_idx].strip()
        if not ioc_val:
            continue

        def _get_col(name: str, default: str = "") -> str:
            idx = col_map.get(name, -1)
            if idx != -1 and idx < len(row):
                return row[idx].strip()
            return default

        ioc_t = _get_col("ioc_type")
        tt = _get_col("threat_type")
        mal_id = _get_col("malware")
        mal_print = _get_col("malware_printable")
        tags_raw = _get_col("tags")
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
        conf_str = _get_col("confidence", "100")
        try:
            conf = int(conf_str)
        except (TypeError, ValueError):
            conf = 100

        _process_indicator(ioc_val, ioc_t, tt, mal_id, mal_print, tags, conf)

    return ips, domains


def parse_threatfox_ips(
    text: str,
    malware: str | list[str] | None = None,
    min_confidence: int = 0,
    threat_type: str | None = None,
) -> list[str]:
    """EN: Extract unique public IPs from ThreatFox feed.
    FR: Extraire les IP publiques uniques d'un flux ThreatFox."""
    ips, _ = parse_threatfox(
        text, kind="ip", malware=malware, min_confidence=min_confidence, threat_type=threat_type
    )
    return ips


def parse_threatfox_domains(
    text: str,
    malware: str | list[str] | None = None,
    min_confidence: int = 0,
    threat_type: str | None = None,
) -> list[str]:
    """EN: Extract unique domains from ThreatFox feed.
    FR: Extraire les domaines uniques d'un flux ThreatFox."""
    _, domains = parse_threatfox(
        text, kind="domain", malware=malware, min_confidence=min_confidence, threat_type=threat_type
    )
    return domains


# ── Threat Feed Presets / Préréglages de flux ─────────────────────────────────

THREATFOX_RECENT_CSV_URL = "https://threatfox.abuse.ch/export/csv/recent/"
THREATFOX_RECENT_JSON_URL = "https://threatfox.abuse.ch/export/json/recent/"

PRESETS: dict[str, dict[str, Any]] = {
    "threatfox": {
        "name": "ThreatFox C2 (abuse.ch)",
        "url": THREATFOX_RECENT_CSV_URL,
        "kind": "threatfox",
        "action": "block",
        "hours": 12,
        "format": "csv",
        "license": "CC0",
        "description": "abuse.ch ThreatFox recent C2 indicators (CC0 / Public Domain)",
    },
    "threatfox_ip": {
        "name": "ThreatFox C2 IPs (abuse.ch)",
        "url": THREATFOX_RECENT_CSV_URL,
        "kind": "threatfox_ip",
        "action": "block",
        "hours": 12,
        "format": "csv",
        "license": "CC0",
        "description": "abuse.ch ThreatFox recent C2 IP indicators (CC0)",
    },
    "threatfox_domain": {
        "name": "ThreatFox C2 Domains (abuse.ch)",
        "url": THREATFOX_RECENT_CSV_URL,
        "kind": "threatfox_domain",
        "action": "block",
        "hours": 12,
        "format": "csv",
        "license": "CC0",
        "description": "abuse.ch ThreatFox recent C2 domain indicators (CC0)",
    },
    "threatfox_json": {
        "name": "ThreatFox C2 JSON (abuse.ch)",
        "url": THREATFOX_RECENT_JSON_URL,
        "kind": "threatfox",
        "action": "block",
        "hours": 12,
        "format": "json",
        "license": "CC0",
        "description": "abuse.ch ThreatFox recent C2 indicators via JSON export (CC0)",
    },
}
