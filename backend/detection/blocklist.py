"""
EN: Blocklist import — turn a hosts-file or plain domain list into
    firewall `domain` rules. Two sources, both explicit:

      * LOCAL FILE — a path on this machine (StevenBlack/hosts exports,
        Pi-hole lists you downloaded yourself…). Reading a file is a
        local operation: nothing leaves the host.
      * REMOTE URL — an OPT-IN outbound HTTPS fetch. This is one of the
        few places Snitch can ever touch the network, so the code is
        honest about it: the URL is fetched verbatim (no telemetry, no
        referer), bounded to 4 MiB and 10 s, and the import reports
        exactly what it did.

    Entries are deduplicated against existing rules and capped
    (`max_entries`) because every `domain` rule costs a DNS
    resolution + OS-firewall entries; giant lists (100k+ entries) belong
    in a resolver, not a per-rule firewall.

FR: Import de blocklist — transformer un fichier hosts ou une liste de
    domaines en règles `domain` du pare-feu. Deux sources, toutes deux
    explicites :

      * FICHIER LOCAL — un chemin sur la machine. Purement local.
      * URL DISTANTE — fetch HTTPS OPT-IN. Un des rares endroits où
        Snitch peut toucher le réseau : URL fetchée telle quelle, bornée
        à 4 Mio / 10 s, et l'import rapporte exactement ce qu'il a fait.

    Entrées dédupliquées et plafonnées (`max_entries`) : chaque règle
    `domain` coûte une résolution DNS + des entrées pare-feu OS.
"""

from __future__ import annotations

import ipaddress
import re
import urllib.request

_MAX_BYTES = 4 * 1024 * 1024          # EN: 4 MiB fetch cap / FR: plafond 4 Mio
_FETCH_TIMEOUT = 10.0
_DEFAULT_MAX = 500
_HARD_MAX = 5000

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


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
