"""
Snitch — DNS reverse resolution + IP geolocation.

EN: Enrichment pipeline for remote IPs:
      1. reverse DNS (hostname)                  via socket.gethostbyaddr
      2. geolocation, local GeoLite2 offline DB  via geoip2 (optional)
      3. OPTIONAL online fallback to ip-api.com  via urllib (45 req/min)

    PRIVACY: the online fallback sends every contacted IP to a third-party
    service in plaintext. For a privacy tool that's contradictory, so it is
    OFF by default — enable it explicitly with SNITCH_ONLINE_GEO=1 and get a
    GeoLite2 DB for fully-offline lookups.

    Reliability fixes vs the naive version:
      - reverse DNS bounded by a global socket timeout (no more executor
        threads parked forever)
      - ip-api results use a TTL cache; failures are NOT cached, so a
        temporary error doesn't permanently blind an IP
      - a tiny client-side rate limiter keeps us under the 45 req/min quota

FR: Pipeline d'enrichissement des IP distantes :
      1. DNS inverse (hostname)                    via socket.gethostbyaddr
      2. géolocalisation, BDD hors ligne GeoLite2  via geoip2 (optionnel)
      3. repli en ligne OPTIONNEL vers ip-api.com  via urllib (45 req/min)

    CONFIDENTIALITÉ : le repli en ligne envoie chaque IP contactée à un service
    tiers en clair. Contradictoire pour un outil de confidentialité : il est
    donc DÉSACTIVÉ par défaut — l'activer explicitement avec
    SNITCH_ONLINE_GEO=1, ou déposer une base GeoLite2 pour des recherches
    100 % hors ligne.

    Corrections de fiabilité :
      - DNS inverse borné par un timeout global de socket (plus de threads
        d'executor bloqués indéfiniment)
      - résultats ip-api dans un cache à TTL ; les échecs ne sont PAS cachés,
        donc une erreur temporaire n'aveugle pas une IP pour toujours
      - un petit limiteur côté client reste sous le quota de 45 req/min
"""

import asyncio
import ipaddress
import json
import logging
import os
import socket
import threading
import time
import urllib.request
from collections import deque
from functools import lru_cache
from pathlib import Path
from typing import Optional

logger = logging.getLogger("snitch.resolver")

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    # EN: geoip2 not installed — MaxMind lookups unavailable.
    # FR: geoip2 non installé — recherches MaxMind indisponibles.
    GEOIP_AVAILABLE = False

# EN: Global ceiling for blocking socket operations (reverse DNS mainly).
#     gethostbyaddr has no per-call timeout, so we bound it globally.
# FR: Plafond global pour les opérations socket bloquantes (DNS inverse surtout).
#     gethostbyaddr n'a pas de timeout par appel : on le borne globalement.
socket.setdefaulttimeout(3)

# EN: Online geolocation is OPT-IN (privacy by default).
# FR: La géolocalisation en ligne est OPT-IN (confidentialité par défaut).
ONLINE_GEO_ENABLED = os.environ.get("SNITCH_ONLINE_GEO", "").strip() == "1"

# EN: Optional GeoLite2 database — drop GeoLite2-City.mmdb into data/.
# FR: Base GeoLite2 optionnelle — déposer GeoLite2-City.mmdb dans data/.
GEOIP_DB_PATH = Path(__file__).parent.parent.parent / "data" / "GeoLite2-City.mmdb"
_geoip_reader = None


def get_geoip_reader():
    """EN: Lazy-open the MaxMind reader once. / FR: Ouverture paresseuse du lecteur MaxMind."""
    global _geoip_reader
    if _geoip_reader is None and GEOIP_AVAILABLE and GEOIP_DB_PATH.exists():
        try:
            _geoip_reader = geoip2.database.Reader(str(GEOIP_DB_PATH))
        except Exception as exc:
            logger.warning("Could not open GeoLite2 DB at %s: %s", GEOIP_DB_PATH, exc)
    return _geoip_reader


def is_private(ip: str) -> bool:
    """EN: RFC1918 / loopback / link-local / ULA check — works for v4 and v6.
    FR: Test RFC1918 / loopback / link-local / ULA — fonctionne en v4 et v6."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


@lru_cache(maxsize=2048)
def resolve_hostname(ip: str) -> Optional[str]:
    """
    EN: Reverse DNS — returns None on NXDOMAIN/timeout. lru_cache caches
        negatives too, which is what we want: failed lookups are stable.
    FR: DNS inverse — renvoie None sur NXDOMAIN/timeout. lru_cache met aussi en
        cache les échecs, ce qui est souhaité : les échecs de résolution sont
        stables.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


@lru_cache(maxsize=2048)
def resolve_geo_maxmind(ip: str) -> dict:
    """
    EN: Offline geolocation via the local GeoLite2 DB. Returns {} when the DB
        is absent, the IP is private, or the lookup fails. Safe to cache —
        results don't change within a session.
    FR: Géolocalisation hors ligne via la base GeoLite2 locale. Renvoie {} si
        la base est absente, l'IP privée, ou la requête en échec. Cache sûr —
        les résultats ne changent pas pendant une session.
    """
    reader = get_geoip_reader()
    if not reader or is_private(ip):
        return {}
    try:
        resp = reader.city(ip)
        return {
            "country": resp.country.name,
            "country_code": resp.country.iso_code,
            "city": resp.city.name,
            "lat": resp.location.latitude,
            "lon": resp.location.longitude,
            "org": resp.traits.autonomous_system_organization,
        }
    except Exception:
        return {}


# ── Online fallback: TTL cache + rate limiter ────────────────────────────────
# ── Repli en ligne : cache TTL + limiteur de débit ───────────────────────────

GEO_CACHE_TTL = 6 * 3600          # EN: 6h / FR: 6 h
GEO_RATE_MAX   = 40               # EN: max requests per window / FR: requêtes max par fenêtre
GEO_RATE_WINDOW = 60              # seconds / secondes

_geo_cache: dict[str, tuple[float, dict]] = {}
_geo_cache_lock = threading.Lock()
_geo_calls: deque = deque()       # EN: timestamps of recent API calls / FR: timestamps des appels récents


def _rate_limit_ok() -> bool:
    """
    EN: Sliding-window rate limiter — returns False when the quota for the
        last 60 s is exhausted.
    FR: Limiteur à fenêtre glissante — renvoie False quand le quota des 60
        dernières secondes est épuisé.
    """
    now = time.time()
    while _geo_calls and now - _geo_calls[0] > GEO_RATE_WINDOW:
        _geo_calls.popleft()
    if len(_geo_calls) >= GEO_RATE_MAX:
        return False
    _geo_calls.append(now)
    return True


def resolve_geo_ipapi(ip: str) -> dict:
    """
    EN: Online fallback — free ip-api.com, no key, ~45 req/min.
        Disabled unless SNITCH_ONLINE_GEO=1. Successes are TTL-cached;
        failures return {} and are NOT cached so the IP can retry later.
    FR: Repli en ligne — ip-api.com gratuit, sans clé, ~45 req/min.
        Désactivé sauf si SNITCH_ONLINE_GEO=1. Les succès sont cachés avec TTL ;
        les échecs renvoient {} et ne sont PAS cachés pour permettre un re-essai.
    """
    if not ONLINE_GEO_ENABLED or is_private(ip):
        return {}

    now = time.time()
    with _geo_cache_lock:
        hit = _geo_cache.get(ip)
        if hit and now - hit[0] < GEO_CACHE_TTL:
            return hit[1]

    if not _rate_limit_ok():
        logger.debug("geo rate limit reached — skipping %s", ip)
        return {}

    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,org"
        req = urllib.request.Request(url, headers={"User-Agent": "snitch/1.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "success":
            geo = {
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "org": data.get("org"),
            }
            with _geo_cache_lock:
                _geo_cache[ip] = (now, geo)
            return geo
    except Exception as exc:
        logger.debug("ip-api lookup failed for %s: %s", ip, exc)
    return {}


def resolve_geo(ip: str) -> dict:
    """
    EN: MaxMind first (offline, private), online fallback second.
    FR: MaxMind d'abord (hors ligne, privé), repli en ligne ensuite.
    """
    geo = resolve_geo_maxmind(ip)
    if geo:
        return geo
    return resolve_geo_ipapi(ip)


async def enrich_ip(ip: str) -> dict:
    """
    EN: Async wrapper — runs the blocking DNS/geo work in the default
        executor so the event loop stays responsive under load.
    FR: Enveloppe async — exécute le travail DNS/geo bloquant dans l'executor
        par défaut pour que la boucle reste réactive sous charge.
    """
    loop = asyncio.get_running_loop()
    hostname = await loop.run_in_executor(None, resolve_hostname, ip)
    geo = await loop.run_in_executor(None, resolve_geo, ip)
    return {
        "ip": ip,
        "hostname": hostname,
        "private": is_private(ip),
        **geo,
    }
