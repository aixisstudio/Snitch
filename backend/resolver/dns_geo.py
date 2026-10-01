"""
Snitch — DNS reverse resolution + IP geolocation.

EN: Enrichment pipeline for remote IPs:
      1. reverse DNS (hostname)                    via socket.gethostbyaddr
      2. geolocation, MaxMind GeoLite2 offline DB  via geoip2 (optional)
      3. geolocation fallback, free ip-api.com     via urllib (45 req/min)
    Everything is memoized with lru_cache — each unique IP is resolved once.

FR: Pipeline d'enrichissement des IP distantes :
      1. DNS inverse (hostname)                     via socket.gethostbyaddr
      2. géolocalisation, BDD hors ligne GeoLite2   via geoip2 (optionnel)
      3. repli de géolocalisation, ip-api.com gratuit via urllib (45 req/min)
    Tout est mémoïsé avec lru_cache — chaque IP unique n'est résolue qu'une fois.
"""

import asyncio
import ipaddress
import json
import socket
import urllib.request
from functools import lru_cache
from pathlib import Path
from typing import Optional

try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    # EN: geoip2 not installed — will fall back to ip-api.com.
    # FR: geoip2 non installé — repli sur ip-api.com.
    GEOIP_AVAILABLE = False

# EN: The GeoLite2-City.mmdb file is optional — drop it into data/ for fully
#     offline geolocation.
# FR: Le fichier GeoLite2-City.mmdb est optionnel — déposez-le dans data/ pour
#     une géolocalisation entièrement hors ligne.
GEOIP_DB_PATH = Path(__file__).parent.parent.parent / "data" / "GeoLite2-City.mmdb"
_geoip_reader = None


def get_geoip_reader():
    """EN: Lazy-open the MaxMind reader once. / FR: Ouverture paresseuse du lecteur MaxMind."""
    global _geoip_reader
    if _geoip_reader is None and GEOIP_AVAILABLE and GEOIP_DB_PATH.exists():
        _geoip_reader = geoip2.database.Reader(str(GEOIP_DB_PATH))
    return _geoip_reader


def is_private(ip: str) -> bool:
    """EN: RFC1918 / loopback / link-local check. / FR: Test RFC1918 / loopback / link-local."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


@lru_cache(maxsize=2048)
def resolve_hostname(ip: str) -> Optional[str]:
    """
    EN: Reverse DNS — returns None on NXDOMAIN/timeout. Never raises.
    FR: DNS inverse — renvoie None sur NXDOMAIN/timeout. Ne lève jamais d'erreur.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


@lru_cache(maxsize=2048)
def resolve_geo_maxmind(ip: str) -> dict:
    """
    EN: Offline geolocation via the local GeoLite2 database. Returns {} when
        the DB is absent, the IP is private, or the lookup fails.
    FR: Géolocalisation hors ligne via la base GeoLite2 locale. Renvoie {} si
        la base est absente, l'IP privée, ou la requête en échec.
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


@lru_cache(maxsize=2048)
def resolve_geo_ipapi(ip: str) -> dict:
    """
    EN: Online fallback — free ip-api.com endpoint, no API key, 45 req/min.
        A 4s timeout keeps a dead connection from stalling the pipeline.
    FR: Repli en ligne — endpoint gratuit ip-api.com, sans clé API, 45 req/min.
        Un timeout de 4 s empêche une connexion morte de bloquer le pipeline.
    """
    if is_private(ip):
        return {}
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,org"
        req = urllib.request.Request(url, headers={"User-Agent": "snitch/1.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "success":
            return {
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "city": data.get("city"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "org": data.get("org"),
            }
    except Exception:
        pass
    return {}


@lru_cache(maxsize=2048)
def resolve_geo(ip: str) -> dict:
    """
    EN: MaxMind first, ip-api.com as fallback — best of offline + online.
    FR: MaxMind d'abord, ip-api.com en repli — le meilleur du hors ligne + en ligne.
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
    loop = asyncio.get_event_loop()
    hostname = await loop.run_in_executor(None, resolve_hostname, ip)
    geo = await loop.run_in_executor(None, resolve_geo, ip)
    return {
        "ip": ip,
        "hostname": hostname,
        "private": is_private(ip),
        **geo,
    }
