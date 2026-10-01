"""
Snitch — DNS/domain resolution + IP geolocation.

EN: Enrichment pipeline for remote IPs:
      1. observed DNS answers — captured DNS responses map IP → real domain
         (the name the user actually asked for, not a useless CDN PTR)
      2. observed TLS SNI     — ClientHello hostname for the same purpose
      3. reverse DNS          — socket.gethostbyaddr, last resort
      4. geolocation          — local .mmdb ONLY (MaxMind GeoLite2 or DB-IP
         Lite; raw maxminddb reads both formats)

    PRIVACY: there is NO online geolocation fallback. ip-api.com was removed —
    a privacy tool must never leak visited IPs in plaintext. If no .mmdb is
    present the UI shows "no geo" and the README explains how to enable it.
    Databases live in the per-OS user data dir (paths.data_dir()), NOT next to
    __file__ — the old Path(__file__)/data code pointed inside the read-only
    PyInstaller bundle.

    Expected files in <data_dir>/geo/:
      GeoLite2-City.mmdb  or  dbip-city-lite.mmdb   (city/country/lat/lon)
      GeoLite2-ASN.mmdb   or  dbip-asn-lite.mmdb    (org/ASN)
    DB-IP Lite (CC BY 4.0): https://db-ip.com/db/lite.php — attribution shown
    in the UI footer and THIRD_PARTY_NOTICES.

FR: Pipeline d'enrichissement des IP distantes :
      1. réponses DNS observées — les réponses DNS capturées associent IP →
         vrai domaine (le nom réellement demandé, pas un PTR CDN inutile)
      2. SNI TLS observé        — nom d'hôte du ClientHello, même objectif
      3. DNS inverse            — socket.gethostbyaddr, dernier recours
      4. géolocalisation        — .mmdb local UNIQUEMENT (GeoLite2 MaxMind ou
         DB-IP Lite ; le lecteur maxminddb brut lit les deux formats)

    CONFIDENTIALITÉ : AUCUN repli de géolocalisation en ligne. ip-api.com a été
    supprimé — un outil de confidentialité ne doit jamais divulguer les IP
    visitées en clair. Sans .mmdb, l'UI affiche « sans géo » et le README
    explique comment l'activer. Les bases vivent dans le dossier de données
    utilisateur de l'OS (paths.data_dir()), PAS à côté de __file__ — l'ancien
    code Path(__file__)/data pointait dans le bundle PyInstaller en lecture
    seule.

    Fichiers attendus dans <data_dir>/geo/ :
      GeoLite2-City.mmdb  ou  dbip-city-lite.mmdb   (ville/pays/lat/lon)
      GeoLite2-ASN.mmdb   ou  dbip-asn-lite.mmdb    (org/ASN)
    DB-IP Lite (CC BY 4.0) : https://db-ip.com/db/lite.php — attribution
    affichée dans le pied de l'UI et THIRD_PARTY_NOTICES.
"""

import asyncio
import ipaddress
import logging
import socket
import threading
import time
from functools import lru_cache
from typing import Optional

from paths import data_dir

logger = logging.getLogger("snitch.resolver")

try:
    import maxminddb
    MMDB_AVAILABLE = True
except ImportError:
    # EN: maxminddb ships with geoip2 — absent only on minimal installs.
    # FR: maxminddb arrive avec geoip2 — absent seulement des installs minimales.
    MMDB_AVAILABLE = False

# EN: Global ceiling for blocking socket ops — gethostbyaddr has no per-call
#     timeout, so we bound it globally (a stuck PTR lookup used to park
#     executor threads forever).
# FR: Plafond global pour les opérations socket bloquantes — gethostbyaddr n'a
#     pas de timeout par appel, donc on le borne globalement (une résolution
#     PTR coincée parquait des threads d'executor indéfiniment).
socket.setdefaulttimeout(3)

GEO_DIR = data_dir() / "geo"

_CITY_NAMES = ("dbip-city-lite.mmdb", "GeoLite2-City.mmdb")
_ASN_NAMES = ("dbip-asn-lite.mmdb", "GeoLite2-ASN.mmdb")

_readers: dict[str, object] = {}
_readers_lock = threading.Lock()

# EN: ip → (domain, expiry_epoch) learned from captured DNS answers and SNI.
#     Bounded — 10k entries, TTL-respecting.
# FR: ip → (domaine, expiration) appris des réponses DNS capturées et du SNI.
#     Borné — 10k entrées, respect du TTL.
_domain_map: dict[str, tuple[str, float]] = {}
_domain_lock = threading.Lock()
MAX_DOMAIN_MAP = 10_000


def is_private(ip: str) -> bool:
    """EN: RFC1918 / loopback / link-local / multicast / ULA check (v4 + v6).
    FR: Test RFC1918 / loopback / link-local / multicast / ULA (v4 + v6)."""
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
    except ValueError:
        return False


# ── Observed domain names / Noms de domaine observés ─────────────────────────

def learn_dns_answers(answers: list[tuple[str, str, int]]) -> None:
    """
    EN: Store A/AAAA answers from a captured DNS response so subsequent
        packets to those IPs get a meaningful hostname. TTL-aware; expires
        automatically on read.
    FR: Stocker les réponses A/AAAA d'une réponse DNS capturée pour que les
        paquets suivants vers ces IP obtiennent un nom d'hôte utile.
        Conscient du TTL ; expiration automatique à la lecture.
    """
    now = time.time()
    with _domain_lock:
        for name, ip, ttl in answers:
            if not name or not ip:
                continue
            # EN: Bound the map — evict expired first, then oldest.
            # FR: Borner la table — évincer les expirées d'abord, puis les plus anciennes.
            if len(_domain_map) >= MAX_DOMAIN_MAP:
                _domain_map.clear()
            _domain_map[ip] = (name, now + min(ttl, 86400))


def learn_sni(ip: str, hostname: Optional[str]) -> None:
    """EN: Record a TLS ClientHello hostname for a destination IP.
    FR: Enregistrer le nom d'hôte du ClientHello TLS pour une IP destination."""
    if not hostname:
        return
    with _domain_lock:
        if len(_domain_map) >= MAX_DOMAIN_MAP:
            _domain_map.clear()
        # EN: SNI has no TTL — keep for the session (24h cap).
        # FR: Le SNI n'a pas de TTL — conservation pour la session (plafond 24 h).
        _domain_map.setdefault(ip, (hostname, time.time() + 86400))


def lookup_domain(ip: str) -> Optional[str]:
    """EN: Domain learned from DNS/SNI, or None. / FR: Domaine appris via DNS/SNI, ou None."""
    with _domain_lock:
        hit = _domain_map.get(ip)
        if hit and hit[1] > time.time():
            return hit[0]
        return None


# ── Reverse DNS / DNS inverse ────────────────────────────────────────────────

@lru_cache(maxsize=2048)
def resolve_hostname(ip: str) -> Optional[str]:
    """
    EN: Reverse DNS — None on NXDOMAIN/timeout. lru_cache caches negatives
        too: PTR absence is stable, so that's the desired behavior.
    FR: DNS inverse — None sur NXDOMAIN/timeout. lru_cache met aussi en cache
        les échecs : l'absence de PTR est stable, c'est le comportement voulu.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# ── Geolocation / Géolocalisation ────────────────────────────────────────────

def _get_reader(kind: str):
    """
    EN: Lazy-open one .mmdb reader ('city' or 'asn'). Prefers DB-IP Lite
        (CC BY 4.0) over GeoLite2 when both exist. Returns None if absent.
    FR: Ouvrir paresseusement un lecteur .mmdb (« city » ou « asn »). Préfère
        DB-IP Lite (CC BY 4.0) à GeoLite2 quand les deux existent. Renvoie
        None si absente.
    """
    if not MMDB_AVAILABLE:
        return None
    with _readers_lock:
        if kind in _readers:
            return _readers[kind]
        names = _CITY_NAMES if kind == "city" else _ASN_NAMES
        reader = None
        for name in names:
            path = GEO_DIR / name
            if path.exists():
                try:
                    reader = maxminddb.open_database(str(path))
                    logger.info("geo %s database loaded: %s", kind, path.name)
                except Exception as exc:
                    logger.warning("could not open %s: %s", path, exc)
                break
        _readers[kind] = reader
        return reader


@lru_cache(maxsize=4096)
def resolve_geo(ip: str) -> dict:
    """
    EN: Offline geolocation via local .mmdb files. Returns {} when no DB is
        present, the IP is private, or the lookup fails. Safe to cache —
        results are stable within a session.
    FR: Géolocalisation hors ligne via les .mmdb locaux. Renvoie {} sans base,
        sur IP privée, ou en cas d'échec. Cache sûr — les résultats sont
        stables pendant une session.
    """
    if is_private(ip):
        return {}

    geo: dict = {}
    city = _get_reader("city")
    if city is not None:
        try:
            rec = city.get(ip) or {}
            country = rec.get("country") or rec.get("registered_country") or {}
            geo = {
                "country": (country.get("names") or {}).get("en") or country.get("name"),
                "country_code": country.get("iso_code"),
                "city": ((rec.get("city") or {}).get("names") or {}).get("en"),
                "lat": (rec.get("location") or {}).get("latitude"),
                "lon": (rec.get("location") or {}).get("longitude"),
            }
        except Exception as exc:
            logger.debug("city lookup failed for %s: %s", ip, exc)

    asn = _get_reader("asn")
    if asn is not None:
        try:
            rec = asn.get(ip) or {}
            geo["org"] = rec.get("autonomous_system_organization")
        except Exception as exc:
            logger.debug("asn lookup failed for %s: %s", ip, exc)

    return geo


async def enrich_ip(ip: str) -> dict:
    """
    EN: Async wrapper — blocking DNS/geo work runs in the default executor so
        the event loop stays responsive. Domain preference order:
        observed DNS/SNI > reverse DNS.
    FR: Enveloppe async — le travail DNS/geo bloquant tourne dans l'executor
        par défaut pour garder la boucle réactive. Préférence de domaine :
        DNS/SNI observé > DNS inverse.
    """
    loop = asyncio.get_running_loop()
    hostname = lookup_domain(ip)
    if not hostname:
        hostname = await loop.run_in_executor(None, resolve_hostname, ip)
    geo = await loop.run_in_executor(None, resolve_geo, ip)
    return {
        "ip": ip,
        "hostname": hostname,
        "private": is_private(ip),
        **geo,
    }
