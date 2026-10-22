"""
Snitch — FastAPI application.

EN: Heart of the backend. Owns the in-memory graph state (nodes / edges /
    LAN devices), receives packets from the libpcap sniffer thread, enriches
    them (observed DNS/SNI + offline geolocation + classification), feeds the
    anomaly detector, persists aggregates to SQLite and pushes realtime
    updates over the WebSocket.

    Pipeline (post-review redesign):
      capture thread → bounded queue.Queue → ONE asyncio drain task every
      250 ms → per-packet: filter + detector (lock-guarded) + graph aggregates
      → ONE "batch" broadcast per tick. No per-packet coroutine storm, no
      per-packet broadcast — json.dumps runs once per 250 ms window.

    Enrichment is fire-and-forget: packets create/update nodes immediately
    with a stub, a deduplicated background task fills in geo/hostname when it
    resolves, then broadcasts a node patch. In-flight lookups are deduplicated
    per IP and failures are never cached permanently.

    Settings (port filter, excluded processes, whitelist) persist in SQLite
    and are restored at startup.

    Security model (see api/security.py):
      - every REST endpoint requires the API token (X-Snitch-Token header or
        ?token= param)
      - the WebSocket requires the token AND a whitelisted Origin header
      - CORS is restricted to the dev server / self-origin / file:// (Electron)

FR: Cœur du backend. Détenir l'état du graphe en mémoire (nœuds / arêtes /
    appareils LAN), recevoir les paquets du thread du sniffer libpcap, les
    enrichir (DNS/SNI observés + géolocalisation hors ligne +
    classification), alimenter le détecteur d'anomalies, persister les
    agrégats dans SQLite et pousser les mises à jour temps réel via le
    WebSocket.

    Pipeline (refonte post-revue) :
      thread de capture → queue.Queue bornée → UNE tâche asyncio de vidage
      toutes les 250 ms → par paquet : filtre + détecteur (sous verrou) +
      agrégats du graphe → UNE diffusion « batch » par tick. Plus de tempête
      de coroutines ni de broadcast par paquet — json.dumps tourne une fois
      par fenêtre de 250 ms.

    L'enrichissement est en tâche de fond : les paquets créent/mettent à jour
    les nœuds immédiatement avec un stub, une tâche dédupliquée remplit
    géo/nom d'hôte quand la résolution aboutit, puis diffuse un patch de
    nœud. Les recherches en vol sont dédupliquées par IP et les échecs ne sont
    jamais cachés définitivement.

    Les réglages (filtre de ports, processus exclus, whitelist) persistent
    dans SQLite et sont restaurés au démarrage.

    Modèle de sécurité (voir api/security.py) :
      - chaque endpoint REST exige le jeton API (en-tête X-Snitch-Token ou
        paramètre ?token=)
      - le WebSocket exige le jeton ET un en-tête Origin autorisé
      - CORS restreint au serveur de dev / à l'origine propre / file:// (Electron)
"""

import asyncio
import ipaddress
import json
import logging
import os
import queue
import socket
import subprocess
import sys
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from api.security import ALLOWED_ORIGIN_REGEX, require_token, ws_authorized
from capture.sniffer import Packet, PacketSniffer, get_local_ips
import demo
from capture.media_monitor import MediaMonitor, MediaState
from classifier.traffic import classify
from resolver.dns_geo import (enrich_ip, is_private, learn_dns_answers,
                              learn_sni, lookup_domain)
from scanner.arp_scanner import ARPScanner, Device, default_gateway as _default_gateway
from scanner.arp_scanner import READ_STATS as _arp_stats
from detection.anomaly import AnomalyDetector, Alert
from detection.customrules import CustomRules
from capture.ebpf_probe import EbpfProbe
from detection.deepinspect import DeepInspector, suspicious_module_paths
from detection.firewall import FirewallManager
from detection.integrity import IntegrityWatcher
from detection import blocklist
from detection import explain as alert_explain
from detection import iocshare
from detection.llm_local import LocalSlm
from detection.miner import MinerDetector
from detection import perfprobe
from detection.sinkresponder import SinkholeResponder
from detection.threatintel import ThreatIntel
from api.notify import notifier
from paths import data_dir
import storage.db as db
from version import __version__

logger = logging.getLogger("snitch.api")

# ── Shared state / État partagé ──────────────────────────────────────────────
# EN: All mutable application state lives here at module level.
# FR: Tout l'état mutable de l'application vit ici au niveau module.
nodes: dict[str, dict] = {}
edges: dict[str, dict] = {}
lan_devices: dict[str, dict] = {}
connected_clients: list[WebSocket] = []
enrichment_cache: dict[str, dict] = {}   # EN: remote_ip -> geo/hostname result
                                        # FR: remote_ip -> résultat geo/hostname
_inflight_geo: set[str] = set()          # EN: IPs with a running enrich task
                                        # FR: IP avec une tâche d'enrichissement en cours
detector = AnomalyDetector()
# EN: Firewall orchestration + threat-intel reputation client — both loaded
#     from persisted settings at startup (see _load_settings).
# FR: Orchestration pare-feu + client de réputation threat-intel — chargés
#     des réglages persistés au démarrage (voir _load_settings).
fw = FirewallManager(data_dir())
ti = ThreatIntel()
# EN: Read-only process integrity watch — exe hash baselines, name/exe
#     mismatch, Linux RWX maps. All local inspection, bounded state.
# FR: Veille d'intégrité des processus en lecture seule — baselines de hash
#     d'exes, mismatch nom/exe, maps RWX Linux. Inspection locale, état borné.
integrity = IntegrityWatcher()
# EN: Optional/kernel-adjacent security modules — every one degrades
#     honestly when its platform requirement isn't met (see each module).
# FR: Modules de sécurité optionnels/proches noyau — chacun dégrade
#     honnêtement quand sa prérequis plateforme manque (cf. chaque module).
ebpf = EbpfProbe()                # EN: kprobe connect attribution (Linux+bcc)
                                  # FR: attribution connect par kprobe
deep = DeepInspector()            # EN: Frida module-origin attribution / FR: attribution de module Frida
sink = SinkholeResponder()        # EN: loopback :80/:443 sinkhole listener / FR: écouteur sinkhole
miner = MinerDetector()           # EN: stratum/pool/CPU mining signals / FR: signaux de minage
slm = LocalSlm()                  # EN: optional localhost LLM enrichment / FR: enrichissement LLM local
custom_rules = CustomRules()      # EN: user-defined alert rules / FR: règles d'alerte utilisateur
_loop: asyncio.AbstractEventLoop | None = None
_sniffer: PacketSniffer | None = None
_scanner: ARPScanner | None = None
_media_monitor: MediaMonitor | None = None
_capturing: bool = True
_port_filter: list[int] = []
_excluded_processes: set[str] = set()
_whitelisted_ips: set[str] = set()
_watchlist: list[str] = []        # EN: user-pinned IPs/domains / FR: IP/domaines épinglés
_media_state: dict = {"mic": [], "camera": [], "supported": True}
_shutdown = False

# EN: Bounded packet queue between the capture thread and the event loop.
#     Full → drop oldest: a stale burst is less useful than fresh traffic.
# FR: File de paquets bornée entre le thread de capture et la boucle.
#     Pleine → on jette le plus ancien : une rafale périmée vaut moins que
#     le trafic frais.
_pkt_queue: queue.Queue = queue.Queue(maxsize=20_000)

# EN: Drop accounting — every skipped/dropped packet is counted with its
#     reason and exposed via /diagnostics. Security rule: nothing is ignored
#     silently — a blind spot is a finding.
# FR: Comptabilité des rejets — chaque paquet écarté/jeté est compté avec sa
#     raison et exposé via /diagnostics. Règle de sécurité : rien n'est
#     ignoré silencieusement — un angle mort est un problème.
_drop_stats = {
    "queue_oldest_dropped": 0,   # EN: full queue → stale packet evicted
                                 # FR: file pleine → paquet périmé évincé
    "queue_put_failed": 0,       # EN: queue still full after eviction
                                 # FR: file encore pleine après éviction
    "excluded_process": 0,       # EN: user-excluded process (settings)
                                 # FR: processus exclu par l'utilisateur
    "whitelisted_ip": 0,         # EN: trusted IP (e.g. the box)
                                 # FR: IP de confiance (ex. la box)
    "noise_filtered": 0,         # EN: multicast/broadcast/etc. noise
                                 # FR: bruit multicast/broadcast/etc.
}

# EN: Hard caps so a long-running instance can't leak memory.
# FR: Plafonds stricts pour qu'une instance longue durée ne fuie pas de mémoire.
MAX_GRAPH_NODES = 800
MAX_ENRICHMENT_CACHE = 4096
DRAIN_INTERVAL_S = 0.25        # EN: ~4 Hz batch broadcasts / FR: ~4 lots par seconde
DRAIN_MAX_PACKETS = 2_000      # EN: per tick / FR: par tick


# ── Pydantic request models / Modèles de requête Pydantic ────────────────────
# EN: Every POST body is validated — no more bare `dict` bodies.
# FR: Chaque corps POST est validé — plus de corps `dict` bruts.

class PortFilterBody(BaseModel):
    """EN: /capture/ports payload. / FR: Charge utile de /capture/ports."""
    ports: list[int] = Field(default_factory=list)


class ProcessFilterBody(BaseModel):
    """EN: /capture/processes payload. / FR: Charge utile de /capture/processes."""
    excluded: list[str] = Field(default_factory=list)


class WhitelistBody(BaseModel):
    """EN: /capture/whitelist payload. / FR: Charge utile de /capture/whitelist."""
    ips: list[str] = Field(default_factory=list)


class SettingsBody(BaseModel):
    """EN: /settings payload — generic key/value settings persisted to SQLite.
    FR: Charge utile de /settings — réglages clé/valeur persistés dans SQLite."""
    settings: dict = Field(default_factory=dict)


class IgnoreBody(BaseModel):
    """EN: /alerts/ignore payload — suppress a host, a type, or both.
    FR: Charge utile de /alerts/ignore — supprimer un hôte, un type, ou les deux."""
    type: Optional[str] = None
    ip: Optional[str] = None


class FirewallRuleBody(BaseModel):
    """EN: /firewall/rules payload — block, sinkhole or throttle an IP,
    domain suffix or process. `action` defaults to "block"; "sinkhole"
    redirects the destination to loopback (hosts file for domains, DNAT
    on Linux for IPs); "throttle" rate-limits to `rate` kbit/s (Linux tc).
    FR: Charge utile de /firewall/rules — bloquer, trou-noircir ou limiter
    une IP, un suffixe de domaine ou un processus. `action` = « block »
    (défaut) ; « sinkhole » redirige vers loopback ; « throttle » limite
    à `rate` kbit/s (tc Linux)."""
    kind: str
    value: str
    action: str = "block"
    rate: int = 64


class PidSecondsBody(BaseModel):
    """EN: PID + bounded duration for inspect/sample endpoints.
    FR: PID + durée bornée pour les endpoints d'inspection/échantillonnage."""
    pid: int
    seconds: int = 20


class ExplainBody(BaseModel):
    """EN: /security/explain payload — alert type + context detail + lang.
    FR: Charge utile de /security/explain — type + contexte + langue."""
    type: str
    detail: dict = Field(default_factory=dict)
    lang: str = "en"


class IocImportBody(BaseModel):
    """EN: /security/iocpack/import payload — a received pack to check
    local indicators against. / FR: Charge utile d'import IOC — un paquet
    reçu à confronter aux indicateurs locaux."""
    pack: dict = Field(default_factory=dict)


class PairingBody(BaseModel):
    """EN: /remote/pairing payload — opt-in LAN exposure. `enabled`
    persists a bind address applied at the NEXT backend start (uvicorn
    cannot rebind a running socket). `bind` accepts "0.0.0.0" or one of
    the machine's own LAN addresses. Token auth remains mandatory —
    pairing never weakens authentication, it only changes the listen
    address.
    FR: Charge utile /remote/pairing — exposition LAN opt-in. `enabled`
    persiste une adresse d'écoute appliquée au PROCHAIN démarrage
    (uvicorn ne peut pas re-binder un socket actif). `bind` accepte
    « 0.0.0.0 » ou une adresse LAN de la machine. Le jeton reste
    obligatoire — le pairing ne change que l'adresse d'écoute."""
    enabled: bool
    bind: str = ""


class SandboxBody(BaseModel):
    """EN: /security/sandbox payload — an executable to detonate inside
    the network-denial sandbox. Path must be absolute; `args` bounded.
    FR: Charge utile /security/sandbox — un exécutable à détoner dans la
    sandbox sans réseau. Chemin absolu exigé ; `args` bornés."""
    path: str
    args: list[str] = Field(default_factory=list)
    seconds: int = 10


class FirewallToggleBody(BaseModel):
    """EN: Enable/disable a single rule. / FR: Activer/désactiver une règle."""
    enabled: bool = True


class BlocklistBody(BaseModel):
    """EN: /firewall/blocklist payload — exactly ONE source: `path`
    (local hosts/domain file) or `url` (OPT-IN outbound fetch — one of
    the few places Snitch can emit network traffic). `action` is the
    firewall action applied to every imported domain.
    FR: Charge utile /firewall/blocklist — exactement UNE source : `path`
    (fichier local) ou `url` (fetch sortant OPT-IN — un des rares
    endroits où Snitch peut émettre du trafic). `action` = l'action
    pare-feu appliquée à chaque domaine importé."""
    path: str = ""
    url: str = ""
    action: str = "block"
    max_entries: int = 500


class CustomRuleBody(BaseModel):
    """EN: /alerts/rules payload — one field, one operator, one value.
    FR: Charge utile /alerts/rules — un champ, un opérateur, une valeur."""
    name: str = ""
    field: str
    op: str
    value: str
    severity: str = "warning"


class ProfileBody(BaseModel):
    """EN: /firewall/profile payload — a named rule bundle:
    permissive (clean slate), balanced (egress baseline), strict
    (baseline + lockdown). / FR: Charge utile /firewall/profile — un lot
    nommé de règles : permissive (table rase), balanced (base sortante),
    strict (base + lockdown)."""
    name: str


class LockdownBody(BaseModel):
    """EN: /firewall/lockdown payload — panic switch on/off.
    FR: Charge utile de /firewall/lockdown — bouton panique on/off."""
    on: bool = True


class PidBody(BaseModel):
    """EN: /processes/* payload — target PID for kill/suspend.
    FR: Charge utile de /processes/* — PID cible pour tuer/suspendre."""
    pid: int


class ThreatCheckBody(BaseModel):
    """EN: /security/threat_check payload — manual IP/domain reputation check.
    FR: Charge utile de /security/threat_check — vérification manuelle de
    réputation d'une IP/domaine."""
    ip: str


class GeoDownloadBody(BaseModel):
    """EN: /geo/download payload — explicit consent is REQUIRED, this is the
    only outbound call in the whole app. / FR: Charge utile de /geo/download —
    consentement explicite OBLIGATOIRE, c'est le seul appel sortant de l'app."""
    consent: bool = False


class InterfaceBody(BaseModel):
    """EN: /capture/interface payload — None/empty means "auto-pick".
    FR: Charge utile de /capture/interface — None/vide = choix automatique."""
    name: Optional[str] = None


class WatchlistBody(BaseModel):
    """EN: /watchlist payload — IPs and/or domain suffixes to watch.
    FR: Charge utile de /watchlist — IP et/ou suffixes de domaine à surveiller."""
    items: list[str] = Field(default_factory=list)


# ── Broadcast / Diffusion ────────────────────────────────────────────────────

async def broadcast(message: dict) -> None:
    """
    EN: Send a JSON message to every connected WebSocket client; drop the
        dead ones. Serialized ONCE for all clients.
    FR: Envoyer un message JSON à tous les clients WebSocket connectés ;
        retirer les morts. Sérialisé UNE fois pour tous les clients.
    """
    if not connected_clients:
        return
    payload = json.dumps(message)
    dead = []
    for ws in connected_clients:
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        # EN: the WS handler may have already dropped it — remove() must not
        #     raise on an absent element or the whole packet batch is lost.
        # FR: le handler WS a pu le retirer avant — remove() ne doit pas
        #     lever sur un élément absent sinon tout le batch est perdu.
        if ws in connected_clients:
            connected_clients.remove(ws)


# ── Noise filtering / Filtrage du bruit ──────────────────────────────────────

def _is_noise_ip(ip: str) -> bool:
    """
    EN: True for traffic that must never become a node: multicast, broadcast,
        loopback, link-local, unspecified. These used to spawn duplicate
        "external" nodes before the ARP scan populated lan_devices.
    FR: True pour le trafic qui ne doit jamais devenir un nœud : multicast,
        broadcast, loopback, link-local, non spécifié. Ce trafic créait des
        nœuds « externes » doublons avant que le scan ARP ne remplisse
        lan_devices.
    """
    try:
        a = ipaddress.ip_address(ip)
        return (a.is_multicast or a.is_loopback or a.is_link_local
                or a.is_unspecified or a.is_reserved)
    except ValueError:
        return ip == "255.255.255.255"


# EN: This machine's own interface IPs, cached 60 s — the local node's IPv6
#     kept appearing as a phantom "LAN device" named by the DNS-sanitized
#     mDNS hostname ("MoneyLisa" losing the "$" from "MoneyLi$a").
# FR: Les IP propres de cette machine, en cache 60 s — l'IPv6 du nœud local
#     apparaissait comme « appareil LAN » fantôme nommé par le hostname mDNS
#     sanitisé (« MoneyLisa » perdant le « $ » de « MoneyLi$a »).
_own_ips_cache: dict = {"ips": set(), "ts": 0.0}


def _own_ips() -> set:
    """EN: Local interface IPs (60 s TTL — DHCP can renumber).
    FR: IP des interfaces locales (TTL 60 s — le DHCP peut renuméroter)."""
    now = time.time()
    if now - _own_ips_cache["ts"] > 60:
        try:
            _own_ips_cache["ips"] = get_local_ips()
        except Exception:
            pass
        _own_ips_cache["ts"] = now
    return _own_ips_cache["ips"]


def _ensure_lan_device(ip: str) -> dict:
    """
    EN: Guarantee a lan_devices entry for a private peer — even before the
        ARP table yields it (router, DHCP guests). Real discoveries later
        overwrite these stub fields with vendor/hostname info.
        EXCEPTION: one of OUR OWN interface IPs is not a LAN peer — it's
        the "local" center node. Purge any phantom entry and return local.
    FR: Garantir une entrée lan_devices pour un pair privé — même avant que
        la table ARP ne le livre (routeur, invités DHCP). Les vraies
        découvertes écrasent ensuite ces champs stub avec fabricant/nom d'hôte.
        EXCEPTION : une IP de NOS PROPRES interfaces n'est pas un pair LAN —
        c'est le nœud central « local ». Purger tout fantôme et renvoyer local.
    """
    key = f"lan:{ip}"
    if ip in _own_ips():
        lan_devices.pop(key, None)
        edges.pop(f"lan-edge-{ip}", None)
        return nodes["local"]
    dev = lan_devices.get(key)
    if dev is None:
        is_gw = ip == _gateway()
        dev = {
            "id": key, "ip": ip, "mac": None,
            "label": ip, "hostname": None, "vendor": "",
            "category": "lan_device",
            "device_type": "router" if is_gw else "unknown",
            "is_gateway": is_gw, "private_mac": False,
            "online": True, "bytes": 0, "packets": 0,
            "color": "#f97316" if is_gw else "#64748b", "alerted": False,
        }
        # EN: A stub seen in traffic may already be a KNOWN device — recall
        #     its persisted identity before showing a bare IP.
        # FR: Un stub vu dans le trafic peut être un appareil déjà CONNU —
        #     rappeler son identité persistée avant d'afficher une IP nue.
        stored = db.device_identity(ip)
        if stored.get("hostname"):
            dev["hostname"] = stored["hostname"]
            dev["label"] = stored["hostname"]
        if stored.get("mac"):
            dev["mac"] = stored["mac"]
            dev["private_mac"] = stored.get("private_mac", False)
        if stored.get("vendor"):
            dev["vendor"] = stored["vendor"]
        if stored.get("device_type") and dev["device_type"] == "unknown":
            dev["device_type"] = stored["device_type"]
        lan_devices[key] = dev
        edges[f"lan-edge-{ip}"] = {
            "id": f"lan-edge-{ip}", "source": "local", "target": key,
            "protocol": "LAN", "label": "LAN", "color": "#64748b",
            "bytes": 0, "packets": 0, "dashed": True,
        }
    return dev


# EN: Default-gateway cache — `route`/`/proc` is re-read at most once per
#     minute so stub creation stays cheap.
# FR: Cache de la passerelle par défaut — `route`/`/proc` relu au maximum
#     une fois par minute pour que la création de stub reste légère.
_gateway_cache: dict = {"ip": None, "ts": 0.0}


def _local_hostname() -> str:
    """
    EN: This machine's DISPLAY name — the one the user actually set:
          macOS   : `scutil --get ComputerName`  ("MoneyLi$a")
          Windows : COMPUTERNAME env var         ("DESKTOP-ABC")
          Linux   : `hostnamectl --pretty`       (may hold spaces/unicode)
        socket.gethostname() is the FALLBACK — it returns the DNS-sanitized
        hostname (no $, no spaces), which is not what users recognize.
    FR: Le nom d'AFFICHAGE de cette machine — celui que l'utilisateur a
        réellement défini :
          macOS   : `scutil --get ComputerName`  (« MoneyLi$a »)
          Windows : variable d'env COMPUTERNAME  (« DESKTOP-ABC »)
          Linux   : `hostnamectl --pretty`       (espaces/unicode possibles)
        socket.gethostname() est le REPLI — il renvoie le hostname sanitisé
        DNS (ni $ ni espaces), que l'utilisateur ne reconnaît pas.
    """
    try:
        if sys.platform == "darwin":
            out = subprocess.run(["scutil", "--get", "ComputerName"],
                                 capture_output=True, text=True,
                                 timeout=3).stdout.strip()
            if out:
                return out
        elif sys.platform.startswith("win"):
            name = os.environ.get("COMPUTERNAME", "").strip()
            if name:
                return name
        elif sys.platform.startswith("linux"):
            try:
                out = subprocess.run(["hostnamectl", "--pretty"],
                                     capture_output=True, text=True,
                                     timeout=3).stdout.strip()
                if out:
                    return out
            except (OSError, subprocess.TimeoutExpired):
                pass
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        return socket.gethostname().removesuffix(".local")
    except OSError:
        return ""


def _gateway() -> Optional[str]:
    """EN: Cached default_gateway() (5 min TTL).
    FR: default_gateway() mis en cache (TTL 5 min)."""
    now = time.time()
    if now - _gateway_cache["ts"] > 300:
        _gateway_cache["ip"] = _default_gateway()
        _gateway_cache["ts"] = now
    return _gateway_cache["ip"]


def _learn_lan_hostname(ip: str, name: str,
                       touched_devices: dict) -> None:
    """
    EN: A passive announcement (mDNS "*.local", LLMNR, NBNS) named this LAN
        device — store the hostname on the entry (stub or real) so the UI
        shows "iPhone-de-Lisa" instead of a bare IP. Never overwrites an
        existing name.
    FR: Une annonce passive (mDNS « *.local », LLMNR, NBNS) a nommé cet
        appareil LAN — stocker le nom d'hôte sur l'entrée (stub ou réelle)
        pour que l'UI affiche « iPhone-de-Lisa » au lieu d'une IP nue.
        N'écrase jamais un nom existant.
    """
    dev = _ensure_lan_device(ip)
    if dev.get("hostname"):
        return
    dev["hostname"] = name
    if dev.get("label") == dev.get("ip"):
        dev["label"] = name
    touched_devices[dev["id"]] = dev
    # EN: A learned name is durable knowledge — persist it so a restart
    #     doesn't drop the device back to a bare IP.
    # FR: Un nom appris est un savoir durable — le persister pour qu'un
    #     redémarrage ne fasse pas retomber l'appareil sur une IP nue.
    db.upsert_device(ip=ip, mac=dev.get("mac"), hostname=name)


def _devname(dns_name: str) -> Optional[str]:
    """
    EN: Extract a device display name from a DNS-style name:
          "iPhone-de-Lisa._device-info._tcp.local" → "iPhone-de-Lisa"
          "MacBook-Pro.local"                      → "MacBook-Pro"
          "DESKTOP-ABC"                            → "DESKTOP-ABC"
    FR: Extraire le nom d'affichage d'un appareil d'un nom DNS :
          « iPhone-de-Lisa._device-info._tcp.local » → « iPhone-de-Lisa »
          « MacBook-Pro.local »                      → « MacBook-Pro »
          « DESKTOP-ABC »                            → « DESKTOP-ABC »
    """
    n = dns_name.strip()
    if n.lower().endswith(".local"):
        n = n[:-len(".local")]
    if "._" in n:                    # EN: mDNS service instance
        n = n.split("._", 1)[0]      # FR: instance de service mDNS
    return n.strip() or None


# EN: DHCP-learned names waiting for their device: a client announces its
#     hostname (option 12) with its MAC, possibly before we know the IP the
#     server will assign. Keyed by MAC, applied when the device appears.
# FR: Noms appris via DHCP en attente de leur appareil : un client annonce
#     son nom (option 12) avec sa MAC, parfois avant que l'IP assignée ne
#     soit connue. Indexés par MAC, appliqués quand l'appareil apparaît.
_pending_mac_names: dict[str, str] = {}


def _learn_dhcp_name(hostname: str, req_ip: Optional[str], mac: str,
                     touched_devices: dict) -> None:
    """
    EN: A client DHCP message revealed "this MAC is called <hostname>".
        If we already know the device (by requested IP or MAC), name it;
        otherwise remember the MAC→name pair for the next discovery.
    FR: Un message DHCP client révèle « cette MAC s'appelle <hostname> ».
        Si l'appareil est déjà connu (par IP demandée ou MAC), on le nomme ;
        sinon on retient le couple MAC→nom pour la prochaine découverte.
    """
    # EN: A DHCP message may carry a requested IP but NO option 12 — bail
    #     out early, otherwise the empty name would overwrite a real one
    #     already stored in _pending_mac_names (name learned then lost).
    # FR: Un message DHCP peut porter une IP demandée mais PAS d'option 12 —
    #     sortir tôt, sinon le nom vide écraserait un vrai nom déjà stocké
    #     dans _pending_mac_names (nom appris puis perdu).
    if not hostname:
        return
    if req_ip and is_private(req_ip):
        _learn_lan_hostname(req_ip, hostname, touched_devices)
        return
    for dev in lan_devices.values():
        if dev.get("mac") == mac:
            _learn_lan_hostname(dev["ip"], hostname, touched_devices)
            return
    _pending_mac_names[mac] = hostname


# ── Packet handling / Traitement des paquets ─────────────────────────────────

def _flag_alert(alert, mapping: dict) -> None:
    """
    EN: Mark a node/device as alerted — but ONLY for warning/critical
        severity. Info alerts (NEW_HOST, NEW_LAN_DEVICE, DEVICE_OFFLINE)
        are informational: ringing every new neighbour in red cries wolf.
        `alert_severity` keeps the worst level seen so the UI can pick the
        ring color.
    FR: Marquer un nœud/appareil en alerte — mais SEULEMENT pour les
        sévérités warning/critical. Les alertes info (NEW_HOST,
        NEW_LAN_DEVICE, DEVICE_OFFLINE) sont informatives : entourer de
        rouge chaque nouveau voisin crie au loup. `alert_severity` garde le
        pire niveau vu pour la couleur de l'anneau.
    """
    if not alert.node_id or alert.node_id not in mapping:
        return
    if alert.severity == "info":
        return
    node = mapping[alert.node_id]
    node["alerted"] = True
    if alert.severity == "critical" or node.get("alert_severity") != "critical":
        node["alert_severity"] = alert.severity


def on_packet(pkt: Packet) -> None:
    """
    EN: Called from the capture THREAD — drop into the bounded queue. The
        event loop drains it in batches; no coroutine is created per packet.
    FR: Appelé depuis le THREAD de capture — déposer dans la file bornée. La
        boucle d'événements la vide par lots ; aucune coroutine n'est créée
        par paquet.
    """
    try:
        _pkt_queue.put_nowait(pkt)
    except queue.Full:
        try:
            _pkt_queue.get_nowait()         # EN: drop oldest / FR: jeter le plus ancien
            _drop_stats["queue_oldest_dropped"] += 1
            _pkt_queue.put_nowait(pkt)
            # EN: Saturated queue = lost traffic — surface it at the 1st drop
            #     and each power of 10 so bursts don't flood the log.
            # FR: File saturée = trafic perdu — signaler au 1er rejet puis à
            #     chaque puissance de 10 pour que les rafales ne noient pas
            #     le journal.
            n = _drop_stats["queue_oldest_dropped"]
            if n == 1 or n % 1000 == 0:
                logger.warning("packet queue saturated — %d stale packets "
                               "dropped so far", n)
        except (queue.Empty, queue.Full):
            _drop_stats["queue_put_failed"] += 1


def _request_enrichment(ip: str) -> None:
    """
    EN: Kick off a deduplicated background enrichment for `ip`. The node is
        patched + broadcast when the lookup resolves. Failures cache a stub
        for 5 min only — never permanently.
    FR: Lancer un enrichissement de fond dédupliqué pour `ip`. Le nœud est
        patché + rediffusé quand la résolution aboutit. Les échecs sont cachés
        5 min seulement — jamais définitivement.
    """
    if ip in _inflight_geo or ip in enrichment_cache:
        return
    _inflight_geo.add(ip)

    async def _enrich() -> None:
        try:
            geo = await enrich_ip(ip)
            if len(enrichment_cache) > MAX_ENRICHMENT_CACHE:
                for stale in list(enrichment_cache.keys())[: MAX_ENRICHMENT_CACHE // 2]:
                    enrichment_cache.pop(stale, None)
            enrichment_cache[ip] = geo
            node = nodes.get(ip)
            if node:
                node.update({
                    "label": geo.get("hostname") or node["label"],
                    "country": geo.get("country"),
                    "country_code": geo.get("country_code"),
                    "city": geo.get("city"),
                    "lat": geo.get("lat"),
                    "lon": geo.get("lon"),
                    "org": geo.get("org"),
                    "asn": geo.get("asn"),
                })
                await broadcast({"type": "node_update", "node": node})
        except Exception as exc:
            logger.debug("enrich_ip failed for %s: %s", ip, exc)
            enrichment_cache[ip] = {"ip": ip, "hostname": None, "private": False,
                                    "_expires": time.time() + 300}
        finally:
            _inflight_geo.discard(ip)

    asyncio.get_running_loop().create_task(_enrich())


def _geo_for(ip: str) -> dict:
    """
    EN: Best geo info available RIGHT NOW — cached result or a stub with the
        observed DNS/SNI domain. Kicks off background enrichment on a miss.
    FR: Meilleure info géo disponible IMMÉDIATEMENT — résultat en cache ou
        stub avec le domaine DNS/SNI observé. Lance un enrichissement de fond
        en cas d'échec.
    """
    cached = enrichment_cache.get(ip)
    if cached and cached.get("_expires", float("inf")) > time.time():
        return cached
    _request_enrichment(ip)
    return {"ip": ip, "hostname": lookup_domain(ip), "private": is_private(ip)}


async def _ti_check(ip: str) -> None:
    """
    EN: Background threat-intel lookup for a newly-seen host. Runs the
        blocking HTTP call in an executor; on a suspicious/malicious verdict
        it raises, logs and broadcasts a THREAT_HIT alert. Silent on errors —
        reputation is a bonus, never a dependency.
    FR: Vérification threat-intel en fond pour un hôte nouvellement vu.
        L'appel HTTP bloquant tourne dans un executor ; sur verdict suspect/
        malveillant, une alerte THREAT_HIT est émise, journalisée et diffusée.
        Silencieux en erreur — la réputation est un bonus, pas une dépendance.
    """
    loop = asyncio.get_running_loop()
    try:
        verdict = await loop.run_in_executor(None, ti.check, ip)
    except Exception as exc:
        logger.debug("ti.check failed for %s: %s", ip, exc)
        return
    if not verdict or verdict.get("verdict") not in ("malicious", "suspicious"):
        return
    alert = Alert(
        type="THREAT_HIT",
        severity="critical" if verdict["verdict"] == "malicious" else "warning",
        message=f"Threat intel: {ip} reported {verdict['verdict']} "
                f"({verdict.get('provider', '?')}: {verdict.get('detail', '')})",
        node_id=ip,
        details=verdict,
    )
    _flag_alert(alert, nodes)
    d = alert.to_dict()
    db.log_alert(d)
    await broadcast({"type": "alert", "alert": d})
    await _notify(d)


async def _notify(alert_dict: dict) -> None:
    """
    EN: Forward one alert to the configured webhook (if any) — the blocking
        POST happens in an executor so detection is never delayed.
    FR: Relayer une alerte vers le webhook configuré (le cas échéant) — le
        POST bloquant passe par un executor pour ne jamais retarder la
        détection.
    """
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(None, notifier.dispatch, alert_dict)
    except Exception as exc:
        logger.debug("webhook notify failed: %s", exc)


def _process_batch(packets: list[Packet]) -> None:
    """
    EN: One drain tick — runs on the event-loop thread. Per packet: filters,
        LAN accounting, graph aggregation, detection (lock-guarded inside).
        Returns the coalesced broadcast payload pieces.
    FR: Un tick de vidage — tourne sur le thread de la boucle. Par paquet :
        filtres, comptabilisation LAN, agrégation du graphe, détection (sous
        verrou à l'intérieur). Renvoie les morceaux du lot à diffuser.
    """
    touched_nodes: dict[str, dict] = {}
    touched_edges: dict[str, dict] = {}
    touched_devices: dict[str, dict] = {}
    out_packets: list[dict] = []
    out_alerts: list[dict] = []
    # EN: (pid, name) pairs seen outbound this batch — handed to the
    #     integrity watcher once per tick (it dedups per process lifetime).
    # FR: Couples (pid, nom) sortants du lot — transmis à la veille
    #     d'intégrité une fois par tick (elle déduplique par processus).
    seen_pids: dict[int, str] = {}

    for pkt in packets:
        if pkt.process_name and pkt.process_name in _excluded_processes:
            _drop_stats["excluded_process"] += 1
            continue

        remote_ip = pkt.dst_ip if pkt.direction == "out" else pkt.src_ip

        # EN: DNS/mDNS learning runs BEFORE the noise filter — mDNS answers
        #     are destined to multicast 224.0.0.251, which must never become
        #     a node but still carries "*.local" device names we want.
        # FR: L'apprentissage DNS/mDNS tourne AVANT le filtre anti-bruit —
        #     les réponses mDNS visent le multicast 224.0.0.251, qui ne doit
        #     jamais devenir un nœud mais porte les noms « *.local » utiles.
        if pkt.dns:
            dns53 = []
            for name, ip, _ttl in pkt.dns:
                low = name.lower()
                if ip == "":
                    # EN: Name CLAIMED BY THE SENDER (mDNS service instance,
                    #     NBNS registration) — the device is pkt.src_ip.
                    # FR: Nom REVENDIQUÉ PAR L'ÉMETTEUR (instance de service
                    #     mDNS, enregistrement NBNS) — l'appareil est
                    #     pkt.src_ip.
                    dev = _devname(name)
                    if dev and is_private(pkt.src_ip):
                        _learn_lan_hostname(pkt.src_ip, dev, touched_devices)
                elif low.endswith(".local"):
                    # EN: Explicit "x.local → ip" binding from an mDNS A/AAAA.
                    # FR: Liaison explicite « x.local → ip » d'un A/AAAA mDNS.
                    if is_private(ip):
                        _learn_lan_hostname(ip, name[:-len(".local")],
                                            touched_devices)
                elif is_private(ip) and "." not in name:
                    # EN: LLMNR "PC-NAME → ip" — Windows name claims.
                    # FR: LLMNR « PC-NAME → ip » — revendications Windows.
                    _learn_lan_hostname(ip, name, touched_devices)
                else:
                    dns53.append((name, ip, _ttl))
            if dns53:
                learn_dns_answers(dns53)
        if pkt.dhcp:
            _learn_dhcp_name(*pkt.dhcp, touched_devices)

        if remote_ip in _whitelisted_ips:
            _drop_stats["whitelisted_ip"] += 1
            continue
        if _is_noise_ip(remote_ip):
            _drop_stats["noise_filtered"] += 1
            continue

        if pkt.sni:
            learn_sni(remote_ip, pkt.sni)

        # ── LAN accounting / Comptabilisation LAN ───────────────────────────
        if is_private(remote_ip):
            dev = _ensure_lan_device(remote_ip)
            dev["bytes"] += pkt.size
            dev["packets"] += 1
            touched_devices[dev["id"]] = dev
            # EN: Our own IP returns the "local" node — no phantom LAN edge.
            # FR: Une IP propre renvoie le nœud « local » — pas d'arête fantôme.
            if dev["id"] != "local":
                edge = edges[f"lan-edge-{remote_ip}"]
                edge["bytes"] += pkt.size
                edge["packets"] += 1
                touched_edges[edge["id"]] = edge
            continue

        geo = _geo_for(remote_ip)

        # EN: remote_port — the fix for the inbound classification bug.
        #     Category is recomputed and updatable (not frozen at creation).
        # FR: remote_port — la correction du bug de classification entrant.
        #     La catégorie est recalculée et modifiable (pas figée à la
        #     création).
        category = classify(geo.get("hostname") or pkt.sni,
                            pkt.remote_port, pkt.protocol)

        node_id = remote_ip
        node = nodes.get(node_id)
        if node is None:
            if len(nodes) >= MAX_GRAPH_NODES:
                _evict_weakest_node()
            node = {
                "id": node_id,
                "label": geo.get("hostname") or remote_ip,
                "ip": remote_ip,
                "country": geo.get("country"),
                "country_code": geo.get("country_code"),
                "city": geo.get("city"),
                "lat": geo.get("lat"),
                "lon": geo.get("lon"),
                "org": geo.get("org"),
                "asn": geo.get("asn"),
                "category": category.category,
                "color": category.color,
                "bytes": 0, "packets": 0, "alerted": False,
            }
            nodes[node_id] = node
        elif node["category"] == "other" and category.category != "other":
            # EN: Upgrade a placeholder category once DNS/SNI gives a real name.
            # FR: Améliorer une catégorie générique quand DNS/SNI donne un vrai nom.
            node["category"] = category.category
            node["color"] = category.color
        elif node["label"] == remote_ip and geo.get("hostname"):
            node["label"] = geo["hostname"]

        node["bytes"] += pkt.size
        node["packets"] += 1

        if pkt.process_name:
            procs = node.setdefault("processes", {})
            proc = procs.setdefault(pkt.process_name, {"bytes": 0, "packets": 0})
            proc["bytes"] += pkt.size
            proc["packets"] += 1
            # EN: Last-seen PID for the kill/suspend actions in the UI.
            # FR: Dernier PID vu pour les actions tuer/suspendre de l'UI.
            if pkt.pid:
                proc["pid"] = pkt.pid

        edge_id = f"local-{node_id}-{pkt.protocol}"
        edge = edges.setdefault(edge_id, {
            "id": edge_id, "source": "local", "target": node_id,
            "protocol": pkt.protocol, "label": category.label,
            "color": category.color, "bytes": 0, "packets": 0,
        })
        edge["bytes"] += pkt.size
        edge["packets"] += 1

        minute = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M")
        db.accumulate(minute, category.category, pkt.size)
        # EN: Per-entity history — feeds the per-host and per-app views.
        # FR: Historique par entité — alimente les vues par hôte et par app.
        db.accumulate_history(minute, "host", remote_ip, pkt.size)
        if pkt.process_name:
            db.accumulate_history(minute, "process", pkt.process_name, pkt.size)

        # EN: Detection runs in the event loop — analyze_packet is
        #     lock-guarded internally, no executor hop needed.
        # FR: La détection tourne dans la boucle — analyze_packet est
        #     protégée par verrou, pas besoin de saut d'executor.
        for alert in detector.analyze_packet(pkt, geo):
            _flag_alert(alert, nodes)
            alert_dict = alert.to_dict()
            db.log_alert(alert_dict)
            out_alerts.append(alert_dict)
            # EN: Relay warning/critical alerts to the external webhook (opt-in).
            # FR: Relayer les alertes warning/critical vers le webhook externe
            #     (opt-in).
            asyncio.get_running_loop().create_task(_notify(alert_dict))
            # EN: A NEW_HOST alert marks the first sighting — the right moment
            #     for an opt-in reputation lookup on public IPs.
            # FR: Une alerte NEW_HOST marque une première vue — le bon moment
            #     pour une vérif de réputation opt-in sur les IP publiques.
            if (alert.type == "NEW_HOST" and ti.enabled
                    and not is_private(remote_ip)
                    and ti.begin_check(remote_ip)):
                asyncio.get_running_loop().create_task(_ti_check(remote_ip))

        # EN: Firewall visibility — a packet matching an active rule (or the
        #     lockdown) raises BLOCKED_ATTEMPT. This flags policy hits; actual
        #     dropping requires the optional privileged rule sync documented
        #     in /firewall/status.
        # FR: Visibilité pare-feu — un paquet correspondant à une règle active
        #     (ou au lockdown) lève BLOCKED_ATTEMPT. Cela signale les violations
        #     de politique ; le drop réel exige la synchro privilégiée
        #     documentée dans /firewall/status.
        fw_rule = fw.check_packet(pkt)
        if fw_rule:
            ctx = fw.note_blocked(fw_rule["id"])
            if ctx:
                matched = ctx.get("rule") or fw_rule
                a = Alert(
                    type="BLOCKED_ATTEMPT", severity="warning",
                    message=f"Firewall rule matched: {matched.get('value')} "
                            f"({matched.get('kind')}) — attempt #{ctx['count']}"
                            + (" by " + pkt.process_name if pkt.process_name else ""),
                    node_id=remote_ip,
                    details={"rule": matched, "process": pkt.process_name,
                             "direction": pkt.direction},
                )
                _flag_alert(a, nodes)
                ad = a.to_dict()
                db.log_alert(ad)
                out_alerts.append(ad)

        # EN: Mining signals — cleartext stratum in the payload head and
        #     pool-port marking for later CPU corroboration (drain loop).
        # FR: Signaux de minage — stratum en clair dans la tête du payload
        #     et marquage port-pool pour corroboration CPU (boucle drain).
        # EN: User-defined alert rules — first match per packet raises
        #     CUSTOM_RULE carrying the rule name (alert-only, never blocks).
        # FR: Règles d'alerte utilisateur — le premier match lève
        #     CUSTOM_RULE portant le nom de la règle (alerte, jamais de blocage).
        for m in custom_rules.check(pkt)[:1]:
            r = m["rule"]
            a = Alert(
                type="CUSTOM_RULE", severity=r["severity"],
                message=f"Custom rule matched: {r['name']} "
                        f"({r['field']} {r['op']} {r['value']}) — hit #{m['count']}"
                        + (" by " + pkt.process_name if pkt.process_name else ""),
                node_id=remote_ip,
                details={"rule": r, "process": pkt.process_name,
                         "direction": pkt.direction},
            )
            _flag_alert(a, nodes)
            ad = a.to_dict()
            db.log_alert(ad)
            out_alerts.append(ad)
            asyncio.get_running_loop().create_task(_notify(ad))

        for f in miner.analyze_packet(pkt):
            a = Alert(
                type=f["type"], severity=f["severity"],
                message=f"Mining: {f['type'].replace('_', ' ').title()} — "
                        f"{f.get('process')}: {f.get('detail', '')}",
                node_id=remote_ip, details=f)
            _flag_alert(a, nodes)
            ad = a.to_dict()
            db.log_alert(ad)
            out_alerts.append(ad)
            asyncio.get_running_loop().create_task(_notify(ad))

        # EN: Outbound packets with attribution feed the integrity watch —
        #     the watcher itself is bounded (one inspection per pid lifetime).
        # FR: Les paquets sortants attribués alimentent la veille d'intégrité —
        #     bornée en interne (une inspection par durée de vie du pid).
        if pkt.direction == "out" and pkt.pid and pkt.pid > 3:
            seen_pids[pkt.pid] = pkt.process_name or ""

        touched_nodes[node_id] = node
        touched_edges[edge_id] = edge
        out_packets.append({
            "src": pkt.src_ip, "dst": pkt.dst_ip,
            "protocol": pkt.protocol, "size": pkt.size,
            "direction": pkt.direction, "process": pkt.process_name,
            "remote_port": pkt.remote_port, "sni": pkt.sni,
            "pid": pkt.pid,
            "timestamp": pkt.timestamp,
        })

    # EN: Integrity checks run AFTER the batch — hashing exe files and
    #     reading /proc maps would stall the 4 Hz drain if done inline.
    # FR: Les contrôles d'intégrité tournent APRÈS le lot — hasher des exes
    #     et lire /proc maps bloquerait le drain 4 Hz en ligne.
    if seen_pids and integrity.enabled:
        asyncio.get_running_loop().create_task(
            _integrity_scan(list(seen_pids.items())))

    return {
        "type": "batch",
        "nodes": list(touched_nodes.values()),
        "edges": list(touched_edges.values()),
        "devices": list(touched_devices.values()),
        "packets": out_packets,
        "alerts": out_alerts,
    }


async def _integrity_scan(items: list[tuple[int, str]]) -> None:
    """
    EN: Background integrity pass for the new PIDs of one drain tick —
        psutil/file-hash/maps reads run in an executor; each finding becomes
        a logged + broadcast alert (and webhook notification when eligible).
    FR: Passage d'intégrité en fond pour les nouveaux PID d'un tick —
        psutil/hash/maps tournent dans un executor ; chaque constat devient
        une alerte journalisée + diffusée (et notification webhook).
    """
    loop = asyncio.get_running_loop()
    try:
        findings = await loop.run_in_executor(None, integrity.check_many, items)
    except Exception as exc:
        logger.debug("integrity scan failed: %s", exc)
        return
    for f in findings:
        proc = f.get("process") or f.get("pid")
        alert = Alert(
            type=f["type"],
            severity=f.get("severity", "warning"),
            message=f"Integrity: {f['type'].replace('_', ' ').title()} — "
                    f"{proc}: {f.get('detail', '')}",
            node_id=None,
            details=f,
        )
        d = alert.to_dict()
        db.log_alert(d)
        await broadcast({"type": "alert", "alert": d})
        if f.get("severity") != "info":
            await _notify(d)


async def _drain_loop() -> None:
    """
    EN: THE consumer of _pkt_queue — one task, ~4 Hz. Each tick drains up to
        DRAIN_MAX_PACKETS, aggregates them, and broadcasts a single "batch"
        message. Replaces the old per-packet coroutine+broadcast storm.
    FR: LE consommateur de _pkt_queue — une tâche, ~4 Hz. Chaque tick vide
        jusqu'à DRAIN_MAX_PACKETS paquets, les agrège et diffuse un unique
        message « batch ». Remplace l'ancienne tempête coroutine+broadcast
        par paquet.
    """
    ticks = 0
    while not _shutdown:
        batch: list[Packet] = []
        for _ in range(DRAIN_MAX_PACKETS):
            try:
                batch.append(_pkt_queue.get_nowait())
            except queue.Empty:
                break
        if batch:
            try:
                await broadcast(_process_batch(batch))
            except Exception as exc:
                logger.exception("packet batch failed: %s", exc)
        ticks += 1
        # EN: ~10 s — pool-port suspects get their CPU corroboration in an
        #     executor (cpu_percent samples briefly; never on the loop).
        # FR: ~10 s — les suspects port-pool reçoivent leur corroboration
        #     CPU dans un executor (cpu_percent échantillonne ; jamais sur
        #     la boucle).
        if ticks % 40 == 0:
            asyncio.get_running_loop().create_task(_miner_corroborate())
        await asyncio.sleep(DRAIN_INTERVAL_S)


async def _miner_corroborate() -> None:
    """EN: Sample CPU for pool-port suspects off the event loop; each
    corroborated case becomes a MINING_SUSPECT alert.
    FR: Échantillonner la CPU des suspects port-pool hors boucle ; chaque
    cas corroboré devient une alerte MINING_SUSPECT."""
    loop = asyncio.get_running_loop()
    try:
        findings = await loop.run_in_executor(None, miner.cpu_corroborate)
    except Exception as exc:
        logger.debug("miner corroboration failed: %s", exc)
        return
    for f in findings:
        a = Alert(type=f["type"], severity=f["severity"],
                  message=f"Mining suspect — {f.get('process')}: "
                          f"{f.get('detail', '')}",
                  node_id=f.get("ip"), details=f)
        d = a.to_dict()
        db.log_alert(d)
        await broadcast({"type": "alert", "alert": d})
        await _notify(d)


def _evict_weakest_node() -> None:
    """
    EN: Remove the lowest-byte, non-alerted, non-local node (and its edges)
        when the graph hits MAX_GRAPH_NODES.
    FR: Retirer le nœud au plus faible trafic, non alerté et non « local »
        (et ses arêtes) quand le graphe atteint MAX_GRAPH_NODES.
    """
    candidates = [n for n in nodes.values()
                  if n["id"] != "local" and not n.get("alerted")]
    if not candidates:
        return
    weakest = min(candidates, key=lambda n: n.get("bytes", 0))
    wid = weakest["id"]
    nodes.pop(wid, None)
    enrichment_cache.pop(wid, None)
    for eid in [eid for eid, e in edges.items()
                if e["target"] == wid or e["source"] == wid]:
        edges.pop(eid, None)


# ── LAN device handling / Gestion des appareils LAN ──────────────────────────

def on_device(device: Device, is_new: bool) -> None:
    """EN: ARP-table scanner callback — schedules async handling.
    FR: Callback du scanner de table ARP — planifie le traitement async."""
    if _loop is None:
        return
    asyncio.run_coroutine_threadsafe(_handle_device(device, is_new), _loop)


async def _handle_device(device: Device, is_new: bool) -> None:
    """
    EN: Register/update a LAN device node, maintain its dashed edge to
        "local", run device-level anomaly rules.
    FR: Enregistrer/mettre à jour le nœud d'un appareil LAN, maintenir son
        arête pointillée vers « local », lancer les règles niveau appareil.
    """
    if device.ip in _own_ips():
        # EN: The ARP table can contain OUR OWN address — it's the "local"
        #     center node, not a LAN peer. Adopt the MAC/real IP onto the
        #     local node instead of spawning a phantom device that would
        #     carry the sanitized hostname ("MoneyLisa" without "$").
        # FR: La table ARP peut contenir NOTRE PROPRE adresse — c'est le nœud
        #     central « local », pas un pair LAN. Adopter la MAC/IP réelle
        #     sur le nœud local au lieu de créer un appareil fantôme qui
        #     porterait le nom sanitisé (« MoneyLisa » sans « $ »).
        local = nodes.get("local")
        if local is not None:
            local["mac"] = device.mac or local.get("mac")
            if local.get("ip") == "local":
                local["ip"] = device.ip
        return
    node = device.to_dict()
    # EN: Preserve accumulated counters + merge any stub the packet path made.
    # FR: Préserver les compteurs + fusionner l'éventuel stub du chemin paquets.
    prev = lan_devices.get(node["id"])
    if prev:
        node["bytes"] = prev.get("bytes", 0)
        node["packets"] = prev.get("packets", 0)
        node["alerted"] = prev.get("alerted", False)
        # EN: Keep names learned from mDNS — reverse-DNS often returns None
        #     where a passive mDNS announcement already gave a real hostname.
        # FR: Garder les noms appris via mDNS — le DNS inverse renvoie souvent
        #     None là où une annonce mDNS passive a déjà donné un vrai nom.
        if not device.hostname and prev.get("hostname"):
            node["hostname"] = prev["hostname"]
            node["label"] = prev["hostname"]
        # EN: A DHCP-learned name waiting for this MAC — applies even when
        #     the stub didn't exist yet.
        # FR: Un nom appris via DHCP en attente de cette MAC — s'applique
        #     même quand le stub n'existait pas encore.
        pending = _pending_mac_names.pop(device.mac, None)
        if pending and not node["hostname"]:
            node["hostname"] = pending
            node["label"] = pending

    # EN: Recall the persisted identity — a device named in a previous
    #     session keeps its name across restarts. MAC-verified (see db.py).
    # FR: Rappeler l'identité persistée — un appareil nommé lors d'une
    #     session précédente garde son nom entre redémarrages. Vérifiée par
    #     MAC (voir db.py).
    if not node["hostname"]:
        stored = db.device_identity(device.ip, device.mac)
        if stored.get("hostname"):
            node["hostname"] = stored["hostname"]
            node["label"] = stored["hostname"]
        if stored.get("vendor") and not node.get("vendor"):
            node["vendor"] = stored["vendor"]
        if stored.get("device_type") and node.get("device_type") in (None, "unknown"):
            node["device_type"] = stored["device_type"]

    # EN: Persist the freshest identity — next boot starts from knowledge,
    #     not from zero.
    # FR: Persister l'identité la plus fraîche — le prochain démarrage part
    #     d'un savoir, pas de zéro.
    db.upsert_device(ip=device.ip, mac=device.mac, vendor=device.vendor,
                     device_type=device.device_type,
                     hostname=node.get("hostname"),
                     private_mac=device.private_mac)

    lan_devices[node["id"]] = node

    edge_id = f"lan-edge-{device.ip}"
    prev_edge = edges.get(edge_id, {})
    edges[edge_id] = {
        "id": edge_id,
        "source": "local",
        "target": node["id"],
        "protocol": "LAN",
        "label": "LAN",
        "color": node["color"],
        "bytes": prev_edge.get("bytes", 0),
        "packets": prev_edge.get("packets", 0),
        "dashed": True,
    }

    loop = asyncio.get_running_loop()
    alerts = await loop.run_in_executor(None, detector.analyze_device, device, is_new)
    for alert in alerts:
        _flag_alert(alert, lan_devices)
        alert_dict = alert.to_dict()
        db.log_alert(alert_dict)
        await broadcast({"type": "alert", "alert": alert_dict})

    await broadcast({
        "type": "device_update",
        "device": node,
        "edge": edges[edge_id],
        "is_new": is_new,
    })


# ── Background threads / Threads d'arrière-plan ──────────────────────────────

def _on_media_change(state: MediaState) -> None:
    """
    EN: MediaMonitor callback — sync the detector's media sets and notify UI.
        `supported=False` (macOS) is forwarded so the badge can hide.
    FR: Callback MediaMonitor — synchroniser les ensembles média du détecteur
        et notifier l'UI. `supported=False` (macOS) est transmis pour que le
        badge se masque.
    """
    global _media_state
    _media_state = {"mic": state.mic, "camera": state.camera,
                    "supported": state.supported}
    detector.update_media_state(state.mic, state.camera)
    if _loop:
        asyncio.run_coroutine_threadsafe(
            broadcast({"type": "media", **_media_state}), _loop)


def _flush_loop() -> None:
    """EN: Periodically flush the traffic accumulator to SQLite.
    FR: Vider périodiquement l'accumulateur de trafic vers SQLite."""
    ticks = 0
    while not _shutdown:
        time.sleep(10)
        ticks += 1
        try:
            db.flush()
            # EN: Snapshot learned process baselines — they power the
            #     baseline-deviation alerts across restarts.
            # FR: Sauvegarder les baselines de processus apprises — elles
            #     alimentent les alertes de déviation entre redémarrages.
            db.set_setting("app_baselines", detector.dump_baselines())
            db.set_setting("integrity_baselines", integrity.dump_baselines())
        except Exception as exc:
            logger.error("db flush failed: %s", exc)
        # EN: Domain rules re-resolve every ~10 min — CDNs rotate IPs, and a
        #     stale resolution would silently stop matching the name.
        # FR: Les règles domaine se re-résolvent toutes les ~10 min — les CDN
        #     font tourner leurs IP et une résolution périmée cesserait de
        #     matcher le nom sans bruit.
        if ticks % 60 == 0:
            try:
                changed = fw.refresh_domains()
                if changed:
                    rules, _lockdown = fw.serialized()
                    db.set_setting("firewall_rules", rules)
                    logger.info("firewall: %d domain rule(s) re-resolved",
                                changed)
            except Exception as exc:
                logger.debug("domain refresh failed: %s", exc)
        # EN: Sinkhole responder lifecycle — listen while at least one
        #     enabled sinkhole rule exists, drain its hits into alerts.
        # FR: Cycle de vie du répondeur sinkhole — écouter tant qu'une
        #     règle sinkhole active existe, vider ses hits en alertes.
        try:
            rules_now, _ld = fw.serialized()
            has_sink = any(r.get("action") == "sinkhole" and r.get("enabled", True)
                           for r in rules_now)
            if has_sink:
                sink.start()
            else:
                sink.stop()
            for hit in sink.pop_hits():
                a = Alert(
                    type="SINKHOLE_HIT", severity="warning",
                    message=f"Sinkholed connection observed: "
                            f"{hit.get('host') or hit.get('kind')} — "
                            f"{hit.get('process') or 'pid ' + str(hit.get('pid'))}",
                    node_id=None, details=hit)
                d = a.to_dict()
                db.log_alert(d)
                if _loop:
                    asyncio.run_coroutine_threadsafe(
                        broadcast({"type": "alert", "alert": d}), _loop)
                    asyncio.run_coroutine_threadsafe(_notify(d), _loop)
        except Exception as exc:
            logger.debug("sinkhole responder tick failed: %s", exc)


def _cleanup_loop() -> None:
    """
    EN: Drop rows older than the configured retention — the DB must not grow
        forever. Retention is a persisted setting (hours, default 24).
    FR: Supprimer les lignes plus anciennes que la rétention configurée — la
        BDD ne doit pas grossir indéfiniment. La rétention est un réglage
        persisté (heures, défaut 24).
    """
    while not _shutdown:
        time.sleep(3600)
        try:
            db.cleanup_old_data(hours=int(db.get_setting("retention_hours", 24)))
        except Exception as exc:
            logger.error("db cleanup failed: %s", exc)


# ── Capture lifecycle / Cycle de vie de la capture ───────────────────────────

def _start_capture() -> None:
    """EN: (Re)start sniffer + ARP-table scanner in daemon threads.
        With SNITCH_DEMO=1 the sniffer is replaced by the synthetic demo
        feeder — no root, no libpcap, no real traffic touched.
    FR: (Re)démarrer sniffer + scanner de table ARP dans des threads daemon.
        Avec SNITCH_DEMO=1 le sniffer est remplacé par le générateur de démo
        — ni root ni libpcap ni trafic réel."""
    global _sniffer, _scanner, _capturing
    if demo.enabled():
        _sniffer = demo.start(on_packet)
        logger.warning("DEMO MODE — synthetic traffic only")
    else:
        _sniffer = PacketSniffer(callback=on_packet, ports=_port_filter,
                                 iface=db.get_setting("interface"))
        # EN: eBPF attribution probe — kernel sees every connect() even
        #     from processes that die before the next socket-table refresh.
        #     Opt-in-able via settings, silently no-ops without bcc/root.
        # FR: Sonde d'attribution eBPF — le noyau voit chaque connect() même
        #     des processus morts avant le prochain rafraîchissement de la
        #     table. Réglable, silencieusement inactive sans bcc/root.
        if db.get_setting("ebpf_probe", True):
            if ebpf.start():
                _sniffer.set_attribution_probe(ebpf)
                logger.info("eBPF connect probe active")
        threading.Thread(target=_sniffer.start, daemon=True).start()
    _scanner = ARPScanner(callback=on_device, interval=30)
    threading.Thread(target=_scanner.start, daemon=True).start()
    _capturing = True
    logger.info("capture started (ports=%s)", _port_filter or "all")


def _stop_capture() -> None:
    """EN: Stop both capture sources. / FR: Arrêter les deux sources de capture."""
    global _capturing
    if _sniffer:
        _sniffer.stop()
    if _scanner:
        _scanner.stop()
    _capturing = False
    logger.info("capture stopped")


# ── Wi-Fi SSID / SSID Wi-Fi ──────────────────────────────────────────────────
# EN: Current wireless network name — displayed in the status bar so the user
#     can tell "home" from "hotel wifi" at a glance. Best-effort per platform,
#     cached 60 s, empty string on Ethernet/unsupported.
# FR: Nom du réseau sans fil courant — affiché dans la barre de statut pour
#     distinguer « maison » et « wifi d'hôtel » d'un coup d'œil. Au mieux par
#     plateforme, en cache 60 s, chaîne vide sur Ethernet/non géré.
_ssid_cache: dict = {"ssid": "", "ts": 0.0}


def _current_ssid() -> str:
    """EN: Active Wi-Fi SSID (60 s cache), "" when not on Wi-Fi or unknown.
    FR: SSID Wi-Fi actif (cache 60 s), « » hors Wi-Fi ou inconnu."""
    now = time.time()
    if now - _ssid_cache["ts"] < 60:
        return _ssid_cache["ssid"]
    ssid = ""
    try:
        if sys.platform == "darwin":
            iface = (_sniffer.iface if _sniffer else None) or "en0"
            out = subprocess.run(
                ["ipconfig", "getsummary", iface],
                capture_output=True, text=True, timeout=3).stdout
            for line in out.splitlines():
                if "SSID :" in line:
                    ssid = line.split("SSID :", 1)[1].strip()
                    break
        elif sys.platform.startswith("linux"):
            out = subprocess.run(
                ["iwgetid", "-r"], capture_output=True, text=True, timeout=3
            ).stdout.strip()
            if out:
                ssid = out
        elif sys.platform == "win32":
            out = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, timeout=3).stdout
            for line in out.splitlines():
                if line.strip().startswith("SSID"):
                    ssid = line.split(":", 1)[1].strip()
                    break
    except (OSError, subprocess.TimeoutExpired):
        pass
    _ssid_cache["ssid"] = ssid
    _ssid_cache["ts"] = now
    return ssid


def _load_settings() -> None:
    """
    EN: Restore persisted settings from SQLite at startup — filters, whitelist
        and process exclusions survive restarts now.
    FR: Restaurer les réglages persistés depuis SQLite au démarrage — filtres,
        whitelist et exclusions de processus survivent aux redémarrages.
    """
    global _port_filter, _excluded_processes, _whitelisted_ips, _watchlist
    _port_filter = db.get_setting("ports", []) or []
    _excluded_processes = set(db.get_setting("excluded_processes", []) or [])
    _whitelisted_ips = set(db.get_setting("whitelisted_ips", []) or [])
    _watchlist = list(db.get_setting("watchlist", []) or [])
    detector.load_suppressions(db.get_setting("suppressions", []) or [])
    detector.set_watchlist(_watchlist)
    detector.set_upload_threshold_mb(
        float(db.get_setting("upload_threshold_mb", 50)))
    # EN: Security modules — firewall rules/lockdown, opt-in threat intel,
    #     learned process baselines and the external webhook.
    # FR: Modules de sécurité — règles/lockdown pare-feu, threat intel opt-in,
    #     baselines de processus apprises et webhook externe.
    fw.load(db.get_setting("firewall_rules", []) or [],
            bool(db.get_setting("firewall_lockdown", False)))
    custom_rules.load(db.get_setting("custom_rules", []) or [])
    ti.configure(db.get_setting("ti_provider", "none") or "none",
                 db.get_setting("ti_api_key", "") or "")
    detector.load_baselines(db.get_setting("app_baselines", {}) or {})
    # EN: Integrity watch is ON by default — it is read-only local
    #     inspection, so it follows the "safe unless told otherwise" rule.
    # FR: La veille d'intégrité est ON par défaut — inspection locale en
    #     lecture seule, donc « sûr sauf indication contraire ».
    integrity.configure(bool(db.get_setting("integrity_watch", True)))
    integrity.load_baselines(db.get_setting("integrity_baselines", {}) or {})
    notifier.configure(db.get_setting("webhook_url", "") or "",
                       bool(db.get_setting("webhook_enabled", False)),
                       db.get_setting("telegram_chat_id", "") or "")
    # EN: Local SLM enrichment — loopback-only by construction, opt-in.
    # FR: Enrichissement SLM local — loopback par construction, opt-in.
    slm.configure(bool(db.get_setting("slm_enabled", False)),
                  db.get_setting("slm_endpoint", "") or "",
                  db.get_setting("slm_model", "") or "",
                  db.get_setting("slm_mode", "") or "",
                  db.get_setting("slm_model_path", "") or "")
    if _port_filter:
        logger.info("restored port filter: %s", _port_filter)


async def _startup() -> None:
    """EN: Startup — create the "local" node, load settings, start capture +
    drain task + background threads.
    FR: Démarrage — créer le nœud « local », charger les réglages, lancer
    capture + tâche de vidage + threads d'arrière-plan."""
    global _loop, _media_monitor
    _loop = asyncio.get_running_loop()

    nodes["local"] = {
        # EN: "local" node = this machine, labeled with its real hostname
        #     ("MoneyLia") — users recognize their own device name better
        #     than a generic "This Device". Falls back to the i18n key.
        # FR: Le nœud « local » = cette machine, étiquetée avec son vrai nom
        #     d'hôte (« MoneyLia ») — l'utilisateur reconnaît mieux le nom
        #     de son appareil qu'un « Cet appareil » générique. Retombe sur
        #     la clé i18n.
        "id": "local", "label": _local_hostname(), "label_key": "node_local",
        "hostname": _local_hostname(), "ip": "local",
        "category": "local", "color": "#3b82f6",
        "bytes": 0, "packets": 0, "alerted": False,
    }

    _load_settings()
    _start_capture()
    asyncio.get_running_loop().create_task(_drain_loop())
    threading.Thread(target=_flush_loop, daemon=True).start()
    threading.Thread(target=_cleanup_loop, daemon=True).start()

    _media_monitor = MediaMonitor(callback=_on_media_change, interval=3)
    threading.Thread(target=_media_monitor.start, daemon=True).start()


async def _shutdown_all() -> None:
    """
    EN: Ordered shutdown — stop capture sources, drain pending packets, flush
        the DB. Threads are daemons so nothing blocks process exit.
    FR: Arrêt ordonné — stopper les sources de capture, vider les paquets en
        attente, flusher la BDD. Les threads sont daemon donc rien ne bloque
        la sortie du processus.
    """
    global _shutdown
    _shutdown = True
    _stop_capture()
    ebpf.stop()
    sink.stop()
    if _media_monitor:
        _media_monitor.stop()
    # EN: Final drain + flush so nothing in flight is lost.
    # FR: Dernier vidage + flush pour ne rien perdre en vol.
    remaining: list[Packet] = []
    while True:
        try:
            remaining.append(_pkt_queue.get_nowait())
        except queue.Empty:
            break
    if remaining:
        try:
            _process_batch(remaining)
        except Exception as exc:
            logger.error("shutdown drain failed: %s", exc)
    try:
        db.flush()
    except Exception as exc:
        logger.error("final db flush failed: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """EN: FastAPI lifespan — startup, yield, then clean shutdown.
    FR: Lifespan FastAPI — démarrage, yield, puis arrêt propre."""
    await _startup()
    try:
        yield
    finally:
        await _shutdown_all()


app = FastAPI(title="Snitch API", lifespan=lifespan)

# EN: Restricted CORS — dev server, self-origin, and `null` (Electron file://).
#     No `*`, no credentials. Combined with the token check this kills the
#     "any open webpage can drive my API" attack.
# FR: CORS restreint — serveur de dev, origine propre et `null` (file://
#     Electron). Pas de `*`, pas de credentials. Combiné au jeton, cela tue
#     l'attaque « n'importe quelle page ouverte pilote mon API ».
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=ALLOWED_ORIGIN_REGEX,
    allow_origins=["null"],              # EN: file:// pages (Electron renderer)
                                         # FR: pages file:// (renderer Electron)
    allow_methods=["GET", "POST", "DELETE"],   # EN: DELETE needed for /alerts/ignore / FR: DELETE requis pour /alerts/ignore
    allow_headers=["X-Snitch-Token", "Content-Type"],
)

# EN: Applied to every route via `dependencies` AND checked explicitly on the
#     WebSocket handshake (WS can't use Depends the same way).
# FR: Appliqué à toutes les routes via `dependencies` ET vérifié explicitement
#     au handshake WebSocket (le WS ne peut pas utiliser Depends pareillement).
_AUTH = [Depends(require_token)]


# ── REST endpoints / Endpoints REST ──────────────────────────────────────────

@app.get("/graph", dependencies=_AUTH)
async def get_graph() -> dict:
    """EN: Full graph snapshot. / FR: Instantané complet du graphe."""
    return {
        "nodes": list(nodes.values()) + list(lan_devices.values()),
        "edges": list(edges.values()),
    }

@app.get("/devices", dependencies=_AUTH)
async def get_devices() -> dict:
    """EN: LAN device list. / FR: Liste des appareils LAN."""
    return {"devices": list(lan_devices.values())}

@app.get("/alerts", dependencies=_AUTH)
async def get_alerts() -> dict:
    """EN: Alert history — SQLite-backed so it survives restarts; falls back
    to the in-memory tail if the DB read fails.
    FR: Historique des alertes — adossé à SQLite donc survit aux
    redémarrages ; repli sur la queue en mémoire si la lecture échoue."""
    loop = asyncio.get_running_loop()
    try:
        rows = await loop.run_in_executor(None, db.get_alerts, 100)
        if rows:
            return {"alerts": rows}
    except Exception as exc:
        logger.debug("get_alerts db read failed: %s", exc)
    return {"alerts": detector.history[-100:]}

@app.get("/media", dependencies=_AUTH)
async def get_media() -> dict:
    """EN: Current mic/camera usage (+ supported flag).
    FR: Usage actuel micro/caméra (+ drapeau supported)."""
    return _media_state

@app.get("/settings", dependencies=_AUTH)
async def get_settings() -> dict:
    """EN: All persisted settings. / FR: Tous les réglages persistés."""
    loop = asyncio.get_running_loop()
    return {"settings": await loop.run_in_executor(None, db.all_settings)}

@app.post("/settings", dependencies=_AUTH)
async def post_settings(body: SettingsBody) -> dict:
    """EN: Persist arbitrary settings keys (language, thresholds…).
    FR: Persister des clés de réglage arbitraires (langue, seuils…)."""
    loop = asyncio.get_running_loop()
    for key, value in body.settings.items():
        await loop.run_in_executor(None, db.set_setting, key, value)
        # EN: Live-apply settings the detector reads dynamically — no restart
        #     needed for the upload threshold to take effect.
        # FR: Appliquer à chaud les réglages que le détecteur lit
        #     dynamiquement — pas besoin de redémarrer pour le seuil d'envoi.
        if key == "upload_threshold_mb":
            try:
                detector.set_upload_threshold_mb(float(value))
            except (TypeError, ValueError):
                pass
        # EN: Live-apply security settings — no restart needed when the user
        #     toggles a provider, rotates a key or flips the webhook switch.
        # FR: Appliquer à chaud les réglages de sécurité — pas de redémarrage
        #     quand l'utilisateur change de fournisseur, de clé ou de webhook.
        if key in ("ti_provider", "ti_api_key"):
            ti.configure(db.get_setting("ti_provider", "none") or "none",
                         db.get_setting("ti_api_key", "") or "")
        if key in ("webhook_url", "webhook_enabled", "telegram_chat_id"):
            notifier.configure(db.get_setting("webhook_url", "") or "",
                               bool(db.get_setting("webhook_enabled", False)),
                               db.get_setting("telegram_chat_id", "") or "")
        if key == "integrity_watch":
            integrity.configure(bool(value))
        if key == "ebpf_probe":
            # EN: Live toggle — start the probe or stop it; never raises
            #     (bcc/root absence is reported by /security/ebpf instead).
            # FR: Bascule à chaud — démarre ou arrête la sonde ; ne lève
            #     jamais (bcc/root absents rapportés par /security/ebpf).
            if value:
                ebpf.start()
                if _sniffer is not None and hasattr(
                        _sniffer, "set_attribution_probe"):
                    _sniffer.set_attribution_probe(ebpf)
            else:
                ebpf.stop()
        if key in ("slm_enabled", "slm_endpoint", "slm_model",
                   "slm_mode", "slm_model_path"):
            slm.configure(bool(db.get_setting("slm_enabled", False)),
                          db.get_setting("slm_endpoint", "") or "",
                          db.get_setting("slm_model", "") or "",
                          db.get_setting("slm_mode", "") or "",
                          db.get_setting("slm_model_path", "") or "")
    return {"ok": True}


def _lan_addresses() -> list[str]:
    """EN: This machine's non-loopback IPv4 addresses — the addresses a
    remote device could reach Snitch on. / FR: Adresses IPv4 non-loopback
    de la machine — celles par lesquelles un appareil distant peut
    joindre Snitch."""
    out = []
    try:
        import psutil
        for addrs in psutil.net_if_addrs().values():
            for a in addrs:
                if a.family.name == "AF_INET":
                    ip = ipaddress.ip_address(a.address)
                    if not ip.is_loopback and not ip.is_link_local:
                        out.append(a.address)
    except Exception:                                # noqa: BLE001
        pass
    return sorted(set(out))


def _current_bind() -> tuple[str, str]:
    """EN: Effective bind address + its source (env > argv > setting >
    default) — mirrors run_backend.py's precedence.
    FR: Adresse d'écoute effective + sa source (env > argv > réglage >
    défaut) — reflète la priorité de run_backend.py."""
    if os.environ.get("SNITCH_BIND"):
        return os.environ["SNITCH_BIND"], "env"
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == "--bind" and i + 1 < len(args):
            return args[i + 1], "argv"
    persisted = db.get_setting("lan_bind", "") or ""
    if persisted:
        return persisted, "setting"
    return "127.0.0.1", "default"


@app.get("/remote/pairing", dependencies=_AUTH)
async def remote_pairing_status() -> dict:
    """EN: Remote-pairing state — where the API listens, which LAN
    addresses clients could use, and whether a persisted opt-in is
    pending for next start. Token auth is ALWAYS required; pairing only
    widens the listen address.
    FR: État du pairing distant — où l'API écoute, quelles adresses LAN
    les clients peuvent utiliser, et si un opt-in persisté attend le
    prochain démarrage. Le jeton reste TOUJOURS exigé ; le pairing
    n'élargit que l'adresse d'écoute."""
    bind, source = _current_bind()
    persisted = db.get_setting("lan_bind", "") or ""
    port = int(os.environ.get("SNITCH_PORT") or "8000")
    return {
        "active": not bind.startswith("127.") and bind not in ("::1", "localhost"),
        "bind": bind, "bind_source": source, "port": port,
        "lan_ips": _lan_addresses(),
        "persisted_bind": persisted,
        "token_required": True,
        "restart_required": bool(persisted) and persisted != bind,
    }


@app.post("/remote/pairing", dependencies=_AUTH)
async def remote_pairing_set(body: PairingBody) -> dict:
    """EN: Opt-in LAN exposure — persist (or clear) a bind address for
        the next backend start. Only "0.0.0.0" or an address the machine
        actually owns is accepted. Returns `restart_required: true`
        because uvicorn cannot rebind a live socket — the UI must say
        this honestly.
    FR: Exposition LAN opt-in — persister (ou effacer) une adresse
        d'écoute pour le prochain démarrage. Seuls « 0.0.0.0 » ou une
        adresse réelle de la machine sont acceptés. `restart_required:
        true` car uvicorn ne peut pas re-binder un socket actif."""
    if not body.enabled:
        db.set_setting("lan_bind", "")
        return {"ok": True, "lan_bind": "", "restart_required": True}
    bind = (body.bind or "0.0.0.0").strip()
    if bind != "0.0.0.0" and bind not in _lan_addresses():
        raise HTTPException(400, "bind must be 0.0.0.0 or a local LAN address")
    db.set_setting("lan_bind", bind)
    return {"ok": True, "lan_bind": bind, "restart_required": True}


@app.get("/capture/status", dependencies=_AUTH)
async def get_capture_status() -> dict:
    """EN: Capture state + all active filters. / FR: État de capture + filtres actifs."""
    return {
        "capturing": _capturing,
        "ports": _port_filter,
        "excluded_processes": sorted(_excluded_processes),
        "whitelisted_ips": sorted(_whitelisted_ips),
        "watchlist": list(_watchlist),
        "interface": _sniffer.iface if _sniffer else None,
        "ssid": _current_ssid(),
    }

@app.post("/capture/stop", dependencies=_AUTH)
async def stop_capture() -> dict:
    """EN: Stop sniffing + ARP scan. / FR: Arrêter le sniffing + le scan ARP."""
    _stop_capture()
    db.set_setting("ports", _port_filter)
    await broadcast({
        "type": "capture_status",
        "capturing": False,
        "ports": _port_filter,
        "excluded_processes": sorted(_excluded_processes),
        "whitelisted_ips": sorted(_whitelisted_ips),
        "watchlist": list(_watchlist),
        "interface": _sniffer.iface if _sniffer else None,
    })
    return {"capturing": False}

@app.post("/capture/ports", dependencies=_AUTH)
async def set_port_filter(body: PortFilterBody) -> dict:
    """
    EN: Restrict capture to a list of ports (empty = all). Graph and detector
        runtime state are both reset so the UI only shows matching traffic.
        Persisted — the filter survives restarts.
    FR: Restreindre la capture à une liste de ports (vide = tous). Le graphe et
        l'état du détecteur sont réinitialisés pour que l'UI n'affiche que le
        trafic correspondant. Persisté — le filtre survit aux redémarrages.
    """
    global _port_filter
    _port_filter = [p for p in body.ports if 1 <= p <= 65535]
    db.set_setting("ports", _port_filter)

    # EN: Clear graph + detector state — keep only the "local" node.
    # FR: Vider graphe + état du détecteur — ne garder que le nœud « local ».
    local = nodes.get("local")
    nodes.clear()
    edges.clear()
    lan_devices.clear()
    if local:
        nodes["local"] = local
    detector.reset_runtime()

    if _capturing:
        _stop_capture()
        _start_capture()

    await broadcast({
        "type": "reset",
        "ports": _port_filter,
        "nodes": list(nodes.values()) + list(lan_devices.values()),
        "edges": list(edges.values()),
    })
    return {"ports": _port_filter}

@app.post("/capture/start", dependencies=_AUTH)
async def start_capture() -> dict:
    """EN: Resume capture. / FR: Reprendre la capture."""
    if not _capturing:
        _start_capture()
        await broadcast({
            "type": "capture_status",
            "capturing": True,
            "ports": _port_filter,
            "excluded_processes": sorted(_excluded_processes),
            "whitelisted_ips": sorted(_whitelisted_ips),
        })
    return {"capturing": True}

@app.post("/capture/processes", dependencies=_AUTH)
async def set_process_filter(body: ProcessFilterBody) -> dict:
    """EN: Hide traffic from named processes (persisted).
    FR: Masquer le trafic de processus nommés (persisté)."""
    global _excluded_processes
    _excluded_processes = {str(p) for p in body.excluded}
    db.set_setting("excluded_processes", sorted(_excluded_processes))

    await broadcast({
        "type": "capture_status",
        "capturing": _capturing,
        "ports": _port_filter,
        "excluded_processes": sorted(_excluded_processes),
        "whitelisted_ips": sorted(_whitelisted_ips),
    })
    return {"excluded_processes": sorted(_excluded_processes)}

@app.post("/capture/whitelist", dependencies=_AUTH)
async def set_ip_whitelist(body: WhitelistBody) -> dict:
    """
    EN: Mark IPs as trusted — dropped from capture and display (persisted).
        Removed nodes also get forgotten by the detector and the enrichment
        cache, so un-whitelisting works correctly afterwards.
    FR: Marquer des IP comme fiables — ignorées de la capture et de
        l'affichage (persisté). Les nœuds retirés sont aussi oubliés par le
        détecteur et le cache d'enrichissement, pour qu'un retrait de la
        whitelist fonctionne ensuite correctement.
    """
    global _whitelisted_ips
    _whitelisted_ips = {str(ip) for ip in body.ips}
    db.set_setting("whitelisted_ips", sorted(_whitelisted_ips))

    removed_ids = [ip for ip in _whitelisted_ips
                   if ip != "local" and nodes.pop(ip, None) is not None]
    if removed_ids:
        removed_set = set(removed_ids)
        for edge_id in [eid for eid, e in edges.items()
                        if e["source"] in removed_set or e["target"] in removed_set]:
            edges.pop(edge_id, None)
        for ip in removed_ids:
            enrichment_cache.pop(ip, None)
            detector.forget(ip)

    await broadcast({
        "type": "capture_status",
        "capturing": _capturing,
        "ports": _port_filter,
        "excluded_processes": sorted(_excluded_processes),
        "whitelisted_ips": sorted(_whitelisted_ips),
    })
    if removed_ids:
        await broadcast({"type": "nodes_removed", "ids": removed_ids})
    return {"whitelisted_ips": sorted(_whitelisted_ips)}


# ── Capture interface + watchlist / Interface de capture + watchlist ────────

@app.get("/capture/interfaces", dependencies=_AUTH)
async def list_interfaces() -> dict:
    """
    EN: Capture-capable interfaces from libpcap + the one currently in use
        (None = auto-picked). Runs in the executor — pcap_findalldevs can be
        slow on Windows.
    FR: Interfaces capturables via libpcap + celle en cours (None = choix
        automatique). Dans l'executor — pcap_findalldevs peut être lent sous
        Windows.
    """
    from capture.pcap import PcapError, list_devices
    loop = asyncio.get_running_loop()
    try:
        devs = await loop.run_in_executor(None, list_devices)
    except PcapError as exc:
        return {"interfaces": [], "current": None, "error": str(exc)}
    return {
        "interfaces": [
            {"name": d.name, "description": d.description,
             "loopback": d.loopback, "addresses": list(d.addresses)}
            for d in devs
        ],
        "current": _sniffer.iface if _sniffer else None,
        "configured": db.get_setting("interface"),
    }


@app.post("/capture/interface", dependencies=_AUTH)
async def set_interface(body: InterfaceBody) -> dict:
    """
    EN: Pin the capture interface (empty body = back to auto). Persisted, and
        the capture restarts immediately on the new interface.
    FR: Épingler l'interface de capture (corps vide = retour à l'auto).
        Persisté, et la capture redémarre aussitôt sur la nouvelle interface.
    """
    name = (body.name or "").strip() or None
    db.set_setting("interface", name)
    if _capturing:
        _stop_capture()
        _start_capture()
    return {"interface": name,
            "current": _sniffer.iface if _sniffer else None}


@app.get("/watchlist", dependencies=_AUTH)
async def get_watchlist() -> dict:
    """EN: Pinned IPs/domains the detector alerts on.
    FR: IP/domaines épinglés sur lesquels le détecteur alerte."""
    return {"items": list(_watchlist)}


@app.post("/watchlist", dependencies=_AUTH)
async def set_watchlist(body: WatchlistBody) -> dict:
    """
    EN: Replace the watchlist — entries are IPs (exact match) or domain
        suffixes ("example.com" catches "api.example.com"). Persisted and
        pushed live into the detector.
    FR: Remplacer la watchlist — les entrées sont des IP (correspondance
        exacte) ou des suffixes de domaine (« example.com » attrape
        « api.example.com »). Persisté et poussé à chaud dans le détecteur.
    """
    global _watchlist
    _watchlist = [str(i).strip() for i in body.items if str(i).strip()][:500]
    db.set_setting("watchlist", _watchlist)
    detector.set_watchlist(_watchlist)
    return {"items": _watchlist}


# EN: Upper bound for `minutes` query params — a week. Prevents absurd
#     values (minutes=1e9) from scanning the whole history table; the
#     retention cleanup makes anything older empty anyway.
# FR: Borne haute pour le paramètre `minutes` — une semaine. Empêche des
#     valeurs absurdes (minutes=1e9) de scanner toute la table d'historique ;
#     le nettoyage par rétention vide de toute façon tout ce qui est plus vieux.
MAX_HISTORY_MINUTES = 7 * 24 * 60


def _clamp_minutes(minutes: int) -> int:
    """EN: Clamp a client-supplied lookback window to [1, one week].
    FR: Borner une fenêtre d'historique fournie par le client à [1, 1 semaine]."""
    return max(1, min(int(minutes), MAX_HISTORY_MINUTES))


@app.get("/timeline", dependencies=_AUTH)
async def get_timeline(minutes: int = 60) -> dict:
    """EN: Per-minute aggregates for the timeline chart.
    FR: Agrégats par minute pour le graphique timeline."""
    loop = asyncio.get_running_loop()
    data = await loop.run_in_executor(
        None, db.get_timeline, _clamp_minutes(minutes))
    return {"timeline": data}


# ── Alert suppression / Suppression d'alertes ────────────────────────────────

@app.post("/alerts/ignore", dependencies=_AUTH)
async def ignore_alert(body: IgnoreBody) -> dict:
    """
    EN: Persisted "ignore this host / this type" — the rule is stored in the
        settings table AND pushed live into the detector so it takes effect
        immediately.
    FR: « Ignorer cet hôte / ce type » persisté — la règle est stockée dans
        settings ET poussée au détecteur pour prise d'effet immédiate.
    """
    suppressions = db.get_setting("suppressions", []) or []
    entry = {"type": body.type, "ip": body.ip}
    if entry not in suppressions and (body.type or body.ip):
        suppressions.append(entry)
        db.set_setting("suppressions", suppressions)
        detector.load_suppressions(suppressions)
    return {"suppressions": suppressions}


@app.get("/alerts/ignore", dependencies=_AUTH)
async def list_ignored() -> dict:
    """EN: List active suppression rules.
    FR: Lister les règles de suppression actives."""
    return {"suppressions": db.get_setting("suppressions", []) or []}


@app.delete("/alerts/ignore", dependencies=_AUTH)
async def unignore_alert(body: IgnoreBody) -> dict:
    """EN: Remove a suppression rule — {type, ip} must match exactly.
    FR: Retirer une règle de suppression — {type, ip} doit correspondre."""
    suppressions = db.get_setting("suppressions", []) or []
    entry = {"type": body.type, "ip": body.ip}
    suppressions = [s for s in suppressions if s != entry]
    db.set_setting("suppressions", suppressions)
    detector.load_suppressions(suppressions)
    return {"suppressions": suppressions}


@app.post("/shutdown", dependencies=_AUTH)
async def shutdown() -> dict:
    """
    EN: Graceful process exit — flushes the DB, stops capture, then exits.
        Needed because an elevated backend (Windows RunAs) CANNOT be killed
        by our unprivileged UI process; the token-gated endpoint is the only
        clean shutdown path. Exit happens 0.5 s later so the HTTP 200 reply
        reaches the caller first.
    FR: Sortie propre du processus — flush la BDD, stoppe la capture, puis
        quitte. Nécessaire car un backend élevé (RunAs Windows) ne PEUT PAS
        être tué par notre UI non privilégiée ; l'endpoint authentifié est le
        seul chemin d'arrêt propre. La sortie survient 0,5 s plus tard pour
        que la réponse HTTP 200 atteigne l'appelant.
    """
    def _exit_soon() -> None:
        try:
            # EN: Synchronous cleanup (uvicorn is already unwinding by the
            #     time the lifespan finally runs — do it ourselves here).
            # FR: Nettoyage synchrone (uvicorn se déroule déjà quand le
            #     finally du lifespan tourne — on le fait nous-même ici).
            _stop_capture()
            db.flush()
        except Exception:
            pass
        os._exit(0)

    asyncio.get_running_loop().call_later(0.5, _exit_soon)
    return {"ok": True}


# ── History / Historique ─────────────────────────────────────────────────────

@app.get("/history/host/{ip}", dependencies=_AUTH)
async def get_host_history(ip: str, minutes: int = 60) -> dict:
    """EN: Per-host byte/packet history. / FR: Historique par hôte."""
    loop = asyncio.get_running_loop()
    return {"history": await loop.run_in_executor(
        None, db.get_history, "host", ip, _clamp_minutes(minutes))}


@app.get("/history/process/{name}", dependencies=_AUTH)
async def get_process_history(name: str, minutes: int = 60) -> dict:
    """EN: Per-process byte/packet history. / FR: Historique par processus."""
    loop = asyncio.get_running_loop()
    return {"history": await loop.run_in_executor(
        None, db.get_history, "process", name, _clamp_minutes(minutes))}


@app.get("/history/top_processes", dependencies=_AUTH)
async def get_top_processes(minutes: int = 60) -> dict:
    """EN: Top talkers by process — the Apps view data source.
    FR: Plus gros émetteurs par processus — la source de la vue Apps."""
    loop = asyncio.get_running_loop()
    return {"processes": await loop.run_in_executor(
        None, db.get_top_processes, _clamp_minutes(minutes))}


# ── Diagnostics / Diagnostic ────────────────────────────────────────────────

@app.get("/diagnostics", dependencies=_AUTH)
async def get_diagnostics() -> dict:
    """
    EN: Sanitized support bundle: versions, capture status, settings, last
        200 log lines, DB sizes. IPs/hostnames stay local — this is served
        only to the authenticated local user.
    FR: Paquet de support assaini : versions, état de capture, réglages, 200
        dernières lignes de log, tailles de la BDD. Les IP/noms d'hôtes
        restent locaux — servi uniquement à l'utilisateur local authentifié.
    """
    import platform
    from paths import data_dir

    log_tail = []
    log_file = data_dir() / "logs" / "snitch.log"
    try:
        if log_file.exists():
            log_tail = log_file.read_text(errors="replace").splitlines()[-200:]
    except OSError:
        # EN: Don't leak the exception text into the API response — the
        #     details stay in the server log, the client gets a generic note.
        # FR: Ne pas fuiter le texte d'exception dans la réponse API — les
        #     détails restent dans le log serveur, le client reçoit un
        #     message générique.
        logger.exception("diagnostics: could not read log tail")
        log_tail = ["<log read failed>"]

    db_file = data_dir() / "snitch.db"
    return {
        "version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "capture": {
            "capturing": _capturing,
            "interface": db.get_setting("interface"),
            "ports": _port_filter,
        },
        "settings": db.all_settings(),
        "counts": {"nodes": len(nodes), "edges": len(edges),
                   "lan_devices": len(lan_devices),
                   "alerts_memory": len(detector.history)},
        # EN: Drop accounting — every ignored/skipped packet, frame and ARP
        #     row, with its reason. Security: no silent blind spots.
        # FR: Comptabilité des rejets — chaque paquet, trame et ligne ARP
        #     ignorée/écartée, avec sa raison. Sécurité : aucun angle mort
        #     silencieux.
        "dropped": {
            **dict(_drop_stats),
            "capture": dict(_sniffer.stats) if _sniffer else {},
            "arp_read": dict(_arp_stats),
        },
        "db_bytes": db_file.stat().st_size if db_file.exists() else 0,
        "log_tail": log_tail,
    }


# ── GeoIP database download (consent-gated) / Téléchargement base GeoIP ─────

def _download_dbip() -> dict:
    """
    EN: Download DB-IP Lite City + ASN into <data_dir>/geo/. This is the ONE
        opt-in outbound call in the entire app — reached only via an explicit
        user action and the `consent` flag. HTTPS, 60 s timeout, gzip decompress.
    FR: Télécharger DB-IP Lite City + ASN dans <data_dir>/geo/. C'est le SEUL
        appel sortant opt-in de toute l'app — atteint uniquement via une
        action explicite et le drapeau `consent`. HTTPS, timeout 60 s,
        décompression gzip.
    """
    import gzip
    import urllib.request
    from paths import data_dir
    import resolver.dns_geo as dg

    month = datetime.now(timezone.utc).strftime("%Y-%m")
    files = {
        f"dbip-city-lite-{month}.mmdb.gz": "dbip-city-lite.mmdb",
        f"dbip-asn-lite-{month}.mmdb.gz":  "dbip-asn-lite.mmdb",
    }
    geo_dir = data_dir() / "geo"
    geo_dir.mkdir(parents=True, exist_ok=True)

    # EN: Sanity ceilings — DB-IP Lite is ~40 MB gzip / ~130 MB plain. A
    #     broken or hostile upstream must not exhaust disk or memory.
    # FR: Plafonds de bon sens — DB-IP Lite fait ~40 Mo gzip / ~130 Mo en
    #     clair. Un amont cassé ou hostile ne doit pas épuiser disque ou RAM.
    MAX_GZIP_BYTES = 128 * 1024 * 1024
    MAX_PLAIN_BYTES = 512 * 1024 * 1024

    downloaded = []
    errors = []
    for remote, local in files.items():
        url = f"https://download.db-ip.com/free/{remote}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Snitch/1.1"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                # EN: Read at most cap+1 so an oversize body is detected, not
                #     silently truncated into a corrupt database.
                # FR: Lire au plus borne+1 pour détecter un corps trop gros
                #     plutôt que de tronquer silencieusement en base corrompue.
                raw = resp.read(MAX_GZIP_BYTES + 1)
            if len(raw) > MAX_GZIP_BYTES:
                raise ValueError("download exceeds size limit")
            data = gzip.decompress(raw)
            if len(data) > MAX_PLAIN_BYTES:
                raise ValueError("decompressed database exceeds size limit")
            # EN: Atomic install — a crashed write must not leave a partial
            #     .mmdb that maxminddb then chokes on.
            # FR: Installation atomique — une écriture interrompue ne doit pas
            #     laisser un .mmdb partiel sur lequel maxminddb échouerait.
            tmp = geo_dir / f"{local}.tmp"
            tmp.write_bytes(data)
            os.replace(tmp, geo_dir / local)
            downloaded.append(local)
        except Exception as exc:
            errors.append(f"{local}: {exc}")
            logger.error("geo download failed for %s: %s", url, exc)

    # EN: Force reader reload on next lookup.
    # FR: Forcer le rechargement des lecteurs à la prochaine recherche.
    dg.reset_readers()
    return {"downloaded": downloaded, "errors": errors, "dir": str(geo_dir)}


@app.post("/geo/download", dependencies=_AUTH)
async def geo_download(body: GeoDownloadBody) -> dict:
    """
    EN: Consent-gated GeoIP DB download. Without consent=true the endpoint
        refuses — the default state of Snitch makes ZERO outbound calls.
    FR: Téléchargement de base GeoIP sous consentement. Sans consent=true le
        endpoint refuse — l'état par défaut de Snitch n'émet AUCUN appel
        sortant.
    """
    if not body.consent:
        return {"ok": False, "reason": "consent_required"}
    loop = asyncio.get_running_loop()
    result = await loop.run_in_executor(None, _download_dbip)
    result["ok"] = not result["errors"]
    return result


@app.get("/geo/status", dependencies=_AUTH)
async def geo_status() -> dict:
    """EN: Which .mmdb files are present. / FR: Quels .mmdb sont présents."""
    from paths import data_dir
    geo_dir = data_dir() / "geo"
    present = sorted(p.name for p in geo_dir.glob("*.mmdb")) if geo_dir.exists() else []
    return {"databases": present, "dir": str(geo_dir)}


# ── Security: firewall / process actions / threat intel / audit / forensics ──
# EN: The firewall API manages user rules (IP / domain / process) and the
#     lockdown panic switch. Rules are MATCHED live so the UI can show which
#     connections violate policy; actually dropping packets needs the
#     optional privileged sync shipped in tools/ (documented honestly in
#     /firewall/status — we never claim kernel enforcement we don't have).
# FR: L'API pare-feu gère les règles utilisateur (IP / domaine / processus)
#     et le bouton panique. Les règles sont ÉVALUÉES en direct pour montrer
#     quelles connexions violent la politique ; le drop réel exige la synchro
#     privilégiée optionnelle de tools/ (documenté honnêtement dans
#     /firewall/status — jamais de prétention à une application noyau absente).

@app.get("/firewall/status", dependencies=_AUTH)
async def firewall_status() -> dict:
    """EN: Rules, lockdown and platform capability report.
    FR: Règles, lockdown et rapport de capacité de la plateforme."""
    return fw.status()


@app.get("/firewall/rules", dependencies=_AUTH)
async def firewall_rules() -> dict:
    """EN: All rules + lockdown flag + privilege sync status.
    FR: Toutes les règles + drapeau lockdown + état de la synchro privilégiée."""
    rules, lockdown = fw.serialized()
    return {"rules": rules, "lockdown": lockdown, "supported": fw.supported()}


@app.post("/firewall/rules", dependencies=_AUTH)
async def firewall_add_rule(body: FirewallRuleBody) -> dict:
    """EN: Create a rule {kind: ip|domain|process, value}. Persisted.
    FR: Créer une règle {kind: ip|domain|process, value}. Persistée."""
    loop = asyncio.get_running_loop()
    try:
        rule = await loop.run_in_executor(
            None, fw.add_rule, body.kind, body.value, body.action, body.rate)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    rules, lockdown = fw.serialized()
    db.set_setting("firewall_rules", rules)
    await broadcast({"type": "firewall", "rules": rules, "lockdown": lockdown})
    return {"rule": rule, "rules": rules}


@app.delete("/firewall/rules/{rule_id}", dependencies=_AUTH)
async def firewall_del_rule(rule_id: str) -> dict:
    """EN: Delete a rule. / FR: Supprimer une règle."""
    loop = asyncio.get_running_loop()
    removed = await loop.run_in_executor(None, fw.remove_rule, rule_id)
    if not removed:
        raise HTTPException(404, "rule not found")
    rules, lockdown = fw.serialized()
    db.set_setting("firewall_rules", rules)
    await broadcast({"type": "firewall", "rules": rules, "lockdown": lockdown})
    return {"ok": True, "rules": rules}


@app.post("/firewall/rules/{rule_id}/toggle", dependencies=_AUTH)
async def firewall_toggle_rule(rule_id: str, body: FirewallToggleBody) -> dict:
    """EN: Enable/disable a rule without deleting it.
    FR: Activer/désactiver une règle sans la supprimer."""
    loop = asyncio.get_running_loop()
    ok = await loop.run_in_executor(None, fw.toggle_rule, rule_id, body.enabled)
    if not ok:
        raise HTTPException(404, "rule not found")
    rules, lockdown = fw.serialized()
    db.set_setting("firewall_rules", rules)
    await broadcast({"type": "firewall", "rules": rules, "lockdown": lockdown})
    return {"ok": True, "rules": rules}


@app.post("/firewall/lockdown", dependencies=_AUTH)
async def firewall_lockdown(body: LockdownBody) -> dict:
    """EN: Panic switch — while ON, every outbound packet is flagged
        BLOCKED_ATTEMPT and (with privilege sync) actually dropped.
        A LOCKDOWN alert is broadcast so every connected client shows it.
    FR: Bouton panique — actif, chaque paquet sortant est signalé
        BLOCKED_ATTEMPT et (avec la synchro privilégiée) réellement droppé.
        Une alerte LOCKDOWN est diffusée pour l'afficher sur tous les clients."""
    loop = asyncio.get_running_loop()
    res = await loop.run_in_executor(None, fw.set_lockdown, body.on)
    db.set_setting("firewall_lockdown", res["lockdown"])
    if body.on:
        alert = Alert(type="LOCKDOWN", severity="critical",
                      message="Lockdown mode ENABLED — all outbound traffic blocked",
                      details={"applied": res["ok"], "error": res["error"]})
        d = alert.to_dict()
        db.log_alert(d)
        await broadcast({"type": "alert", "alert": d})
    rules, lockdown = fw.serialized()
    await broadcast({"type": "firewall", "rules": rules, "lockdown": lockdown})
    return res


@app.get("/firewall/profiles", dependencies=_AUTH)
async def firewall_profiles() -> dict:
    """EN: Available named profiles (labels resolved by the UI).
    FR: Profils nommés disponibles (libellés résolus par l'UI)."""
    return {"profiles": sorted(fw.PROFILES)}


@app.post("/firewall/profile", dependencies=_AUTH)
async def firewall_profile(body: ProfileBody) -> dict:
    """EN: Apply a named profile — expands into ordinary rules + lockdown
        state through the normal machinery, persists the result, and
        broadcasts the new policy to every connected client.
    FR: Appliquer un profil nommé — déplié en règles ordinaires + état
        lockdown par la machinerie normale, résultat persisté et politique
        diffusée à tous les clients connectés."""
    loop = asyncio.get_running_loop()
    try:
        res = await loop.run_in_executor(None, fw.apply_profile, body.name)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    rules, lockdown = fw.serialized()
    db.set_setting("firewall_rules", rules)
    db.set_setting("firewall_lockdown", lockdown)
    await broadcast({"type": "firewall", "rules": rules, "lockdown": lockdown})
    return {"ok": True, "rules": rules, "lockdown": lockdown, **res}


@app.post("/firewall/blocklist", dependencies=_AUTH)
async def firewall_blocklist(body: BlocklistBody) -> dict:
    """EN: Import a blocklist into `domain` rules. `path` reads a local
        file (purely local); `url` performs an OPT-IN outbound HTTPS
        fetch — surfaced as `remote_fetch: true` in the response so the
        UI can show that Snitch emitted traffic. Entries deduplicated
        against existing rules and capped at `max_entries` (<= 5000).
    FR: Importer une blocklist en règles `domain`. `path` lit un fichier
        local ; `url` effectue un fetch HTTPS sortant OPT-IN — signalé
        par `remote_fetch: true` dans la réponse pour que l'UI montre
        que Snitch a émis du trafic. Entrées dédupliquées et plafonnées
        à `max_entries` (<= 5000)."""
    if bool(body.path) == bool(body.url):
        raise HTTPException(400, "provide exactly one of path or url")
    if body.action not in ("block", "sinkhole"):
        raise HTTPException(400, "action must be block or sinkhole")
    remote = bool(body.url)

    def _load_text() -> str:
        if remote:
            return blocklist.fetch_url(body.url)
        p = Path(body.path).expanduser()
        if not p.is_file():
            raise ValueError("file not found")
        if p.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("blocklist too large (>4 MiB)")
        return p.read_text(errors="replace")

    loop = asyncio.get_running_loop()
    try:
        text = await loop.run_in_executor(None, _load_text)
    except (ValueError, OSError) as exc:
        raise HTTPException(400, str(exc))
    domains = blocklist.parse_domains(text)
    cap = blocklist.clamp_max(body.max_entries)
    truncated = len(domains) > cap
    domains = domains[:cap]

    def _apply() -> tuple[int, int]:
        added = skipped = 0
        for d in domains:
            if fw._find_rule("domain", d, body.action):
                skipped += 1
                continue
            fw.add_rule("domain", d, body.action)
            added += 1
        return added, skipped

    added, skipped = await loop.run_in_executor(None, _apply)
    rules, lockdown = fw.serialized()
    db.set_setting("firewall_rules", rules)
    await broadcast({"type": "firewall", "rules": rules, "lockdown": lockdown})
    return {"ok": True, "remote_fetch": remote, "parsed": len(domains),
            "added": added, "skipped": skipped, "truncated": truncated}


# ── Custom alert rules / Règles d'alerte utilisateur ─────────────────────────

@app.get("/alerts/rules", dependencies=_AUTH)
async def alert_rules() -> dict:
    """EN: All user-defined alert rules + the matcher vocabulary.
    FR: Toutes les règles utilisateur + le vocabulaire du moteur."""
    return {"rules": custom_rules.serialized(),
            "fields": ["remote_ip", "host", "process_name", "remote_port",
                       "protocol", "direction", "size"],
            "ops": ["eq", "ne", "contains", "regex", "gt", "lt", "cidr"]}


@app.post("/alerts/rules", dependencies=_AUTH)
async def alert_rules_add(body: CustomRuleBody) -> dict:
    """EN: Create a user alert rule — validated up front (field/op/severity,
    regex compiles, cidr parses). Alert-only: matching packets raise
    CUSTOM_RULE alerts, nothing is blocked.
    FR: Créer une règle d'alerte — validée d'emblée (champ/op/sévérité,
    regex compilable, cidr analysable). Alerte seule : les paquets
    correspondants lèvent CUSTOM_RULE, rien n'est bloqué."""
    try:
        rule = custom_rules.add(body.name, body.field, body.op,
                                body.value, body.severity)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    db.set_setting("custom_rules", custom_rules.serialized())
    return {"ok": True, "rule": rule}


@app.delete("/alerts/rules/{rule_id}", dependencies=_AUTH)
async def alert_rules_delete(rule_id: str) -> dict:
    """EN: Remove a user alert rule. / FR: Supprimer une règle utilisateur."""
    if not custom_rules.remove(rule_id):
        raise HTTPException(404, "rule not found")
    db.set_setting("custom_rules", custom_rules.serialized())
    return {"ok": True}


@app.post("/alerts/rules/{rule_id}/toggle", dependencies=_AUTH)
async def alert_rules_toggle(rule_id: str, body: FirewallToggleBody) -> dict:
    """EN: Enable/disable a rule without deleting it.
    FR: Activer/désactiver une règle sans la supprimer."""
    rule = custom_rules.toggle(rule_id, body.enabled)
    if rule is None:
        raise HTTPException(404, "rule not found")
    db.set_setting("custom_rules", custom_rules.serialized())
    return {"ok": True, "rule": rule}


@app.post("/processes/kill", dependencies=_AUTH)
async def kill_process(body: PidBody) -> dict:
    """EN: Kill a process by PID — incident-response action. Refuses to kill
        PIDs 0..3 and Snitch itself. Requires normal OS privileges.
    FR: Tuer un processus par PID — action de réponse à incident. Refuse les
        PID 0..3 et Snitch lui-même. Exige les privilèges OS usuels."""
    import psutil
    if body.pid <= 3 or body.pid == os.getpid():
        raise HTTPException(400, "refusing to kill a system/critical pid")
    loop = asyncio.get_running_loop()

    def _do() -> str:
        p = psutil.Process(body.pid)
        name = p.name()
        p.kill()
        return name
    try:
        name = await loop.run_in_executor(None, _do)
    except Exception as exc:
        raise HTTPException(400, f"kill failed: {exc}")
    return {"ok": True, "pid": body.pid, "name": name}


@app.post("/processes/suspend", dependencies=_AUTH)
async def suspend_process(body: PidBody) -> dict:
    """EN: Suspend/resume a process by PID (SIGSTOP/SIGCONT semantics).
    FR: Suspendre/reprendre un processus par PID (sémantique SIGSTOP/SIGCONT)."""
    import psutil
    if body.pid <= 3 or body.pid == os.getpid():
        raise HTTPException(400, "refusing to suspend a system/critical pid")
    loop = asyncio.get_running_loop()

    def _do() -> dict:
        p = psutil.Process(body.pid)
        name = p.name()
        if p.status() == "stopped":
            p.resume()
            return {"name": name, "suspended": False}
        p.suspend()
        return {"name": name, "suspended": True}
    try:
        res = await loop.run_in_executor(None, _do)
    except Exception as exc:
        raise HTTPException(400, f"suspend failed: {exc}")
    return {"ok": True, "pid": body.pid, **res}


@app.get("/security/ti", dependencies=_AUTH)
async def ti_status() -> dict:
    """EN: Threat-intel configuration (provider, cache size, key masked).
    FR: Configuration threat-intel (fournisseur, taille du cache, clé masquée)."""
    return ti.config()


@app.post("/security/threat_check", dependencies=_AUTH)
async def threat_check(body: ThreatCheckBody) -> dict:
    """EN: Manual reputation check for one IP/domain. Only actually queries
        the provider when threat intel is enabled — otherwise it reports the
        disabled state (and never makes a call).
    FR: Vérification manuelle de réputation pour une IP/domaine. N'interroge
        le fournisseur que si la threat intel est activée — sinon renvoie
        l'état désactivé (et ne fait aucun appel)."""
    loop = asyncio.get_running_loop()
    verdict = await loop.run_in_executor(None, ti.check, body.ip)
    return {"verdict": verdict, "config": ti.config()}


@app.get("/security/integrity", dependencies=_AUTH)
async def integrity_status() -> dict:
    """EN: Integrity-watch capability + recent findings report. Honest about
        platform support — RWX scan is Linux-only, hash watch everywhere.
    FR: Rapport de capacité + constats de la veille d'intégrité. Honnête sur
        le support plateforme — scan RWX Linux seulement, hash partout."""
    return integrity.status()


@app.post("/security/integrity/check", dependencies=_AUTH)
async def integrity_check(body: PidBody) -> dict:
    """EN: Manual on-demand integrity check for one PID — hash, name/exe
        match, RWX maps. Runs the checks even if the pid was already seen
        (clears its dedup entry first), so analysts can force a re-check.
    FR: Contrôle d'intégrité manuel à la demande pour un PID — hash,
        correspondance nom/exe, maps RWX. Force la vérification même si le
        pid a déjà été vu (purge son entrée de dédup d'abord)."""
    import psutil
    if body.pid <= 3 or body.pid == os.getpid():
        raise HTTPException(400, "refusing to check a system/critical pid")
    loop = asyncio.get_running_loop()

    def _do() -> list[dict]:
        # EN: Drop the dedup key so a manual check always re-inspects.
        # FR: Retirer la clé de dédup pour qu'un contrôle manuel ré-inspecte.
        with integrity._lock:                        # noqa: SLF001 — same service
            for k in [k for k in integrity._checked if k[0] == body.pid]:
                integrity._checked.pop(k, None)
        try:
            name = psutil.Process(body.pid).name()
        except psutil.NoSuchProcess:
            return []
        return integrity.check(body.pid, name)

    findings = await loop.run_in_executor(None, _do)
    return {"pid": body.pid, "findings": findings}


@app.get("/security/ebpf", dependencies=_AUTH)
async def ebpf_status() -> dict:
    """EN: eBPF connect-probe status — availability reason is always
        reported honestly (linux-only, root, python3-bcc).
    FR: État de la sonde eBPF — la raison d'indisponibilité est toujours
        rapportée honnêtement (linux, root, python3-bcc)."""
    return ebpf.status()


@app.post("/security/deep_inspect", dependencies=_AUTH)
async def deep_inspect(body: PidSecondsBody) -> dict:
    """EN: Bounded Frida inspection — attach to ONE pid for ≤60 s and
        report which module (exe/DLL) initiated each connection attempt,
        plus staging-path flags for injected code. Requires the optional
        `frida` package and the OS's usual debugger permissions.
    FR: Inspection Frida bornée — attache à UN pid ≤60 s et rapporte quel
        module (exe/DLL) a initié chaque connexion, plus les signalements
        de chemins de staging pour le code injecté. Exige le paquet
        `frida` optionnel et les droits de débogage usuels de l'OS."""
    if body.pid <= 3 or body.pid == os.getpid():
        raise HTTPException(400, "refusing to inspect a system/critical pid")
    loop = asyncio.get_running_loop()
    res = await loop.run_in_executor(
        None, deep.inspect, body.pid, min(body.seconds, 60))
    res["suspicious_paths"] = suspicious_module_paths(
        res.get("events", []) + res.get("flows", []))
    if res["suspicious_paths"]:
        a = Alert(type="INJECT_SUSPECT", severity="critical",
                  message=f"Injected-module suspicion in pid {body.pid} — "
                          f"module(s) in staging paths made connections",
                  details={"pid": body.pid,
                           "paths": res["suspicious_paths"]})
        d = a.to_dict()
        db.log_alert(d)
        await broadcast({"type": "alert", "alert": d})
        await _notify(d)
    return res


@app.post("/security/sandbox", dependencies=_AUTH)
async def sandbox_run(body: SandboxBody) -> dict:
    """EN: Detonate an executable inside the network-denial sandbox —
        Linux `unshare -U -n` (unprivileged userns) or macOS
        `sandbox-exec` deny-network. Bounded runtime + output; the binary
        runs unprivileged with zero egress. Explicit user action only —
        Snitch never detonates on its own.
    FR: Détoner un exécutable dans la sandbox sans réseau — `unshare -U -n`
        Linux ou `sandbox-exec` deny-network macOS. Durée + sortie bornées ;
        le binaire tourne non privilégié, égress zéro. Action utilisateur
        explicite uniquement — Snitch ne détone jamais seul."""
    import os
    from detection.contain import run_sandboxed
    if not os.path.isabs(body.path):
        raise HTTPException(400, "path must be absolute")
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, run_sandboxed, body.path,
        [a[:256] for a in body.args[:8]], body.seconds)


@app.get("/security/sinkhole", dependencies=_AUTH)
async def sinkhole_status() -> dict:
    """EN: Sinkhole responder state — which loopback listeners are bound
        (80 HTTP / 443 SNI) plus the recent captured hits.
    FR: État du répondeur sinkhole — quels écouteurs loopback sont liés
        (80 HTTP / 443 SNI) plus les hits capturés récents."""
    return sink.status()


@app.post("/security/perf", dependencies=_AUTH)
async def perf_sample(body: PidSecondsBody) -> dict:
    """EN: Hardware-counter sample for one pid — cycles, instructions,
        cache-misses over ≤10 s via perf_event_open (Linux; gated by
        kernel.perf_event_paranoid). Corroborates MINING_SUSPECT.
    FR: Échantillon de compteurs matériels pour un pid — cycles,
        instructions, cache-misses sur ≤10 s via perf_event_open (Linux ;
        sous réserve de kernel.perf_event_paranoid)."""
    if body.pid <= 3:
        raise HTTPException(400, "refusing to sample a kernel pid")
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, perfprobe.sample, body.pid, min(body.seconds, 10))


@app.get("/security/slm", dependencies=_AUTH)
async def slm_status() -> dict:
    """EN: Local SLM (Ollama-compatible) status — enabled, loopback
        endpoint, reachable model. Never hides "unreachable".
    FR: État du SLM local (compatible Ollama) — activé, endpoint loopback,
        modèle joignable. Ne cache jamais « injoignable »."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, slm.status)


@app.get("/security/iocpack", dependencies=_AUTH)
async def iocpack_export(format: str = "bloom") -> dict:
    """EN: Export a privacy-preserving IOC pack built from this machine's
        firewall rules + alert indicators — `format=bloom` (default)
        produces a deniable Bloom+randomized-response pack; `format=proof`
        produces a salted Merkle commitment pack (exact membership,
        selective disclosure). The user shares the JSON themselves —
        nothing is sent.
    FR: Exporter un paquet d'IOC depuis les règles pare-feu + indicateurs
        d'alertes — `format=bloom` (défaut) produit un paquet déni plausible
        ; `format=proof` un paquet d'engagement Merkle salé (appartenance
        exacte, divulgation sélective). L'utilisateur partage le JSON
        lui-même — rien n'est envoyé."""
    loop = asyncio.get_running_loop()
    indicators = await loop.run_in_executor(None, _collect_indicators)
    if format == "proof":
        return iocshare.build_proof_pack(indicators)
    return iocshare.build_pack(indicators)


@app.post("/security/iocpack/import", dependencies=_AUTH)
async def iocpack_import(body: IocImportBody) -> dict:
    """EN: Check this machine's observed destinations against a received
        community pack — Bloom packs return probabilistic hints, proof
        packs exact matches; never auto-blocks either way.
    FR: Confronter les destinations observées à un paquet communautaire
        reçu — indices probabilistes pour Bloom, correspondances exactes
        pour proof ; jamais de blocage automatique."""
    candidates = [ip for ip in nodes if ip != "local"]
    loop = asyncio.get_running_loop()
    if isinstance(body.pack, dict) and body.pack.get("format") == "snitch-ioc-proof/1":
        return await loop.run_in_executor(
            None, iocshare.check_proof_pack, body.pack, candidates)
    return await loop.run_in_executor(
        None, iocshare.check_pack, body.pack, candidates)


def _collect_indicators() -> list[str]:
    """EN: Local indicators worth sharing — firewall rule targets,
    alert IPs of the serious types, changed-binary hashes. Bounded.
    FR: Indicateurs locaux partageables — cibles des règles pare-feu,
    IP des alertes sérieuses, hash des binaires modifiés. Borné."""
    out: list[str] = []
    rules, _ld = fw.serialized()
    for r in rules:
        v = str(r.get("value", ""))
        if v and r.get("kind") in ("ip", "cidr", "domain"):
            out.append(v)
    try:
        for a in db.get_alerts(500):
            d = a.get("details") or {}
            for key in ("ip", "host", "exe", "actual"):
                v = d.get(key)
                if isinstance(v, str) and v:
                    out.append(v)
    except Exception:                                # noqa: BLE001
        pass
    return list(dict.fromkeys(out))[:4096]


@app.post("/security/explain", dependencies=_AUTH)
async def security_explain_post(body: ExplainBody) -> dict:
    """EN: Alert explanation — deterministic bilingual templates always;
        `llm` carries the optional localhost-SLM natural-language variant
        when slm_enabled and the model answers (else absent).
    FR: Explication d'alerte — gabarits bilingues déterministes toujours ;
        `llm` porte la variante SLM local quand activé et joignable."""
    rec = alert_explain.explain(body.type)
    if rec is None:
        raise HTTPException(404, f"no explanation for alert type {body.type!r}")
    out = {"type": body.type.upper(), **rec}
    loop = asyncio.get_running_loop()
    llm = await loop.run_in_executor(
        None, slm.enrich, body.type, body.detail,
        body.lang if body.lang in ("en", "fr") else "en")
    if llm:
        out["llm"] = llm
    return out


@app.get("/security/explain", dependencies=_AUTH)
async def security_explain(type: str = "") -> dict:
    """EN: Plain-language, bilingual explanation for one alert type —
        deterministic templates, works fully offline (no model involved).
    FR: Explication bilingue en langage clair pour un type d'alerte —
        gabarits déterministes, 100 % hors-ligne (aucun modèle)."""
    rec = alert_explain.explain(type)
    if rec is None:
        raise HTTPException(404, f"no explanation for alert type {type!r}")
    return {"type": type.upper(), **rec}


@app.get("/security/audit", dependencies=_AUTH)
async def security_audit() -> dict:
    """EN: Hardening report computed from the last 500 alerts + live graph:
        alert-type breakdown, high-risk-country contacts, cleartext usage,
        unseen domains, firewall posture, and a defensible 0–100 score.
    FR: Rapport de durcissement calculé sur les 500 dernières alertes + le
        graphe : répartition par type, contacts vers pays à risque, trafic en
        clair, domaines sans nom, posture pare-feu et score 0–100."""
    loop = asyncio.get_running_loop()
    alerts = await loop.run_in_executor(None, db.get_alerts, 500)
    counts: dict[str, int] = {}
    for a in alerts:
        counts[a.get("type", "?")] = counts.get(a.get("type", "?"), 0) + 1
    critical = sum(1 for a in alerts if a.get("severity") == "critical")
    warning = sum(1 for a in alerts if a.get("severity") == "warning")

    # EN: Nodes currently on the graph whose geo country is in the high-risk
    #     watchlist — a finding worth surfacing, not an accusation.
    # FR: Nœuds du graphe dont le pays géolocalisé est dans la liste à risque
    #     — un constat à remonter, pas une accusation.
    risky = sorted({
        ip for ip, n in nodes.items()
        if ip != "local" and (n.get("country_code") or "").upper()
        in {"RU", "KP", "IR", "BY", "CU", "SY", "AF", "MM", "VE", "NI"}
    })
    unlabeled = sorted({
        ip for ip, n in nodes.items()
        if ip != "local" and not n.get("label") and not n.get("hostname")
    })

    rules, lockdown = fw.serialized()
    active_rules = sum(1 for r in rules if r.get("enabled"))
    blocked_total = sum(r.get("blocked_total", 0) for r in rules)

    score = 100 - min(60, critical * 8) - min(20, warning) \
        - min(10, len(risky)) - (5 if lockdown else 0)
    score = max(0, score)

    return {
        "score": score,
        "period": "last 500 alerts",
        "alert_counts": counts,
        "critical": critical, "warning": warning,
        "findings": {
            "high_risk_countries": risky,
            "unresolved_hosts": unlabeled[:50],
            "cleartext_alerts": counts.get("CLEARTEXT", 0),
            "dns_tunnel_alerts": counts.get("DNS_TUNNEL", 0),
            "threat_hits": counts.get("THREAT_HIT", 0),
        },
        "firewall": {
            "active_rules": active_rules,
            "lockdown": lockdown,
            "blocked_attempts": blocked_total,
            "supported": fw.supported(),
            "platform": fw.status().get("platform"),
        },
        "threat_intel": ti.config(),
        "integrity": {
            "enabled": integrity.enabled,
            "checked": integrity.status().get("checked", 0),
            "findings": integrity.status().get("findings", [])[-10:],
        },
        "recommendations": _audit_recommendations(
            counts, risky, unlabeled, active_rules, lockdown),
    }


def _audit_recommendations(counts: dict, risky: list, unlabeled: list,
                           active_rules: int, lockdown: bool) -> list[dict]:
    """EN: Plain-language next steps derived from the findings.
    FR: Étapes concrètes en langage clair dérivées des constats."""
    recs: list[dict] = []
    if lockdown:
        recs.append({"level": "info", "text": "Lockdown is ON — every outbound "
                     "attempt is being flagged. / Lockdown actif — chaque "
                     "tentative sortante est signalée."})
    if counts.get("CLEARTEXT"):
        recs.append({"level": "high", "text": "Plain-text traffic on port 80 "
                     "detected — prefer HTTPS or flag the destination. / "
                     "Trafic en clair sur le port 80 détecté — privilégier "
                     "HTTPS ou signaler la destination."})
    if counts.get("DNS_TUNNEL"):
        recs.append({"level": "high", "text": "Possible DNS tunnelling — "
                     "inspect the flagged process and consider blocking it. / "
                     "Tunnel DNS possible — inspecter le processus signalé et "
                     "envisager de le bloquer."})
    if counts.get("THREAT_HIT"):
        recs.append({"level": "high", "text": "Threat intel flagged hosts — "
                     "add firewall rules for the reported IPs. / La threat "
                     "intel a signalé des hôtes — ajouter des règles pare-feu "
                     "pour les IP rapportées."})
    if counts.get("BEACON"):
        recs.append({"level": "medium", "text": "Regular-interval connections "
                     "(beaconing) observed — review the flagged process's "
                     "executable hash in the forensics export. / Connexions à "
                     "intervalle régulier (beaconing) observées — vérifier le "
                     "hash de l'exécutable via l'export forensique."})
    if risky:
        recs.append({"level": "medium", "text": "Connections to high-risk "
                     "countries observed — verify they match expected services "
                     "(news, CDN, gaming). / Connexions vers des pays à risque "
                     "observées — vérifier qu'elles correspondent à des "
                     "services attendus."})
    if active_rules == 0 and not lockdown:
        recs.append({"level": "low", "text": "No firewall rules configured — "
                     "create one from any connection row to harden egress. / "
                     "Aucune règle pare-feu — en créer une depuis une ligne de "
                     "connexion pour durcir les sorties."})
    if len(unlabeled) > 20:
        recs.append({"level": "low", "text": "Many hosts have no resolved "
                     "domain — check the GeoIP database is downloaded. / "
                     "Beaucoup d'hôtes sans domaine résolu — vérifier que la "
                     "base GeoIP est téléchargée."})
    return recs


@app.get("/forensics/export", dependencies=_AUTH)
async def forensics_export(process: Optional[str] = None,
                           ip: Optional[str] = None,
                           format: str = "json"):
    """EN: One-click investigation bundle — process tree + SHA-256 of the
        executable, matching alerts and traffic history. format=json (default)
        returns the bundle; format=csv a flat spreadsheet; format=stix a
        minimal STIX 2.1 bundle (indicators + observed-data) for SIEM import.
        Local data only; nothing is sent anywhere.
    FR: Paquet d'investigation en un clic — arbre de processus + SHA-256 de
        l'exécutable, alertes et historique associés. format=json (défaut)
        renvoie le bundle ; format=csv un tableur plat ; format=stix un
        bundle STIX 2.1 minimal (indicateurs + observed-data) pour SIEM.
        Données locales uniquement ; rien n'est envoyé nulle part."""
    import hashlib
    import psutil
    loop = asyncio.get_running_loop()
    bundle: dict = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "version": __version__,
        "host": socket.gethostname(),
        "processes": [],
        "alerts": [],
        "history": {},
    }

    def _sha256(path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return None

    if process:
        def _procs() -> list[dict]:
            out = []
            for p in psutil.process_iter(["pid", "name", "exe", "ppid",
                                          "cmdline", "create_time"]):
                try:
                    info = p.info
                    if info["name"] != process:
                        continue
                    chain, cur = [], p.ppid()
                    for _ in range(8):
                        if not cur:
                            break
                        try:
                            par = psutil.Process(cur)
                            chain.append({"pid": par.pid, "name": par.name()})
                            cur = par.ppid()
                        except Exception:
                            break
                    out.append({
                        "pid": info["pid"], "name": info["name"],
                        "exe": info["exe"],
                        "sha256": _sha256(info["exe"]) if info["exe"] else None,
                        "cmdline": info["cmdline"],
                        "started": info["create_time"],
                        "parents": chain,
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            return out
        bundle["processes"] = await loop.run_in_executor(None, _procs)
        bundle["history"]["process"] = await loop.run_in_executor(
            None, db.get_history, "process", process, 1440)
    if ip:
        bundle["history"]["host"] = await loop.run_in_executor(
            None, db.get_history, "host", ip, 1440)
        bundle["geo"] = enrichment_cache.get(ip)

    all_alerts = await loop.run_in_executor(None, db.get_alerts, 500)
    # EN: No filter → export every stored alert; with a filter, keep the
    #     alerts mentioning the process or tied to the node.
    # FR: Sans filtre → exporter toutes les alertes stockées ; avec filtre,
    #     garder celles mentionnant le processus ou liées au nœud.
    bundle["alerts"] = all_alerts if not (process or ip) else [
        a for a in all_alerts
        if (process and process in (a.get("message") or "")
                + str(a.get("details") or ""))
        or (ip and a.get("node_id") == ip)
    ]

    if format == "csv":
        return _forensics_csv(bundle)
    if format == "stix":
        return _forensics_stix(bundle, ip=ip)
    return bundle


def _forensics_csv(bundle: dict) -> PlainTextResponse:
    """EN: Flatten the bundle into one CSV (section, key/value rows) —
        spreadsheet- and grep-friendly.
    FR: Aplatir le bundle en un CSV (section, lignes clé/valeur) — lisible
        en tableur comme en grep."""
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["section", "field", "value"])
    w.writerow(["meta", "generated_at", bundle["generated_at"]])
    w.writerow(["meta", "version", bundle["version"]])
    w.writerow(["meta", "host", bundle["host"]])
    for p in bundle.get("processes", []):
        for field in ("pid", "name", "exe", "sha256", "cmdline", "started"):
            val = p.get(field)
            w.writerow(["process", field,
                        " ".join(val) if isinstance(val, list) else val])
        for par in p.get("parents", []):
            w.writerow(["process", "parent",
                        f"{par.get('name')} (pid {par.get('pid')})"])
    for section, rows in (bundle.get("history") or {}).items():
        for row in rows:
            w.writerow([f"history_{section}", row.get("bucket", ""),
                        json.dumps(row, ensure_ascii=False)])
    for a in bundle.get("alerts", []):
        w.writerow(["alert", a.get("type", ""), a.get("message", "")])
    return PlainTextResponse(
        buf.getvalue(), media_type="text/csv",
        headers={"Content-Disposition":
                 'attachment; filename="snitch-forensics.csv"'})


def _forensics_stix(bundle: dict, ip: Optional[str] = None) -> dict:
    """EN: Minimal STIX 2.1 bundle — an identity for Snitch, indicators for
        the flagged IPs/hashes and observed-data sightings. Enough for a
        SIEM to ingest; deliberately not a full graph.
    FR: Bundle STIX 2.1 minimal — une identity pour Snitch, des indicateurs
        pour les IP/hashes signalés et des observed-data. Suffisant pour un
        SIEM ; volontairement pas un graphe complet."""
    import uuid
    ts = bundle["generated_at"]
    def _uid(s: str) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"snitch.local/{s}"))
    objects: list[dict] = [{
        "type": "identity", "spec_version": "2.1",
        "id": f"identity--{_uid('exporter')}",
        "created": ts, "modified": ts,
        "name": "Snitch local forensics export",
        "identity_class": "system",
    }]
    # EN: One indicator per flagged IP (alert node_id that looks like an
    #     address) + one per process hash — STIX patterning expressions.
    # FR: Un indicateur par IP signalée (node_id d'alerte ressemblant à une
    #     adresse) + un par hash de processus — expressions STIX patterning.
    seen: set[str] = set()
    for i, a in enumerate(bundle.get("alerts", [])):
        node = a.get("node_id") or ""
        try:
            ipaddress.ip_address(node)
        except ValueError:
            continue
        if node in seen:
            continue
        seen.add(node)
        objects.append({
            "type": "indicator", "spec_version": "2.1",
            "id": f"indicator--{_uid(node)}",
            "created": ts, "modified": ts,
            "name": f"Snitch alert: {a.get('type', 'ALERT')} → {node}",
            "description": a.get("message", "")[:500],
            "pattern": f"[ipv4-addr:value = '{node}']"
                       if ":" not in node
                       else f"[ipv6-addr:value = '{node}']",
            "pattern_type": "stix",
            "valid_from": ts,
        })
    if ip:
        try:
            ipaddress.ip_address(ip)
            objects.append({
                "type": "observed-data", "spec_version": "2.1",
                "id": f"observed-data--{_uid('obs/' + ip)}",
                "created": ts, "modified": ts,
                "first_observed": ts, "last_observed": ts,
                "number_observed": 1,
                "objects": {
                    "0": {"type": "ipv4-addr" if ":" not in ip else "ipv6-addr",
                          "value": ip},
                },
            })
        except ValueError:
            pass
    for i, p in enumerate(bundle.get("processes", [])):
        if not p.get("sha256"):
            continue
        objects.append({
            "type": "indicator", "spec_version": "2.1",
            "id": f"indicator--{_uid('sha256/' + p['sha256'])}",
            "created": ts, "modified": ts,
            "name": f"Snitch process: {p.get('name')}",
            "pattern": f"[file:hashes.'SHA-256' = '{p['sha256']}']",
            "pattern_type": "stix",
            "valid_from": ts,
        })
    return {
        "type": "bundle",
        "id": f"bundle--{_uid('bundle/' + ts)}",
        "objects": objects,
    }


@app.get("/forensics/pcap", dependencies=_AUTH)
async def forensics_pcap(ip: Optional[str] = None,
                         process: Optional[str] = None,
                         seconds: int = 300):
    """EN: Export the forensic ring as a real .pcap — wireshark/tcpdump
        open it directly. Filters: remote `ip`, attributed `process`
        (substring), `seconds` of look-back (cap 3600, the ring itself
        holds ~4 MB of recent frames). Empty in demo mode — the demo
        synthesizes packets, it has no wire frames.
    FR: Exporter l'anneau forensique en vrai .pcap — lisible par
        wireshark/tcpdump. Filtres : `ip` distante, `process` attribué
        (sous-chaîne), `seconds` de recul (plafond 3600, l'anneau garde
        ~4 Mo de trames récentes). Vide en mode démo — la démo synthétise
        des paquets, elle n'a pas de trames fil."""
    from fastapi.responses import Response
    from capture.pcapwriter import pcap_bytes
    if _sniffer is None or not hasattr(_sniffer, "pcap_frames"):
        return Response(status_code=204)
    loop = asyncio.get_running_loop()
    linktype, frames = await loop.run_in_executor(
        None, _sniffer.pcap_frames, ip, process,
        max(1, min(int(seconds or 300), 3600)))
    if not frames:
        return Response(status_code=204)
    body = await loop.run_in_executor(None, pcap_bytes, linktype, frames)
    return Response(
        content=body, media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition":
                 'attachment; filename="snitch-forensics.pcap"',
                 "X-Snitch-Frames": str(len(frames))})


# ── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """
    EN: Realtime channel. Handshake is gated by ws_authorized() — Origin
        allowlist + token. On success we send the `init` snapshot BEFORE
        registering the client so no `batch` can reference unknown nodes.
    FR: Canal temps réel. Le handshake est filtré par ws_authorized() — liste
        blanche d'Origin + jeton. En cas de succès on envoie l'instantané
        `init` AVANT d'enregistrer le client pour qu'aucun « batch » ne
        référence de nœud inconnu.
    """
    if not await ws_authorized(websocket):
        return
    await websocket.accept()

    await websocket.send_text(json.dumps({
        "type": "init",
        "nodes": list(nodes.values()) + list(lan_devices.values()),
        "edges": list(edges.values()),
        "alerts": detector.history[-50:],
        "media": _media_state,
        "capturing": _capturing,
        "ports": _port_filter,
        "excluded_processes": sorted(_excluded_processes),
        "whitelisted_ips": sorted(_whitelisted_ips),
        "watchlist": list(_watchlist),
        "interface": _sniffer.iface if _sniffer else None,
        "ssid": _current_ssid(),
    }))

    connected_clients.append(websocket)

    try:
        while True:
            # EN: We never read client messages — receive_text() only serves
            #     to detect disconnection (the UI's 20 s '{}' heartbeat lands
            #     here and is simply discarded).
            # FR: On ne lit jamais les messages clients — receive_text() sert
            #     seulement à détecter la déconnexion (le heartbeat « {} » de
            #     20 s de l'UI arrive ici et est simplement ignoré).
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        # EN: ANY termination path (disconnect, malformed frame, error) must
        #     drop the client — a stale socket would error on next broadcast.
        # FR: TOUTE sortie (déconnexion, trame malformée, erreur) doit retirer
        #     le client — un socket périmé échouerait au prochain broadcast.
        if websocket in connected_clients:
            connected_clients.remove(websocket)


# ── Serve the React build — MUST be registered last ──────────────────────────
# EN: In Docker / non-Electron mode, FastAPI serves the compiled frontend as
#     static files. Mounted at "/" it catches all unmatched routes — so it has
#     to be the LAST route registered.
# FR: En mode Docker / hors Electron, FastAPI sert le frontend compilé en
#     fichiers statiques. Monté sur "/", il intercepte toutes les routes non
#     correspondantes — donc enregistré en DERNIER.
_frontend_dist = Path(__file__).parent.parent.parent / 'frontend_dist'
if _frontend_dist.exists():
    app.mount('/', StaticFiles(directory=str(_frontend_dist), html=True), name='frontend')
