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

from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from api.security import ALLOWED_ORIGIN_REGEX, require_token, ws_authorized
from capture.sniffer import Packet, PacketSniffer, get_local_ips
from capture.media_monitor import MediaMonitor, MediaState
from classifier.traffic import classify
from resolver.dns_geo import (enrich_ip, is_private, learn_dns_answers,
                              learn_sni, lookup_domain)
from scanner.arp_scanner import ARPScanner, Device, default_gateway as _default_gateway
from scanner.arp_scanner import READ_STATS as _arp_stats
from detection.anomaly import AnomalyDetector
import storage.db as db

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
_loop: asyncio.AbstractEventLoop | None = None
_sniffer: PacketSniffer | None = None
_scanner: ARPScanner | None = None
_media_monitor: MediaMonitor | None = None
_capturing: bool = True
_port_filter: list[int] = []
_excluded_processes: set[str] = set()
_whitelisted_ips: set[str] = set()
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


class GeoDownloadBody(BaseModel):
    """EN: /geo/download payload — explicit consent is REQUIRED, this is the
    only outbound call in the whole app. / FR: Charge utile de /geo/download —
    consentement explicite OBLIGATOIRE, c'est le seul appel sortant de l'app."""
    consent: bool = False


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

        touched_nodes[node_id] = node
        touched_edges[edge_id] = edge
        out_packets.append({
            "src": pkt.src_ip, "dst": pkt.dst_ip,
            "protocol": pkt.protocol, "size": pkt.size,
            "direction": pkt.direction, "process": pkt.process_name,
            "remote_port": pkt.remote_port, "sni": pkt.sni,
            "timestamp": pkt.timestamp,
        })

    return {
        "type": "batch",
        "nodes": list(touched_nodes.values()),
        "edges": list(touched_edges.values()),
        "devices": list(touched_devices.values()),
        "packets": out_packets,
        "alerts": out_alerts,
    }


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
        await asyncio.sleep(DRAIN_INTERVAL_S)


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
    while not _shutdown:
        time.sleep(10)
        try:
            db.flush()
        except Exception as exc:
            logger.error("db flush failed: %s", exc)


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
    FR: (Re)démarrer sniffer + scanner de table ARP dans des threads daemon."""
    global _sniffer, _scanner, _capturing
    _sniffer = PacketSniffer(callback=on_packet, ports=_port_filter,
                             iface=db.get_setting("interface"))
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


def _load_settings() -> None:
    """
    EN: Restore persisted settings from SQLite at startup — filters, whitelist
        and process exclusions survive restarts now.
    FR: Restaurer les réglages persistés depuis SQLite au démarrage — filtres,
        whitelist et exclusions de processus survivent aux redémarrages.
    """
    global _port_filter, _excluded_processes, _whitelisted_ips
    _port_filter = db.get_setting("ports", []) or []
    _excluded_processes = set(db.get_setting("excluded_processes", []) or [])
    _whitelisted_ips = set(db.get_setting("whitelisted_ips", []) or [])
    detector.load_suppressions(db.get_setting("suppressions", []) or [])
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
    return {"ok": True}

@app.get("/capture/status", dependencies=_AUTH)
async def get_capture_status() -> dict:
    """EN: Capture state + all active filters. / FR: État de capture + filtres actifs."""
    return {
        "capturing": _capturing,
        "ports": _port_filter,
        "excluded_processes": sorted(_excluded_processes),
        "whitelisted_ips": sorted(_whitelisted_ips),
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

@app.get("/timeline", dependencies=_AUTH)
async def get_timeline(minutes: int = 60) -> dict:
    """EN: Per-minute aggregates for the timeline chart.
    FR: Agrégats par minute pour le graphique timeline."""
    loop = asyncio.get_running_loop()
    data = await loop.run_in_executor(None, db.get_timeline, minutes)
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
        None, db.get_history, "host", ip, minutes)}


@app.get("/history/process/{name}", dependencies=_AUTH)
async def get_process_history(name: str, minutes: int = 60) -> dict:
    """EN: Per-process byte/packet history. / FR: Historique par processus."""
    loop = asyncio.get_running_loop()
    return {"history": await loop.run_in_executor(
        None, db.get_history, "process", name, minutes)}


@app.get("/history/top_processes", dependencies=_AUTH)
async def get_top_processes(minutes: int = 60) -> dict:
    """EN: Top talkers by process — the Apps view data source.
    FR: Plus gros émetteurs par processus — la source de la vue Apps."""
    loop = asyncio.get_running_loop()
    return {"processes": await loop.run_in_executor(
        None, db.get_top_processes, minutes)}


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
    except OSError as exc:
        log_tail = [f"<log read failed: {exc}>"]

    db_file = data_dir() / "snitch.db"
    return {
        "version": "1.1.0",
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

    downloaded = []
    errors = []
    for remote, local in files.items():
        url = f"https://download.db-ip.com/free/{remote}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Snitch/1.1"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = gzip.decompress(resp.read())
            (geo_dir / local).write_bytes(data)
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
