"""
Snitch — FastAPI application.

EN: Heart of the backend. Owns the in-memory graph state (nodes / edges /
    LAN devices), receives packets from the Scapy sniffer thread, enriches
    them (DNS + geolocation + classification), feeds the anomaly detector,
    persists aggregates to SQLite and pushes realtime updates over the
    WebSocket.

    Security model (see api/security.py):
      - every REST endpoint requires the API token (X-Snitch-Token header or
        ?token= param)
      - the WebSocket requires the token AND a whitelisted Origin header
      - CORS is restricted to the dev server / self-origin / file:// (Electron)

FR: Cœur du backend. Détenir l'état du graphe en mémoire (nœuds / arêtes /
    appareils LAN), recevoir les paquets du thread du sniffer Scapy, les
    enrichir (DNS + géolocalisation + classification), alimenter le détecteur
    d'anomalies, persister les agrégats dans SQLite et pousser les mises à
    jour temps réel via le WebSocket.

    Modèle de sécurité (voir api/security.py) :
      - chaque endpoint REST exige le jeton API (en-tête X-Snitch-Token ou
        paramètre ?token=)
      - le WebSocket exige le jeton ET un en-tête Origin autorisé
      - CORS restreint au serveur de dev / à l'origine propre / file:// (Electron)
"""

import asyncio
import json
import logging
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from api.security import ALLOWED_ORIGINS_LIST, require_token, ws_authorized
from capture.sniffer import Packet, PacketSniffer
from capture.media_monitor import MediaMonitor, MediaState
from classifier.traffic import classify
from resolver.dns_geo import enrich_ip
from scanner.arp_scanner import ARPScanner, Device
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
detector = AnomalyDetector()
_loop: asyncio.AbstractEventLoop | None = None
_sniffer: PacketSniffer | None = None
_scanner: ARPScanner | None = None
_capturing: bool = True
_port_filter: list[int] = []
_excluded_processes: set[str] = set()
_whitelisted_ips: set[str] = set()
_media_state: dict = {"mic": [], "camera": []}

# EN: Hard caps so a long-running instance can't leak memory.
# FR: Plafonds stricts pour qu'une instance longue durée ne fuie pas de mémoire.
MAX_GRAPH_NODES = 800
MAX_ENRICHMENT_CACHE = 4096


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


# ── Broadcast / Diffusion ────────────────────────────────────────────────────

async def broadcast(message: dict) -> None:
    """
    EN: Send a JSON message to every connected WebSocket client; drop the
        dead ones.
    FR: Envoyer un message JSON à tous les clients WebSocket connectés ;
        retirer les morts.
    """
    dead = []
    for ws in connected_clients:
        try:
            await ws.send_text(json.dumps(message))
        except Exception:
            dead.append(ws)
    for ws in dead:
        connected_clients.remove(ws)


# ── Packet handling / Traitement des paquets ─────────────────────────────────

def on_packet(pkt: Packet) -> None:
    """
    EN: Called from the Scapy sniffer THREAD — schedule the async handler on
        the event loop.
    FR: Appelé depuis le THREAD du sniffer Scapy — planifier le handler async
        sur la boucle d'événements.
    """
    if _loop is None:
        return
    asyncio.run_coroutine_threadsafe(_handle_packet(pkt), _loop)


async def _handle_packet(pkt: Packet) -> None:
    """
    EN: Per-packet pipeline — filter, enrich, update graph, persist, detect.
        LAN-destined traffic is accounted on the device node instead of being
        dropped, so LAN devices show real byte counters.
    FR: Pipeline par paquet — filtrer, enrichir, mettre à jour le graphe,
        persister, détecter. Le trafic vers le LAN est comptabilisé sur le nœud
        de l'appareil au lieu d'être ignoré, pour que les appareils LAN
        affichent de vrais compteurs d'octets.
    """
    if pkt.process_name and pkt.process_name in _excluded_processes:
        return

    remote_ip = pkt.dst_ip if pkt.direction == "out" else pkt.src_ip

    if remote_ip in _whitelisted_ips:
        return

    # ── LAN traffic accounting / Comptabilisation du trafic LAN ─────────────
    lan_key = f"lan:{remote_ip}"
    if lan_key in lan_devices:
        lan_devices[lan_key]["bytes"] = lan_devices[lan_key].get("bytes", 0) + pkt.size
        lan_devices[lan_key]["packets"] = lan_devices[lan_key].get("packets", 0) + 1
        edge = edges.get(f"lan-edge-{remote_ip}")
        if edge:
            edge["bytes"] += pkt.size
            edge["packets"] += 1
        await broadcast({
            "type": "device_update",
            "device": lan_devices[lan_key],
            "edge": edge,
            "is_new": False,
        })
        return

    # EN: Enrich once per IP (reverse DNS + geolocation), then cache it.
    #     The cache is bounded — evict the oldest half when full.
    # FR: Enrichir une fois par IP (DNS inverse + géolocalisation), puis cacher.
    #     Le cache est borné — évincer la moitié la plus ancienne quand plein.
    if remote_ip not in enrichment_cache:
        if len(enrichment_cache) > MAX_ENRICHMENT_CACHE:
            for stale in list(enrichment_cache.keys())[: MAX_ENRICHMENT_CACHE // 2]:
                enrichment_cache.pop(stale, None)
        try:
            enrichment_cache[remote_ip] = await enrich_ip(remote_ip)
        except Exception as exc:
            logger.debug("enrich_ip failed for %s: %s", remote_ip, exc)
            enrichment_cache[remote_ip] = {"ip": remote_ip, "hostname": None, "private": False}
    geo = enrichment_cache[remote_ip]

    category = classify(geo.get("hostname"), pkt.dst_port, pkt.protocol)

    # ── Graph node update / Mise à jour du nœud ─────────────────────────────
    node_id = remote_ip
    if node_id not in nodes:
        # EN: Bound the graph — evict the lowest-traffic non-alerted node.
        # FR: Borner le graphe — évincer le nœud au plus faible trafic non alerté.
        if len(nodes) >= MAX_GRAPH_NODES:
            _evict_weakest_node()
        nodes[node_id] = {
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
            "bytes": 0,
            "packets": 0,
            "alerted": False,
        }

    nodes[node_id]["bytes"] += pkt.size
    nodes[node_id]["packets"] += 1

    # EN: Track per-process traffic on this node (top talkers in the UI).
    # FR: Suivre le trafic par processus sur ce nœud (top parleurs dans l'UI).
    if pkt.process_name:
        procs = nodes[node_id].setdefault("processes", {})
        if pkt.process_name not in procs:
            procs[pkt.process_name] = {"bytes": 0, "packets": 0}
        procs[pkt.process_name]["bytes"] += pkt.size
        procs[pkt.process_name]["packets"] += 1

    # ── Graph edge update / Mise à jour de l'arête ──────────────────────────
    edge_id = f"local-{node_id}-{pkt.protocol}"
    if edge_id not in edges:
        edges[edge_id] = {
            "id": edge_id,
            "source": "local",
            "target": node_id,
            "protocol": pkt.protocol,
            "label": category.label,
            "color": category.color,
            "bytes": 0,
            "packets": 0,
        }
    edges[edge_id]["bytes"] += pkt.size
    edges[edge_id]["packets"] += 1

    # EN: Persist per-minute aggregates — batched, non-blocking.
    # FR: Persister les agrégats par minute — par lots, sans blocage.
    minute = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M")
    db.accumulate(minute, category.category, pkt.size)

    # ── Anomaly detection / Détection d'anomalies ───────────────────────────
    loop = asyncio.get_running_loop()
    alerts = await loop.run_in_executor(None, detector.analyze_packet, pkt, geo)
    for alert in alerts:
        if alert.node_id and alert.node_id in nodes:
            nodes[alert.node_id]["alerted"] = True
        alert_dict = alert.to_dict()
        await loop.run_in_executor(None, db.log_alert, alert_dict)
        await broadcast({"type": "alert", "alert": alert_dict})

    await broadcast({
        "type": "update",
        "node": nodes[node_id],
        "edge": edges[edge_id],
        "packet": {
            "src": pkt.src_ip,
            "dst": pkt.dst_ip,
            "protocol": pkt.protocol,
            "size": pkt.size,
            "direction": pkt.direction,
            "process": pkt.process_name,
            "timestamp": pkt.timestamp,
        },
    })


def _evict_weakest_node() -> None:
    """
    EN: Remove the lowest-byte, non-alerted, non-local node (and its edges)
        when the graph hits MAX_GRAPH_NODES. Called from _handle_packet.
    FR: Retirer le nœud au plus faible trafic, non alerté et non « local »
        (et ses arêtes) quand le graphe atteint MAX_GRAPH_NODES. Appelé depuis
        _handle_packet.
    """
    candidates = [
        n for n in nodes.values()
        if n["id"] != "local" and not n.get("alerted")
    ]
    if not candidates:
        return
    weakest = min(candidates, key=lambda n: n.get("bytes", 0))
    wid = weakest["id"]
    nodes.pop(wid, None)
    enrichment_cache.pop(wid, None)
    for eid in [eid for eid, e in edges.items() if e["target"] == wid or e["source"] == wid]:
        edges.pop(eid, None)


# ── LAN device handling / Gestion des appareils LAN ──────────────────────────

def on_device(device: Device, is_new: bool) -> None:
    """EN: ARP scanner callback — schedules async handling.
    FR: Callback du scanner ARP — planifie le traitement async."""
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
    node = device.to_dict()
    # EN: Preserve accumulated byte counters across rediscovery.
    # FR: Préserver les compteurs d'octets accumulés à travers les redécouvertes.
    prev = lan_devices.get(node["id"])
    if prev:
        node["bytes"] = prev.get("bytes", 0)
        node["packets"] = prev.get("packets", 0)
        node["alerted"] = prev.get("alerted", False)
    else:
        node["alerted"] = False
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
        if alert.node_id and alert.node_id in lan_devices:
            lan_devices[alert.node_id]["alerted"] = True
        alert_dict = alert.to_dict()
        await loop.run_in_executor(None, db.log_alert, alert_dict)
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
    FR: Callback MediaMonitor — synchroniser les ensembles média du détecteur
        et notifier l'UI.
    """
    global _media_state
    _media_state = {"mic": state.mic, "camera": state.camera}
    detector.update_media_state(state.mic, state.camera)
    if _loop:
        asyncio.run_coroutine_threadsafe(
            broadcast({"type": "media", "mic": state.mic, "camera": state.camera}),
            _loop,
        )


def _flush_loop() -> None:
    """EN: Periodically flush the traffic accumulator to SQLite.
    FR: Vider périodiquement l'accumulateur de trafic vers SQLite."""
    while True:
        time.sleep(10)
        try:
            db.flush()
        except Exception as exc:
            logger.error("db flush failed: %s", exc)


def _cleanup_loop() -> None:
    """
    EN: Drop rows older than 24h — the timeline is a sliding window, the DB
        must not grow forever.
    FR: Supprimer les lignes de plus de 24 h — la timeline est une fenêtre
        glissante, la BDD ne doit pas grossir indéfiniment.
    """
    while True:
        time.sleep(3600)
        try:
            db.cleanup_old_data(hours=24)
        except Exception as exc:
            logger.error("db cleanup failed: %s", exc)


# ── Capture lifecycle / Cycle de vie de la capture ───────────────────────────

def _start_capture() -> None:
    """EN: (Re)start sniffer + ARP scanner in daemon threads.
    FR: (Re)démarrer sniffer + scanner ARP dans des threads daemon."""
    global _sniffer, _scanner, _capturing
    _sniffer = PacketSniffer(callback=on_packet, ports=_port_filter)
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


async def _startup() -> None:
    """EN: Startup — create the "local" node, start capture + background threads.
    FR: Démarrage — créer le nœud « local », lancer capture + threads d'arrière-plan."""
    global _loop
    _loop = asyncio.get_running_loop()

    nodes["local"] = {
        "id": "local", "label": "This Device", "ip": "local",
        "category": "local", "color": "#3b82f6",
        "bytes": 0, "packets": 0, "alerted": False,
    }

    _start_capture()
    threading.Thread(target=_flush_loop, daemon=True).start()
    threading.Thread(target=_cleanup_loop, daemon=True).start()

    media = MediaMonitor(callback=_on_media_change, interval=3)
    threading.Thread(target=media.start, daemon=True).start()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """EN: FastAPI lifespan — startup logic, then yield for the app's life.
    FR: Lifespan FastAPI — logique de démarrage, puis yield pour la vie de l'app."""
    await _startup()
    yield


app = FastAPI(title="Snitch API", lifespan=lifespan)

# EN: Restricted CORS — dev server, self-origin, and `null` (Electron file://).
#     No `*`, no credentials. Combined with the token check this kills the
#     "any open webpage can drive my API" attack.
# FR: CORS restreint — serveur de dev, origine propre et `null` (file://
#     Electron). Pas de `*`, pas de credentials. Combiné au jeton, cela tue
#     l'attaque « n'importe quelle page ouverte pilote mon API ».
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS_LIST,
    allow_methods=["GET", "POST"],
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
    """EN: Last 100 in-memory alerts. / FR: Les 100 dernières alertes en mémoire."""
    return {"alerts": detector.history[-100:]}

@app.get("/media", dependencies=_AUTH)
async def get_media() -> dict:
    """EN: Current mic/camera usage. / FR: Usage actuel micro/caméra."""
    return _media_state

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
    FR: Restreindre la capture à une liste de ports (vide = tous). Le graphe et
        l'état du détecteur sont réinitialisés pour que l'UI n'affiche que le
        trafic correspondant.
    """
    global _port_filter
    _port_filter = [p for p in body.ports if 1 <= p <= 65535]

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
    """EN: Hide traffic from named processes. / FR: Masquer le trafic de processus nommés."""
    global _excluded_processes
    _excluded_processes = {str(p) for p in body.excluded}

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
    EN: Mark IPs as trusted — dropped from capture and display. Removed nodes
        also get forgotten by the detector and the enrichment cache, so
        un-whitelisting works correctly afterwards.
    FR: Marquer des IP comme fiables — ignorées de la capture et de
        l'affichage. Les nœuds retirés sont aussi oubliés par le détecteur et
        le cache d'enrichissement, pour qu'un retrait de la whitelist
        fonctionne ensuite correctement.
    """
    global _whitelisted_ips
    _whitelisted_ips = {str(ip) for ip in body.ips}

    removed_ids = [ip for ip in _whitelisted_ips if ip != "local" and nodes.pop(ip, None) is not None]
    if removed_ids:
        removed_set = set(removed_ids)
        for edge_id in [eid for eid, e in edges.items() if e["source"] in removed_set or e["target"] in removed_set]:
            edges.pop(edge_id, None)
        for ip in removed_ids:
            enrichment_cache.pop(ip, None)
            detector.forget(ip)   # EN: clear seen/beacon/spike state too
                                  # FR: vider aussi l'état seen/beacon/spike

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


# ── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """
    EN: Realtime channel. Handshake is gated by ws_authorized() — Origin
        allowlist + token. On success we send the `init` snapshot BEFORE
        registering the client so no `update` can reference unknown nodes.
    FR: Canal temps réel. Le handshake est filtré par ws_authorized() — liste
        blanche d'Origin + jeton. En cas de succès on envoie l'instantané
        `init` AVANT d'enregistrer le client pour qu'aucun `update` ne
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
            #     to detect disconnection.
            # FR: On ne lit jamais les messages clients — receive_text() sert
            #     seulement à détecter la déconnexion.
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in connected_clients:
            connected_clients.remove(websocket)


# ── Serve the React build — MUST be registered last ──────────────────────────
# EN: In Docker / non-Electron mode, FastAPI serves the compiled frontend as
#     static files. Mounted at "/" it catches all unmatched routes — so it has
#     to be the LAST route registered.
# FR: En mode Docker / hors Electron, FastAPI sert le frontend compilé en
#     fichiers statiques. Monté sur "/", il intercepte toutes les routes non
#     correspondantes — donc enregistré en DERNIER.
from pathlib import Path
from fastapi.staticfiles import StaticFiles

_frontend_dist = Path(__file__).parent.parent.parent / 'frontend_dist'
if _frontend_dist.exists():
    app.mount('/', StaticFiles(directory=str(_frontend_dist), html=True), name='frontend')
