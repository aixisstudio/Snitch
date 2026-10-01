"""
Snitch — FastAPI application.

EN: This module is the heart of the backend. It owns the in-memory graph
    state (nodes / edges / LAN devices), receives packets from the Scapy
    sniffer thread, enriches them (DNS + geolocation + classification),
    feeds the anomaly detector, persists aggregates to SQLite, and pushes
    real-time updates to every connected frontend over a WebSocket.

FR: Ce module est le cœur du backend. Il détient l'état du graphe en mémoire
    (nœuds / arêtes / appareils LAN), reçoit les paquets du thread du sniffer
    Scapy, les enrichit (DNS + géolocalisation + classification), alimente le
    détecteur d'anomalies, persiste les agrégats dans SQLite et pousse les
    mises à jour en temps réel vers chaque frontend connecté via WebSocket.
"""

import asyncio
import json
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from capture.sniffer import Packet, PacketSniffer
from capture.media_monitor import MediaMonitor, MediaState
from classifier.traffic import classify
from resolver.dns_geo import enrich_ip
from scanner.arp_scanner import ARPScanner, Device
from detection.anomaly import AnomalyDetector
import storage.db as db

# ── Shared state / État partagé ──────────────────────────────────────────────
# EN: All mutable application state lives here at module level.
#     `nodes` and `edges` describe the external-traffic graph; `lan_devices`
#     describes ARP-discovered local devices.
# FR: Tout l'état mutable de l'application vit ici au niveau module.
#     `nodes` et `edges` décrivent le graphe de trafic externe ;
#     `lan_devices` décrit les appareils locaux découverts par ARP.
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


# ── Broadcast / Diffusion ────────────────────────────────────────────────────

async def broadcast(message: dict) -> None:
    """
    EN: Send a JSON message to every connected WebSocket client.
        Clients that fail to receive (disconnected, closed tab…) are removed.
    FR: Envoie un message JSON à tous les clients WebSocket connectés.
        Les clients en échec (déconnectés, onglet fermé…) sont retirés.
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
    EN: Called from the Scapy sniffer THREAD for every captured packet.
        We cannot `await` there, so the real work is scheduled on the
        asyncio event loop via `run_coroutine_threadsafe`.
    FR: Appelé depuis le THREAD du sniffer Scapy pour chaque paquet capturé.
        Impossible d'utiliser `await` là-bas : le vrai travail est planifié
        sur la boucle asyncio via `run_coroutine_threadsafe`.
    """
    if _loop is None:
        return
    asyncio.run_coroutine_threadsafe(_handle_packet(pkt), _loop)


async def _handle_packet(pkt: Packet) -> None:
    """
    EN: Per-packet pipeline — filter, enrich, update graph, persist, detect.
    FR: Pipeline par paquet — filtrer, enrichir, mettre à jour le graphe,
        persister, détecter.
    """
    # EN: Drop packets produced by user-excluded processes.
    # FR: Ignorer les paquets produits par les processus exclus par l'utilisateur.
    if pkt.process_name and pkt.process_name in _excluded_processes:
        return

    # EN: The "remote" endpoint is the destination for outbound traffic and
    #     the source for inbound traffic.
    # FR: L'endpoint « distant » est la destination pour le trafic sortant et
    #     la source pour le trafic entrant.
    remote_ip = pkt.dst_ip if pkt.direction == "out" else pkt.src_ip

    # EN: Trusted IPs are skipped entirely — not shown, not stored.
    # FR: Les IP de confiance sont totalement ignorées — ni affichées ni stockées.
    if remote_ip in _whitelisted_ips:
        return

    # EN: Enrich once per IP (reverse DNS + geolocation), then cache it.
    # FR: On enrichit une fois par IP (DNS inverse + géolocalisation), puis cache.
    if remote_ip not in enrichment_cache:
        enrichment_cache[remote_ip] = await enrich_ip(remote_ip)
    geo = enrichment_cache[remote_ip]

    # EN: LAN devices already appear in the device list — skip duplicates.
    # FR: Les appareils LAN apparaissent déjà dans la liste — on évite les doublons.
    if f"lan:{remote_ip}" in lan_devices:
        return

    # EN: Classify the connection (HTTPS, DNS, tracking, CDN…) for color/label.
    # FR: Classifier la connexion (HTTPS, DNS, tracking, CDN…) pour couleur/label.
    category = classify(geo.get("hostname"), pkt.dst_port, pkt.protocol)

    # ── Graph node update / Mise à jour du nœud ─────────────────────────────
    node_id = remote_ip
    if node_id not in nodes:
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
    # EN: One edge per (remote host, protocol) pair, always anchored on "local".
    # FR: Une arête par couple (hôte distant, protocole), toujours ancrée sur « local ».
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

    # EN: Persist per-minute aggregates in a batched, non-blocking way.
    # FR: Persister les agrégats par minute, par lots et sans bloquer.
    minute = datetime.utcnow().strftime("%Y-%m-%dT%H:%M")
    db.accumulate(minute, category.category, pkt.size)

    # ── Anomaly detection / Détection d'anomalies ───────────────────────────
    # EN: Detection runs in a thread executor — it is CPU-only and must not
    #     block the event loop on busy networks.
    # FR: La détection tourne dans un executor — purement CPU, elle ne doit pas
    #     bloquer la boucle événementielle sur les réseaux chargés.
    loop = asyncio.get_running_loop()
    alerts = await loop.run_in_executor(None, detector.analyze_packet, pkt, geo)
    for alert in alerts:
        if alert.node_id and alert.node_id in nodes:
            nodes[alert.node_id]["alerted"] = True
        alert_dict = alert.to_dict()
        await loop.run_in_executor(None, db.log_alert, alert_dict)
        await broadcast({"type": "alert", "alert": alert_dict})

    # EN: Push the node/edge update plus the raw packet to all clients.
    # FR: Pousser la mise à jour nœud/arête plus le paquet brut à tous les clients.
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


# ── LAN device handling / Gestion des appareils LAN ──────────────────────────

def on_device(device: Device, is_new: bool) -> None:
    """
    EN: Called from the ARP scanner thread — schedules async handling.
    FR: Appelé depuis le thread du scanner ARP — planifie le traitement async.
    """
    if _loop is None:
        return
    asyncio.run_coroutine_threadsafe(_handle_device(device, is_new), _loop)


async def _handle_device(device: Device, is_new: bool) -> None:
    """
    EN: Register/update a LAN device node, add its dashed edge to "local",
        run device-level anomaly checks (new device, device offline).
    FR: Enregistrer/mettre à jour le nœud d'un appareil LAN, ajouter son arête
        pointillée vers « local », lancer les détections au niveau appareil
        (nouvel appareil, appareil hors ligne).
    """
    node = device.to_dict()
    node["alerted"] = False
    lan_devices[node["id"]] = node

    # EN: LAN devices use a dashed edge — visual distinction in the graph.
    # FR: Les appareils LAN utilisent une arête pointillée — distinction visuelle.
    edge_id = f"lan-edge-{device.ip}"
    edges[edge_id] = {
        "id": edge_id,
        "source": "local",
        "target": node["id"],
        "protocol": "LAN",
        "label": "LAN",
        "color": node["color"],
        "bytes": 0,
        "packets": 0,
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
    EN: Called by the MediaMonitor thread whenever mic/camera usage changes.
        Updates the detector (media-exfil rule) and notifies the UI.
    FR: Appelé par le thread MediaMonitor quand l'usage micro/caméra change.
        Met à jour le détecteur (règle d'exfiltration média) et notifie l'UI.
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
    """
    EN: Periodically flush the in-memory traffic accumulator to SQLite.
    FR: Vider périodiquement l'accumulateur de trafic en mémoire vers SQLite.
    """
    while True:
        time.sleep(10)
        try:
            db.flush()
        except Exception:
            pass


def _cleanup_loop() -> None:
    """
    EN: Drop traffic/alert rows older than 24h — the timeline is a sliding
        window, the DB must not grow forever.
    FR: Supprimer les lignes trafic/alertes de plus de 24 h — la timeline est
        une fenêtre glissante, la BDD ne doit pas grossir indéfiniment.
    """
    while True:
        time.sleep(3600)
        try:
            db.cleanup_old_data(hours=24)
        except Exception:
            pass


# ── Capture lifecycle / Cycle de vie de la capture ───────────────────────────

def _start_capture() -> None:
    """
    EN: (Re)start the packet sniffer and the ARP scanner in daemon threads.
    FR: (Re)démarrer le sniffer de paquets et le scanner ARP dans des threads daemon.
    """
    global _sniffer, _scanner, _capturing
    _sniffer = PacketSniffer(callback=on_packet, ports=_port_filter)
    threading.Thread(target=_sniffer.start, daemon=True).start()
    _scanner = ARPScanner(callback=on_device, interval=30)
    threading.Thread(target=_scanner.start, daemon=True).start()
    _capturing = True


def _stop_capture() -> None:
    """
    EN: Stop both capture sources. Safe to call when already stopped.
    FR: Arrêter les deux sources de capture. Sans effet si déjà arrêtées.
    """
    global _capturing
    if _sniffer:
        _sniffer.stop()
    if _scanner:
        _scanner.stop()
    _capturing = False


async def _startup() -> None:
    """
    EN: Application startup — create the "local" node, start capture, and
        spawn background threads (flush, cleanup, media monitor).
    FR: Démarrage de l'application — créer le nœud « local », lancer la capture
        et les threads d'arrière-plan (flush, nettoyage, moniteur média).
    """
    global _loop
    _loop = asyncio.get_running_loop()

    # EN: The local machine is always the center of the graph.
    # FR: La machine locale est toujours le centre du graphe.
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
    # EN: FastAPI lifespan — run startup logic, then yield for the app's life.
    # FR: Lifespan FastAPI — logique de démarrage, puis yield pour la vie de l'app.
    await _startup()
    yield


app = FastAPI(title="Snitch API", lifespan=lifespan)

# EN: Permissive CORS — the API only listens on localhost in production, and
#     the dev frontend runs on another port (Vite proxy would also work).
# FR: CORS permissif — l'API n'écoute que sur localhost en production, et le
#     frontend de dev tourne sur un autre port (le proxy Vite fonctionne aussi).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── REST endpoints / Endpoints REST ──────────────────────────────────────────

@app.get("/graph")
async def get_graph() -> dict:
    """EN: Full graph snapshot. / FR: Instantané complet du graphe."""
    return {
        "nodes": list(nodes.values()) + list(lan_devices.values()),
        "edges": list(edges.values()),
    }

@app.get("/devices")
async def get_devices() -> dict:
    """EN: LAN device list. / FR: Liste des appareils LAN."""
    return {"devices": list(lan_devices.values())}

@app.get("/alerts")
async def get_alerts() -> dict:
    """EN: Last 100 in-memory alerts. / FR: Les 100 dernières alertes en mémoire."""
    return {"alerts": detector.history[-100:]}

@app.get("/media")
async def get_media() -> dict:
    """EN: Current mic/camera usage. / FR: Usage actuel micro/caméra."""
    return _media_state

@app.get("/capture/status")
async def get_capture_status() -> dict:
    """EN: Capture state + all active filters. / FR: État de capture + filtres actifs."""
    return {
        "capturing": _capturing,
        "ports": _port_filter,
        "excluded_processes": sorted(_excluded_processes),
        "whitelisted_ips": sorted(_whitelisted_ips),
    }

@app.post("/capture/stop")
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

@app.post("/capture/ports")
async def set_port_filter(body: dict) -> dict:
    """
    EN: Restrict capture to a list of ports (empty list = all ports).
        The graph is wiped so the UI only shows traffic matching the filter.
    FR: Restreindre la capture à une liste de ports (liste vide = tous).
        Le graphe est vidé pour que l'UI n'affiche que le trafic filtré.
    """
    global _port_filter
    ports = [int(p) for p in body.get("ports", []) if str(p).isdigit() and 1 <= int(p) <= 65535]
    _port_filter = ports

    # EN: Clear graph state — keep only the "local" node.
    # FR: Vider l'état du graphe — ne garder que le nœud « local ».
    local = nodes.get("local")
    nodes.clear()
    edges.clear()
    lan_devices.clear()
    if local:
        nodes["local"] = local

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

@app.post("/capture/start")
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

@app.post("/capture/processes")
async def set_process_filter(body: dict) -> dict:
    """EN: Hide traffic from named processes. / FR: Masquer le trafic de processus nommés."""
    global _excluded_processes
    _excluded_processes = {str(p) for p in body.get("excluded", []) if isinstance(p, str)}

    await broadcast({
        "type": "capture_status",
        "capturing": _capturing,
        "ports": _port_filter,
        "excluded_processes": sorted(_excluded_processes),
        "whitelisted_ips": sorted(_whitelisted_ips),
    })
    return {"excluded_processes": sorted(_excluded_processes)}

@app.post("/capture/whitelist")
async def set_ip_whitelist(body: dict) -> dict:
    """
    EN: Mark IPs as trusted — they are no longer captured or displayed.
        Existing nodes/edges for those IPs are removed immediately.
    FR: Marquer des IP comme fiables — elles ne sont plus capturées ni affichées.
        Les nœuds/arêtes existants pour ces IP sont retirés immédiatement.
    """
    global _whitelisted_ips
    _whitelisted_ips = {str(ip) for ip in body.get("ips", []) if isinstance(ip, str)}

    removed_ids = [ip for ip in _whitelisted_ips if ip != "local" and nodes.pop(ip, None) is not None]
    if removed_ids:
        removed_set = set(removed_ids)
        for edge_id in [eid for eid, e in edges.items() if e["source"] in removed_set or e["target"] in removed_set]:
            edges.pop(edge_id, None)
        for ip in removed_ids:
            enrichment_cache.pop(ip, None)

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

@app.get("/timeline")
async def get_timeline(minutes: int = 60) -> dict:
    """EN: Per-minute traffic/alert aggregates for the timeline chart.
    FR: Agrégats trafic/alertes par minute pour le graphique timeline."""
    loop = asyncio.get_running_loop()
    data = await loop.run_in_executor(None, db.get_timeline, minutes)
    return {"timeline": data}


# ── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """
    EN: Main realtime channel. On connect we send an `init` snapshot BEFORE
        registering the client — this guarantees no `update` referencing an
        unknown node can reach the client first and corrupt its graph state.
    FR: Canal temps réel principal. À la connexion on envoie un instantané
        `init` AVANT d'enregistrer le client — cela garantit qu'aucun `update`
        référençant un nœud inconnu n'arrive en premier et ne corrompe l'état.
    """
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
#     static files. Mounted at "/" it catches all unmatched routes, so it has
#     to be the LAST route registered.
# FR: En mode Docker / hors Electron, FastAPI sert le frontend compilé en
#     fichiers statiques. Monté sur "/", il intercepte toutes les routes non
#     correspondantes — il doit donc être enregistré en DERNIER.
from pathlib import Path
from fastapi.staticfiles import StaticFiles

_frontend_dist = Path(__file__).parent.parent.parent / 'frontend_dist'
if _frontend_dist.exists():
    app.mount('/', StaticFiles(directory=str(_frontend_dist), html=True), name='frontend')
