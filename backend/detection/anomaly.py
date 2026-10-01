"""
Snitch — anomaly detector.

EN: Stateful, rule-based detector fed with every captured packet and every
    ARP-discovered device. Emits `Alert` objects broadcast to the UI and
    persisted to SQLite. Alert *messages* stay English — the frontend maps
    `alert.type` + `alert.details` to fully translated strings, so rules only
    need to ship parameters, not prose.

    Rules:
      - NEW_HOST           first time we see a remote IP
      - SUSPICIOUS_PROCESS known dual-use/abused binaries making connections
      - SUSPICIOUS_PORT    traffic to ports associated with shells/botnets/Tor
      - BEACON             *regular-interval* traffic (low interval variance)
                           — real C2 heartbeat detection, not a dumb rate count
      - PORT_SCAN          many distinct remote ports from one origin in a
                           short window (both directions)
      - VOLUME_SPIKE       bytes-per-window far above the rolling baseline
      - MEDIA_EXFIL        mic/camera-using process (not whitelisted) sending out
      - NEW_LAN_DEVICE     device appears on the local network
      - DEVICE_OFFLINE     device disappears from the local network

    Robustness:
      - every public method takes `self._lock` — the API calls us from a
        thread-pool executor, so shared structures must be serialized
      - all sets are size-bounded (`BoundedSet`, LRU eviction) so memory
        can't grow forever on long-running sessions
      - whitelists are deliberately strict: browsers are NOT in the media
        whitelist (a malicious extension exfiltrating mic audio through
        Chrome must still be caught)

FR: Détecteur à état basé sur des règles, alimenté par chaque paquet capturé
    et chaque appareil découvert par ARP. Émet des `Alert` diffusés à l'UI et
    persistés dans SQLite. Les *messages* d'alerte restent en anglais — le
    frontend traduit à partir de `alert.type` + `alert.details`, donc les
    règles n'expédient que des paramètres, pas du texte.

    Règles :
      - NEW_HOST           première fois qu'on voit une IP distante
      - SUSPICIOUS_PROCESS binaires à double usage/abusés qui se connectent
      - SUSPICIOUS_PORT    trafic vers des ports associés shells/botnets/Tor
      - BEACON             trafic à intervalles *réguliers* (faible variance) —
                           vraie détection de heartbeat C2, pas un simple compteur
      - PORT_SCAN          beaucoup de ports distants distincts depuis une
                           origine sur une courte fenêtre (deux sens)
      - VOLUME_SPIKE       octets par fenêtre bien au-dessus de la base roulante
      - MEDIA_EXFIL        processus micro/caméra (non whitelisté) qui émet
      - NEW_LAN_DEVICE     un appareil apparaît sur le réseau local
      - DEVICE_OFFLINE     un appareil disparaît du réseau local

    Robustesse :
      - chaque méthode publique prend `self._lock` — l'API nous appelle depuis
        un pool de threads, les structures partagées doivent être sérialisées
      - tous les ensembles sont bornés (`BoundedSet`, éviction LRU) pour que la
        mémoire ne grossisse pas sans fin sur les longues sessions
      - whitelists volontairement strictes : les navigateurs ne sont PAS dans
        la whitelist média (une extension malveillante exfiltrant le micro via
        Chrome doit être détectée)
"""

import ipaddress
import logging
import math
import threading
import time
import uuid
from collections import OrderedDict, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from capture.sniffer import Packet
from scanner.arp_scanner import Device

logger = logging.getLogger("snitch.detection")

# ── Constants / Constantes ───────────────────────────────────────────────────

# EN: Windows binaries frequently abused for "living off the land" attacks.
# FR: Binaires Windows fréquemment abusés dans les attaques « living off the land ».
SUSPICIOUS_PROCESSES = {
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "rundll32.exe", "msiexec.exe", "schtasks.exe", "at.exe",
}

# EN: Ports strongly associated with backdoors/botnets. 8080 and 5900/5901
#     were REMOVED — far too many false positives on legitimate dev tools
#     and VNC on home networks.
# FR: Ports fortement associés aux backdoors/botnets. 8080 et 5900/5901 ont
#     été RETIRÉS — trop de faux positifs sur les outils de dev légitimes et
#     VNC domestique.
SUSPICIOUS_PORTS = {
    4444: "Metasploit shell",
    4445: "Metasploit shell",
    1337: "Hacker port",
    31337: "Back Orifice",
    6666: "IRC botnet",
    6667: "IRC botnet",
    1080: "SOCKS proxy",
    9001: "Tor relay",
    9050: "Tor SOCKS",
}

# ── Beacon detection parameters / Paramètres de détection beacon ─────────────
# EN: A beacon is periodic traffic: many similarly-sized gaps between packets.
#     We require enough samples, a plausible C2 interval (1 s – 10 min) and a
#     coefficient of variation below BEACON_MAX_CV — streaming/downloads have
#     irregular intervals and won't trigger.
# FR: Un beacon est un trafic périodique : beaucoup d'intervalles similaires
#     entre paquets. On exige assez d'échantillons, un intervalle C2 plausible
#     (1 s – 10 min) et un coefficient de variation sous BEACON_MAX_CV — le
#     streaming/téléchargement a des intervalles irréguliers et ne déclenche pas.
BEACON_MIN_SAMPLES = 12
BEACON_MIN_INTERVAL_S = 1.0
BEACON_MAX_INTERVAL_S = 600.0
BEACON_MAX_CV = 0.35
BEACON_MIN_SPAN_S = 60.0

# ── Volume spike / Pic de volume ─────────────────────────────────────────────
# EN: Bytes in a trailing window vs a rolling baseline of completed windows —
#     NOT single-packet size (a 1.5 KB packet after 100-byte ACKs used to fire).
# FR: Octets dans une fenêtre glissante vs base roulante des fenêtres passées —
#     PAS la taille d'un paquet (un paquet de 1,5 Ko après des ACK de 100 o
#     déclenchait tout le temps).
VOLUME_WINDOW_S = 60
VOLUME_MIN_BYTES = 5 * 1024 * 1024     # EN: windows under 5 MB never alert
                                       # FR: les fenêtres sous 5 Mo n'alertent pas
VOLUME_MULTIPLIER = 5.0

# ── Port scan / Scan de ports ────────────────────────────────────────────────
SCAN_WINDOW_S = 60
SCAN_THRESHOLD = 20                    # EN: distinct remote ports / FR: ports distants
SCAN_COMMON_PORTS = {53, 80, 123, 443, 853}   # EN: chatty-by-design ports
                                              # FR: ports bavards par nature

# EN: Resolver/NTP ports + known DNS-stack processes — excluded from
#     port-scan counting (they legitimately touch many ports).
# FR: Ports résolveurs/NTP + processus de pile DNS connus — exclus du comptage
#     de scan de ports (ils touchent légitimement beaucoup de ports).
KNOWN_RESOLVER_PORTS = {53, 853, 123}
KNOWN_RESOLVER_PROCS = {"systemd-resolved", "dnsmasq", "named", "svchost"}

COOLDOWN = 60              # EN: seconds before re-alerting the same key
                           # FR: secondes avant de re-alerter la même clé

# EN: Legitimate conferencing apps allowed to use mic/camera + network.
#     Browsers were DELIBERATELY removed: an extension exfiltrating mic audio
#     through Chrome/Firefox would otherwise be invisible.
# FR: Apps de visio légitimes autorisées à utiliser micro/caméra + réseau.
#     Les navigateurs ont été RETIRÉS volontairement : une extension
#     exfiltrant l'audio via Chrome/Firefox serait sinon invisible.
MEDIA_WHITELIST = {
    "discord.exe", "discord",
    "teams.exe", "ms-teams.exe", "teams",
    "zoom.exe", "zoom",
    "skype.exe", "skype",
    "slack.exe", "slack",
    "webex.exe", "webex",
    "facetime", "whatsapp.exe", "whatsapp",
}

# EN: IPs that legitimately receive frequent small packets — never beacon-flagged.
# FR: IP recevant légitimement de fréquents petits paquets — jamais signalées beacon.
BEACON_WHITELIST = {
    "1.1.1.1", "1.0.0.1",                    # Cloudflare
    "8.8.8.8", "8.8.4.4",                    # Google DNS
    "9.9.9.9", "149.112.112.112",            # Quad9
    "208.67.222.222", "208.67.220.220",      # OpenDNS
    "4.2.2.1", "4.2.2.2",                    # Level3
    "216.239.35.0", "216.239.35.4",          # Google NTP
    "216.239.35.8", "216.239.35.12",         # Google NTP
    "129.6.15.28", "129.6.15.29",            # NIST NTP
}

# EN: Caps on long-lived state — a Snitch instance running for days must not
#     leak memory through unbounded sets/dicts.
# FR: Plafonds sur l'état longue durée — une instance Snitch tournant des jours
#     ne doit pas fuiter de mémoire via des ensembles/dicts non bornés.
MAX_SEEN_HOSTS = 50_000
MAX_SEEN_PROC_CONNS = 50_000
MAX_TRACKED_IPS = 10_000
MAX_COOLDOWN_KEYS = 10_000


class BoundedSet:
    """
    EN: Insertion-ordered set with a hard cap — evicts the oldest entry when
        full. Used for _seen_hosts / _seen_process_conns.
    FR: Ensemble ordonné par insertion avec plafond strict — évince l'entrée
        la plus ancienne quand il est plein. Utilisé pour _seen_hosts /
        _seen_process_conns.
    """

    def __init__(self, maxlen: int):
        self._d: OrderedDict = OrderedDict()
        self._maxlen = maxlen

    def add(self, key: str) -> None:
        self._d[key] = None
        self._d.move_to_end(key)
        while len(self._d) > self._maxlen:
            self._d.popitem(last=False)

    def discard(self, key: str) -> None:
        self._d.pop(key, None)

    def __contains__(self, key: str) -> bool:
        return key in self._d

    def __len__(self) -> int:
        return len(self._d)


# ── Alert model / Modèle d'alerte ────────────────────────────────────────────

@dataclass
class Alert:
    """
    EN: One detection event. `severity` drives the UI color; `type` + `details`
        carry everything the frontend needs to render a translated message.
    FR: Un événement de détection. `severity` pilote la couleur dans l'UI ;
        `type` + `details` portent tout ce qu'il faut au frontend pour rendre
        un message traduit.
    """
    type: str
    severity: str          # "info" | "warning" | "critical"
    message: str           # EN: English fallback / FR: texte de repli en anglais
    node_id: Optional[str] = None
    details: dict = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "severity": self.severity,
            "message": self.message,
            "node_id": self.node_id,
            "details": self.details,
            "timestamp": self.timestamp,
        }


# ── Detector / Détecteur ─────────────────────────────────────────────────────

class AnomalyDetector:
    """
    EN: Per-host sliding windows (packet timestamps for regularity, byte
        sizes for spikes), bounded seen-sets and a cooldown map to avoid
        alert spam. All public methods hold `self._lock` — they are invoked
        concurrently from the API's thread-pool executor.
    FR: Fenêtres glissantes par hôte (timestamps des paquets pour la
        régularité, tailles pour les pics), ensembles bornés et table de
        cooldown anti-spam. Toutes les méthodes publiques tiennent
        `self._lock` — elles sont appelées en concurrence depuis le pool de
        threads de l'API.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._seen_hosts = BoundedSet(MAX_SEEN_HOSTS)
        self._seen_process_conns = BoundedSet(MAX_SEEN_PROC_CONNS)
        self._pkt_times: dict[str, deque] = defaultdict(lambda: deque(maxlen=120))
        self._host_bytes_window: dict[str, deque] = defaultdict(lambda: deque(maxlen=60))
        # EN: (ts, port) events per scan-origin key + (ts, bytes) per remote IP.
        # FR: Événements (ts, port) par clé d'origine de scan + (ts, octets)
        #     par IP distante.
        self._scan_events: dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._byte_window: dict[str, deque] = defaultdict(lambda: deque(maxlen=5000))
        self._byte_baseline: dict[str, deque] = defaultdict(lambda: deque(maxlen=10))
        self._byte_last_fold: dict[str, float] = {}

        # EN: User suppressions — persisted in the settings table, loaded at
        #     startup. An entry is {"type": "BEACON"|None, "ip": "1.2.3.4"|None};
        #     a packet is suppressed when BOTH non-None fields match.
        # FR: Suppressions utilisateur — persistées dans la table settings,
        #     chargées au démarrage. Une entrée vaut
        #     {"type": "BEACON"|None, "ip": "1.2.3.4"|None} ; un paquet est
        #     supprimé quand les DEUX champs non-None correspondent.
        self._suppressions: list[dict] = []
        self._cooldowns: dict[str, float] = {}
        self.history: list[dict] = []
        self._mic_procs: set[str] = set()
        self._cam_procs: set[str] = set()

    def load_suppressions(self, items: list[dict]) -> None:
        """EN: Replace the suppression list (from persisted settings).
        FR: Remplacer la liste de suppression (depuis les réglages persistés)."""
        with self._lock:
            self._suppressions = [
                {"type": s.get("type"), "ip": s.get("ip")}
                for s in items if isinstance(s, dict)
            ]

    def _suppressed(self, alert_type: str, ip: str) -> bool:
        """EN: True when a suppression rule covers (type, ip) — either field
        may be None (=match all). / FR: True quand une règle de suppression
        couvre (type, ip) — chaque champ peut être None (= tout)."""
        for s in self._suppressions:
            if s["type"] in (None, alert_type) and s["ip"] in (None, ip):
                return True
        return False

    def update_media_state(self, mic: list[str], camera: list[str]) -> None:
        """EN: Sync mic/camera process sets from the media monitor.
        FR: Synchroniser les ensembles micro/caméra depuis le moniteur média."""
        with self._lock:
            self._mic_procs = {p.lower() for p in mic}
            self._cam_procs = {p.lower() for p in camera}

    def forget(self, ip: str) -> None:
        """
        EN: Drop all runtime state for an IP (e.g. after it is whitelisted).
            Without this, a previously-seen IP stays "known" forever.
        FR: Oublier tout l'état d'une IP (ex. après whitelistage). Sans cela,
            une IP déjà vue resterait « connue » pour toujours.
        """
        with self._lock:
            self._seen_hosts.discard(ip)
            self._pkt_times.pop(ip, None)
            self._host_bytes_window.pop(ip, None)
            for k in [k for k in self._cooldowns if k.endswith(f":{ip}") or k == ip]:
                self._cooldowns.pop(k, None)

    def reset_runtime(self) -> None:
        """
        EN: Clear detection state (used when the port filter resets the graph).
            History is kept — resetting the view shouldn't erase the past.
        FR: Vider l'état de détection (utilisé quand le filtre de ports
            réinitialise le graphe). L'historique est conservé — réinitialiser
            la vue ne doit pas effacer le passé.
        """
        with self._lock:
            self._seen_hosts = BoundedSet(MAX_SEEN_HOSTS)
            self._seen_process_conns = BoundedSet(MAX_SEEN_PROC_CONNS)
            self._pkt_times.clear()
            self._host_bytes_window.clear()
            self._scan_events.clear()
            self._byte_window.clear()
            self._byte_baseline.clear()
            self._cooldowns.clear()

    # ── Public API / API publique ────────────────────────────────────────────

    def analyze_packet(self, pkt: Packet, geo: dict) -> list[Alert]:
        """
        EN: Run every packet-level rule under the lock. Private/LAN IPs are
            ignored — LAN devices have their own device-level rules.
        FR: Exécuter toutes les règles niveau paquet sous le verrou. Les IP
            privées/LAN sont ignorées — les appareils LAN ont leurs propres
            règles.
        """
        remote_ip = pkt.dst_ip if pkt.direction == "out" else pkt.src_ip
        if _is_private(remote_ip):
            return []

        with self._lock:
            # EN: Compute "never seen" BEFORE _check_new_host records the IP —
            #     otherwise the suspicious-port rule always read "old host"
            #     and could never escalate to critical (ordering bug).
            # FR: Calculer « jamais vu » AVANT que _check_new_host n'inscrive
            #     l'IP — sinon la règle de port suspect lisait toujours
            #     « hôte connu » et ne pouvait jamais monter en critique
            #     (bug d'ordre).
            is_new_host = remote_ip not in self._seen_hosts
            alerts: list[Alert] = []
            alerts += self._check_new_host(remote_ip, geo)
            alerts += self._check_suspicious_process(pkt, remote_ip, geo)
            alerts += self._check_suspicious_port(pkt, remote_ip, geo,
                                                  is_new_host)
            alerts += self._check_port_scan(pkt, remote_ip, geo)
            alerts += self._check_beacon(remote_ip, geo)
            alerts += self._check_volume_spike(remote_ip, pkt, geo)
            alerts += self._check_media_exfil(pkt, remote_ip, geo)
            # EN: Drop suppressed alerts before recording — persisted
            #     "ignore this host/type" rules from the UI.
            # FR: Écarter les alertes supprimées avant l'enregistrement —
            #     règles « ignorer cet hôte/ce type » persistées depuis l'UI.
            alerts = [a for a in alerts if not self._suppressed(a.type, remote_ip)]
            self._record(alerts)
            return alerts

    def analyze_device(self, device: Device, is_new: bool) -> list[Alert]:
        """
        EN: Device-level rules — alert when a device joins or leaves the LAN.
        FR: Règles niveau appareil — alerter quand un appareil rejoint ou
            quitte le LAN.
        """
        alerts: list[Alert] = []
        label = device.hostname or device.vendor or device.ip

        with self._lock:
            if is_new:
                if self._cooldown_ok(f"new_device:{device.ip}"):
                    alerts.append(Alert(
                        type="NEW_LAN_DEVICE",
                        severity="info",
                        message=f"New device on the network: {label}",
                        node_id=f"lan:{device.ip}",
                        details={"ip": device.ip, "mac": device.mac, "vendor": device.vendor, "host": label},
                    ))
            elif not device.online:
                if self._cooldown_ok(f"offline:{device.ip}"):
                    alerts.append(Alert(
                        type="DEVICE_OFFLINE",
                        severity="info",
                        message=f"Device went offline: {label}",
                        node_id=f"lan:{device.ip}",
                        details={"ip": device.ip, "host": label},
                    ))

            # EN: Device alerts honour suppressions too (keyed on the LAN ip).
            # FR: Les alertes d'appareil respectent aussi les suppressions
            #     (clés sur l'IP LAN).
            alerts = [a for a in alerts if not self._suppressed(a.type, device.ip)]
            self._record(alerts)
            return alerts

    # ── Detection rules / Règles de détection ────────────────────────────────
    # EN: All called with self._lock held.
    # FR: Toutes appelées avec self._lock tenu.

    def _check_new_host(self, ip: str, geo: dict) -> list[Alert]:
        """EN: First contact with a remote IP → info alert, once ever.
        FR: Premier contact avec une IP distante → alerte info, une fois."""
        if ip in self._seen_hosts:
            return []
        self._seen_hosts.add(ip)
        label = geo.get("hostname") or ip
        return [Alert(
            type="NEW_HOST",
            severity="info",
            message=f"New host contacted: {label}",
            node_id=ip,
            details={"ip": ip, "host": label, "org": geo.get("org", ""), "country": geo.get("country", "")},
        )]

    def _check_suspicious_process(self, pkt: Packet, remote_ip: str, geo: dict) -> list[Alert]:
        """EN: Known dual-use binary opening a connection → warning, once per
        (process, ip) pair. / FR: Binaire à double usage connu ouvrant une
        connexion → warning, une fois par couple (processus, ip)."""
        if not pkt.process_name:
            return []
        proc = pkt.process_name.lower()
        if proc not in SUSPICIOUS_PROCESSES:
            return []
        key = f"proc:{proc}:{remote_ip}"
        if key in self._seen_process_conns:
            return []
        self._seen_process_conns.add(key)
        label = geo.get("hostname") or remote_ip
        return [Alert(
            type="SUSPICIOUS_PROCESS",
            severity="warning",
            message=f"Suspicious process: {pkt.process_name} -> {label}",
            node_id=remote_ip,
            details={"process": pkt.process_name, "ip": remote_ip, "host": label, "port": pkt.dst_port},
        )]

    def _check_suspicious_port(self, pkt: Packet, remote_ip: str, geo: dict,
                               is_new_host: bool = False) -> list[Alert]:
        """
        EN: Traffic involving a notorious REMOTE port → warning. remote_port
            is direction-aware — the old dst_port code flagged inbound
            traffic by OUR local port. Severity rises when a brand-new host
            touches the port (context, not just the number).
        FR: Trafic impliquant un port DISTANT sulfureux → warning.
            remote_port tient compte du sens — l'ancien code sur dst_port
            signalait le trafic entrant via NOTRE port local. La sévérité
            monte quand un hôte tout nouveau touche le port (contexte, pas
            juste le numéro).
        """
        port = pkt.remote_port
        if port not in SUSPICIOUS_PORTS:
            return []
        if not self._cooldown_ok(f"port:{port}:{remote_ip}"):
            return []
        label = geo.get("hostname") or remote_ip
        reason = SUSPICIOUS_PORTS[port]
        return [Alert(
            type="SUSPICIOUS_PORT",
            severity="critical" if is_new_host else "warning",
            message=f"Suspicious port {port} ({reason}) -> {label}",
            node_id=remote_ip,
            details={"port": port, "reason": reason, "ip": remote_ip, "host": label,
                     "direction": pkt.direction, "process": pkt.process_name},
        )]

    def _check_port_scan(self, pkt: Packet, remote_ip: str, geo: dict) -> list[Alert]:
        """
        EN: Port-scan rule (advertised by the README, previously absent):
            ≥ SCAN_THRESHOLD distinct remote ports within SCAN_WINDOW_S from
            one origin — works in BOTH directions: an inbound scan (one remote
            IP probing many local ports) and an outbound scan (one local
            process touching many remote ports) both register. Common chatty
            ports (53/80/443/853/123) can't feed the counter — a browser
            hitting :443 on 40 servers is traffic, not a scan.
        FR: Règle de scan de ports (annoncée par le README, absente avant) :
            ≥ SCAN_THRESHOLD ports distants distincts en SCAN_WINDOW_S depuis
            une origine — dans les DEUX sens : scan entrant (une IP distante
            sonde beaucoup de ports locaux) et sortant (un processus local
            touche beaucoup de ports distants) comptent tous deux. Les ports
            bavards courants (53/80/443/853/123) n'alimentent pas le compteur —
            un navigateur sur :443 vers 40 serveurs est du trafic, pas un scan.
        """
        remote_port = pkt.remote_port
        if not remote_port or remote_port in SCAN_COMMON_PORTS:
            return []
        proc = (pkt.process_name or "").lower()
        if remote_port in KNOWN_RESOLVER_PORTS or proc in KNOWN_RESOLVER_PROCS:
            return []

        # EN: Key by origin — inbound scans key on the remote IP, outbound on
        #     the local process so different apps don't pool their counts.
        # FR: Clé par origine — les scans entrants se clés sur l'IP distante,
        #     les sortants sur le processus local pour ne pas fusionner les
        #     compteurs d'apps différentes.
        key = remote_ip if pkt.direction == "in" else f"local:{proc or 'unknown'}"
        now = time.time()
        dq = self._scan_events[key]
        dq.append((now, remote_port))
        cutoff = now - SCAN_WINDOW_S
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        if len({p for _, p in dq}) < SCAN_THRESHOLD:
            return []
        dq.clear()                          # EN: don't re-fire on the same burst
                                            # FR: ne pas redéclencher sur la même rafale
        if not self._cooldown_ok(f"scan:{key}", cooldown=300):
            return []
        label = geo.get("hostname") or remote_ip
        source = remote_ip if pkt.direction == "in" else (pkt.process_name or "local")
        return [Alert(
            type="PORT_SCAN",
            severity="warning",
            message=f"Port scan: {source} touched {SCAN_THRESHOLD}+ ports in {SCAN_WINDOW_S}s",
            node_id=remote_ip,
            details={"source": source, "ip": remote_ip, "host": label,
                     "ports": SCAN_THRESHOLD, "window_s": SCAN_WINDOW_S,
                     "direction": pkt.direction},
        )]

    def _check_beacon(self, remote_ip: str, geo: dict) -> list[Alert]:
        """
        EN: True beacon detection — regularity, not volume. We look at the
            inter-packet intervals in a per-host window and require:
              * ≥ BEACON_MIN_SAMPLES intervals,
              * a window spanning ≥ BEACON_MIN_SPAN_S,
              * mean interval inside a C2-plausible range (1 s – 10 min),
              * coefficient of variation < BEACON_MAX_CV.
            Streaming and bulk downloads have wildly varying (or sub-second)
            intervals and won't trip this.
        FR: Vraie détection de beacon — la régularité, pas le volume. On
            observe les intervalles inter-paquets dans une fenêtre par hôte et
            on exige :
              * ≥ BEACON_MIN_SAMPLES intervalles,
              * une fenêtre couvrant ≥ BEACON_MIN_SPAN_S,
              * un intervalle moyen dans la plage plausible C2 (1 s – 10 min),
              * un coefficient de variation < BEACON_MAX_CV.
            Le streaming et les gros téléchargements ont des intervalles très
            variables (ou sous la seconde) et ne déclenchent pas.
        """
        if remote_ip in BEACON_WHITELIST:
            return []

        dq = self._pkt_times[remote_ip]
        dq.append(time.time())

        # EN: Bound the tracking dict itself — forget hosts with stale windows.
        # FR: Borner aussi le dict de suivi — oublier les hôtes à fenêtre périmée.
        if len(self._pkt_times) > MAX_TRACKED_IPS:
            self._pkt_times.clear()

        if len(dq) < BEACON_MIN_SAMPLES + 1:
            return []

        times = list(dq)
        span = times[-1] - times[0]
        if span < BEACON_MIN_SPAN_S:
            return []

        intervals = [b - a for a, b in zip(times, times[1:])]
        mean = sum(intervals) / len(intervals)
        if not (BEACON_MIN_INTERVAL_S <= mean <= BEACON_MAX_INTERVAL_S):
            return []
        if mean <= 0:
            return []

        variance = sum((i - mean) ** 2 for i in intervals) / len(intervals)
        cv = math.sqrt(variance) / mean
        if cv >= BEACON_MAX_CV:
            return []

        if not self._cooldown_ok(f"beacon:{remote_ip}", cooldown=300):
            return []

        label = geo.get("hostname") or remote_ip
        return [Alert(
            type="BEACON",
            severity="warning",
            message=f"Beacon-like regularity: ~{mean:.0f}s interval to {label} (CV {cv:.2f})",
            node_id=remote_ip,
            details={"ip": remote_ip, "host": label, "interval_s": round(mean, 1), "cv": round(cv, 3), "samples": len(intervals)},
        )]

    def _check_volume_spike(self, remote_ip: str, pkt: Packet, geo: dict) -> list[Alert]:
        """
        EN: Bytes per trailing window vs rolling baseline — not single-packet
            size. Outbound only (exfil risk). Each completed window folds into
            the baseline; a spike is > VOLUME_MULTIPLIER × median AND
            > VOLUME_MIN_BYTES so tiny hosts can't trip it.
        FR: Octets par fenêtre glissante vs base roulante — pas la taille
            d'un paquet. Sortant seulement (risque d'exfiltration). Chaque
            fenêtre terminée alimente la base ; un pic = > VOLUME_MULTIPLIER
            × médiane ET > VOLUME_MIN_BYTES, donc les petits hôtes ne
            déclenchent pas.
        """
        if pkt.direction != "out":
            return []
        if len(self._byte_window) > MAX_TRACKED_IPS:
            self._byte_window.clear()

        now = time.time()
        dq = self._byte_window[remote_ip]
        dq.append((now, pkt.size))
        cutoff = now - VOLUME_WINDOW_S
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        window_bytes = sum(s for _, s in dq)

        baseline = self._byte_baseline[remote_ip]
        base_med = sorted(baseline)[len(baseline) // 2] if len(baseline) >= 3 else 0

        if window_bytes > VOLUME_MIN_BYTES and window_bytes > base_med * VOLUME_MULTIPLIER:
            if not self._cooldown_ok(f"spike:{remote_ip}", cooldown=120):
                return []
            label = geo.get("hostname") or remote_ip
            return [Alert(
                type="VOLUME_SPIKE",
                severity="warning",
                message=f"Data spike to {label}: {window_bytes // 1024} KB in {VOLUME_WINDOW_S}s",
                node_id=remote_ip,
                details={"ip": remote_ip, "host": label, "bytes": window_bytes,
                         "window_s": VOLUME_WINDOW_S, "baseline": int(base_med),
                         "process": pkt.process_name},
            )]

        # EN: Fold the trailing window into the baseline once per
        #     VOLUME_WINDOW_S — one sample per completed window.
        # FR: Plier la fenêtre glissante dans la base une fois par
        #     VOLUME_WINDOW_S — un échantillon par fenêtre terminée.
        if now - self._byte_last_fold.get(remote_ip, 0) >= VOLUME_WINDOW_S:
            baseline.append(window_bytes)
            self._byte_last_fold[remote_ip] = now
            if len(self._byte_last_fold) > MAX_TRACKED_IPS:
                self._byte_last_fold.clear()
        return []

    def _check_media_exfil(self, pkt: Packet, remote_ip: str, geo: dict) -> list[Alert]:
        """
        EN: Signature rule — a process holding the mic/camera, NOT a known
            conferencing app, sending outbound traffic → critical.
            Browsers are intentionally excluded from the whitelist.
        FR: Règle signature — un processus qui tient le micro/la caméra, qui
            N'EST PAS une app de visio connue, et qui émet du trafic sortant →
            critique. Les navigateurs sont volontairement exclus de la whitelist.
        """
        if not pkt.process_name:
            return []
        proc = pkt.process_name.lower()
        if proc not in self._mic_procs and proc not in self._cam_procs:
            return []
        if proc in MEDIA_WHITELIST:
            return []
        if pkt.direction != "out":
            return []
        if not self._cooldown_ok(f"media_exfil:{proc}:{remote_ip}", cooldown=300):
            return []
        device = "microphone" if proc in self._mic_procs else "camera"
        label = geo.get("hostname") or remote_ip
        return [Alert(
            type="MEDIA_EXFIL",
            severity="critical",
            message=f"Suspected {device} exfiltration: {pkt.process_name} -> {label}",
            node_id=remote_ip,
            details={"process": pkt.process_name, "device": device, "ip": remote_ip, "host": label, "org": geo.get("org", "")},
        )]

    # ── Helpers / Utilitaires ────────────────────────────────────────────────

    def _cooldown_ok(self, key: str, cooldown: int = COOLDOWN) -> bool:
        """
        EN: True (and re-arm) if this key hasn't fired within `cooldown`
            seconds. The map is pruned when it grows past its cap.
        FR: True (et réarme) si cette clé n'a pas tiré depuis `cooldown`
            secondes. La table est purgée quand elle dépasse son plafond.
        """
        now = time.time()
        if len(self._cooldowns) > MAX_COOLDOWN_KEYS:
            # EN: Drop expired entries first; if still huge, wipe.
            # FR: Évincer d'abord les entrées expirées ; si encore énorme, vider.
            self._cooldowns = {k: v for k, v in self._cooldowns.items() if now - v < 3600}
            if len(self._cooldowns) > MAX_COOLDOWN_KEYS:
                self._cooldowns.clear()
        if now - self._cooldowns.get(key, 0) < cooldown:
            return False
        self._cooldowns[key] = now
        return True

    def _record(self, alerts: list[Alert]) -> None:
        """EN: Append to the bounded in-memory history (last 500).
        FR: Ajouter à l'historique en mémoire borné (500 dernières)."""
        for a in alerts:
            self.history.append(a.to_dict())
        if len(self.history) > 500:
            self.history = self.history[-500:]


def _is_private(ip: str) -> bool:
    """EN: RFC1918 / loopback / link-local / ULA check (v4 + v6).
    FR: Test RFC1918 / loopback / link-local / ULA (v4 + v6)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
