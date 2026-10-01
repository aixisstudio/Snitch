"""
Snitch — anomaly detector.

EN: Stateful, rule-based detector fed with every captured packet and every
    ARP-discovered device. Emits `Alert` objects that are broadcast to the UI
    and persisted to SQLite. Rules:
      - NEW_HOST           first time we see a remote IP
      - SUSPICIOUS_PROCESS known dual-use/abused binaries making connections
      - SUSPICIOUS_PORT    traffic to ports associated with shells/proxies/Tor
      - BEACON             > N packets/min to the same host (C2 heartbeat)
      - VOLUME_SPIKE       a single packet far above the host's average size
      - MEDIA_EXFIL        mic/camera-using process (not whitelisted) sending out
      - NEW_LAN_DEVICE     device appears on the local network
      - DEVICE_OFFLINE     device disappears from the local network

FR: Détecteur à état, basé sur des règles, alimenté par chaque paquet capturé
    et chaque appareil découvert par ARP. Émet des objets `Alert` diffusés à
    l'UI et persistés dans SQLite. Règles :
      - NEW_HOST           première fois qu'on voit une IP distante
      - SUSPICIOUS_PROCESS binaires à double usage/abusés établissant des connexions
      - SUSPICIOUS_PORT    trafic vers des ports associés à shells/proxies/Tor
      - BEACON             > N paquets/min vers le même hôte (heartbeat C2)
      - VOLUME_SPIKE       un paquet bien au-dessus de la taille moyenne de l'hôte
      - MEDIA_EXFIL        processus utilisant micro/caméra (non whitelisté) qui émet
      - NEW_LAN_DEVICE     un appareil apparaît sur le réseau local
      - DEVICE_OFFLINE     un appareil disparaît du réseau local
"""

import ipaddress
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from capture.sniffer import Packet
from scanner.arp_scanner import Device

# ── Constants / Constantes ───────────────────────────────────────────────────

# EN: Windows binaries frequently abused for "living off the land" attacks.
# FR: Binaires Windows fréquemment abusés dans les attaques « living off the land ».
SUSPICIOUS_PROCESSES = {
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "rundll32.exe", "msiexec.exe", "schtasks.exe", "at.exe",
}

# EN: Ports historically associated with backdoors, botnets and proxies.
# FR: Ports historiquement associés aux backdoors, botnets et proxies.
SUSPICIOUS_PORTS = {
    4444: "Metasploit shell",
    4445: "Metasploit shell",
    1337: "Hacker port",
    31337: "Back Orifice",
    6666: "IRC botnet",
    6667: "IRC botnet",
    5900: "VNC (remote desktop)",
    5901: "VNC (remote desktop)",
    1080: "SOCKS proxy",
    8080: "Alt HTTP / proxy",
    9001: "Tor relay",
    9050: "Tor SOCKS",
}

BEACON_THRESHOLD = 30      # EN: packets/min to same IP → suspicious beacon
                           # FR: paquets/min vers la même IP → beacon suspect
VOLUME_SPIKE_FACTOR = 8    # EN: 8× average bytes → spike
                           # FR: 8× la moyenne d'octets → pic
COOLDOWN = 60              # EN: seconds before re-alerting the same key
                           # FR: secondes avant de re-alerter la même clé

# EN: Legitimate apps known to use mic/camera + network (calls, meetings) —
#     never flagged for media exfiltration.
# FR: Apps légitimes connues pour utiliser micro/caméra + réseau (appels,
#     réunions) — jamais signalées pour exfiltration média.
MEDIA_WHITELIST = {
    "discord.exe", "discord",
    "teams.exe", "ms-teams.exe", "teams",
    "zoom.exe", "zoom",
    "skype.exe", "skype",
    "slack.exe", "slack",
    "webex.exe", "webex",
    "chrome.exe", "chrome",
    "firefox.exe", "firefox",
    "msedge.exe", "msedge",
    "brave.exe", "brave",
    "opera.exe", "opera",
    "facetime", "whatsapp.exe", "whatsapp",
}

# EN: IPs that legitimately receive frequent small packets (DNS resolvers,
#     NTP servers) — never flagged as beaconing.
# FR: IP qui reçoivent légitimement de fréquents petits paquets (résolveurs
#     DNS, serveurs NTP) — jamais signalées comme beaconing.
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


# ── Alert model / Modèle d'alerte ────────────────────────────────────────────

@dataclass
class Alert:
    """
    EN: One detection event. `severity` drives the UI color; `type` maps to a
        translated label key in the frontend i18n dictionary.
    FR: Un événement de détection. `severity` pilote la couleur dans l'UI ;
        `type` correspond à une clé de traduction du dictionnaire i18n du
        frontend.
    """
    type: str
    severity: str          # "info" | "warning" | "critical"
    message: str
    node_id: Optional[str] = None
    details: dict = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

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
    EN: Keeps per-host sliding windows (packet timestamps, byte sizes), a set
        of seen hosts/connections and a cooldown map to avoid alert spam.
        All methods are synchronous and CPU-only — callers run them in a
        thread executor.
    FR: Maintient des fenêtres glissantes par hôte (timestamps des paquets,
        tailles en octets), un ensemble d'hôtes/connexions déjà vus et une
        table de cooldown pour éviter le spam d'alertes. Toutes les méthodes
        sont synchrones et purement CPU — l'appelant les exécute dans un
        thread executor.
    """

    def __init__(self):
        self._seen_hosts: set[str] = set()
        self._seen_process_conns: set[str] = set()
        self._pkt_times: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._host_bytes_window: dict[str, deque] = defaultdict(lambda: deque(maxlen=60))
        self._cooldowns: dict[str, float] = {}
        self.history: list[dict] = []
        self._mic_procs: set[str] = set()
        self._cam_procs: set[str] = set()

    def update_media_state(self, mic: list[str], camera: list[str]) -> None:
        """
        EN: Called by the API whenever the media monitor reports a change.
        FR: Appelé par l'API à chaque changement rapporté par le moniteur média.
        """
        self._mic_procs = {p.lower() for p in mic}
        self._cam_procs = {p.lower() for p in camera}

    # ── Public API / API publique ────────────────────────────────────────────

    def analyze_packet(self, pkt: Packet, geo: dict) -> list[Alert]:
        """
        EN: Run every packet-level rule and return the alerts produced.
            Private/LAN IPs are ignored — LAN devices have their own rules.
        FR: Exécuter toutes les règles au niveau paquet et renvoyer les alertes
            produites. Les IP privées/LAN sont ignorées — les appareils LAN
            ont leurs propres règles.
        """
        alerts: list[Alert] = []
        remote_ip = pkt.dst_ip if pkt.direction == "out" else pkt.src_ip

        if _is_private(remote_ip):
            return alerts

        alerts += self._check_new_host(remote_ip, geo)
        alerts += self._check_suspicious_process(pkt, remote_ip, geo)
        alerts += self._check_suspicious_port(pkt, remote_ip, geo)
        alerts += self._check_beacon(remote_ip, geo)
        alerts += self._check_volume_spike(remote_ip, pkt.size, geo)
        alerts += self._check_media_exfil(pkt, remote_ip, geo)

        self._record(alerts)
        return alerts

    def analyze_device(self, device: Device, is_new: bool) -> list[Alert]:
        """
        EN: Device-level rules — alert when a device joins or leaves the LAN.
        FR: Règles au niveau appareil — alerter quand un appareil rejoint ou
            quitte le LAN.
        """
        alerts: list[Alert] = []

        if is_new:
            key = f"new_device:{device.ip}"
            alert = Alert(
                type="NEW_LAN_DEVICE",
                severity="info",
                message=f"New device on the network: {device.hostname or device.vendor or device.ip}",
                node_id=f"lan:{device.ip}",
                details={"ip": device.ip, "mac": device.mac, "vendor": device.vendor},
            )
            if self._cooldown_ok(key):
                alerts.append(alert)

        elif not device.online:
            key = f"offline:{device.ip}"
            alert = Alert(
                type="DEVICE_OFFLINE",
                severity="info",
                message=f"Device went offline: {device.hostname or device.ip}",
                node_id=f"lan:{device.ip}",
                details={"ip": device.ip},
            )
            if self._cooldown_ok(key):
                alerts.append(alert)

        self._record(alerts)
        return alerts

    # ── Detection rules / Règles de détection ────────────────────────────────

    def _check_new_host(self, ip: str, geo: dict) -> list[Alert]:
        """EN: First contact with a remote IP → info alert.
        FR: Premier contact avec une IP distante → alerte info."""
        if ip in self._seen_hosts:
            return []
        self._seen_hosts.add(ip)
        label = geo.get("hostname") or ip
        return [Alert(
            type="NEW_HOST",
            severity="info",
            message=f"New host contacted: {label}",
            node_id=ip,
            details={"ip": ip, "org": geo.get("org", ""), "country": geo.get("country", "")},
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
            details={"process": pkt.process_name, "ip": remote_ip, "port": pkt.dst_port},
        )]

    def _check_suspicious_port(self, pkt: Packet, remote_ip: str, geo: dict) -> list[Alert]:
        """EN: Traffic to a notorious port → warning (cooldown-limited).
        FR: Trafic vers un port sulfureux → warning (limité par cooldown)."""
        port = pkt.dst_port
        if port not in SUSPICIOUS_PORTS:
            return []
        key = f"port:{port}:{remote_ip}"
        if not self._cooldown_ok(key):
            return []
        label = geo.get("hostname") or remote_ip
        reason = SUSPICIOUS_PORTS[port]
        return [Alert(
            type="SUSPICIOUS_PORT",
            severity="warning",
            message=f"Suspicious port {port} ({reason}) -> {label}",
            node_id=remote_ip,
            details={"port": port, "reason": reason, "ip": remote_ip},
        )]

    def _check_beacon(self, remote_ip: str, geo: dict) -> list[Alert]:
        """
        EN: >BEACON_THRESHOLD packets to the same host within 60s looks like
            a C2 heartbeat → warning, 5-minute cooldown.
        FR: >BEACON_THRESHOLD paquets vers le même hôte en 60 s ressemblent à
            un heartbeat C2 → warning, cooldown de 5 minutes.
        """
        if remote_ip in BEACON_WHITELIST:
            return []
        now = time.time()
        dq = self._pkt_times[remote_ip]
        dq.append(now)
        recent = sum(1 for t in dq if now - t < 60)
        if recent < BEACON_THRESHOLD:
            return []
        key = f"beacon:{remote_ip}"
        if not self._cooldown_ok(key, cooldown=300):
            return []
        label = geo.get("hostname") or remote_ip
        return [Alert(
            type="BEACON",
            severity="warning",
            message=f"Beacon-like behavior: {recent} packets/min to {label}",
            node_id=remote_ip,
            details={"ip": remote_ip, "rate": recent},
        )]

    def _check_volume_spike(self, remote_ip: str, size: int, geo: dict) -> list[Alert]:
        """
        EN: A single packet ≥ 8× the rolling average for that host suggests a
            data burst (possible exfiltration) → warning.
        FR: Un paquet ≥ 8× la moyenne glissante pour cet hôte suggère une
            rafale de données (exfiltration possible) → warning.
        """
        dq = self._host_bytes_window[remote_ip]
        dq.append(size)
        if len(dq) < 10:
            return []
        avg = sum(dq) / len(dq)
        if size < avg * VOLUME_SPIKE_FACTOR or avg < 100:
            return []
        key = f"spike:{remote_ip}"
        if not self._cooldown_ok(key, cooldown=120):
            return []
        label = geo.get("hostname") or remote_ip
        return [Alert(
            type="VOLUME_SPIKE",
            severity="warning",
            message=f"Traffic spike to {label} ({size // 1024} KB in one packet)",
            node_id=remote_ip,
            details={"ip": remote_ip, "size": size, "avg": int(avg)},
        )]

    def _check_media_exfil(self, pkt: Packet, remote_ip: str, geo: dict) -> list[Alert]:
        """
        EN: A process that currently holds the mic or camera, is NOT a known
            conferencing app, and is sending outbound traffic → critical.
            This is Snitch's signature rule.
        FR: Un processus qui détient actuellement le micro ou la caméra, qui
            N'EST PAS une app de visio connue et qui émet du trafic sortant →
            critique. C'est la règle signature de Snitch.
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
        key = f"media_exfil:{proc}:{remote_ip}"
        if not self._cooldown_ok(key, cooldown=300):
            return []
        device = "microphone" if proc in self._mic_procs else "camera"
        label = geo.get("hostname") or remote_ip
        return [Alert(
            type="MEDIA_EXFIL",
            severity="critical",
            message=f"Suspected {device} exfiltration: {pkt.process_name} -> {label}",
            node_id=remote_ip,
            details={"process": pkt.process_name, "device": device, "ip": remote_ip, "org": geo.get("org", "")},
        )]

    # ── Helpers / Utilitaires ────────────────────────────────────────────────

    def _cooldown_ok(self, key: str, cooldown: int = COOLDOWN) -> bool:
        """
        EN: Return True (and arm the timer) if this alert key has not fired
            within `cooldown` seconds. Prevents alert storms.
        FR: Renvoyer True (et armer le minuteur) si cette clé d'alerte n'a pas
            tiré depuis `cooldown` secondes. Évite les tempêtes d'alertes.
        """
        now = time.time()
        if now - self._cooldowns.get(key, 0) < cooldown:
            return False
        self._cooldowns[key] = now
        return True

    def _record(self, alerts: list[Alert]) -> None:
        """
        EN: Append alerts to the bounded in-memory history (last 500).
        FR: Ajouter les alertes à l'historique en mémoire borné (500 dernières).
        """
        for a in alerts:
            self.history.append(a.to_dict())
        if len(self.history) > 500:
            self.history = self.history[-500:]


def _is_private(ip: str) -> bool:
    """EN: RFC1918 / loopback / link-local check. / FR: Test RFC1918 / loopback / link-local."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False
