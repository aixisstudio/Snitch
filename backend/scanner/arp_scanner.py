"""
Snitch — LAN device discovery via the system ARP table.

EN: Scapy is gone (GPL-2.0-only), so active ARP broadcast scanning went with
    it. Discovery now reads the OS neighbour cache — populated passively by
    normal traffic, so it catches what your machine actually talks to:

      - Linux   : /proc/net/arp
      - Windows : `arp -a`   ("  192.168.1.1   00-11-22-33-44-55   dynamic")
      - macOS   : `arp -a`   ("? (192.168.1.1) at 0:11:22:33:44:55 on en0")

    Entries marked "incomplete"/permanent-failed are skipped. Each responder
    is reverse-DNS'd and OUI-matched to guess vendor + device type. Devices
    absent from a scan are flagged offline and announced once more.

FR: Scapy est parti (GPL-2.0-only), donc le scan ARP broadcast actif l'a suivi.
    La découverte lit désormais le cache de voisinage de l'OS — alimenté
    passivement par le trafic normal, donc il attrape ce à quoi votre machine
    parle vraiment :

      - Linux   : /proc/net/arp
      - Windows : `arp -a`   («  192.168.1.1   00-11-22-33-44-55   dynamic »)
      - macOS   : `arp -a`   (« ? (192.168.1.1) at 0:11:22:33:44:55 on en0 »)

    Les entrées « incomplete »/échouées sont ignorées. Chaque répondant passe
    en DNS inverse + correspondance OUI pour deviner fabricant et type
    d'appareil. Les appareils absents d'un scan passent hors ligne et sont
    annoncés une dernière fois.
"""

import ipaddress
import logging
import re
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import psutil

from scanner.oui import lookup, DEVICE_TYPE_COLORS

logger = logging.getLogger("snitch.scanner")

# EN: MAC address matcher — handles both : and - separators.
# FR: Reconnaisseur d'adresse MAC — gère les séparateurs : et -.
MAC_RE = re.compile(r"([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}")
IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


@dataclass
class Device:
    """
    EN: One LAN device as displayed in the graph.
    FR: Un appareil LAN tel qu'affiché dans le graphe.
    """
    ip: str
    mac: str
    vendor: str = "Unknown"
    device_type: str = "unknown"        # phone / pc / router / iot / tv / unknown
    hostname: Optional[str] = None
    online: bool = True
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    bytes: int = 0
    packets: int = 0
    color: str = "#64748b"

    def to_dict(self) -> dict:
        """EN: Serialize for JSON transport. / FR: Sérialiser pour le transport JSON."""
        return {
            "id": f"lan:{self.ip}",
            "ip": self.ip,
            "mac": self.mac,
            "label": self.hostname or self.vendor or self.ip,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "category": "lan_device",
            "device_type": self.device_type,
            "online": self.online,
            "bytes": self.bytes,
            "packets": self.packets,
            "color": self.color,
        }


def _get_local_ips() -> set[str]:
    """EN: This host's own IPv4 addresses — filtered out of results.
    FR: Les IPv4 propres à cet hôte — filtrées des résultats."""
    return {
        addr.address
        for addrs in psutil.net_if_addrs().values()
        for addr in addrs
        if addr.family == socket.AF_INET
    }


def _read_arp_table() -> list[tuple[str, str]]:
    """
    EN: Snapshot of the system ARP/neighbour table as (ip, mac) pairs.
        Platform-specific reader; returns [] on failure — the scanner stays
        alive and retries next interval.
    FR: Instantané de la table ARP/voisinage système en couples (ip, mac).
        Lecteur par plateforme ; renvoie [] en cas d'échec — le scanner reste
        vivant et réessaie à l'intervalle suivant.
    """
    if sys.platform.startswith("linux"):
        return _read_arp_linux()
    return _read_arp_cmd()


def _read_arp_linux() -> list[tuple[str, str]]:
    """EN: Parse /proc/net/arp — flag 0x0 or 00:00:... means incomplete.
    FR: Analyser /proc/net/arp — flag 0x0 ou MAC 00:00:… signifie incomplet."""
    out = []
    try:
        lines = Path("/proc/net/arp").read_text().splitlines()[1:]
    except OSError as exc:
        logger.debug("/proc/net/arp unreadable: %s", exc)
        return out
    for line in lines:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip, _hwtype, flags, mac = parts[0], parts[1], parts[2], parts[3]
        if int(flags, 16) == 0 or mac == "00:00:00:00:00:00":
            continue
        out.append((ip, mac.upper()))
    return out


def _read_arp_cmd() -> list[tuple[str, str]]:
    """EN: Parse `arp -a` on Windows ("-"-separated MACs) and macOS
    (parenthesized IPs). / FR: Analyser `arp -a` sous Windows (MAC séparées par
    « - ») et macOS (IP entre parenthèses)."""
    try:
        proc = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                              timeout=10)
        out_text = proc.stdout
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.debug("arp -a failed: %s", exc)
        return []

    pairs = []
    for line in out_text.splitlines():
        if "incomplete" in line.lower():
            continue
        ip_m = IPV4_RE.search(line)
        mac_m = MAC_RE.search(line)
        if ip_m and mac_m:
            pairs.append((ip_m.group(0), mac_m.group(0).replace("-", ":").upper()))
    return pairs


def _resolve_hostname(ip: str) -> Optional[str]:
    """EN: Reverse-DNS a LAN IP; None on failure. / FR: DNS inverse d'une IP LAN ; None en cas d'échec."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


class ARPScanner:
    """
    EN: Background scanner — re-reads the neighbour table every `interval`
        seconds. Invokes `callback(device, is_new)` for each entry, and once
        with online=False when a known device disappears.
    FR: Scanner d'arrière-plan — relit la table de voisinage toutes les
        `interval` secondes. Appelle `callback(device, is_new)` pour chaque
        entrée, et une fois avec online=False quand un appareil connu
        disparaît.
    """

    def __init__(self, callback: Callable[[Device, bool], None], interval: int = 30):
        self.callback = callback
        self.interval = interval
        self._known: dict[str, Device] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def _run(self) -> None:
        """
        EN: Scan loop. `seen_ips` tracks devices present this round; known
            devices absent from it are flipped to offline.
        FR: Boucle de scan. `seen_ips` suit les appareils présents ce tour ;
            les appareils connus absents passent hors ligne.
        """
        local_ips = _get_local_ips()
        while self._running:
            seen_ips: set[str] = set()

            for ip, mac in _read_arp_table():
                if ip in local_ips:
                    continue
                try:
                    addr = ipaddress.ip_address(ip)
                    if addr.is_multicast or addr.is_loopback or addr.is_link_local:
                        continue
                except ValueError:
                    continue

                seen_ips.add(ip)
                is_new = ip not in self._known
                if is_new:
                    vendor, device_type = lookup(mac)
                    hostname = _resolve_hostname(ip)
                    self._known[ip] = Device(
                        ip=ip, mac=mac, vendor=vendor, device_type=device_type,
                        hostname=hostname, online=True,
                        color=DEVICE_TYPE_COLORS.get(device_type, "#64748b"),
                    )
                else:
                    self._known[ip].last_seen = time.time()
                    if not self._known[ip].online:
                        self._known[ip].online = True
                        is_new = True  # EN: treat reappearance as a change event
                                       # FR: traiter la réapparition comme un événement
                self.callback(self._known[ip], is_new)

            # EN: Mark disappeared devices as offline.
            # FR: Marquer hors ligne les appareils disparus.
            for ip, device in list(self._known.items()):
                if ip not in seen_ips and device.online:
                    device.online = False
                    self.callback(device, False)

            time.sleep(self.interval)

    def start(self) -> None:
        """EN: Spawn the daemon scan thread. / FR: Lancer le thread de scan daemon."""
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """EN: Signal the loop to exit. / FR: Demander à la boucle de s'arrêter."""
        self._running = False

    @property
    def devices(self) -> list[dict]:
        """EN: Snapshot of all known devices. / FR: Instantané de tous les appareils connus."""
        return [d.to_dict() for d in self._known.values()]
