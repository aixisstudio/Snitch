"""
Snitch — LAN scanner (ARP discovery).

EN: Periodically ARP-scans every IPv4 subnet the host is attached to and
    reports each responder as a `Device`. Devices that stop answering are
    marked offline. Vendor/device-type identification comes from the local
    OUI table (scanner/oui.py).

FR: Scanne périodiquement en ARP chaque sous-réseau IPv4 auquel l'hôte est
    rattaché et rapporte chaque répondant comme `Device`. Les appareils qui
    cessent de répondre sont marqués hors ligne. L'identification du
    fabricant/type vient de la table OUI locale (scanner/oui.py).
"""

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import psutil

from scanner.oui import lookup, DEVICE_TYPE_COLORS

try:
    from scapy.all import ARP, Ether, srp
    SCAPY_AVAILABLE = True
except ImportError:
    # EN: Without Scapy there is no ARP scan — the rest of the app still works.
    # FR: Sans Scapy pas de scan ARP — le reste de l'app fonctionne quand même.
    SCAPY_AVAILABLE = False


@dataclass
class Device:
    """
    EN: One host discovered on the local network.
    FR: Un hôte découvert sur le réseau local.
    """
    ip: str
    mac: str
    vendor: str
    device_type: str        # "router" | "phone" | "pc" | "tv" | "iot" | "unknown"
    hostname: Optional[str]
    online: bool = True
    color: str = "#64748b"
    icon: str = "?"

    def to_dict(self) -> dict:
        """
        EN: Serialize to the node shape the frontend graph expects. The `lan:`
            id prefix keeps LAN nodes from colliding with external-IP nodes.
        FR: Sérialiser vers la forme de nœud attendue par le graphe frontend.
            Le préfixe d'id « lan: » évite les collisions avec les nœuds
            d'IP externes.
        """
        return {
            "id": f"lan:{self.ip}",
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "hostname": self.hostname,
            "label": self.hostname or self.vendor or self.ip,
            "online": self.online,
            "category": "lan_device",
            "color": self.color,
            "icon": self.icon,
            "bytes": 0,
            "packets": 0,
        }


def _get_local_subnets() -> list[str]:
    """
    EN: Build the list of local IPv4 subnets (CIDR) from interface addresses
        and netmasks. Skips loopback and absurdly large/small networks.
    FR: Construire la liste des sous-réseaux IPv4 locaux (CIDR) à partir des
        adresses d'interfaces et masques. Ignore le loopback et les réseaux
        absurdement grands/petits.
    """
    subnets = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue
            ip = addr.address
            netmask = addr.netmask
            if not netmask or ip.startswith("127."):
                continue
            try:
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                if network.num_addresses <= 2 or network.num_addresses > 65536:
                    continue
                subnets.append(str(network))
            except ValueError:
                continue
    return subnets


def _resolve_hostname(ip: str) -> Optional[str]:
    """EN: Reverse-DNS a LAN IP; None on failure. / FR: DNS inverse d'une IP LAN ; None en cas d'échec."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def _scan_subnet(subnet: str, timeout: int = 2) -> list[Device]:
    """
    EN: Send one broadcast ARP request per subnet and collect answers.
        This host's own IPs are filtered out — the graph already has a
        dedicated "local" node.
    FR: Envoyer une requête ARP broadcast par sous-réseau et collecter les
        réponses. Les IP de cette machine sont filtrées — le graphe possède
        déjà un nœud « local » dédié.
    """
    if not SCAPY_AVAILABLE:
        return []
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            timeout=timeout,
            verbose=False,
            retry=1,
        )
    except Exception:
        return []

    devices = []
    local_ips = {
        addr.address
        for addrs in psutil.net_if_addrs().values()
        for addr in addrs
        if addr.family == socket.AF_INET
    }

    for sent, received in ans:
        ip = received.psrc
        mac = received.hwsrc

        if ip in local_ips:
            continue

        vendor, device_type = lookup(mac)
        hostname = _resolve_hostname(ip)

        devices.append(Device(
            ip=ip,
            mac=mac,
            vendor=vendor,
            device_type=device_type,
            hostname=hostname,
            online=True,
            color=DEVICE_TYPE_COLORS.get(device_type, "#64748b"),
        ))

    return devices


class ARPScanner:
    """
    EN: Background scanner — scans all local subnets every `interval` seconds
        and invokes `callback(device, is_new)` for each responder, plus once
        more with online=False when a known device disappears.
    FR: Scanner d'arrière-plan — scanne tous les sous-réseaux locaux toutes les
        `interval` secondes et appelle `callback(device, is_new)` pour chaque
        répondant, plus une fois avec online=False quand un appareil connu
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
        EN: Scan loop. `seen_ips` tracks responders this round; known devices
            absent from it are flipped to offline.
        FR: Boucle de scan. `seen_ips` suit les répondants du tour ; les
            appareils connus absents passent hors ligne.
        """
        while self._running:
            subnets = _get_local_subnets()
            seen_ips: set[str] = set()

            for subnet in subnets:
                for device in _scan_subnet(subnet):
                    seen_ips.add(device.ip)
                    is_new = device.ip not in self._known
                    self._known[device.ip] = device
                    self.callback(device, is_new)

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
