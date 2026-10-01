"""
Snitch — packet sniffer.

EN: Wraps Scapy's AsyncSniffer to capture IPv4 AND IPv6 packets on the host,
    determine their direction (in/out), and attribute them to a local process.
    Process attribution used to call `psutil.net_connections()` per packet —
    thousands of syscall-heavy scans per second on busy links. It now reads
    from a `ConnectionTable`: a snapshot refreshed every ~1.5 s by a dedicated
    thread, making per-packet lookup a dict hit.

FR: Enveloppe l'AsyncSniffer de Scapy pour capturer les paquets IPv4 ET IPv6 de
    l'hôte, déterminer leur direction (entrant/sortant) et les attribuer à un
    processus local. L'attribution appelait avant `psutil.net_connections()`
    par paquet — des milliers de scans coûteux par seconde sur un lien actif.
    Elle lit désormais une `ConnectionTable` : un instantané rafraîchi toutes
    les ~1,5 s par un thread dédié, ramenant la recherche par paquet à un accès
    dict.
"""

import logging
import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

try:
    from scapy.all import IP, IPv6, TCP, UDP, AsyncSniffer
    SCAPY_AVAILABLE = True
except ImportError:
    # EN: Scapy (or libpcap/Npcap) missing — capture disabled, API still runs.
    # FR: Scapy (ou libpcap/Npcap) absent — capture désactivée, l'API tourne quand même.
    SCAPY_AVAILABLE = False

import psutil

logger = logging.getLogger("snitch.capture.sniffer")


@dataclass
class Packet:
    """
    EN: Normalized representation of one captured packet — everything the
        rest of the pipeline needs and nothing more.
    FR: Représentation normalisée d'un paquet capturé — tout ce dont le reste
        du pipeline a besoin, et rien de plus.
    """
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    size: int
    timestamp: str
    direction: str  # "out" | "in"  (sortant | entrant)
    pid: Optional[int] = None
    process_name: Optional[str] = None


def get_local_ips() -> set[str]:
    """
    EN: Collect every IPv4 and IPv6 address bound to a local interface.
        IPv6 entries may carry a scope suffix ("fe80::1%eth0") — stripped.
    FR: Collecter toutes les adresses IPv4 et IPv6 des interfaces locales.
        Les IPv6 peuvent porter un suffixe de scope (« fe80::1%eth0 ») — retiré.
    """
    ips = set()
    for iface_addrs in psutil.net_if_addrs().values():
        for addr in iface_addrs:
            if addr.family in (socket.AF_INET, socket.AF_INET6):
                ips.add(addr.address.split("%")[0])
    return ips


class ConnectionTable:
    """
    EN: Periodic snapshot of the OS connection table:
            { "tcp": {local_port: (pid, name)}, "udp": {...} }
        `psutil.net_connections()` is expensive (it walks every socket of
        every process), so we refresh once per `interval` in a background
        thread and let the hot path do plain dict lookups.
    FR: Instantané périodique de la table de connexions de l'OS :
            { "tcp": {port_local: (pid, nom)}, "udp": {...} }
        `psutil.net_connections()` est coûteux (il parcourt chaque socket de
        chaque processus) : on rafraîchit une fois par `interval` dans un
        thread d'arrière-plan et le chemin chaud fait de simples accès dict.
    """

    def __init__(self, interval: float = 1.5):
        self.interval = interval
        self._map = {"tcp": {}, "udp": {}}
        self._lock = threading.Lock()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    def _refresh(self) -> None:
        """EN: Rebuild the whole snapshot. / FR: Reconstruire tout l'instantané."""
        new_map = {"tcp": {}, "udp": {}}
        for kind in ("tcp", "udp"):
            try:
                for conn in psutil.net_connections(kind=kind):
                    if conn.laddr and conn.pid:
                        name = None
                        try:
                            name = psutil.Process(conn.pid).name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                        new_map[kind][conn.laddr.port] = (conn.pid, name)
            except Exception as exc:
                logger.debug("net_connections(%s) failed: %s", kind, exc)
        with self._lock:
            self._map = new_map

    def _run(self) -> None:
        """EN: Refresh loop — runs in a daemon thread. / FR: Boucle de rafraîchissement — thread daemon."""
        while self._running:
            self._refresh()
            time.sleep(self.interval)

    def start(self) -> None:
        """EN: Prime the table synchronously, then start the refresh thread.
        FR: Remplir la table en synchrone, puis lancer le thread de rafraîchissement."""
        self._refresh()
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def lookup(self, port: int, proto: str) -> tuple[Optional[int], Optional[str]]:
        """
        EN: Hot-path lookup — O(1), no syscalls. A miss means the socket
            appeared/disappeared between refreshes; returned as (None, None).
        FR: Recherche du chemin chaud — O(1), sans appel système. Un échec
            signifie que le socket est apparu/disparu entre deux
            rafraîchissements ; renvoyé comme (None, None).
        """
        kind = "tcp" if proto == "TCP" else "udp"
        with self._lock:
            return self._map[kind].get(port, (None, None))


class PacketSniffer:
    """
    EN: Scapy-based capture with an optional BPF port filter. The user
        callback fires once per relevant packet — from the sniffer thread,
        not the event loop.
    FR: Capture basée sur Scapy avec filtre de ports BPF optionnel. Le callback
        utilisateur est appelé une fois par paquet pertinent — depuis le thread
        du sniffer, pas depuis la boucle asyncio.
    """

    def __init__(self, callback: Callable[[Packet], None], ports: list[int] | None = None):
        self.callback = callback
        self.ports = ports or []
        self.local_ips = get_local_ips()
        self._sniffer: Optional[AsyncSniffer] = None
        self._conn_table = ConnectionTable()
        self._running = False

    @property
    def _bpf_filter(self) -> str:
        """
        EN: Berkeley Packet Filter expression — kernel-side filtering is far
            cheaper than Python-side. Covers IPv4 AND IPv6.
        FR: Expression BPF — le filtrage côté noyau coûte bien moins cher que
            côté Python. Couvre IPv4 ET IPv6.
        """
        if not self.ports:
            return "ip or ip6"
        port_expr = " or ".join(f"port {p}" for p in self.ports)
        return f"(ip or ip6) and ({port_expr})"

    def _process_packet(self, pkt) -> None:
        """
        EN: Convert a raw Scapy packet into our normalized Packet. Drops
            non-IP traffic and packets that do not involve this host.
            IPv6 is handled transparently: TCP/UDP layers sit above either
            network layer.
        FR: Convertir un paquet Scapy brut en Packet normalisée. Ignore le
            trafic non-IP et les paquets qui ne concernent pas cet hôte.
            IPv6 est géré de façon transparente : les couches TCP/UDP se
            placent au-dessus de l'une ou l'autre couche réseau.
        """
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
        elif SCAPY_AVAILABLE and pkt.haslayer(IPv6):
            ip_layer = pkt[IPv6]
        else:
            return

        src = ip_layer.src.split("%")[0]
        dst = ip_layer.dst.split("%")[0]

        # EN: Only care about traffic from/to this machine.
        # FR: On ne garde que le trafic de/vers cette machine.
        if src not in self.local_ips and dst not in self.local_ips:
            return

        proto = "OTHER"
        src_port = dst_port = None

        if pkt.haslayer(TCP):
            proto = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        direction = "out" if src in self.local_ips else "in"
        local_port = src_port if direction == "out" else dst_port

        # EN: Process attribution via the cached connection table.
        # FR: Attribution du processus via la table de connexions en cache.
        pid, process_name = None, None
        if local_port and proto in ("TCP", "UDP"):
            pid, process_name = self._conn_table.lookup(local_port, proto)

        packet = Packet(
            src_ip=src,
            dst_ip=dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            size=len(pkt),
            timestamp=datetime.now(timezone.utc).isoformat(),
            direction=direction,
            pid=pid,
            process_name=process_name,
        )
        self.callback(packet)

    def start(self) -> None:
        """
        EN: Blocking call — run inside a daemon thread. Starts the connection
            table first, then the AsyncSniffer, then idles while it works.
        FR: Appel bloquant — à lancer dans un thread daemon. Démarre d'abord la
            table de connexions, puis l'AsyncSniffer, puis se met en attente.
        """
        if not SCAPY_AVAILABLE:
            logger.warning("scapy not available — packet capture disabled")
            return
        self._running = True
        try:
            self._conn_table.start()
            self._sniffer = AsyncSniffer(
                filter=self._bpf_filter,
                prn=self._process_packet,
                store=False,   # EN: never keep packets in memory / FR: ne jamais garder les paquets en mémoire
            )
            self._sniffer.start()
            while self._running:
                time.sleep(1)
        except Exception as exc:
            logger.error("sniffer failed to start: %s", exc)

    def stop(self) -> None:
        """EN: Stop capture + the connection-table thread. / FR: Arrêter la capture + le thread de la table."""
        self._running = False
        self._conn_table.stop()
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception as exc:
                logger.debug("sniffer stop failed: %s", exc)
