"""
Snitch — packet sniffer (libpcap edition).

EN: Captures IPv4 AND IPv6 frames through a ctypes libpcap binding
    (capture/pcap.py) and decodes them with our own parser
    (capture/parser.py) — Scapy is gone, along with its GPL-2.0-only license.

    Per packet we keep: addresses, transport ports, the REMOTE port (the fix
    for the inbound-classification bug — dst_port is a local port on inbound
    traffic), TCP flags, DNS answers and TLS SNI.

    Process attribution reads from `ConnectionTable`: a psutil snapshot of
    the OS connection table refreshed every ~1.5 s by a dedicated thread —
    per-packet lookup is a dict hit, not a syscall storm.

FR: Capture les trames IPv4 ET IPv6 via une liaison ctypes à libpcap
    (capture/pcap.py) et les décode avec notre propre parseur
    (capture/parser.py) — Scapy est parti, avec sa licence GPL-2.0-only.

    Par paquet on conserve : adresses, ports de transport, le port DISTANT
    (correction du bug de classification entrant — dst_port est un port local
    en trafic entrant), les flags TCP, les réponses DNS et le SNI TLS.

    L'attribution de processus lit `ConnectionTable` : un instantané psutil de
    la table de connexions OS rafraîchi toutes les ~1,5 s par un thread dédié —
    la recherche par paquet est un accès dict, pas une tempête d'appels système.
"""

import logging
import os
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

import psutil

from capture.pcap import PcapError, PcapSession, is_available, list_devices
from capture.parser import parse_frame

logger = logging.getLogger("snitch.capture.sniffer")

# EN: libpcap presence check — capture disabled but the API still runs.
# FR: Vérification de présence de libpcap — capture désactivée mais l'API tourne.
PCAP_AVAILABLE = is_available()


@dataclass
class Packet:
    """
    EN: Normalized representation of one captured packet.
        `remote_port` is the port on the OTHER end — always the meaningful
        one for classification, regardless of direction.
        `dns` carries DNS answer tuples (name, ip, ttl) observed in the packet.
        `sni` is the TLS ClientHello hostname when seen.
    FR: Représentation normalisée d'un paquet capturé.
        `remote_port` est le port de l'AUTRE extrémité — toujours le port
        pertinent pour la classification, quel que soit le sens.
        `dns` transporte les tuples de réponse DNS (nom, ip, ttl) observés.
        `sni` est le nom d'hôte du ClientHello TLS quand vu.
    """
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    remote_port: Optional[int]
    protocol: str
    size: int
    timestamp: str
    direction: str                       # "out" | "in"
    pid: Optional[int] = None
    process_name: Optional[str] = None
    tcp_flags: int = 0
    sni: Optional[str] = None
    dns: list = field(default_factory=list)
    # EN: (hostname, requested_ip|None, mac) learned from a client DHCP
    #     message — names the device before mDNS/LLMNR ever do.
    # FR: (nom d'hôte, ip demandée|None, mac) appris d'un message DHCP
    #     client — nomme l'appareil avant même mDNS/LLMNR.
    dhcp: Optional[tuple] = None


def get_local_ips() -> set[str]:
    """
    EN: Every IPv4 and IPv6 address bound to a local interface. IPv6 scope
        suffixes ("fe80::1%eth0") are stripped.
    FR: Toutes les adresses IPv4 et IPv6 des interfaces locales. Les suffixes
        de scope IPv6 (« fe80::1%eth0 ») sont retirés.
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
        `psutil.net_connections()` walks every socket of every process — far
        too expensive per packet. Refreshed once per `interval` in a daemon
        thread; the hot path does plain dict lookups.
    FR: Instantané périodique de la table de connexions de l'OS :
            { "tcp": {port_local: (pid, nom)}, "udp": {...} }
        `psutil.net_connections()` parcourt chaque socket de chaque processus —
        bien trop coûteux par paquet. Rafraîchi une fois par `interval` dans un
        thread daemon ; le chemin chaud fait de simples accès dict.
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
    EN: libpcap-backed capture with an optional BPF port filter and an
        interface selector (SNITCH_IFACE env or constructor arg; default =
        first non-loopback device). The user callback fires once per packet
        from the capture thread.
    FR: Capture adossée à libpcap avec filtre de ports BPF optionnel et
        sélecteur d'interface (env SNITCH_IFACE ou argument ; défaut = premier
        périphérique non-loopback). Le callback utilisateur est appelé une fois
        par paquet depuis le thread de capture.
    """

    def __init__(self, callback: Callable[[Packet], None],
                 ports: list[int] | None = None, iface: str | None = None):
        self.callback = callback
        self.ports = ports or []
        self.iface = iface or os.environ.get("SNITCH_IFACE") or self._default_iface()
        self.local_ips = get_local_ips()
        self._session: Optional[PcapSession] = None
        self._conn_table = ConnectionTable()
        self._running = False
        self._thread: Optional[threading.Thread] = None

    @staticmethod
    def _default_iface() -> Optional[str]:
        """EN: First non-loopback capture device. / FR: Premier périphérique de capture non-loopback."""
        try:
            for d in list_devices():
                if not d.loopback:
                    return d.name
            devs = list_devices()
            return devs[0].name if devs else None
        except PcapError as exc:
            logger.warning("cannot list capture devices: %s", exc)
            return None

    @property
    def _bpf_filter(self) -> str:
        """
        EN: Berkeley Packet Filter — kernel-side filtering beats Python-side.
            Covers IPv4 AND IPv6.
        FR: Filtre BPF — le filtrage côté noyau bat le filtrage Python.
            Couvre IPv4 ET IPv6.
        """
        if not self.ports:
            return "ip or ip6"
        port_expr = " or ".join(f"port {p}" for p in self.ports)
        return f"(ip or ip6) and ({port_expr})"

    def _handle_frame(self, buf: bytes, wire_len: int) -> None:
        """
        EN: Decode + normalize one frame. Drops non-IP traffic and packets
            that do not involve this host.
        FR: Décoder + normaliser une trame. Ignore le trafic non-IP et les
            paquets qui ne concernent pas cet hôte.
        """
        assert self._session is not None
        parsed = parse_frame(self._session.linktype, buf)
        if parsed is None:
            return

        src, dst = parsed.src_ip, parsed.dst_ip
        if src not in self.local_ips and dst not in self.local_ips:
            return

        direction = "out" if src in self.local_ips else "in"
        local_port = parsed.src_port if direction == "out" else parsed.dst_port
        # EN: The remote port is the one that matters for classification —
        #     for inbound traffic dst_port is OUR port, not theirs.
        # FR: Le port distant est celui qui compte pour la classification —
        #     en trafic entrant, dst_port est NOTRE port, pas le leur.
        remote_port = parsed.dst_port if direction == "out" else parsed.src_port

        pid, process_name = None, None
        if local_port and parsed.protocol in ("TCP", "UDP"):
            pid, process_name = self._conn_table.lookup(local_port, parsed.protocol)

        self.callback(Packet(
            src_ip=src,
            dst_ip=dst,
            src_port=parsed.src_port,
            dst_port=parsed.dst_port,
            remote_port=remote_port,
            protocol=parsed.protocol,
            size=parsed.size or wire_len,
            timestamp=datetime.now(timezone.utc).isoformat(),
            direction=direction,
            pid=pid,
            process_name=process_name,
            tcp_flags=parsed.tcp_flags,
            sni=parsed.sni,
            dns=parsed.dns,
            dhcp=parsed.dhcp,
        ))

    def start(self) -> None:
        """EN: Launch the capture thread. / FR: Lancer le thread de capture."""
        if not PCAP_AVAILABLE:
            logger.warning("libpcap unavailable — packet capture disabled")
            return
        if not self.iface:
            logger.warning("no capture interface found — packet capture disabled")
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        """EN: Capture loop — blocks ≤100 ms per poll so stop() stays snappy.
        FR: Boucle de capture — bloque ≤100 ms par sondage pour que stop()
            reste réactif."""
        try:
            self._conn_table.start()
            self._session = PcapSession(self.iface, timeout_ms=100,
                                        bpf_filter=self._bpf_filter)
            logger.info("capture on %s (linktype=%d, filter=%r)",
                        self.iface, self._session.linktype, self._bpf_filter)
            while self._running:
                try:
                    pkt = self._session.next_packet()
                except PcapError as exc:
                    logger.error("capture error: %s", exc)
                    break
                if pkt is not None:
                    self._handle_frame(*pkt)
        except PcapError as exc:
            logger.error("sniffer failed to start: %s", exc)
        finally:
            if self._session:
                self._session.close()

    def stop(self) -> None:
        """EN: Stop capture + the connection-table thread.
        FR: Arrêter la capture + le thread de la table de connexions."""
        self._running = False
        self._conn_table.stop()
        if self._thread:
            self._thread.join(timeout=2)
