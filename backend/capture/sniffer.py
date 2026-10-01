"""
Snitch — packet sniffer.

EN: Wraps Scapy's AsyncSniffer to capture IP packets on the host, determine
    their direction (in/out), and attribute them to a local process by
    matching the local port against psutil's connection table.

FR: Enveloppe l'AsyncSniffer de Scapy pour capturer les paquets IP de l'hôte,
    déterminer leur direction (entrant/sortant) et les attribuer à un
    processus local en comparant le port local à la table de connexions
    de psutil.
"""

import asyncio
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, AsyncSniffer
    SCAPY_AVAILABLE = True
except ImportError:
    # EN: Scapy (or libpcap/Npcap) missing — capture disabled, API still runs.
    # FR: Scapy (ou libpcap/Npcap) absent — capture désactivée, l'API tourne quand même.
    SCAPY_AVAILABLE = False

import psutil


@dataclass
class Packet:
    """
    EN: Normalized representation of one captured packet, everything the
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
    EN: Collect every IPv4 address bound to a local interface — used to
        decide packet direction and to ignore host-to-host noise.
    FR: Collecter toutes les adresses IPv4 des interfaces locales — sert à
        déterminer la direction des paquets et ignorer le bruit inter-hôtes.
    """
    ips = set()
    for iface_addrs in psutil.net_if_addrs().values():
        for addr in iface_addrs:
            if addr.family == socket.AF_INET:
                ips.add(addr.address)
    return ips


def get_process_for_port(port: int, proto: str) -> tuple[Optional[int], Optional[str]]:
    """
    EN: Best-effort process attribution — find which local PID owns the local
        port of this connection, then resolve the process name.
        Note: this is inherently racy for short-lived UDP flows; misses are
        simply returned as (None, None).
    FR: Attribution de processus au mieux — trouver quel PID local possède le
        port local de la connexion, puis résoudre le nom du processus.
        Remarque : intrinsèquement sujet aux courses pour les flux UDP courts ;
        les échecs renvoient simplement (None, None).
    """
    kind = "tcp" if proto == "TCP" else "udp"
    try:
        for conn in psutil.net_connections(kind=kind):
            if conn.laddr and conn.laddr.port == port and conn.pid:
                try:
                    return conn.pid, psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    return conn.pid, None
    except Exception:
        pass
    return None, None


class PacketSniffer:
    """
    EN: Scapy-based packet capture with an optional BPF port filter.
        The user callback is invoked once per relevant packet — from the
        sniffer thread, not the event loop.
    FR: Capture de paquets basée sur Scapy avec filtre de ports BPF optionnel.
        Le callback utilisateur est appelé une fois par paquet pertinent —
        depuis le thread du sniffer, pas depuis la boucle asyncio.
    """

    def __init__(self, callback: Callable[[Packet], None], ports: list[int] | None = None):
        self.callback = callback
        self.ports = ports or []
        self.local_ips = get_local_ips()
        self._sniffer: Optional[AsyncSniffer] = None
        self._running = False

    @property
    def _bpf_filter(self) -> str:
        """
        EN: Build a Berkeley Packet Filter expression. Filtering in the kernel
            (Npcap/libpcap) is far cheaper than filtering in Python.
        FR: Construire une expression BPF. Filtrer dans le noyau
            (Npcap/libpcap) coûte bien moins cher que filtrer en Python.
        """
        if not self.ports:
            return "ip"
        port_expr = " or ".join(f"port {p}" for p in self.ports)
        return f"ip and ({port_expr})"

    def _process_packet(self, pkt) -> None:
        """
        EN: Convert a raw Scapy packet into our normalized Packet dataclass.
            Drops non-IP traffic and packets that do not involve this host.
        FR: Convertir un paquet Scapy brut en dataclass Packet normalisée.
            Ignore le trafic non-IP et les paquets qui ne concernent pas cet hôte.
        """
        if not pkt.haslayer(IP):
            return

        ip = pkt[IP]
        src, dst = ip.src, ip.dst

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

        # EN: Try to attribute the flow to a local process.
        # FR: Tenter d'attribuer le flux à un processus local.
        pid, process_name = None, None
        if local_port and proto in ("TCP", "UDP"):
            pid, process_name = get_process_for_port(local_port, proto)

        packet = Packet(
            src_ip=src,
            dst_ip=dst,
            src_port=src_port,
            dst_port=dst_port,
            protocol=proto,
            size=len(pkt),
            timestamp=datetime.utcnow().isoformat(),
            direction=direction,
            pid=pid,
            process_name=process_name,
        )
        self.callback(packet)

    def start(self) -> None:
        """
        EN: Blocking call — run this inside a daemon thread. Keeps itself
            alive so the thread does not exit while AsyncSniffer works.
        FR: Appel bloquant — à lancer dans un thread daemon. Se maintient en
            vie pour que le thread ne se termine pas pendant que l'AsyncSniffer
            travaille.
        """
        if not SCAPY_AVAILABLE:
            print("[sniffer] scapy not available — packet capture disabled", flush=True)
            return
        self._running = True
        try:
            self._sniffer = AsyncSniffer(
                filter=self._bpf_filter,
                prn=self._process_packet,
                store=False,   # EN: never keep packets in memory / FR: ne jamais garder les paquets en mémoire
            )
            self._sniffer.start()
            while self._running:
                time.sleep(1)
        except Exception as exc:
            print(f"[sniffer] failed to start: {exc}", flush=True)

    def stop(self) -> None:
        """EN: Stop capture. / FR: Arrêter la capture."""
        self._running = False
        if self._sniffer:
            self._sniffer.stop()
