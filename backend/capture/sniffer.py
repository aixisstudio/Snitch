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
from collections import deque
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


def _default_route_ip() -> Optional[str]:
    """
    EN: Local IP the OS would use for outbound traffic. A UDP connect() only
        asks the routing table — no packet is ever sent (zero outbound
        calls, as promised).
    FR: IP locale que l'OS utiliserait pour le trafic sortant. Un connect()
        UDP interroge seulement la table de routage — aucun paquet n'est
        envoyé (zéro appel sortant, comme promis).
    """
    for family, target in ((socket.AF_INET, "192.0.2.1"),
                           (socket.AF_INET6, "2001:db8::1")):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.connect((target, 9))
                return s.getsockname()[0].split("%")[0]
        except OSError:
            continue
    return None


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
    # EN: ≤64B of cleartext payload for in-process protocol fingerprinting
    #     (stratum miner detection). Internal only — never broadcast.
    # FR: ≤64 o. de payload en clair pour la signature de protocole en
    #     interne (détection mineur stratum). Interne — jamais diffusé.
    app_head: bytes = b""
    # EN: Leaf TLS cert metadata (passive handshake watch) — internal use:
    #     anomaly checks, never persisted raw. None when not observed.
    # FR: Métadonnées du cert feuille TLS (veille passive) — usage interne
    #     (contrôles d'anomalies), jamais persistées. None sinon.
    tls_cert: Optional[dict] = None


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
        # EN: Optional kernel-level attribution probe (eBPF) — consulted when
        #     the socket table misses. Set via set_attribution_probe().
        # FR: Sonde d'attribution noyau optionnelle (eBPF) — consultée quand
        #     la table des sockets rate. Réglée via set_attribution_probe().
        self._attribution_probe = None
        self._running = False
        self._thread: Optional[threading.Thread] = None
        # EN: Forensic ring — the last ~4 MB of "for us" frames with wire
        #     timestamp + process attribution, kept for /forensics/pcap
        #     exports. Byte-accounted: evict oldest until under budget.
        # FR: Anneau forensique — les ~4 derniers Mo de trames « pour nous »
        #     avec timestamp fil + attribution processus, gardés pour les
        #     exports /forensics/pcap. Compté en octets : éviction des plus
        #     anciennes.
        self._ring: deque[tuple] = deque()
        self._ring_bytes = 0
        self._ring_lock = threading.Lock()
        # EN: Drop accounting — every discarded frame is counted with its
        #     reason and surfaced in /diagnostics. Security rule: no silent
        #     skips — an unparsed frame could be the one that mattered.
        # FR: Comptabilité des rejets — chaque trame écartée est comptée avec
        #     sa raison et exposée dans /diagnostics. Règle de sécurité :
        #     zéro rejet silencieux — une trame non lue pourrait être celle
        #     qui comptait.
        self.stats = {"frames": 0, "delivered": 0, "parse_failed": 0,
                      "not_for_us": 0}
        # EN: Fatal capture failure surfaced to the API/UI — pcap_open_live
        #     dying (no privileges, missing Npcap) used to fail silently in
        #     this thread while the ARP scan kept feeding the device list:
        #     "devices but no traffic" with zero explanation. `on_error` is
        #     called from the capture thread, like `callback`.
        # FR: Échec fatal de capture remonté à l'API/UI — un pcap_open_live
        #     mourant (droits manquants, Npcap absent) échouait silencieusement
        #     dans ce thread pendant que le scan ARP remplissait la liste
        #     d'appareils : « appareils mais pas de trafic » sans explication.
        #     `on_error` est appelé depuis le thread de capture, comme
        #     `callback`.
        self.last_error: Optional[str] = None
        self.on_error: Optional[Callable[[str], None]] = None

    def _fail(self, msg: str) -> None:
        """EN: Record a fatal capture failure and notify the API layer.
        FR: Enregistrer un échec fatal de capture et notifier la couche API."""
        self.last_error = msg
        logger.error("capture failed: %s", msg)
        if self.on_error:
            try:
                self.on_error(msg)
            except Exception:                      # noqa: BLE001
                logger.debug("capture error callback failed", exc_info=True)

    @property
    def running(self) -> bool:
        """EN: True while the capture thread is actually alive — the honest
            answer to "are we capturing", unlike the intent flag.
        FR: Vrai tant que le thread de capture est réellement vivant — la
            réponse honnête à « est-ce qu'on capture », contrairement au
            drapeau d'intention."""
        return (self._running and self._thread is not None
                and self._thread.is_alive())

    def set_attribution_probe(self, probe) -> None:
        """EN: Register an object exposing lookup(ip, port) → (pid, name)
        used as fallback when the connection table misses.
        FR: Enregistre un objet exposant lookup(ip, port) → (pid, nom)
        utilisé en repli quand la table des connexions rate."""
        self._attribution_probe = probe

    @staticmethod
    def _default_iface() -> Optional[str]:
        """
        EN: The interface that actually carries OUR traffic — the one owning
            a non-loopback local IP (macOS's "ap1" AWDL device is listed
            before the real Wi-Fi "en1": picking blindly by order captured
            AirDrop chatter and missed every real packet — frames: 0).
            Order: device owning the default-route source IP → device owning
            a local IP → first non-loopback. The default-route step matters
            on Windows, where WSL/Hyper-V virtual adapters are listed first
            and also own private IPs.
        FR: L'interface qui porte réellement NOTRE trafic — celle qui
            possède une IP locale non-loopback (« ap1 » AWDL de macOS est
            listée avant le vrai Wi-Fi « en1 » : choisir à l'aveugle
            capturait le bavardage AirDrop et ratait chaque vrai paquet —
            frames : 0). Ordre : périphérique possédant une IP locale →
            interface de la route par défaut → premier non-loopback. L'étape
            route par défaut compte sous Windows, où les cartes virtuelles
            WSL/Hyper-V sont listées en premier et possèdent aussi des IP
            privées.
        """
        try:
            devs = list_devices()
            names = {d.name for d in devs}
            # EN: Match on libpcap's own addresses first (works on Windows,
            #     where Npcap names differ from psutil's friendly names).
            # FR: Correspondance d'abord sur les adresses de libpcap (marche
            #     sous Windows, où les noms Npcap diffèrent de ceux de psutil).
            route_ip = _default_route_ip()
            if route_ip:
                for d in devs:
                    if route_ip in d.addresses:
                        return d.name
            # EN: iface → its IPv4/IPv6 addresses via psutil (same source as
            #     self.local_ips, so the match is consistent).
            # FR: interface → ses adresses IPv4/IPv6 via psutil (même source
            #     que self.local_ips, donc la correspondance est cohérente).
            import ipaddress as _ipa
            try:
                for iface, addrs in psutil.net_if_addrs().items():
                    if iface not in names:
                        continue
                    for a in addrs:
                        if a.family in (socket.AF_INET, socket.AF_INET6):
                            ip = _ipa.ip_address(a.address.split("%")[0])
                            if not (ip.is_loopback or ip.is_link_local
                                    or ip.is_multicast):
                                return iface
            except Exception as exc:
                logger.debug("net_if_addrs failed: %s", exc)
            for d in devs:
                if not d.loopback:
                    return d.name
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

    _RING_BUDGET = 4 * 1024 * 1024   # EN: forensic ring cap / FR: plafond de l'anneau

    def _handle_frame(self, buf: bytes, wire_len: int, ts: float) -> None:
        """
        EN: Decode + normalize one frame. Drops non-IP traffic and packets
            that do not involve this host.
        FR: Décoder + normaliser une trame. Ignore le trafic non-IP et les
            paquets qui ne concernent pas cet hôte.
        """
        assert self._session is not None
        self.stats["frames"] += 1
        parsed = parse_frame(self._session.linktype, buf)
        if parsed is None:
            self.stats["parse_failed"] += 1
            # EN: Warn at the 1st failure then each power of 10 — the count
            #     matters (format drift, corruption), not each individual line.
            # FR: Avertir à la 1re erreur puis à chaque puissance de 10 — c'est
            #     le compte qui importe (dérive de format, corruption), pas
            #     chaque ligne isolée.
            n = self.stats["parse_failed"]
            if n == 1 or n % 1000 == 0:
                logger.warning("unparseable frame #%d (%d bytes, linktype=%d)",
                               n, len(buf), self._session.linktype)
            return

        src, dst = parsed.src_ip, parsed.dst_ip
        if src not in self.local_ips and dst not in self.local_ips:
            self.stats["not_for_us"] += 1
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
        # EN: eBPF fallback — the socket table misses processes that died
        #     between refreshes (short-lived connects); the kprobe ring saw
        #     every connect() call. Only unambiguous events are used.
        # FR: Repli eBPF — la table des sockets rate les processus morts
        #     entre deux rafraîchissements ; l'anneau kprobe a vu chaque
        #     connect(). Seuls les événements non ambigus servent.
        if pid is None and direction == "out" and parsed.protocol == "TCP" \
                and self._attribution_probe is not None:
            pid, process_name = self._attribution_probe.lookup(
                dst, parsed.dst_port)

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
            app_head=parsed.app_head,
            tls_cert=parsed.tls_cert,
        ))
        # EN: Forensic ring entry — raw frame + wire ts + attribution, so
        #     /forensics/pcap can export exactly what was on the wire.
        # FR: Entrée d'anneau forensique — trame brute + ts fil +
        #     attribution, pour que /forensics/pcap exporte exactement ce
        #     qui était sur le fil.
        remote = dst if direction == "out" else src
        with self._ring_lock:
            self._ring.append((ts, buf, wire_len, remote, pid, process_name))
            self._ring_bytes += len(buf)
            while self._ring_bytes > self._RING_BUDGET and self._ring:
                old = self._ring.popleft()
                self._ring_bytes -= len(old[1])
        self.stats["delivered"] += 1

    def pcap_frames(self, remote_ip: str | None = None,
                    process: str | None = None,
                    seconds: float | None = None) -> tuple[int, list]:
        """
        EN: Drain a filtered copy of the forensic ring for pcap export —
            returns (linktype, [(ts, buf, wire_len)]). Filters by remote
            IP, attributed process name (case-insensitive substring) and
            age in seconds. Read-only: the ring keeps rolling.
        FR: Extraire une copie filtrée de l'anneau pour l'export pcap —
            renvoie (linktype, [(ts, buf, wire_len)]). Filtres : IP
            distante, nom de processus attribué (sous-chaîne insensible à
            la casse), âge en secondes. Lecture seule : l'anneau continue.
        """
        linktype = self._session.linktype if self._session else 1
        cutoff = (time.time() - seconds) if seconds else 0.0
        proc = process.lower() if process else None
        out: list[tuple] = []
        with self._ring_lock:
            for ts, buf, wire_len, remote, _pid, pname in self._ring:
                if ts < cutoff:
                    continue
                if remote_ip and remote != remote_ip:
                    continue
                if proc and proc not in (pname or "").lower():
                    continue
                out.append((ts, buf, wire_len))
        return linktype, out

    def start(self) -> None:
        """EN: Launch the capture thread. / FR: Lancer le thread de capture."""
        if not PCAP_AVAILABLE:
            self._fail("libpcap unavailable — install Npcap (Windows) or "
                       "libpcap (Linux); on macOS it is built in")
            return
        if not self.iface:
            self._fail("no capture interface found — packet capture disabled")
            return
        self.last_error = None
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
            # EN: Refresh the local-IP set periodically — a VPN toggle or a
            #     DHCP renewal changes our addresses, and a frozen set would
            #     silently classify all new traffic as "not_for_us".
            # FR: Rafraîchir périodiquement les IP locales — une bascule VPN
            #     ou un renouvellement DHCP change nos adresses, et un
            #     ensemble figé classerait tout le nouveau trafic en
            #     « not_for_us ».
            last_ip_refresh = time.monotonic()
            while self._running:
                try:
                    pkt = self._session.next_packet()
                except PcapError as exc:
                    # EN: A pcap error racing a user stop() is benign — only
                    #     report failures while capture is meant to run.
                    # FR: Une erreur pcap concurrente d'un stop() utilisateur
                    #     est bénigne — ne remonter que les échecs survenant
                    #     pendant que la capture doit tourner.
                    if self._running:
                        self._fail(f"capture error: {exc}")
                    break
                if time.monotonic() - last_ip_refresh > 30:
                    self.local_ips = get_local_ips()
                    last_ip_refresh = time.monotonic()
                if pkt is not None:
                    self._handle_frame(*pkt)
        except PcapError as exc:
            self._fail(f"sniffer failed to start: {exc}")
        except Exception as exc:                    # noqa: BLE001
            self._fail(f"sniffer crashed: {exc}")
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
