# EN: Demo mode — feeds synthetic packets into the normal pipeline so the UI
#     can be explored (and screenshotted) without root/libpcap and without
#     ever touching real traffic. Enable with SNITCH_DEMO=1.
#     Everything is fake: public IPs are well-known ranges so the bundled
#     DB-IP Lite GeoIP resolves real countries, LAN devices get mDNS names,
#     and a beaconing pattern demonstrates the anomaly alerts.
# FR: Mode démo — injecte des paquets synthétiques dans le pipeline normal
#     pour explorer (et capturer) l'interface sans root/libpcap et sans
#     toucher au trafic réel. Activer avec SNITCH_DEMO=1.
#     Tout est fictif : les IP publiques sont des plages connues pour que le
#     GeoIP DB-IP Lite embarqué résolve de vrais pays, les appareils LAN
#     reçoivent des noms mDNS, et un pattern de balisage démontre les
#     alertes d'anomalies.

import os
import random
import threading
import time
from datetime import datetime, timezone

from capture.sniffer import Packet

# EN: Well-known public IPs so offline GeoIP produces a varied map:
#     Google/Cloudflare (US), OVH (FR), Amazon AWS (IE), Apple (US), etc.
# FR: IP publiques connues pour que le GeoIP hors ligne produise une carte
#     variée : Google/Cloudflare (US), OVH (FR), AWS (IE), Apple (US), etc.
EXTERNAL_HOSTS = [
    # (ip, port, sni, process)
    ("142.250.179.142", 443, "www.google.com", "Google Chrome"),
    ("142.251.36.14", 443, "mail.google.com", "Google Chrome"),
    ("104.16.249.249", 443, "cloudflare.com", "Google Chrome"),
    ("151.101.65.140", 443, "www.reddit.com", "Safari"),
    ("157.240.239.35", 443, "www.facebook.com", "Google Chrome"),
    ("20.190.160.17", 443, "login.microsoftonline.com", "Microsoft Edge"),
    ("17.253.144.10", 443, "apple.com", "Safari"),
    ("3.163.189.90", 443, "d3ag4hukkh62yn.cloudfront.net", "Docker"),
    ("146.75.118.217", 443, "api.github.com", "node"),
    ("52.94.234.117", 443, "s3.amazonaws.com", "aws"),
    ("188.114.96.7", 443, "discord.com", "Discord"),
    ("149.154.167.99", 443, "core.telegram.org", "Telegram"),
    ("87.98.154.146", 443, "www.ovhcloud.com", "Safari"),
    ("162.159.130.234", 443, "signal.org", "Signal"),
]

# EN: Fake LAN neighbours — mDNS name claims make the perimeter readable.
# FR: Faux voisins LAN — les revendications de nom mDNS rendent le périmètre lisible.
LAN_DEVICES = [
    ("192.168.1.1", "router.local"),
    ("192.168.1.42", "iPhone-MoneyLisa.local"),
    ("192.168.1.33", "HomePod-Cuisine.local"),
    ("192.168.1.57", "MacBook-Air.local"),
    ("192.168.1.88", "TV-Salon.local"),
]

LOCAL_IP = "192.168.1.20"


def _pkt(direction, remote_ip, remote_port, size, process=None,
         sni=None, protocol="TCP", dns=None):
    """EN: Build one normalized Packet exactly as the parser would emit it.
    FR: Construit un Packet normalisé comme le parser l'émettrait."""
    return Packet(
        src_ip=LOCAL_IP if direction == "out" else remote_ip,
        dst_ip=remote_ip if direction == "out" else LOCAL_IP,
        src_port=random.randint(49152, 65535) if direction == "out" else remote_port,
        dst_port=remote_port if direction == "out" else random.randint(49152, 65535),
        remote_port=remote_port,
        protocol=protocol,
        size=size,
        timestamp=datetime.now(timezone.utc).isoformat(),
        direction=direction,
        process_name=process,
        sni=sni,
        dns=dns or [],
    )


class DemoFeeder(threading.Thread):
    """
    EN: Daemon thread that emits believable traffic bursts to the packet
        callback. Stops with the process (daemon), ~10-40 pkt/s — enough to
        animate the graph, bandwidth sparkline and alerts.
    FR: Thread daemon qui émet des rafales de trafic crédibles vers le
        callback paquets. S'arrête avec le processus (daemon),
        ~10-40 pkt/s — assez pour animer graphe, sparkline et alertes.
    """

    def __init__(self, callback):
        super().__init__(daemon=True)
        self._cb = callback
        self._t0 = time.time()
        self._stopped = threading.Event()

    def stop(self):
        """EN: Same interface as PacketSniffer.stop() — ends the loop.
        FR: Même interface que PacketSniffer.stop() — termine la boucle."""
        self._stopped.set()

    def run(self):                          # noqa: D401 — long-lived loop
        self._announce_lan()
        beacon_ip = "185.220.101.4"         # EN: Tor-exit range → suspicious / FR: plage Tor → suspect
        while not self._stopped.is_set():
            # EN: 3-8 external packets per tick, mostly HTTPS.
            # FR: 3-8 paquets externes par tick, surtout du HTTPS.
            for _ in range(random.randint(3, 8)):
                ip, port, sni, proc = random.choice(EXTERNAL_HOSTS)
                direction = "out" if random.random() < 0.6 else "in"
                size = random.randint(60, 60000 if direction == "in" else 2500)
                self._cb(_pkt(direction, ip, port, size, proc, sni))

            # EN: Occasional DNS answers so hostnames learn organically.
            # FR: Réponses DNS occasionnelles pour l'apprentissage des noms.
            if random.random() < 0.3:
                ip, _, sni, _ = random.choice(EXTERNAL_HOSTS)
                self._cb(_pkt("in", "192.168.1.1", 53, 120,
                              protocol="UDP",
                              dns=[(sni, ip, 300)]))

            # EN: Chatter between LAN devices (perimeter demo).
            # FR: Bavardage entre appareils LAN (démo du périmètre).
            if random.random() < 0.5:
                ip, _ = random.choice(LAN_DEVICES[1:])
                self._cb(_pkt("out" if random.random() < 0.5 else "in",
                              ip, random.choice([443, 80, 548, 62078]),
                              random.randint(80, 8000)))

            # EN: Beaconing pattern — regular small packets to a suspicious
            #     host trigger the anomaly alerts after ~1 min.
            # FR: Balisage — petits paquets réguliers vers un hôte suspect,
            #     déclenche les alertes d'anomalies après ~1 min.
            if int(time.time() - self._t0) % 5 == 0:
                self._cb(_pkt("out", beacon_ip, 4444, 88, "curl"))

            # EN: Occasional tracker to show the Tracking filter.
            # FR: Tracker occasionnel pour montrer le filtre Tracking.
            if random.random() < 0.15:
                self._cb(_pkt("out", "142.251.46.174", 443,
                              random.randint(200, 3000), "Google Chrome",
                              "google-analytics.com"))

            time.sleep(random.uniform(0.15, 0.5))

    def _announce_lan(self):
        """EN: Seed the LAN with mDNS-style name claims (multicast dst, learned
               by the DNS pipeline without creating noise nodes).
        FR: Amorce le LAN avec des revendications de nom façon mDNS (destination
            multicast, apprises par le pipeline DNS sans créer de nœuds bruit)."""
        for ip, name in LAN_DEVICES:
            self._cb(_pkt("out", "224.0.0.251", 5353, 140,
                          protocol="UDP", dns=[(name, ip, 120)]))
            time.sleep(0.05)


def enabled() -> bool:
    """EN: SNITCH_DEMO=1 (truthy) → synthetic traffic instead of libpcap.
    FR: SNITCH_DEMO=1 (valeur vraie) → trafic synthétique au lieu de libpcap."""
    return os.environ.get("SNITCH_DEMO", "").lower() in ("1", "true", "yes")


def start(callback) -> DemoFeeder:
    """EN: Start the synthetic feeder — drop-in for PacketSniffer.
    FR: Démarre le générateur synthétique — remplaçant de PacketSniffer."""
    feeder = DemoFeeder(callback)
    feeder.start()
    return feeder
