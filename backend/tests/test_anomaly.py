"""
Snitch — anomaly detector tests.

EN: Covers per-packet rules: private-IP skip, NEW_HOST once-only, suspicious
    ports/processes, MEDIA_EXFIL (whitelisting), forget(), and the
    regularity-based beacon detection (regular intervals alert, bursty
    traffic doesn't).
FR: Couvre les règles par paquet : exclusion des IP privées, NEW_HOST une
    seule fois, ports/processus suspects, MEDIA_EXFIL (whitelist), forget(),
    et la détection de beacon par régularité (intervalles réguliers → alerte,
    trafic en rafales → non).
"""

import time
from collections import deque
from datetime import datetime, timezone

from capture.sniffer import Packet
from detection.anomaly import AnomalyDetector, BEACON_MIN_SAMPLES

PUBLIC_IP = "91.198.174.192"   # EN: real public IP (wikipedia.org)
                               # FR: vraie IP publique (wikipedia.org)


def pkt(remote=PUBLIC_IP, direction="out", port=443, size=500, process=None, proto="TCP"):
    """EN: Build a Packet for tests. / FR: Construire un paquet de test."""
    local = "192.168.1.10"
    return Packet(
        src_ip=local if direction == "out" else remote,
        dst_ip=remote if direction == "out" else local,
        src_port=50000 if direction == "out" else port,
        dst_port=port if direction == "out" else 50000,
        protocol=proto,
        size=size,
        timestamp=datetime.now(timezone.utc).isoformat(),
        direction=direction,
        process_name=process,
    )


def test_private_ip_produces_no_alerts():
    det = AnomalyDetector()
    assert det.analyze_packet(pkt(remote="192.168.1.55"), {}) == []


def test_new_host_alerts_once():
    det = AnomalyDetector()
    first = det.analyze_packet(pkt(), {})
    assert any(a.type == "NEW_HOST" for a in first)
    assert det.analyze_packet(pkt(), {}) == []


def test_suspicious_port():
    det = AnomalyDetector()
    alerts = det.analyze_packet(pkt(port=4444), {})
    assert any(a.type == "SUSPICIOUS_PORT" and a.details["port"] == 4444 for a in alerts)


def test_port_8080_not_flagged():
    """EN: 8080 was removed from SUSPICIOUS_PORTS — dev servers must not alert.
    FR: 8080 a été retiré des SUSPICIOUS_PORTS — les serveurs de dev ne doivent pas alerter."""
    det = AnomalyDetector()
    alerts = det.analyze_packet(pkt(port=8080), {})
    assert not any(a.type == "SUSPICIOUS_PORT" for a in alerts)


def test_suspicious_process():
    det = AnomalyDetector()
    alerts = det.analyze_packet(pkt(process="powershell.exe"), {})
    assert any(a.type == "SUSPICIOUS_PROCESS" for a in alerts)


def test_media_exfil_critical_for_unknown_process():
    det = AnomalyDetector()
    det.update_media_state(["evil.exe"], [])
    alerts = det.analyze_packet(pkt(process="evil.exe"), {})
    media = [a for a in alerts if a.type == "MEDIA_EXFIL"]
    assert media and media[0].severity == "critical"


def test_media_whitelisted_process_no_exfil():
    """EN: A known conferencing app using the mic is not flagged.
    FR: Une app de visio connue utilisant le micro n'est pas signalée."""
    det = AnomalyDetector()
    det.update_media_state(["zoom.exe"], [])
    alerts = det.analyze_packet(pkt(process="zoom.exe"), {})
    assert not any(a.type == "MEDIA_EXFIL" for a in alerts)


def test_browser_not_media_whitelisted():
    """EN: Browsers were removed from the whitelist — a mic-using Chrome
    process exfiltrating MUST alert. / FR: Les navigateurs ont été retirés de
    la whitelist — un Chrome micro-actif qui émet DOIT alerter."""
    det = AnomalyDetector()
    det.update_media_state(["chrome.exe"], [])
    alerts = det.analyze_packet(pkt(process="chrome.exe"), {})
    assert any(a.type == "MEDIA_EXFIL" for a in alerts)


def test_inbound_traffic_never_media_exfil():
    det = AnomalyDetector()
    det.update_media_state(["evil.exe"], [])
    alerts = det.analyze_packet(pkt(process="evil.exe", direction="in"), {})
    assert not any(a.type == "MEDIA_EXFIL" for a in alerts)


def test_forget_resets_seen_state():
    """EN: After forget(), the host is treated as new again — needed when the
    user removes an IP from the whitelist. / FR: Après forget(), l'hôte est
    traité comme nouveau — nécessaire quand l'utilisateur retire une IP de la
    whitelist."""
    det = AnomalyDetector()
    det.analyze_packet(pkt(), {})
    det.forget(PUBLIC_IP)
    alerts = det.analyze_packet(pkt(), {})
    assert any(a.type == "NEW_HOST" for a in alerts)


def test_beacon_detects_regular_intervals(monkeypatch):
    """
    EN: Regular 5 s intervals over a 60 s+ window → BEACON alert.
        time.time is patched so the appended 'now' continues the cadence.
    FR: Intervalles réguliers de 5 s sur une fenêtre de 60 s+ → alerte BEACON.
        time.time est patché pour que le « maintenant » ajouté poursuive la
        cadence.
    """
    det = AnomalyDetector()
    t0 = 1_000_000.0
    det._pkt_times[PUBLIC_IP] = deque(
        [t0 + i * 5.0 for i in range(BEACON_MIN_SAMPLES)], maxlen=120
    )
    monkeypatch.setattr(time, "time", lambda: t0 + BEACON_MIN_SAMPLES * 5.0)
    alerts = det._check_beacon(PUBLIC_IP, {})
    assert any(a.type == "BEACON" for a in alerts)
    monkeypatch.undo()


def test_beacon_ignores_bursty_traffic(monkeypatch):
    """EN: Irregular intervals (bursts) must NOT be flagged as beacons —
    that's what streaming/download looks like. / FR: Des intervalles
    irréguliers (rafales) ne doivent PAS être signalés — c'est à ça que
    ressemble le streaming/téléchargement."""
    det = AnomalyDetector()
    t0 = 1_000_000.0
    # EN: Wildly varying gaps: 0.01 s … 40 s. / FR: Écarts très variables : 0,01 s … 40 s.
    gaps = [0.01, 12, 0.4, 30, 0.05, 8, 40, 0.1, 3, 25, 0.02, 15, 7]
    times, cur = [t0], t0
    for g in gaps:
        cur += g
        times.append(cur)
    det._pkt_times[PUBLIC_IP] = deque(times, maxlen=120)
    monkeypatch.setattr(time, "time", lambda: cur + 0.1)
    alerts = det._check_beacon(PUBLIC_IP, {})
    assert not any(a.type == "BEACON" for a in alerts)


def test_beacon_whitelisted_dns_never_alerts():
    """EN: Public resolvers get constant small traffic — never beacons.
    FR: Les résolveurs publics reçoivent du trafic constant — jamais de beacon."""
    det = AnomalyDetector()
    det._pkt_times["8.8.8.8"] = deque([time.time() - i * 5 for i in range(60)], maxlen=120)
    assert det._check_beacon("8.8.8.8", {}) == []


def test_reset_runtime_clears_state():
    det = AnomalyDetector()
    det.analyze_packet(pkt(), {})
    det.reset_runtime()
    alerts = det.analyze_packet(pkt(), {})
    assert any(a.type == "NEW_HOST" for a in alerts)
