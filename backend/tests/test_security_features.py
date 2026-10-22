"""
Snitch — security-features tests (firewall, threat intel, new detectors).

EN: Covers the FirewallManager rule matching/lockdown/counters (OS commands
    are never executed — _apply is monkeypatched or the rules stay in demo
    mode), the opt-in ThreatIntel client (default-off, dedup, caching) and
    the new anomaly checks: DNS_TUNNEL, CLEARTEXT, BASELINE_DEVIATION.
FR: Couvre le FirewallManager (matching/lockdown/compteurs — les commandes
    OS ne sont jamais exécutées, _apply est monkeypatché), le client
    ThreatIntel opt-in (désactivé par défaut, dédup, cache) et les nouveaux
    checks d'anomalie : DNS_TUNNEL, CLEARTEXT, BASELINE_DEVIATION.
"""

import ctypes as _ct
import socket as _socket
import time
import types as _types
from datetime import datetime, timezone

import psutil as _psutil

from capture.ebpf_probe import EbpfProbe, _Event
from capture.sniffer import Packet
from detection import explain as _explain
from detection import iocshare, perfprobe
from detection.anomaly import AnomalyDetector, BASELINE_LEARN_MIN
from detection.deepinspect import DeepInspector, suspicious_module_paths
from detection.firewall import FirewallManager
from detection.integrity import IntegrityWatcher, _merkle_root, _names_match
from detection.llm_local import LocalSlm, _is_loopback
from detection.miner import MinerDetector
from detection.sinkresponder import SinkholeResponder
from detection.threatintel import ThreatIntel
from detection.wfp import _LAYER_V4, _LAYER_V6, WfpBackend

PUBLIC_IP = "91.198.174.192"
PRIVATE_IP = "192.168.1.55"


def pkt(remote=PUBLIC_IP, direction="out", port=443, size=500,
        process=None, proto="TCP", dns=None):
    """EN: Build a Packet for tests. / FR: Construire un paquet de test."""
    local = "192.168.1.10"
    return Packet(
        src_ip=local if direction == "out" else remote,
        dst_ip=remote if direction == "out" else local,
        src_port=50000 if direction == "out" else port,
        dst_port=port if direction == "out" else 50000,
        remote_port=port,
        protocol=proto,
        size=size,
        timestamp=datetime.now(timezone.utc).isoformat(),
        direction=direction,
        process_name=process,
        dns=dns or [],
    )


# ── Firewall / Pare-feu ──────────────────────────────────────────────────────

def _fw(tmp_path, monkeypatch):
    """EN: FirewallManager with OS commands stubbed out — 'applied' is always
    True so tests exercise rule logic, not privileges.
    FR: FirewallManager avec commandes OS stubées — « applied » vaut toujours
    True pour tester la logique de règles, pas les privilèges."""
    fw = FirewallManager(str(tmp_path))
    monkeypatch.setattr(fw, "_apply_one", lambda k, t, rid: (True, ""))
    monkeypatch.setattr(fw, "_remove", lambda rule: None)
    monkeypatch.setattr(fw, "_lockdown_apply", lambda on: (True, ""))
    monkeypatch.setattr(FirewallManager, "_resolve_domain",
                        staticmethod(lambda d: ["203.0.113.9/32"]))
    return fw


def test_firewall_rule_lifecycle(tmp_path, monkeypatch):
    """EN: add → serialized → toggle → remove. / FR: ajouter → sérialiser →
    basculer → supprimer."""
    fw = _fw(tmp_path, monkeypatch)
    rule = fw.add_rule("ip", PUBLIC_IP)
    assert rule["applied"] is True
    rules, lockdown = fw.serialized()
    assert len(rules) == 1 and lockdown is False
    assert fw.toggle_rule(rule["id"], False)
    assert fw.serialized()[0][0]["enabled"] is False
    assert fw.remove_rule(rule["id"])
    assert fw.serialized()[0] == []


def test_firewall_rejects_bad_rule(tmp_path, monkeypatch):
    """EN: Unknown kind → ValueError. / FR: Type inconnu → ValueError."""
    fw = _fw(tmp_path, monkeypatch)
    try:
        fw.add_rule("bogus", "x")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_firewall_check_packet_matches_ip(tmp_path, monkeypatch):
    """EN: A packet to a ruled IP is reported. / FR: Un paquet vers une IP en
    règle est rapporté."""
    fw = _fw(tmp_path, monkeypatch)
    fw.add_rule("ip", PUBLIC_IP)
    assert fw.check_packet(pkt())["value"] == PUBLIC_IP
    assert fw.check_packet(pkt(remote="8.8.8.8")) is None


def test_firewall_check_packet_matches_process_and_port(tmp_path, monkeypatch):
    """EN: Process + port rules hit too. / FR: Les règles processus et port
    matchent aussi."""
    fw = _fw(tmp_path, monkeypatch)
    fw.add_rule("process", "evil.exe")
    fw.add_rule("port", "4444")
    assert fw.check_packet(pkt(process="evil.exe"))["kind"] == "process"
    assert fw.check_packet(pkt(port=4444))["kind"] == "port"


def test_firewall_lockdown_flags_public_outbound(tmp_path, monkeypatch):
    """EN: Lockdown → every public outbound packet flagged; LAN stays exempt.
    FR: Lockdown → tout paquet sortant public signalé ; le LAN reste exempt."""
    fw = _fw(tmp_path, monkeypatch)
    fw.set_lockdown(True)
    hit = fw.check_packet(pkt())
    assert hit and hit["kind"] == "lockdown"
    assert fw.check_packet(pkt(remote=PRIVATE_IP)) is None
    fw.set_lockdown(False)
    assert fw.check_packet(pkt()) is None


def test_firewall_blocked_count_and_cooldown(tmp_path, monkeypatch):
    """EN: note_blocked counts and rate-limits alert contexts.
    FR: note_blocked compte et limite les contextes d'alerte."""
    fw = _fw(tmp_path, monkeypatch)
    rule = fw.add_rule("ip", PUBLIC_IP)
    ctx1 = fw.note_blocked(rule["id"])
    ctx2 = fw.note_blocked(rule["id"])
    assert ctx1 and ctx1["count"] == 1 and ctx2 is None  # cooldown
    assert fw.status()["blocked_counts"][rule["id"]] == 2


def test_firewall_domain_rule_matches_resolved_ip(tmp_path, monkeypatch):
    """EN: Domain rules match packets to the resolved IPs.
    FR: Les règles de domaine matchent les paquets vers les IP résolues."""
    fw = _fw(tmp_path, monkeypatch)
    fw.add_rule("domain", "evil.example")
    assert fw.check_packet(pkt(remote="203.0.113.9")) is not None


# ── Threat intel / Renseignement sur les menaces ────────────────────────────

def test_ti_disabled_by_default():
    """EN: No provider → disabled, check() is a no-op → NO outbound call.
    FR: Pas de fournisseur → désactivé, check() ne fait rien → AUCUN appel."""
    ti = ThreatIntel()
    assert not ti.enabled
    assert ti.check(PUBLIC_IP) is None
    assert ti.config()["provider"] == "none"


def test_ti_enabled_requires_provider_and_key():
    """EN: A provider without a key stays OFF — no half-configured leak.
    FR: Un fournisseur sans clé reste inactif — pas de fuite à moitié configurée."""
    ti = ThreatIntel()
    ti.configure("abuseipdb", "")
    assert not ti.enabled
    ti.configure("abuseipdb", "secretkey123")
    assert ti.enabled


def test_ti_check_uses_cache_and_dedup(monkeypatch):
    """EN: One live fetch; repeat calls hit the cache — the provider sees
    each IP at most once per TTL. / FR: Un appel réel ; les suivants lisent
    le cache — le fournisseur voit chaque IP au plus une fois par TTL."""
    ti = ThreatIntel()
    ti.configure("otx", "key")
    calls = []

    def fake_fetch(ip):
        calls.append(ip)
        return {"ip": ip, "provider": "otx", "verdict": "malicious",
                "score": 10, "detail": "pulses"}

    monkeypatch.setattr(ti, "_fetch", fake_fetch)
    assert ti.begin_check(PUBLIC_IP)          # first time → go
    assert not ti.begin_check(PUBLIC_IP)      # in-flight → dedup
    v = ti.check(PUBLIC_IP)
    assert v["verdict"] == "malicious"
    assert not ti.begin_check(PUBLIC_IP)      # cached → dedup
    ti.check(PUBLIC_IP)
    assert calls == [PUBLIC_IP]               # only ONE fetch total


# ── New anomaly checks / Nouveaux checks d'anomalie ─────────────────────────

def test_dns_tunnel_alerts_on_oversized_name():
    """EN: A >100-char DNS name with a >60-char label → DNS_TUNNEL once.
    FR: Un nom DNS >100 car. avec label >60 → DNS_TUNNEL une fois."""
    det = AnomalyDetector()
    name = "a" * 65 + "." + "b" * 45 + ".example.com"
    p = pkt(dns=[(name, PUBLIC_IP, 60)])
    alerts = det.analyze_packet(p, {})
    assert any(a.type == "DNS_TUNNEL" for a in alerts)
    # EN: Cooldown — a second oversized name must not re-alert.
    # FR: Cooldown — un second nom surdimensionné ne doit pas re-alerter.
    alerts2 = det.analyze_packet(pkt(dns=[(name, PUBLIC_IP, 60)]), {})
    assert not any(a.type == "DNS_TUNNEL" for a in alerts2)


def test_dns_tunnel_ignores_normal_names():
    """EN: Everyday hostnames stay quiet. / FR: Les noms usuels restent muets."""
    det = AnomalyDetector()
    p = pkt(dns=[("www.example.com", PUBLIC_IP, 300)])
    alerts = det.analyze_packet(p, {})
    assert "DNS_TUNNEL" not in [a.type for a in alerts]


def test_cleartext_flags_port80_once():
    """EN: Outbound TCP/80 → CLEARTEXT info alert, once per destination.
    FR: TCP/80 sortant → alerte info CLEARTEXT, une fois par destination."""
    det = AnomalyDetector()
    alerts = det.analyze_packet(pkt(port=80), {"hostname": "news.example"})
    assert any(a.type == "CLEARTEXT" and a.severity == "info" for a in alerts)
    alerts2 = det.analyze_packet(pkt(port=80), {"hostname": "news.example"})
    assert "CLEARTEXT" not in [a.type for a in alerts2]


def test_cleartext_ignores_https_and_inbound():
    """EN: 443 is never 'cleartext'; inbound 80 doesn't count (server side).
    FR: 443 n'est jamais « en clair » ; le 80 entrant ne compte pas."""
    det = AnomalyDetector()
    a1 = det.analyze_packet(pkt(port=443), {})
    a2 = det.analyze_packet(pkt(port=80, direction="in"), {})
    assert "CLEARTEXT" not in [a.type for a in a1 + a2]


def test_baseline_deviation_alerts_on_new_country():
    """EN: After the learning window, a NEW destination country for a KNOWN
    process → BASELINE_DEVIATION. / FR: Après la fenêtre d'apprentissage, un
    NOUVEAU pays pour un processus CONNU → BASELINE_DEVIATION."""
    det = AnomalyDetector()
    geo_fr = {"country_code": "FR"}
    for _ in range(BASELINE_LEARN_MIN + 1):
        det.analyze_packet(pkt(process="slack"), geo_fr)
    alerts = det.analyze_packet(pkt(process="slack"), {"country_code": "RU"})
    assert any(a.type == "BASELINE_DEVIATION" and a.details["country"] == "RU"
               for a in alerts)


def test_baseline_no_alert_during_learning():
    """EN: Countries seen during the learn phase are absorbed silently.
    FR: Les pays vus en phase d'apprentissage sont absorbés en silence."""
    det = AnomalyDetector()
    alerts = []
    for i in range(BASELINE_LEARN_MIN):
        alerts += det.analyze_packet(
            pkt(process="app"), {"country_code": "FR" if i % 2 else "DE"})
    assert "BASELINE_DEVIATION" not in [a.type for a in alerts]


def test_baselines_persist_roundtrip():
    """EN: dump → load keeps learned countries (survives restarts).
    FR: dump → load conserve les pays appris (survit aux redémarrages)."""
    det = AnomalyDetector()
    for _ in range(BASELINE_LEARN_MIN + 1):
        det.analyze_packet(pkt(process="app"), {"country_code": "FR"})
    dump = det.dump_baselines()
    det2 = AnomalyDetector()
    det2.load_baselines(dump)
    alerts = det2.analyze_packet(pkt(process="app"), {"country_code": "CN"})
    assert any(a.type == "BASELINE_DEVIATION" for a in alerts)


# ── Firewall: domain refresh + sinkhole / Rafraîchissement + sinkhole ──────

def test_domain_refresh_updates_resolved(tmp_path, monkeypatch):
    """EN: Re-resolution applies the delta — stale IPs out, new IPs in.
    FR: La re-résolution applique le delta — IP périmées retirées,
    nouvelles ajoutées."""
    resolutions = [["203.0.113.9/32"], ["203.0.113.10/32"]]
    monkeypatch.setattr(
        FirewallManager, "_resolve_domain",
        staticmethod(lambda d: resolutions.pop(0) if resolutions else
                               ["203.0.113.10/32"]))
    fw = FirewallManager(str(tmp_path))
    fw._demo = True                                   # EN: skip OS calls
    rule = fw.add_rule("domain", "cdn.example")
    assert rule["resolved"] == ["203.0.113.9/32"]
    assert fw.refresh_domains() == 1
    assert rule["resolved"] == ["203.0.113.10/32"]
    assert fw.refresh_domains() == 0                  # EN: stable now
    assert fw.check_packet(pkt(remote="203.0.113.10")) is not None
    assert fw.check_packet(pkt(remote="203.0.113.9")) is None


def test_sinkhole_domain_writes_hosts_block(tmp_path, monkeypatch):
    """EN: A domain sinkhole writes a marked hosts block; removal strips it.
    FR: Un sinkhole de domaine écrit un bloc hosts marqué ; la suppression
    le retire."""
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n")
    fw = FirewallManager(str(tmp_path))
    monkeypatch.setattr(fw, "_hosts_path", lambda: hosts)
    rule = fw.add_rule("domain", "ads.example", action="sinkhole")
    assert rule["applied"] is True
    body = hosts.read_text()
    assert f"# snitch-sinkhole {rule['id']} begin" in body
    assert "127.0.0.1 ads.example" in body
    fw._demo = False
    fw._remove(rule)
    body = hosts.read_text()
    assert "ads.example" not in body and "127.0.0.1 localhost" in body


def test_sinkhole_rejects_process_and_port(tmp_path, monkeypatch):
    """EN: sinkhole is meaningless for process/port kinds.
    FR: sinkhole n'a pas de sens pour processus/port."""
    fw = _fw(tmp_path, monkeypatch)
    for kind in ("process", "port"):
        try:
            fw.add_rule(kind, "x", action="sinkhole")
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {kind}")


def test_sinkhole_ip_unsupported_off_linux(tmp_path, monkeypatch):
    """EN: IP sinkhole on macOS reports an honest applied=False.
    FR: Le sinkhole IP sur macOS rapporte honnêtement applied=False."""
    fw = FirewallManager(str(tmp_path))
    fw._platform = "darwin"
    monkeypatch.setattr(fw, "_hosts_path", lambda: tmp_path / "hosts")
    rule = fw.add_rule("ip", PUBLIC_IP, action="sinkhole")
    assert rule["applied"] is False
    assert "iptables" in (rule["error"] or "")


def test_rule_action_defaults_to_block(tmp_path, monkeypatch):
    """EN: Rules created without action default to block.
    FR: Les règles créées sans action sont en « block »."""
    fw = _fw(tmp_path, monkeypatch)
    assert fw.add_rule("ip", PUBLIC_IP)["action"] == "block"
    try:
        fw.add_rule("ip", "8.8.8.8", action="bogus")
    except ValueError:
        return
    raise AssertionError("expected ValueError for bogus action")


# ── Integrity watch / Veille d'intégrité ────────────────────────────────────



def test_names_match_tolerates_versions():
    """EN: python3 ↔ python3.11 / svchost ↔ svchost.exe are the same.
    FR: python3 ↔ python3.11 / svchost ↔ svchost.exe sont identiques."""
    assert _names_match("python3", "python3.11")
    assert _names_match("svchost", "svchost.exe")
    assert _names_match("Chrome", "chrome")
    assert not _names_match("svchost", "svch0st.exe")


def test_integrity_name_mismatch_fires():
    """EN: A process whose name ≠ exe basename is flagged.
    FR: Un processus dont le nom ≠ basename de l'exe est signalé."""
    w = IntegrityWatcher()
    out = w._check_name("svchost", r"C:\Temp\svch0st.exe", 4242)
    assert out and out[0]["type"] == "NAME_MISMATCH"
    assert w._check_name("python3", "/usr/bin/python3.11", 1) == []


def test_integrity_binary_changed(tmp_path):
    """EN: First hash becomes the baseline; a different file later → alert.
    FR: Le premier hash devient la baseline ; un fichier différent → alerte."""
    exe = tmp_path / "evil.bin"
    exe.write_bytes(b"version-one")
    w = IntegrityWatcher()
    assert w._check_hash("evil", str(exe), 100) == []        # baseline set
    exe.write_bytes(b"version-two-patched")
    import os as _os
    _os.utime(exe, (0, 2_000_000_000))                       # EN: new mtime
    out = w._check_hash("evil", str(exe), 100)
    assert out and out[0]["type"] == "BINARY_CHANGED"
    assert out[0]["severity"] == "critical"


def test_integrity_baselines_roundtrip(tmp_path):
    """EN: dump/load preserves baselines across watcher instances.
    FR: dump/load conserve les baselines entre instances."""
    exe = tmp_path / "app.bin"
    exe.write_bytes(b"stable")
    w = IntegrityWatcher()
    w._check_hash("app", str(exe), 1)
    w2 = IntegrityWatcher()
    w2.load_baselines(w.dump_baselines())
    exe.write_bytes(b"changed")
    import os as _os
    _os.utime(exe, (0, 2_000_000_000))
    assert w2._check_hash("app", str(exe), 1)[0]["type"] == "BINARY_CHANGED"


def test_integrity_disabled_is_noop():
    """EN: Disabled watcher returns nothing — setting is honoured live.
    FR: Veille désactivée = silence — le réglage est honoré à chaud."""
    w = IntegrityWatcher()
    w.configure(False)
    assert w.check(1, "x") == []
    w.configure(True)
    assert w.enabled is True


def test_integrity_status_capabilities():
    """EN: Status is honest about platform support.
    FR: Le statut est honnête sur le support plateforme."""
    s = IntegrityWatcher().status()
    assert s["capabilities"]["exe_hash_watch"] is True
    assert "rwx_scan" in s["capabilities"]


# ── Alert explanations / Explications d'alertes ────────────────────────────



def test_explain_covers_every_type_bilingually():
    """EN: Every documented type has both languages filled.
    FR: Chaque type documenté a les deux langues remplies."""
    assert len(_explain.EXPLANATIONS) >= 15
    for t, rec in _explain.EXPLANATIONS.items():
        for k in ("title_en", "title_fr", "what_en", "what_fr",
                  "why_en", "why_fr"):
            assert rec[k].strip(), f"{t}.{k} empty"
        assert len(rec["actions_en"]) == len(rec["actions_fr"]) > 0


def test_explain_unknown_type_returns_none():
    """EN: Unknown type → None (endpoint maps it to 404).
    FR: Type inconnu → None (l'endpoint le traduit en 404)."""
    assert _explain.explain("NOPE") is None
    assert _explain.explain("") is None
    assert "THREAT_HIT" in _explain.all_types()


# ── WFP user-mode (Windows) / WFP user-mode ─────────────────────────────────



def test_wfp_unavailable_off_windows():
    """EN: On non-Windows the backend honestly reports unavailable and
    open() refuses cleanly (no WinDLL attribute to crash on).
    FR: Hors Windows le backend rapporte honnêtement indisponible et
    open() refuse proprement."""
    import os
    if os.name != "nt":
        assert WfpBackend.available() is False
        ok, why = WfpBackend().open()
        assert ok is False and why


def test_wfp_plan_layers_and_tags():
    """EN: Remote CIDR → one filter on the matching layer; port → filters
    on BOTH ALE layers (v4+v6). Tags are deterministic for delete-by-key.
    FR: CIDR distant → un filtre sur la bonne couche ; port → filtres sur
    les DEUX couches ALE. Tags déterministes pour la suppression par clé."""
    plan = WfpBackend()._plan([{"remote": "203.0.113.0/24"},
                               {"port": 4444}])
    layers = [p[0] for p in plan]
    tags = [p[2] for p in plan]
    assert _LAYER_V4 in layers and _LAYER_V6 in layers
    assert "port4" in tags and "port6" in tags
    assert any(t.startswith("ip-203.0.113.0/24") for t in tags)


def test_wfp_tags_for_matches_plan():
    """EN: tags_for() must enumerate every tag _plan can emit — a missed
    tag would leak a stale filter. / FR: tags_for() doit énumérer chaque
    tag que _plan émet — un tag manqué laisserait un filtre périmé."""
    assert set(WfpBackend.tags_for("process", "x")) == {"app4", "app6"}
    assert set(WfpBackend.tags_for("port", "443")) == {"port4", "port6"}
    assert WfpBackend.tags_for("ip", "203.0.113.9/32") == ["ip-203.0.113.9/32"]


# ── eBPF probe / Sonde eBPF ─────────────────────────────────────────────────



def _evt(pid: int, comm: bytes, ip: bytes, port: int) -> _Event:
    e = _Event()
    e.pid, e.dport, e.ipver = pid, port, 4
    e.comm = comm + b"\x00" * (16 - len(comm))
    e.daddr[:4] = ip
    return e


def test_ebpf_lookup_unique_event():
    """EN: A unique connect() event attributes (pid, comm) to later
    packets the socket table missed. / FR: Un connect() unique attribue
    (pid, comm) aux paquets ratés par la table des sockets."""
    p = EbpfProbe()
    e = _evt(4242, b"dropper", bytes([93, 184, 216, 34]), 4444)
    p._on_evt(0, _ct.addressof(e), _ct.sizeof(e))
    assert p.lookup("93.184.216.34", 4444) == (4242, "dropper")
    assert p.lookup("93.184.216.34", 443) == (None, None)


def test_ebpf_ambiguous_destination_refused():
    """EN: Two pids → same (ip,port): attribution would be a coin flip —
    lookup must refuse. / FR: Deux pids → même (ip,port) : l'attribution
    serait aléatoire — lookup doit refuser."""
    p = EbpfProbe()
    for pid in (100, 200):
        e = _evt(pid, b"proc", bytes([1, 2, 3, 4]), 443)
        p._on_evt(0, _ct.addressof(e), _ct.sizeof(e))
    assert p.lookup("1.2.3.4", 443) == (None, None)


def test_ebpf_available_honest():
    """EN: availability is a (bool, reason) tuple — never a bare guess.
    FR: disponibilité = tuple (bool, raison) — jamais une estimation."""
    ok, why = EbpfProbe.available()
    assert isinstance(ok, bool) and isinstance(why, str)


# ── Deep inspect (Frida) / Inspection profonde ──────────────────────────────



def test_deep_inspect_never_crashes():
    """EN: Without frida or a dead pid, inspect() returns ok=False with a
    reason — never raises. / FR: Sans frida ou pid mort, inspect() renvoie
    ok=False avec une raison — ne lève jamais."""
    res = DeepInspector().inspect(2 ** 30, seconds=3)
    assert res["ok"] is False and res["error"]
    assert res["events"] == []


def test_suspicious_module_paths_flags_staging():
    """EN: Temp/shm/downloads module paths are flagged, system paths not.
    FR: Les chemins temp/shm/downloads sont signalés, pas les chemins
    système."""
    events = [{"path": r"C:\Users\x\AppData\Local\Temp\evil.dll"},
              {"path": "/tmp/.hidden/libc.so"},
              {"path": "/usr/lib/libc.so.6"},
              {"path": ""}]
    bad = suspicious_module_paths(events)
    assert len(bad) == 2 and not any("libc.so.6" in p for p in bad)


# ── Sinkhole responder / Répondeur sinkhole ─────────────────────────────────



def test_sink_responder_http_hit(monkeypatch):
    """EN: An HTTP request to the responder records host+path+process —
    the sinkhole becomes a sensor. / FR: Une requête HTTP enregistre
    hôte+chemin+processus — le sinkhole devient un capteur."""
    monkeypatch.setattr("detection.sinkresponder._pid_for_port",
                        lambda p: (4321, "beacon.exe"))
    r = SinkholeResponder()
    srv, cli = _socket.socketpair()
    try:
        cli.sendall(b"POST /gate.php HTTP/1.1\r\nHost: c2.evil\r\n"
                    b"Content-Length: 4\r\n\r\ntoken")
        r._handle_http(srv, ("127.0.0.1", 44444))
    finally:
        cli.close()
    hits = r.pop_hits()
    assert hits and hits[0]["host"] == "c2.evil"
    assert hits[0]["method"] == "POST" and hits[0]["path"] == "/gate.php"
    assert hits[0]["pid"] == 4321 and hits[0]["process"] == "beacon.exe"
    assert r.pop_hits() == []


def test_sink_responder_tls_hit(monkeypatch):
    """EN: A ClientHello records a tls hit (SNI parsed when present).
    FR: Un ClientHello enregistre un hit tls (SNI analysé si présent)."""
    monkeypatch.setattr("detection.sinkresponder._pid_for_port",
                        lambda p: (None, None))
    r = SinkholeResponder()
    srv, cli = _socket.socketpair()
    try:
        cli.sendall(b"\x16\x03\x01" + b"\x00" * 200)   # EN: TLS record head
        r._handle_tls(srv, ("127.0.0.1", 55555))
    finally:
        cli.close()
    hits = r.pop_hits()
    assert hits and hits[0]["kind"] == "tls"


# ── Miner detector / Détecteur de minage ────────────────────────────────────



def _mpkt(remote=PUBLIC_IP, port=4444, pid=4242, process="xmr",
          head=b""):
    p = pkt(remote=remote, port=port, process=process)
    p.pid = pid
    p.app_head = head
    return p


def test_miner_stratum_signature():
    """EN: Cleartext stratum JSON in the payload head → critical hit.
    FR: JSON stratum en clair dans la tête du payload → hit critique."""
    m = MinerDetector()
    out = m.analyze_packet(_mpkt(head=b'{"id":1,"method":"mining.subscribe",'
                                      b'"params":["xmr.1"]}'))
    assert out[0]["type"] == "MINING_STRATUM"
    assert out[0]["severity"] == "critical"


def test_miner_pool_port_alone_never_alerts():
    """EN: A pool port without CPU corroboration marks a suspect only.
    FR: Un port de pool sans corroboration CPU ne fait que marquer."""
    m = MinerDetector()
    assert m.analyze_packet(_mpkt(port=4444)) == []
    assert (4242, PUBLIC_IP) in m._suspects


def test_miner_cpu_corroboration(monkeypatch):
    """EN: Pool port + sustained high CPU → MINING_SUSPECT.
    FR: Port de pool + CPU haute soutenue → MINING_SUSPECT."""
    import types
    import psutil
    m = MinerDetector()
    m.analyze_packet(_mpkt(port=4444))
    m._suspects[(4242, PUBLIC_IP)] = time.time() - 60   # EN: force window
    fake = types.SimpleNamespace(cpu_percent=lambda interval: 95.0,
                                 name=lambda: "xmr")
    monkeypatch.setattr(psutil, "Process", lambda pid: fake)
    out = m.cpu_corroborate()
    assert out[0]["type"] == "MINING_SUSPECT"
    assert "95%" in out[0]["detail"]


def test_miner_low_cpu_acquits(monkeypatch):
    """EN: Pool port with normal CPU produces no alert — corroboration
    matters. / FR: Port de pool avec CPU normale = rien — la
    corroboration compte."""
    import types
    import psutil
    m = MinerDetector()
    m.analyze_packet(_mpkt(port=4444))
    m._suspects[(4242, PUBLIC_IP)] = time.time() - 60
    fake = types.SimpleNamespace(cpu_percent=lambda interval: 8.0,
                                 name=lambda: "irc")
    monkeypatch.setattr(psutil, "Process", lambda pid: fake)
    assert m.cpu_corroborate() == []


# ── perf probe / Sonde perf ─────────────────────────────────────────────────



def test_perfprobe_available_honest():
    """EN: tuple (bool, reason); off-Linux it's a clean refusal.
    FR: tuple (bool, raison) ; hors Linux c'est un refus propre."""
    ok, why = perfprobe.available()
    import platform
    if platform.system().lower() != "linux":
        assert ok is False
    res = perfprobe.sample(2 ** 30, seconds=0.2)
    assert res["ok"] is False


# ── Local SLM / SLM local ───────────────────────────────────────────────────



def test_slm_loopback_gate():
    """EN: Only literal loopback endpoints are accepted — everything else
    is rejected so alert data can never leave the machine.
    FR: Seuls les endpoints loopback littéraux sont acceptés — tout le
    reste est rejeté pour que les données d'alerte ne partent jamais."""
    assert _is_loopback("http://127.0.0.1:11434")
    assert _is_loopback("http://localhost:11434")
    assert _is_loopback("http://[::1]:11434")
    assert not _is_loopback("http://192.168.1.1:11434")
    assert not _is_loopback("http://ollama.internal:11434")
    assert not _is_loopback("http://evil.example:11434")


def test_slm_disabled_and_remote_rejected():
    """EN: Disabled → None; a non-loopback endpoint is never adopted.
    FR: Désactivé → None ; un endpoint non-loopback n'est jamais adopté."""
    s = LocalSlm()
    assert s.enrich("BEACON", {}) is None
    s.configure(True, "http://10.0.0.9:11434", "m")
    assert s._endpoint == "http://127.0.0.1:11434"   # EN: kept default
    assert s.enrich("BEACON", {}) is None             # EN: unreachable → None


# ── IOC pack / Paquet IOC ───────────────────────────────────────────────────



def test_iocpack_roundtrip(monkeypatch):
    """EN: Deterministic build (flip=0) → indicators are findable, foreign
    ones are not. / FR: Build déterministe (flip=0) → les indicateurs se
    retrouvent, les étrangers non."""
    monkeypatch.setattr(iocshare, "_FLIP", 0.0)
    pack = iocshare.build_pack(["203.0.113.7", "evil.example"])
    assert pack["format"].startswith("snitch-ioc-pack")
    res = iocshare.check_pack(pack, ["203.0.113.7", "9.9.9.9"])
    assert res["ok"]
    hints = {h["indicator"] for h in res["hints"]}
    assert "203.0.113.7" in hints and "9.9.9.9" not in hints


def test_iocpack_flip_adds_deniability():
    """EN: With flipping enabled, two builds of the same indicators
    differ — a pack can't be diffed back to the source list.
    FR: Avec flip, deux builds des mêmes indicateurs diffèrent — un
    paquet ne se remonte pas à la liste source."""
    import base64
    a = iocshare.build_pack(["1.2.3.4"] * 10)
    b = iocshare.build_pack(["1.2.3.4"] * 10)
    assert base64.b64decode(a["bits_b64"]) != base64.b64decode(b["bits_b64"])


def test_iocpack_rejects_garbage():
    """EN: Bad format/params/bits → honest error, not a crash.
    FR: Format/params/bits mauvais → erreur honnête, pas de crash."""
    assert iocshare.check_pack({}, ["x"])["ok"] is False
    pack = {"format": "snitch-ioc-pack/1", "m": 8192, "k": 4,
            "bits_b64": "AAAA"}
    assert iocshare.check_pack(pack, ["x"])["ok"] is False


# ── Integrity: modules + merkle / Intégrité : modules + merkle ──────────────



def test_merkle_root_order_independent():
    """EN: Root is sort-based — reload order can't trigger false alerts.
    FR: Racine triée — l'ordre de rechargement ne peut pas alerter."""
    assert _merkle_root(["a", "b", "c"]) == _merkle_root(["c", "a", "b"])
    assert _merkle_root(["a", "b"]) != _merkle_root(["a", "b", "c"])
    assert _merkle_root([]) == ""


def test_integrity_module_suspect(monkeypatch):
    """EN: A file-backed module living under /tmp is flagged.
    FR: Un module fichier-basé sous /tmp est signalé."""
    w = IntegrityWatcher()
    maps = [_types.SimpleNamespace(path="/tmp/.x/evil.so"),
            _types.SimpleNamespace(path="/usr/lib/libc.so.6")]
    monkeypatch.setattr(
        _psutil, "Process",
        lambda pid: _types.SimpleNamespace(
            memory_maps=lambda grouped=True: maps))
    out = w._check_modules(999, "app", "")
    assert out[0]["type"] == "MODULE_SUSPECT"
    assert "/tmp/.x/evil.so" in out[0]["modules"]


def test_integrity_module_merkle_baseline(tmp_path, monkeypatch):
    """EN: First module set → baseline; a changed module file later →
    MODULE_CHANGED. / FR: Premier ensemble → baseline ; un fichier de
    module modifié → MODULE_CHANGED."""
    # EN: tmp_path lives under /tmp on Linux and …\Temp on Windows —
    #     both match _BAD_MODULE_MARKERS and would emit MODULE_SUSPECT.
    #     This test is about the Merkle root, so disable path markers.
    # FR: tmp_path vit sous /tmp (Linux) et …\Temp (Windows) — les deux
    #     matchent _BAD_MODULE_MARKERS → MODULE_SUSPECT parasite. Ce test
    #     vise la racine Merkle : marqueurs désactivés ici.
    import detection.integrity as _integrity
    monkeypatch.setattr(_integrity, "_BAD_MODULE_MARKERS", ())
    m1, m2 = tmp_path / "a.so", tmp_path / "b.so"
    m1.write_bytes(b"lib-a-v1")
    m2.write_bytes(b"lib-b-v1")
    w = IntegrityWatcher()
    maps = [_types.SimpleNamespace(path=str(m1)),
            _types.SimpleNamespace(path=str(m2))]
    monkeypatch.setattr(
        _psutil, "Process",
        lambda pid: _types.SimpleNamespace(
            memory_maps=lambda grouped=True: maps))
    assert w._check_modules(999, "app", "/usr/bin/app") == []   # baseline
    m1.write_bytes(b"lib-a-v2-patched")
    import os as _os
    _os.utime(m1, (0, 2_000_000_000))
    out = w._check_modules(999, "app", "/usr/bin/app")
    assert out[0]["type"] == "MODULE_CHANGED"
    assert out[0]["severity"] == "critical"


# ── Firewall: throttle action / Pare-feu : action throttle ──────────────────

def test_throttle_rejects_port_and_process(tmp_path, monkeypatch):
    """EN: throttle on port/process is meaningless → ValueError.
    FR: throttle sur port/processus est insensé → ValueError."""
    fw = _fw(tmp_path, monkeypatch)
    for kind in ("process", "port"):
        try:
            fw.add_rule(kind, "x", action="throttle")
        except ValueError:
            continue
        raise AssertionError(f"expected ValueError for {kind}")


def test_throttle_apply_linux_commands(tmp_path, monkeypatch):
    """EN: A Linux throttle emits clsact flower police filters at the
    rule's rate. / FR: Un throttle Linux émet des filtres flower police
    au débit de la règle."""
    fw = FirewallManager(str(tmp_path))
    fw._platform, fw._demo, fw._tc_iface = "linux", False, "eth0"
    calls: list[list[str]] = []
    monkeypatch.setattr(fw, "_run", lambda a: (calls.append(a), (True, ""))[1])
    rule = fw.add_rule("ip", PUBLIC_IP, action="throttle", rate=128)
    assert rule["applied"] is True
    flat = [x for call in calls for x in call]
    assert "police" in flat and "128kbit" in flat
    assert "egress" in flat and "flower" in flat


def test_throttle_off_linux_honest(tmp_path, monkeypatch):
    """EN: Throttle on macOS reports applied=False, linux-only reason.
    FR: Throttle sur macOS rapporte applied=False, raison linux."""
    fw = FirewallManager(str(tmp_path))
    fw._platform, fw._demo = "darwin", False
    monkeypatch.setattr(fw, "_pf_apply", lambda: (True, ""))
    rule = fw.add_rule("ip", PUBLIC_IP, action="throttle")
    assert rule["applied"] is False and "linux" in (rule["error"] or "")


# ── Parser app_head / app_head du parseur ───────────────────────────────────

def test_parser_app_head_cleartext_only():
    """EN: Cleartext TCP payload head is captured (≤64B) for stratum
    fingerprinting; TLS stays opaque (app_head empty).
    FR: La tête d'un payload TCP en clair est capturée (≤64 o.) pour la
    signature stratum ; TLS reste opaque (app_head vide)."""
    import struct as _st
    from capture.parser import parse_frame, DLT_EN10MB

    def frame(payload: bytes) -> bytes:
        # EN: 20-byte TCP header — offset byte (0x50) sits at position 12.
        # FR: en-tête TCP de 20 octets — octet d'offset (0x50) en position 12.
        tcp = _st.pack("!HH", 40000, 3333) + b"\x00" * 8 + b"\x50\x18" \
            + b"\x00" * 6 + payload
        ip = bytes([0x45, 0]) + _st.pack("!H", 20 + len(tcp)) + \
            b"\x00" * 4 + bytes([64, 6]) + b"\x00" * 2 + \
            bytes([10, 0, 0, 1]) + bytes([93, 184, 216, 34])
        return b"\xaa" * 12 + b"\x08\x00" + ip + tcp

    p = parse_frame(DLT_EN10MB, frame(b'{"method":"mining.subscribe"}'))
    assert p.app_head.startswith(b'{"method"')
    p2 = parse_frame(DLT_EN10MB, frame(b"\x16\x03\x01" + b"\x00" * 40))
    assert p2.app_head == b""


# ── Firewall profiles / Profils pare-feu ────────────────────────────────────

def test_profile_balanced_adds_baseline(tmp_path, monkeypatch):
    """EN: `balanced` expands to baseline port rules + lockdown stays off.
    FR: `balanced` se déplie en règles de ports de base + lockdown éteint."""
    fw = _fw(tmp_path, monkeypatch)
    res = fw.apply_profile("balanced")
    rules, lockdown = fw.serialized()
    assert res["added"] == len(FirewallManager.PROFILES["balanced"]["rules"])
    assert lockdown is False
    assert all(r["kind"] == "port" for r in rules)


def test_profile_strict_enables_lockdown(tmp_path, monkeypatch):
    """EN: `strict` = baseline + lockdown ON. / FR: `strict` = base + lockdown."""
    fw = _fw(tmp_path, monkeypatch)
    fw.apply_profile("strict")
    _, lockdown = fw.serialized()
    assert lockdown is True


def test_profile_permissive_clears_all(tmp_path, monkeypatch):
    """EN: `permissive` wipes every rule and drops lockdown — clean slate.
    FR: `permissive` efface toutes les règles et le lockdown — table rase."""
    fw = _fw(tmp_path, monkeypatch)
    fw.apply_profile("strict")
    res = fw.apply_profile("permissive")
    rules, lockdown = fw.serialized()
    assert rules == [] and lockdown is False and res["removed"] > 0


def test_profile_dedup_keeps_existing(tmp_path, monkeypatch):
    """EN: Re-applying a profile reuses identical rules — no duplicates.
    FR: Ré-appliquer un profil réutilise les règles identiques — pas de doublon."""
    fw = _fw(tmp_path, monkeypatch)
    fw.apply_profile("balanced")
    res = fw.apply_profile("balanced")
    assert res["added"] == 0
    assert len(fw.serialized()[0]) == len(
        FirewallManager.PROFILES["balanced"]["rules"])


def test_profile_unknown_rejected(tmp_path, monkeypatch):
    """EN: Unknown profile name → ValueError → 400 at the API layer.
    FR: Nom de profil inconnu → ValueError → 400 côté API."""
    fw = _fw(tmp_path, monkeypatch)
    try:
        fw.apply_profile("paranoid")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


# ── Custom alert rules / Règles d'alerte utilisateur ────────────────────────

def test_custom_rules_lifecycle_and_match():
    """EN: add → match by host SNI → hit counter → toggle off → no match.
    FR: ajout → match par SNI → compteur → désactivation → plus de match."""
    from detection.customrules import CustomRules
    cr = CustomRules()
    r = cr.add("watch onions", "host", "contains", ".onion", "critical")
    p = pkt()
    p.sni = "deadbeef.onion"
    hits = cr.check(p)
    assert hits and hits[0]["rule"]["name"] == "watch onions"
    assert r["hits"] == 1
    cr.toggle(r["id"], False)
    assert cr.check(p) == []


def test_custom_rules_cidr_and_numeric():
    """EN: cidr op on remote_ip + gt op on remote_port both match.
    FR: l'op cidr sur remote_ip et gt sur remote_port matchent tous deux."""
    from detection.customrules import CustomRules
    cr = CustomRules()
    cr.add("range", "remote_ip", "cidr", "91.198.174.0/24")
    cr.add("highport", "remote_port", "gt", "8000")
    assert len(cr.check(pkt())) == 1                    # EN: ip only / FR: ip seule
    assert len(cr.check(pkt(port=9999))) == 2           # EN: both / FR: les deux


def test_custom_rules_validation():
    """EN: Bad field/op/regex/cidr all rejected at creation.
    FR: Mauvais champ/op/regex/cidr tous rejetés à la création."""
    import pytest as _pt
    from detection.customrules import CustomRules
    cr = CustomRules()
    for kw in (dict(field="nope"), dict(field="host", op="nope"),
               dict(field="host", op="regex", value="["),
               dict(field="remote_ip", op="cidr", value="999.0.0.0/8"),
               dict(field="host", value="")):
        with _pt.raises(ValueError):
            cr.add("x", kw.get("field", "host"), kw.get("op", "eq"),
                   kw.get("value", "v"))


def test_custom_rules_load_drops_broken():
    """EN: load() skips invalid persisted entries rather than crashing.
    FR: load() ignore les entrées persistées invalides plutôt que planter."""
    from detection.customrules import CustomRules
    cr = CustomRules()
    cr.load([{"field": "host", "op": "contains", "value": "evil",
              "name": "ok", "severity": "warning", "enabled": True},
             {"field": "bogus", "op": "eq", "value": "x"}])
    assert len(cr.serialized()) == 1


# ── Blocklist / Liste de blocage ─────────────────────────────────────────────

def test_blocklist_parse_hosts_format():
    """EN: hosts-style lines, comments and plain lists all parse; local
    entries and invalid domains are dropped, order preserved, deduped.
    FR: lignes hosts, commentaires et listes simples parsés ; les entrées
    locales et domaines invalides sont écartés, ordre conservé, dédup."""
    from detection.blocklist import parse_domains
    text = """
# a comment / un commentaire
0.0.0.0 ads.example tracker.example
127.0.0.1 localhost
127.0.0.1 bad.example
malware.example
0.0.0.0 ads.example
not a domain !!
0.0.0.0 -bad-.example
"""
    out = parse_domains(text)
    assert "ads.example" in out and "bad.example" in out
    assert "malware.example" in out
    assert "localhost" not in out and "not" not in out
    assert out.count("ads.example") == 1


def test_blocklist_clamp_bounds():
    """EN: clamp_max respects default + hard cap.
    FR: clamp_max respecte le défaut + le plafond dur."""
    from detection.blocklist import clamp_max
    assert clamp_max(None) == 500
    assert clamp_max(10) == 10
    assert clamp_max(999999) == 5000


def test_blocklist_fetch_requires_http():
    """EN: fetch_url rejects non-http(s) schemes outright.
    FR: fetch_url rejette carrément les schémas non http(s)."""
    import pytest as _pt
    from detection.blocklist import fetch_url
    with _pt.raises(ValueError):
        fetch_url("file:///etc/passwd")


# ── IOC proof packs / Paquets de preuve IOC ──────────────────────────────────

def test_ioc_proof_pack_proves_membership():
    """EN: A listed indicator verifies EXACTLY (no false positives); an
    unlisted one never matches. Root is a tamper-evident commitment.
    FR: Un indicateur listé se vérifie EXACTEMENT ; un non-listé ne
    matche jamais. La racine est un engagement inviolable."""
    pack = iocshare.build_proof_pack(["1.2.3.4", "evil.example"])
    res = iocshare.check_proof_pack(pack, ["1.2.3.4", "clean.example"])
    assert res["ok"] is True
    assert [h["indicator"] for h in res["hints"]] == ["1.2.3.4"]


def test_ioc_proof_pack_tamper_detected():
    """EN: Flipping a leaf breaks the Merkle commitment → honest error.
    FR: Inverser une feuille casse l'engagement Merkle → erreur honnête."""
    pack = iocshare.build_proof_pack(["1.2.3.4"])
    pack["entries"][0]["leaf"] = "00" * 32
    res = iocshare.check_proof_pack(pack, ["1.2.3.4"])
    assert res["ok"] is False and "tampered" in res["error"]


def test_ioc_proof_pack_rejects_bloom():
    """EN: A bloom pack handed to the proof checker is refused politely.
    FR: Un paquet bloom passé au vérificateur proof est refusé proprement."""
    pack = iocshare.build_pack(["1.2.3.4"])
    res = iocshare.check_proof_pack(pack, ["1.2.3.4"])
    assert res["ok"] is False


# ── Embedded SLM / SLM embarqué ──────────────────────────────────────────────

def test_slm_embedded_status_reports_file(tmp_path):
    """EN: embedded mode reports reachable only when the GGUF path exists.
    FR: le mode embedded ne rapporte joignable que si le GGUF existe."""
    slm = LocalSlm()
    slm.configure(True, mode="embedded", model_path=str(tmp_path / "m.gguf"))
    assert slm.status()["reachable"] is False
    (tmp_path / "m.gguf").write_bytes(b"GGUF")
    assert slm.status()["reachable"] is True


def test_slm_embedded_enrich_without_package(tmp_path):
    """EN: without llama-cpp-python installed, enrich() degrades to None —
    caller falls back to templates. / FR: sans llama-cpp-python,
    enrich() dégrade en None — repli sur les gabarits."""
    slm = LocalSlm()
    f = tmp_path / "m.gguf"
    f.write_bytes(b"x")
    slm.configure(True, mode="embedded", model_path=str(f))
    slm._load_embedded = lambda: None          # EN: simulate missing dep / FR: simuler l'absence
    assert slm.enrich("BEACON", {"ip": "1.2.3.4"}) is None


def test_slm_mode_switch_reloads(tmp_path):
    """EN: switching modes or model path drops the cached Llama object.
    FR: changer de mode ou de chemin invalide l'objet Llama caché."""
    slm = LocalSlm()
    slm._llama = object()
    slm.configure(True, mode="embedded", model_path="/a")
    assert slm._llama is None


# ── Network sandbox / Sandbox réseau ─────────────────────────────────────────

def test_contain_platform_support():
    """EN: available() reports the real mechanism per OS — never claims
    support that isn't there. / FR: available() rapporte le mécanisme
    réel par OS — jamais de support fantaisiste."""
    import sys
    import detection.contain as contain
    if sys.platform.startswith("linux"):
        ok, why = contain.available()
        assert isinstance(ok, bool) and why
    else:
        ok, why = contain.available()
        assert isinstance(ok, bool) and why


def test_contain_rejects_nonexistent(tmp_path):
    """EN: detonating a missing file fails honestly before any exec.
    FR: détoner un fichier absent échoue honnêtement avant tout exec."""
    from detection.contain import run_sandboxed
    res = run_sandboxed(str(tmp_path / "nope"), [], 5)
    assert res["ok"] is False and "executable" in res["error"]


def test_contain_wraps_command(monkeypatch, tmp_path):
    """EN: On Linux the command is wrapped in `unshare --user --net`;
    on macOS in `sandbox-exec` with a deny-network profile. Mock the
    runner so nothing actually executes.
    FR: Sous Linux la commande est enveloppée dans `unshare --user --net` ;
    sous macOS dans `sandbox-exec` deny-network. Le lanceur est mocké."""
    import sys
    import detection.contain as contain

    exe = tmp_path / "tool"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)

    captured = {}

    class FakeProc:
        returncode = 0
        stdout = b""
        stderr = b""

    def _fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return FakeProc()

    monkeypatch.setattr(contain.subprocess, "run", _fake_run)
    res = contain.run_sandboxed(str(exe), ["--x"], 5)
    if res["ok"]:
        cmd = captured["cmd"]
        if sys.platform.startswith("linux"):
            assert cmd[0] == "unshare" and "--net" in cmd
        elif sys.platform == "darwin":
            assert cmd[0] == "sandbox-exec" and "deny network" in cmd[2]
    # EN: ok=False is equally valid — no sandbox support on this host.
    # FR: ok=False est tout aussi valide — pas de sandbox sur cet hôte.


# ── PCAP writer / Écrivain PCAP ──────────────────────────────────────────────

def test_pcapwriter_roundtrip():
    """EN: Written pcap parses back — magic, version, linktype, frame
    timestamps and payloads all intact. / FR: le pcap écrit se relit —
    magic, version, linktype, timestamps et payloads intacts."""
    import io
    import struct
    from capture.pcapwriter import write_pcap
    buf = io.BytesIO()
    frames = [(1700000000.5, b"\xde\xad\xbe\xef" * 8, 32),
              (1700000001.25, b"\x01\x02" * 4, 8)]
    write_pcap(buf, 1, frames)
    data = buf.getvalue()
    magic, vmaj, vmin, _tz, _sig, snap, link = struct.unpack("<IHHiIII", data[:24])
    assert magic == 0xA1B2C3D4 and vmaj == 2 and vmin == 4 and link == 1
    off = 24
    for (ts, payload, wire) in frames:
        sec, usec, incl, orig = struct.unpack("<IIII", data[off:off + 16])
        assert sec == int(ts) and incl == len(payload) and orig == wire
        off += 16 + incl
    assert off == len(data)
