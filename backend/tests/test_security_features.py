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

import time
from datetime import datetime, timezone

from capture.sniffer import Packet
from detection.anomaly import AnomalyDetector, BASELINE_LEARN_MIN
from detection.firewall import FirewallManager
from detection.threatintel import ThreatIntel

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

from detection.integrity import IntegrityWatcher, _names_match


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

from detection import explain as _explain


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
