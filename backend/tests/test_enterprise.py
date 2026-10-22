"""
EN: Tests for the enterprise layer — declarative config file, Sigma
    import, IP-feed blocklists, fleet merge, CEF/ECS output.
FR: Tests de la couche entreprise — fichier de config déclaratif,
    import Sigma, blocklists IP, fusion de flotte, sorties CEF/ECS.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ── configfile / fichier de config ─────────────────────────────────────────────

def test_configfile_toml(tmp_path, monkeypatch):
    import configfile
    monkeypatch.delenv("SNITCH_CONFIG", raising=False)
    (tmp_path / "snitch.toml").write_text(
        'syslog_addr = "siem:514"\nkill_switch_enabled = true\nports = [80, 443]\n')
    cfg = configfile.load(tmp_path)
    assert cfg["syslog_addr"] == "siem:514" and cfg["ports"] == [80, 443]


def test_configfile_env_wins(tmp_path, monkeypatch):
    import configfile
    env_file = tmp_path / "elsewhere.toml"
    env_file.write_text('ask_enabled = true\n')
    monkeypatch.setenv("SNITCH_CONFIG", str(env_file))
    cfg = configfile.load(tmp_path)              # no local file → env only
    assert cfg == {"ask_enabled": True}


def test_configfile_invalid_is_empty(tmp_path, monkeypatch):
    import configfile
    monkeypatch.delenv("SNITCH_CONFIG", raising=False)
    (tmp_path / "snitch.toml").write_text('this is = = broken [[[\n')
    assert configfile.load(tmp_path) == {}       # EN: never crashes / FR: ne plante jamais


def test_configfile_apply_overrides(tmp_path, monkeypatch):
    import configfile
    monkeypatch.delenv("SNITCH_CONFIG", raising=False)
    (tmp_path / "snitch.toml").write_text('kill_switch_enabled = true\n')
    store = {"kill_switch_enabled": False}
    n = configfile.apply(tmp_path, lambda k, v: store.__setitem__(k, v))
    assert n == 1 and store["kill_switch_enabled"] is True


# ── blocklist IP feeds / flux IP ──────────────────────────────────────────────

def test_parse_ips_basic():
    from detection import blocklist
    text = "# comment\n1.2.3.4\n5.6.7.8,443,2024-01-01\n1.2.3.4\n"
    assert blocklist.parse_ips(text) == ["1.2.3.4", "5.6.7.8"]


def test_parse_ips_skips_private():
    from detection import blocklist
    ips = blocklist.parse_ips("10.0.0.1\n192.168.1.1\n127.0.0.1\n8.8.8.8\n")
    assert ips == ["8.8.8.8"]


def test_parse_ips_cidr_bounded():
    from detection import blocklist
    # EN: 91.198.174.x is RIPE NCC — genuinely public, unlike 203.0.113.x
    #     (TEST-NET-3, correctly filtered as reserved).
    # FR: 91.198.174.x est RIPE NCC — vraiment public, contrairement à
    #     203.0.113.x (TEST-NET-3, filtré à juste titre comme réservé).
    ips = blocklist.parse_ips("91.198.174.0/29\n10.0.0.0/8\nnot-an-ip\n")
    assert len(ips) == 6 and all(x.startswith("91.198.174.") for x in ips)


def test_parse_ips_rejects_doc_ranges():
    from detection import blocklist
    assert blocklist.parse_ips("203.0.113.5\n198.51.100.9\n192.0.2.1\n") == []


# ── sigma ────────────────────────────────────────────────────────────────────

_SIGMA = """
title: Suspicious outbound to C2
id: abc-123
level: high
detection:
  selection:
    DestinationIp|cidr: 198.51.100.0/24
    DestinationPort: 4444
  condition: selection
"""


def test_sigma_convert_simple():
    import pytest
    pytest.importorskip("yaml")
    from detection import sigma
    out = sigma.convert(_SIGMA)
    assert len(out["rules"]) == 1 and not out["skipped"]
    conds = out["rules"][0]["conds"]
    assert {"field": "remote_ip", "op": "cidr",
            "value": "198.51.100.0/24"} in conds
    assert {"field": "remote_port", "op": "eq",
            "value": "4444"} in conds
    assert out["rules"][0]["severity"] == "warning"      # EN: level=high / FR: level=high


def test_sigma_or_list_becomes_regex():
    import pytest
    pytest.importorskip("yaml")
    from detection import sigma
    out = sigma.convert("""
title: multi
detection:
  selection:
    Domain: [evil.com, bad.org]
  condition: selection
""")
    c = out["rules"][0]["conds"][0]
    assert c["op"] == "regex" and "evil\\.com" in c["value"]


def test_sigma_unmapped_skipped_honestly():
    import pytest
    pytest.importorskip("yaml")
    from detection import sigma
    out = sigma.convert("""
title: has commandline
detection:
  selection:
    CommandLine|contains: powershell
  condition: selection
""")
    assert not out["rules"] and out["skipped"]            # EN: honest skip / FR: skip honnête


def test_sigma_conds_rule_matches_all_clauses():
    from detection.customrules import CustomRules
    cr = CustomRules()
    cr.add("multi", None, None, None, conds=[
        {"field": "remote_port", "op": "eq", "value": "4444"},
        {"field": "protocol", "op": "eq", "value": "tcp"},
    ])

    class P:
        dst_ip, src_ip = "1.2.3.4", "10.0.0.5"
        direction, remote_port, protocol = "out", 4444, "tcp"
        sni, dns, process_name, size, pid = "", [], "", 100, 1
    assert len(cr.check(P())) == 1
    P.protocol = "udp"                                     # EN: one clause fails → no match
    assert cr.check(P()) == []                             # FR: une clause rate → pas de match


def test_sigma_conds_reject_bad_field():
    import pytest
    from detection.customrules import CustomRules
    with pytest.raises(ValueError):
        CustomRules().add("bad", None, None, None, conds=[
            {"field": "nope", "op": "eq", "value": "x"}])


# ── ReDoS guard / garde ReDoS ────────────────────────────────────────────

def test_regex_rejects_nested_quantifiers():
    """EN: (a+)+-shaped patterns are refused at validation — Python's re
    has no match timeout so the shape itself is rejected.
    FR: Les motifs de forme (a+)+ sont refusés à la validation — le re de
    Python n'a pas de timeout donc la forme est rejetée."""
    import pytest
    from detection.customrules import CustomRules
    for pat in ("(a+)+", "(.*)*", "([a-z]+)+", "(a?)+",
                "(a{1,3})+", "((a+)b)+", "(?:a+)+", "(x{2,})+"):
        with pytest.raises(ValueError, match="nested quantifiers"):
            CustomRules().add("redos", "host", "regex", pat)


def test_regex_accepts_safe_patterns():
    """EN: Bounded and non-nested patterns stay legal — the guard must
    not overblock. / FR: Les motifs bornés et non imbriqués restent
    légaux — la garde ne doit pas surbloquer."""
    from detection.customrules import CustomRules
    for pat in ("a+b", r"[a-z]+$", "(?:ab)+", "(a|b)+", r"\+x+",
                "(a+){2}", "x{2,3}y", "(a?b)c", "foo{bar}"):
        CustomRules().add("ok", "host", "regex", pat)


def test_nested_quantifier_scanner():
    """EN: Direct unit coverage of the shape detector — escapes, char
    classes and group-type prefixes must not confuse it.
    FR: Couverture unitaire directe du détecteur — échappements, classes
    et préfixes de groupe ne doivent pas le perturber."""
    from detection.customrules import _has_nested_quantifier as f
    assert f("(a+)+") and f("((a+)b)+") and f("([a-z]+)+")
    assert not f("(?:ab)+") and not f("(?P<n>a)b") and not f("[+*]+")
    assert not f(r"a\(x\)+b")                    # EN: escaped parens / FR: parenthèses échappées


# ── ask-mode bounds / bornes du mode ask ─────────────────────────────────

def test_askmode_decided_bounded():
    """EN: Verdict memory evicts the oldest entries past _MAX_DECIDED.
    FR: La mémoire des verdicts évinçe les plus anciens au-delà de la borne."""
    import sys
    import pytest
    if sys.platform != "linux":
        pytest.skip("NFQUEUE backend is Linux-only")
    from detection.askmode import AskMode, _MAX_DECIDED
    am = AskMode(on_ask=lambda e: None)
    with am._lock:
        for i in range(_MAX_DECIDED + 100):
            am._remember((f"10.0.0.{i % 250}", i, "TCP"), True)
    assert len(am._decided) == _MAX_DECIDED - _MAX_DECIDED // 4 + 100 \
        or len(am._decided) <= _MAX_DECIDED


def test_askmode_rollback_mirrors_inserts(monkeypatch):
    """EN: _rollback_rules turns every -I insert into the -D delete, in
    reverse order. / FR: _rollback_rules transforme chaque insertion -I
    en suppression -D, en ordre inverse."""
    import sys
    import pytest
    if sys.platform != "linux":
        pytest.skip("iptables is Linux-only")
    from detection.askmode import AskMode
    calls = []
    monkeypatch.setattr("subprocess.run",
                        lambda c, **kw: calls.append(c) or None)
    AskMode._rollback_rules([
        ["iptables", "-w", "-I", "OUTPUT", "-o", "lo", "-j", "RETURN"],
        ["iptables", "-w", "-I", "OUTPUT", "-j", "NFQUEUE",
         "--queue-num", "7"],
    ])
    assert calls[0][2] == "-D" and "NFQUEUE" in calls[0]  # EN: jump first / FR: saut d'abord
    assert calls[1][2] == "-D" and "lo" in calls[1]
    assert all("-I" not in c for c in calls)


# ── fleet merge / fusion de flotte ───────────────────────────────────────────

def test_fleet_audit_merge(monkeypatch):
    from detection.gossip import PeerSync
    import urllib.request
    import json

    ps = PeerSync(lambda: "tok")
    ps.configure(["peer-a:8000", "peer-b:8000"])

    class FakeResp:
        def __init__(self, payload):
            self._b = json.dumps(payload).encode()
        def read(self, size=-1):
            return self._b if size < 0 else self._b[:size]
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    calls = []

    def fake_open(req, timeout=None):
        calls.append(req.full_url)
        if "peer-a" in req.full_url:
            return FakeResp({"score": 42, "findings": []})
        raise urllib.error.URLError("down")

    monkeypatch.setattr(urllib.request, "urlopen", fake_open)
    out = ps.fleet_audit()
    assert out["agent_count"] == 2 and out["reachable"] == 1
    assert out["worst_score"] == 42 and out["mean_score"] == 42.0
    assert out["agents"][1]["reachable"] is False


# ── CEF / ECS ────────────────────────────────────────────────────────────────

def test_to_cef_escapes_and_maps():
    from api.notify import to_cef
    line = to_cef({"type": "CUSTOM_RULE", "severity": "critical",
                   "message": "a|b=c\\d", "timestamp": "2024-01-01T00:00:00Z",
                   "details": {"ip": "1.2.3.4", "process": "evil",
                               "pid": 42}}, "1.5.3")
    assert line.startswith("CEF:0|Cognition|Snitch|1.5.3|CUSTOM_RULE|")
    assert "|8|" in line                       # EN: critical→cef 8 / FR: critical→cef 8
    assert "dst=1.2.3.4" in line and "sproc=evil" in line
    assert "\\\\" in line or "\\|" in line or "\\=" in line   # EN: escaped / FR: échappé


def test_to_cef_header_pipes_escaped():
    from api.notify import _cef_escape
    assert _cef_escape("a|b", header=True) == "a\\|b"
    assert _cef_escape("a=b") == "a\\=b"


# ── YARA-L export / export YARA-L ────────────────────────────────────────────

def test_yaral_single_rule():
    from detection import yaral
    out = yaral.export([{"id": "r1", "name": "bad c2", "severity": "critical",
                         "field": "remote_ip", "op": "cidr",
                         "value": "10.0.0.0/8"}])
    assert "rule snitch_r1" in out
    assert 'net.ip_in_range_cidr($e.target.ip, "10.0.0.0/8")' in out
    assert 'severity = "CRITICAL"' in out


def test_yaral_conds_and():
    from detection import yaral
    out = yaral.export([{"id": "s1", "name": "multi", "severity": "warning",
                         "conds": [
                             {"field": "remote_port", "op": "eq",
                              "value": "4444"},
                             {"field": "host", "op": "contains",
                              "value": "evil.com"}]}])
    assert "$e.target.port = 4444" in out and " and\n" in out
    assert "network.tls.client.server_name" in out
    assert "network.dns.questions.name" in out


def test_yaral_unmappable_skipped_honestly():
    from detection import yaral
    out = yaral.export([{"id": "x", "name": "nope", "severity": "info",
                         "field": "direction", "op": "contains",
                         "value": "y"}])
    assert "// SKIPPED rule 'nope'" in out
    assert "rule snitch_x {" not in out


def test_yaral_numeric_fields_unquoted():
    from detection import yaral
    out = yaral.export([{"id": "n", "name": "p", "severity": "info",
                         "field": "remote_port", "op": "gt",
                         "value": "1024"}])
    assert "$e.target.port > 1024" in out


# ── Agent ingest / ingestion d'agent ─────────────────────────────────────────

def test_ingest_events_endpoint():
    import pytest
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from api.main import app
    from api.security import API_TOKEN
    c = TestClient(app)
    r = c.post("/ingest/events",
               headers={"X-Snitch-Token": API_TOKEN},
               json={"agent": "snitch-agent/1", "host": "a1",
                     "events": [{"src_ip": "10.0.0.5", "dst_ip": "93.184.216.34",
                                 "src_port": 51000, "dst_port": 443,
                                 "proto": "tcp", "direction": "out"}]})
    assert r.status_code == 200
    assert r.json()["accepted"] == 1


def test_ingest_events_auth_required():
    import pytest
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from api.main import app
    c = TestClient(app)
    r = c.post("/ingest/events", json={"events": []})
    assert r.status_code in (401, 403)


def test_ingest_events_bounded_and_validated():
    import pytest
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from api.main import app
    from api.security import API_TOKEN
    c = TestClient(app)
    r = c.post("/ingest/events",
               headers={"X-Snitch-Token": API_TOKEN},
               json={"agent": "x", "host": "h",
                     "events": [{"dst_ip": ""},        # EN: dropped / FR: rejeté
                                "not-a-dict",          # EN: dropped / FR: rejeté
                                {"dst_ip": "8.8.8.8", "dst_port": "junk"}]})
    body = r.json()
    assert body["accepted"] == 1                        # EN: only the valid one / FR: seul le valide
    assert body["received"] == 3


def test_ingest_enroll_and_agent_token():
    # EN: Master enrolls an agent → returns a one-shot sagt_ token; the
    #     agent then ingests with X-Snitch-Agent and its enrolled name is
    #     authoritative. Revoking removes the token hash → 401 again.
    # FR: Le maître enrôle un agent → jeton sagt_ one-shot ; l'agent ingère
    #     ensuite avec X-Snitch-Agent et son nom enrôlé fait foi. La
    #     révocation supprime le hash → 401.
    import pytest
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient
    from api.main import app
    from api.security import API_TOKEN
    c = TestClient(app)
    auth = {"X-Snitch-Token": API_TOKEN}

    # EN: enroll requires the master token / FR: enrôlement = jeton maître
    assert c.post("/ingest/enroll", json={"name": "edge-1"}).status_code in (401, 403)
    r = c.post("/ingest/enroll", headers=auth, json={"name": "edge-1"})
    assert r.status_code == 200
    tok = r.json()["token"]
    assert tok.startswith("sagt_")

    # EN: duplicate name rejected / FR: nom dupliqué rejeté
    assert c.post("/ingest/enroll", headers=auth,
                  json={"name": "edge-1"}).status_code == 409

    # EN: agent token ingests, master-free / FR: le jeton agent ingère sans maître
    r = c.post("/ingest/events", headers={"X-Snitch-Agent": tok},
               json={"agent": "snitch-agent/1", "host": "spoofed",
                     "events": [{"dst_ip": "8.8.8.8", "dst_port": 443,
                                 "proto": "tcp"}]})
    # EN: enrolled name is authoritative, not the body's claimed host
    # FR: le nom enrôlé fait foi, pas le host déclaré dans le corps
    assert r.status_code == 200 and r.json()["host"] == "edge-1"

    # EN: list + revoke / FR: liste + révocation
    assert "edge-1" in c.get("/ingest/agents", headers=auth).json()["agents"]
    c.post("/ingest/revoke", headers=auth, json={"name": "edge-1"})
    r = c.post("/ingest/events", headers={"X-Snitch-Agent": tok},
               json={"events": []})
    assert r.status_code in (401, 403)


def test_feeds_setting_bounded():
    # EN: ti_feeds is a plain setting — the loop only reads it; verify a
    #     path-feed import works end-to-end through the shared importer.
    # FR: ti_feeds est un réglage simple — la boucle ne fait que le lire ;
    #     on vérifie l'import de flux `path:` de bout en bout via
    #     l'importeur partagé.
    import pytest
    pytest.importorskip("httpx")
    from api.main import _import_blocklist_text
    added, skipped, parsed, truncated = _import_blocklist_text(
        "8.8.8.8\n# comment\n1.1.1.1\n10.0.0.1\n", "ip", "block", 5000)
    assert parsed == 2                    # EN: private IP filtered / FR: IP privée filtrée
    assert added >= 0 and not truncated
