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
        def read(self):
            return self._b
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
