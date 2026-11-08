"""
EN: Unit tests for ThreatFox C2 feed parser, presets, and integration.
FR: Tests unitaires pour le parseur de flux C2 ThreatFox, préréglages et intégration.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.main import _import_blocklist_text, app, fw
from api.security import API_TOKEN
from detection import blocklist


SAMPLE_THREATFOX_CSV = """################################################################
# ThreatFox IOC export (CSV)                                   #
# Last updated: 2026-11-08 12:00:00 UTC                         #
#                                                              #
# Terms of Use: https://threatfox.abuse.ch/faq/#tos             #
################################################################
#
# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","reporter","reference","tags"
"2026-11-08 10:00:00","101","194.26.29.112:8080","ip:port","botnet_cc","win.cobalt_strike","Cobalt Strike","Cobalt Strike","2026-11-08 10:00:00","100","abuse_ch","","CobaltStrike,C2"
"2026-11-08 10:05:00","102","c2.sliver-command.org:443","domain:port","botnet_cc","win.sliver","Sliver C2","Sliver","2026-11-08 10:05:00","90","abuse_ch","","Sliver,C2"
"2026-11-08 10:10:00","103","192.168.1.100:8000","ip:port","botnet_cc","win.cobalt_strike","Cobalt Strike","Cobalt Strike","2026-11-08 10:10:00","100","abuse_ch","","CobaltStrike"
"2026-11-08 10:15:00","104","10.0.0.5:443","ip:port","botnet_cc","win.cobalt_strike","Cobalt Strike","Cobalt Strike","2026-11-08 10:15:00","100","abuse_ch","","CobaltStrike"
"2026-11-08 10:20:00","105","bad-beacon.com","domain","botnet_cc","win.asyncrat","AsyncRAT","AsyncRAT","2026-11-08 10:20:00","50","abuse_ch","","AsyncRAT"
"2026-11-08 10:25:00","106","44d88612fea8a8f36de82e1278abb02f","md5_hash","payload_delivery","win.redline","RedLine","RedLine","2026-11-08 10:25:00","100","abuse_ch","","RedLine"
"2026-11-08 10:30:00","107","http://185.220.101.5:80/payload.exe","url","payload_delivery","win.redline","RedLine","RedLine","2026-11-08 10:30:00","85","abuse_ch","","RedLine"
"2026-11-08 10:35:00","108","https://dl.malicious-stage.net:8443/beacon","url","payload_delivery","win.cobalt_strike","Cobalt Strike","Cobalt Strike","2026-11-08 10:35:00","95","abuse_ch","","CobaltStrike"
"2026-11-08 10:40:00","109","194.26.29.112:8080","ip:port","botnet_cc","win.cobalt_strike","Cobalt Strike","Cobalt Strike","2026-11-08 10:40:00","100","abuse_ch","","Duplicate"
"""


SAMPLE_THREATFOX_JSON = {
    "query_status": "ok",
    "data": [
        {
            "id": "201",
            "ioc": "185.196.220.14:9001",
            "ioc_type": "ip:port",
            "threat_type": "botnet_cc",
            "malware": "win.havoc",
            "malware_printable": "Havoc C2",
            "confidence_level": 100,
            "tags": ["Havoc", "C2"],
        },
        {
            "id": "202",
            "ioc": "havoc-listener.org:443",
            "ioc_type": "domain:port",
            "threat_type": "botnet_cc",
            "malware": "win.havoc",
            "malware_printable": "Havoc C2",
            "confidence_level": 90,
            "tags": ["Havoc"],
        },
        {
            "id": "203",
            "ioc": "127.0.0.1:4444",
            "ioc_type": "ip:port",
            "threat_type": "botnet_cc",
            "malware": "win.havoc",
            "malware_printable": "Havoc C2",
            "confidence_level": 100,
            "tags": ["Localhost"],
        },
        {
            "id": "204",
            "ioc": "low-conf.org",
            "ioc_type": "domain",
            "threat_type": "botnet_cc",
            "malware": "win.sliver",
            "malware_printable": "Sliver",
            "confidence_level": 40,
            "tags": ["LowConfidence"],
        },
    ],
}


def test_threatfox_parse_csv_basic():
    """EN: Parse standard ThreatFox CSV export and extract valid IPs & domains."""
    ips, domains = blocklist.parse_threatfox(SAMPLE_THREATFOX_CSV)
    # Check IPs: public extracted, private (192.168.1.100, 10.0.0.5) skipped, duplicates deduped
    assert ips == ["194.26.29.112", "185.220.101.5"]
    # Check domains: valid extracted, hashes skipped
    assert domains == ["c2.sliver-command.org", "bad-beacon.com", "dl.malicious-stage.net"]


def test_threatfox_parse_private_and_local_skipped():
    """EN: Private/reserved IPs and localhost domains are never emitted."""
    raw = (
        '# "id","ioc","ioc_type","threat_type","malware","confidence_level"\n'
        '100,"127.0.0.1:80","ip:port","botnet_cc","win.cobalt_strike",100\n'
        '101,"10.1.2.3:443","ip:port","botnet_cc","win.cobalt_strike",100\n'
        '102,"172.16.5.6:8080","ip:port","botnet_cc","win.cobalt_strike",100\n'
        '103,"192.168.0.1:8080","ip:port","botnet_cc","win.cobalt_strike",100\n'
        '104,"localhost:8080","domain:port","botnet_cc","win.cobalt_strike",100\n'
        '105,"test.localhost","domain","botnet_cc","win.cobalt_strike",100\n'
        '106,"broadcasthost","domain","botnet_cc","win.cobalt_strike",100\n'
        '107,"8.8.8.8:53","ip:port","botnet_cc","win.cobalt_strike",100\n'
    )
    ips, domains = blocklist.parse_threatfox(raw)
    assert ips == ["8.8.8.8"]
    assert domains == []


def test_threatfox_parse_hashes_skipped():
    """EN: MD5/SHA256 hashes must be ignored (firewall rules only take IP/domain)."""
    raw = (
        '1,"44d88612fea8a8f36de82e1278abb02f","md5_hash","payload_delivery","win.redline",,,100\n'
        '2,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","sha256_hash","payload_delivery","win.redline",,,100\n'
    )
    ips, domains = blocklist.parse_threatfox(raw)
    assert ips == []
    assert domains == []


def test_threatfox_parse_malware_filter():
    """EN: Filter indicators by malware family name or tag."""
    # Filter for Cobalt Strike only
    ips_cs, domains_cs = blocklist.parse_threatfox(SAMPLE_THREATFOX_CSV, malware="cobalt_strike")
    assert ips_cs == ["194.26.29.112"]
    assert domains_cs == ["dl.malicious-stage.net"]

    # Filter for Sliver only
    ips_sl, domains_sl = blocklist.parse_threatfox(SAMPLE_THREATFOX_CSV, malware="sliver")
    assert ips_sl == []
    assert domains_sl == ["c2.sliver-command.org"]

    # Filter for multiple malware families
    ips_multi, domains_multi = blocklist.parse_threatfox(
        SAMPLE_THREATFOX_CSV, malware=["sliver", "asyncrat"]
    )
    assert ips_multi == []
    assert domains_multi == ["c2.sliver-command.org", "bad-beacon.com"]


def test_threatfox_parse_confidence_and_threat_type_filter():
    """EN: Test min_confidence and threat_type filtering."""
    # min_confidence = 75: bad-beacon.com (conf 50) is excluded
    _, domains_conf = blocklist.parse_threatfox(SAMPLE_THREATFOX_CSV, min_confidence=75)
    assert "bad-beacon.com" not in domains_conf
    assert "c2.sliver-command.org" in domains_conf

    # threat_type = "botnet_cc": payload_delivery URLs excluded
    ips_c2, domains_c2 = blocklist.parse_threatfox(SAMPLE_THREATFOX_CSV, threat_type="botnet_cc")
    assert ips_c2 == ["194.26.29.112"]
    assert domains_c2 == ["c2.sliver-command.org", "bad-beacon.com"]


def test_threatfox_parse_json_formats():
    """EN: Parse ThreatFox JSON export structure."""
    text = json.dumps(SAMPLE_THREATFOX_JSON)
    ips, domains = blocklist.parse_threatfox(text)
    assert ips == ["185.196.220.14"]
    assert domains == ["havoc-listener.org", "low-conf.org"]

    # Test JSON list directly
    text_list = json.dumps(SAMPLE_THREATFOX_JSON["data"])
    ips2, domains2 = blocklist.parse_threatfox(text_list, min_confidence=80)
    assert ips2 == ["185.196.220.14"]
    assert domains2 == ["havoc-listener.org"]


def test_threatfox_convenience_functions():
    """EN: Test parse_threatfox_ips and parse_threatfox_domains."""
    ips = blocklist.parse_threatfox_ips(SAMPLE_THREATFOX_CSV)
    assert ips == ["194.26.29.112", "185.220.101.5"]

    domains = blocklist.parse_threatfox_domains(SAMPLE_THREATFOX_CSV)
    assert domains == ["c2.sliver-command.org", "bad-beacon.com", "dl.malicious-stage.net"]


def test_threatfox_presets_registered():
    """EN: Verify that built-in presets are registered with proper metadata."""
    assert "threatfox" in blocklist.PRESETS
    assert "threatfox_ip" in blocklist.PRESETS
    assert "threatfox_domain" in blocklist.PRESETS
    assert "threatfox_json" in blocklist.PRESETS

    tf = blocklist.PRESETS["threatfox"]
    assert tf["url"] == blocklist.THREATFOX_RECENT_CSV_URL
    assert tf["kind"] == "threatfox"
    assert tf["action"] == "block"
    assert tf["license"] == "CC0"
    assert tf["hours"] == 12


def test_import_blocklist_text_threatfox_integration():
    """EN: Test _import_blocklist_text with kind='threatfox' importing both IP & domain rules."""
    added, skipped, parsed, truncated = _import_blocklist_text(
        SAMPLE_THREATFOX_CSV, "threatfox", "block", 500
    )
    assert parsed == 5  # 2 IPs + 3 Domains
    assert added >= 0
    assert not truncated

    # Test threatfox_ip kind
    added_ip, _, parsed_ip, _ = _import_blocklist_text(
        SAMPLE_THREATFOX_CSV, "threatfox_ip", "block", 500
    )
    assert parsed_ip == 2

    # Test threatfox_domain kind
    added_dom, _, parsed_dom, _ = _import_blocklist_text(
        SAMPLE_THREATFOX_CSV, "threatfox_domain", "block", 500
    )
    assert parsed_dom == 3


def test_api_firewall_presets_endpoint():
    """EN: GET /firewall/presets returns available presets list."""
    client = TestClient(app)
    resp = client.get("/firewall/presets", headers={"X-Snitch-Token": API_TOKEN})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert "threatfox" in data["presets"]
    assert data["presets"]["threatfox"]["license"] == "CC0"


def test_api_firewall_blocklist_preset_resolution(monkeypatch):
    """EN: POST /firewall/blocklist resolves preset='threatfox'."""
    client = TestClient(app)

    # Mock fetch_url to return our sample CSV without network access
    monkeypatch.setattr(blocklist, "fetch_url", lambda url: SAMPLE_THREATFOX_CSV)

    resp = client.post(
        "/firewall/blocklist",
        headers={"X-Snitch-Token": API_TOKEN},
        json={"preset": "threatfox", "action": "block", "max_entries": 100},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["remote_fetch"] is True
    assert data["kind"] == "threatfox"
    assert data["parsed"] == 5
    assert data["added"] >= 0
