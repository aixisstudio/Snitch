"""
EN: Unit tests for the NetAPI compromised-IP preset (keyless `ip` feed).
FR: Tests unitaires du préréglage NetAPI compromised-IP (flux `ip` sans clé).
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from api.main import app
from api.security import API_TOKEN
from detection import blocklist


# EN: Shape of the live feed: one `#` comment line, then one IPv4 per line.
# FR: Forme du flux réel : une ligne de commentaire `#`, puis une IPv4 par ligne.
SAMPLE_NETAPI_IPS = """# NetAPI.com - compromised IPs, custom list (2026-11-18 12:37 UTC), 4 addresses. Source: https://netapi.com/compromised-ips/ (CC BY 4.0).
1.165.7.108
45.148.10.81
192.168.1.20
45.148.10.81
"""


def test_netapi_preset_registered():
    """EN: The preset is registered with the expected metadata.
    FR: Le préréglage est enregistré avec les métadonnées attendues."""
    p = blocklist.PRESETS["netapi_compromised"]
    assert p["url"] == blocklist.NETAPI_COMPROMISED_IP_URL
    assert p["url"].startswith("https://netapi.com/api2/")
    assert "dataset_type=ip" in p["url"] and "category=A" in p["url"]
    assert p["kind"] == "ip"
    assert p["action"] == "block"
    assert p["hours"] == 12
    assert p["license"] == "CC BY 4.0"
    assert "auth_key" not in p


def test_netapi_parse_skips_comment_private_and_duplicates():
    """EN: parse_ips() drops the `#` header, the private address and the repeat.
    FR: parse_ips() ignore l'en-tête `#`, l'adresse privée et le doublon."""
    assert blocklist.parse_ips(SAMPLE_NETAPI_IPS) == ["1.165.7.108", "45.148.10.81"]


def test_api_firewall_presets_lists_netapi():
    """EN: GET /firewall/presets exposes the preset.
    FR: GET /firewall/presets expose le préréglage."""
    client = TestClient(app)
    resp = client.get("/firewall/presets", headers={"X-Snitch-Token": API_TOKEN})
    assert resp.status_code == 200
    preset = resp.json()["presets"]["netapi_compromised"]
    assert preset["kind"] == "ip"
    assert preset["license"] == "CC BY 4.0"


def test_api_firewall_blocklist_netapi_preset_resolution(monkeypatch):
    """EN: POST /firewall/blocklist with preset='netapi_compromised' fetches the
    preset URL without an Auth-Key and imports `ip` rules.
    FR: POST /firewall/blocklist avec preset='netapi_compromised' récupère l'URL
    du préréglage sans Auth-Key et importe des règles `ip`."""
    calls: list[tuple[str, str]] = []

    def fake_fetch(url: str, auth_key: str = "") -> str:
        calls.append((url, auth_key))
        return SAMPLE_NETAPI_IPS

    monkeypatch.setattr(blocklist, "fetch_url", fake_fetch)
    client = TestClient(app)
    resp = client.post(
        "/firewall/blocklist",
        headers={"X-Snitch-Token": API_TOKEN},
        json={"preset": "netapi_compromised", "action": "block", "max_entries": 100},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["remote_fetch"] is True
    assert data["kind"] == "ip"
    assert data["parsed"] == 2
    assert calls == [(blocklist.NETAPI_COMPROMISED_IP_URL, "")]
