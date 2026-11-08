"""
EN: Unit tests for passive TLS ClientHello fingerprinting (JA3 / JA4) and C2 detection.
FR: Tests unitaires pour l'empreinte TLS ClientHello passive (JA3 / JA4) et la détection C2.
"""

from __future__ import annotations

import struct

from fastapi.testclient import TestClient
import pytest

from api.main import app
from api.security import API_TOKEN
from capture.parser import parse_tls_client_hello, parse_tls_sni
from capture.sniffer import Packet
from detection import c2_fingerprints
from detection.customrules import CustomRules


def build_synthetic_client_hello(
    sni: str | None = "c2.adversary.org",
    ciphers: list[int] | None = None,
    groups: list[int] | None = None,
    point_formats: list[int] | None = None,
    alpn_protocols: list[str] | None = None,
    include_grease: bool = False,
    tls_version: int = 0x0303,
) -> bytes:
    """EN: Helper creating valid TLS ClientHello wire bytes for hermetic testing.
    FR: Utilitaire créant des octets ClientHello TLS valides pour les tests hermétiques."""
    if ciphers is None:
        ciphers = [0xC02F, 0xC030]  # ECDHE-RSA-AES128-GCM-SHA256, ECDHE-RSA-AES256-GCM-SHA384
    if groups is None:
        groups = [0x001D, 0x0017]  # x25519, secp256r1
    if point_formats is None:
        point_formats = [0]  # uncompressed
    if alpn_protocols is None:
        alpn_protocols = ["h2", "http/1.1"]

    extensions_parts: list[bytes] = []

    # SNI extension 0x0000
    if sni is not None:
        sni_raw = sni.encode("ascii")
        sni_data = struct.pack("!HHB", len(sni_raw) + 3, 0, len(sni_raw)) + sni_raw
        extensions_parts.append(struct.pack("!HH", 0x0000, len(sni_data)) + sni_data)

    # Supported groups 0x000a
    groups_list = list(groups)
    if include_grease:
        groups_list.insert(0, 0x2A2A)
    groups_data = struct.pack("!H", len(groups_list) * 2) + b"".join(
        struct.pack("!H", g) for g in groups_list
    )
    extensions_parts.append(struct.pack("!HH", 0x000A, len(groups_data)) + groups_data)

    # EC point formats 0x000b
    pf_list = list(point_formats)
    pf_data = struct.pack("!B", len(pf_list)) + bytes(pf_list)
    extensions_parts.append(struct.pack("!HH", 0x000B, len(pf_data)) + pf_data)

    # ALPN extension 0x0010
    if alpn_protocols:
        alpn_buf = bytearray()
        for proto in alpn_protocols:
            p_bytes = proto.encode("ascii")
            alpn_buf.append(len(p_bytes))
            alpn_buf.extend(p_bytes)
        alpn_data = struct.pack("!H", len(alpn_buf)) + bytes(alpn_buf)
        extensions_parts.append(struct.pack("!HH", 0x0010, len(alpn_data)) + alpn_data)

    # GREASE extension
    if include_grease:
        extensions_parts.insert(0, struct.pack("!HH", 0x1A1A, 0))

    exts_payload = b"".join(extensions_parts)
    exts_block = struct.pack("!H", len(exts_payload)) + exts_payload

    c_list = list(ciphers)
    if include_grease:
        c_list.insert(0, 0x0A0A)
    ciphers_block = struct.pack("!H", len(c_list) * 2) + b"".join(
        struct.pack("!H", c) for c in c_list
    )
    comp_block = b"\x01\x00"

    # ClientHello body: Version(2) + Random(32) + SessionId(1 + 0) + Ciphers + Comp + Exts
    ch_body = (
        struct.pack("!H", tls_version)
        + (b"\xaa" * 32)
        + b"\x00"
        + ciphers_block
        + comp_block
        + exts_block
    )

    # Handshake: Type(1=ClientHello) + Length(3) + Body
    handshake = struct.pack("!B", 0x01) + struct.pack("!I", len(ch_body))[1:] + ch_body

    # TLS Record: Type(0x16) + Version(0x0301) + Length(2) + Handshake
    record = struct.pack("!BBBH", 0x16, 0x03, 0x01, len(handshake)) + handshake
    return record


class TestPassiveTlsParser:
    """EN: Test ClientHello parsing, JA3 hash, and JA4 string generation.
    FR: Test de l'analyse ClientHello, du hash JA3 et de la chaîne JA4."""

    def test_parse_tls_client_hello_synthetic(self) -> None:
        rec = build_synthetic_client_hello(sni="malicious-c2.org")
        sni, ja3, ja4 = parse_tls_client_hello(rec)

        assert sni == "malicious-c2.org"
        assert ja3 is not None
        assert len(ja3) == 32  # MD5 hex
        assert all(c in "0123456789abcdef" for c in ja3)

        assert ja4 is not None
        assert ja4.startswith("t12d")  # TCP, TLS 1.2, domain SNI
        parts = ja4.split("_")
        assert len(parts) == 3
        assert len(parts[1]) == 12  # 12-char SHA256 of ciphers
        assert len(parts[2]) == 12  # 12-char SHA256 of extensions

    def test_grease_filtered_cleanly(self) -> None:
        rec_clean = build_synthetic_client_hello(include_grease=False)
        rec_grease = build_synthetic_client_hello(include_grease=True)

        s1, ja3_1, ja4_1 = parse_tls_client_hello(rec_clean)
        s2, ja3_2, ja4_2 = parse_tls_client_hello(rec_grease)

        assert s1 == s2
        assert ja3_1 == ja3_2, "GREASE ciphers/exts/curves must be filtered from JA3"
        assert ja4_1 == ja4_2, "GREASE ciphers/exts/curves must be filtered from JA4"

    def test_ja4_sni_flag_domain_vs_ip_vs_none(self) -> None:
        # Domain SNI
        rec_dom = build_synthetic_client_hello(sni="beacon.sliver.sh")
        _, _, ja4_dom = parse_tls_client_hello(rec_dom)
        assert ja4_dom is not None and ja4_dom[3] == "d"

        # IP SNI
        rec_ip = build_synthetic_client_hello(sni="194.26.29.112")
        _, _, ja4_ip = parse_tls_client_hello(rec_ip)
        assert ja4_ip is not None and ja4_ip[3] == "i"

        # No SNI
        rec_no_sni = build_synthetic_client_hello(sni=None)
        _, _, ja4_no_sni = parse_tls_client_hello(rec_no_sni)
        assert ja4_no_sni is not None and ja4_no_sni[3] == "i"

    def test_ja4_alpn_representation(self) -> None:
        rec_h2 = build_synthetic_client_hello(alpn_protocols=["h2"])
        _, _, ja4_h2 = parse_tls_client_hello(rec_h2)
        assert ja4_h2 is not None and ja4_h2.split("_")[0].endswith("h2")

        rec_http1 = build_synthetic_client_hello(alpn_protocols=["http/1.1"])
        _, _, ja4_http1 = parse_tls_client_hello(rec_http1)
        assert ja4_http1 is not None and ja4_http1.split("_")[0].endswith("h1")

        rec_none = build_synthetic_client_hello(alpn_protocols=[])
        _, _, ja4_none = parse_tls_client_hello(rec_none)
        assert ja4_none is not None and ja4_none.split("_")[0].endswith("00")

    def test_malformed_and_non_tls_payloads(self) -> None:
        assert parse_tls_client_hello(b"") == (None, None, None)
        assert parse_tls_client_hello(b"GET / HTTP/1.1\r\n\r\n") == (None, None, None)
        assert parse_tls_client_hello(b"\x16\x03\x01\x00\x05\x01") == (None, None, None)

    def test_parse_tls_sni_backward_compat(self) -> None:
        rec = build_synthetic_client_hello(sni="cobalt.target.com")
        assert parse_tls_sni(rec) == "cobalt.target.com"
        assert parse_tls_sni(b"garbage") is None


class TestC2FingerprintsDatabase:
    """EN: Test C2 profiles lookup, list, and reload.
    FR: Test de la recherche de profils C2, de la liste et du rechargement."""

    def test_list_fingerprints_contains_profiles(self) -> None:
        fps = c2_fingerprints.list_fingerprints()
        assert len(fps) >= 10
        frameworks = {fp.get("framework") for fp in fps}
        assert "Cobalt Strike" in frameworks
        assert "Sliver" in frameworks
        assert "Havoc" in frameworks

        for fp in fps:
            assert "name" in fp
            assert "framework" in fp
            assert fp.get("severity") in ("critical", "warning", "info")
            assert fp.get("confidence", 0) >= 50
            assert "source" in fp and fp["source"]
            assert "provenance" in fp and fp["provenance"]
            assert "ja3" in fp or "ja4" in fp

    def test_lookup_c2_by_known_ja3(self) -> None:
        # Cobalt Strike default malleable profile JA3
        match = c2_fingerprints.lookup_c2(ja3="a0e9f5d64349fb13191bc781f81f42e1")
        assert match is not None
        assert match["framework"] == "Cobalt Strike"
        assert match["severity"] == "critical"
        assert "source" in match
        assert "provenance" in match

    def test_lookup_c2_by_known_ja4(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Verify JA4 lookup logic against an auditable profile
        test_profile = {
            "name": "Test-C2-JA4",
            "framework": "Cobalt Strike",
            "threat_type": "botnet_cc",
            "ja3": None,
            "ja4": "t13d1516h2_8daaf6152771_b09938846cad",
            "confidence": 95,
            "severity": "critical",
            "source": "Verified Test Profile",
            "provenance": "Synthetic test fixture",
        }
        monkeypatch.setattr(c2_fingerprints, "_JA4_MAP", {"t13d1516h2_8daaf6152771_b09938846cad": test_profile})
        match = c2_fingerprints.lookup_c2(ja4="t13d1516h2_8daaf6152771_b09938846cad")
        assert match is not None
        assert match["framework"] == "Cobalt Strike"
        assert match["name"] == "Test-C2-JA4"
        # Test case insensitivity on JA4
        upper_match = c2_fingerprints.lookup_c2(ja4="T13D1516H2_8DAAF6152771_B09938846CAD")
        assert upper_match == match

    def test_lookup_case_insensitivity(self) -> None:
        match = c2_fingerprints.lookup_c2(ja3="A0E9F5D64349FB13191BC781F81F42E1")
        assert match is not None
        assert match["framework"] == "Cobalt Strike"

    def test_lookup_unknown_returns_none(self) -> None:
        match = c2_fingerprints.lookup_c2(
            ja3="00000000000000000000000000000000",
            ja4="t13d000000_000000000000_000000000000",
        )
        assert match is None

    def test_reload_fingerprints(self) -> None:
        loaded = c2_fingerprints.reload_fingerprints()
        assert loaded >= 10


class TestCustomRulesWithJa3Ja4:
    """EN: Test custom rules matching on ja3 and ja4 packet fields.
    FR: Test des règles personnalisées correspondant aux champs ja3 et ja4."""

    def test_custom_rule_ja3_matching(self) -> None:
        rules = CustomRules()
        rules.add(
            name="Block-Cobalt-JA3",
            field="ja3",
            op="eq",
            value="a0e9f5d64349fb13191bc781f81f42e1",
            severity="critical",
            action="alert",
        )

        hit_pkt = Packet(
            src_ip="192.168.1.50",
            dst_ip="198.51.100.22",
            src_port=52341,
            dst_port=443,
            remote_port=443,
            protocol="TCP",
            size=512,
            timestamp="2026-11-08T12:00:00Z",
            direction="out",
            ja3="a0e9f5d64349fb13191bc781f81f42e1",
        )
        miss_pkt = Packet(
            src_ip="192.168.1.50",
            dst_ip="198.51.100.22",
            src_port=52341,
            dst_port=443,
            remote_port=443,
            protocol="TCP",
            size=512,
            timestamp="2026-11-08T12:00:00Z",
            direction="out",
            ja3="b1f9f5d64349fb13191bc781f81f42e2",
        )

        matches_hit = rules.check(hit_pkt, None)
        assert len(matches_hit) == 1
        assert matches_hit[0]["rule"]["name"] == "Block-Cobalt-JA3"

        matches_miss = rules.check(miss_pkt, None)
        assert len(matches_miss) == 0

    def test_custom_rule_ja4_regex_and_contains(self) -> None:
        rules = CustomRules()
        rules.add(
            name="Flag-JA4-Prefix",
            field="ja4",
            op="contains",
            value="t12d",
            severity="warning",
            action="alert",
        )

        pkt = Packet(
            src_ip="192.168.1.50",
            dst_ip="198.51.100.33",
            src_port=52342,
            dst_port=443,
            remote_port=443,
            protocol="TCP",
            size=512,
            timestamp="2026-11-08T12:00:00Z",
            direction="out",
            ja4="t12d190800_210d3224b898_a4b9c1d2e3f4",
        )

        matches = rules.check(pkt, None)
        assert len(matches) == 1
        assert matches[0]["rule"]["name"] == "Flag-JA4-Prefix"


class TestApiC2Endpoints:
    """EN: Test FastAPI REST endpoints for C2 fingerprints and alert rule fields.
    FR: Test des endpoints REST FastAPI pour les empreintes C2 et les champs de règles."""

    @pytest.fixture
    def client(self) -> TestClient:
        return TestClient(app)

    def test_get_c2_fingerprints_authenticated(self, client: TestClient) -> None:
        resp = client.get("/c2/fingerprints", headers={"X-Snitch-Token": API_TOKEN})
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["count"] >= 10
        assert isinstance(data["fingerprints"], list)

    def test_get_c2_fingerprints_alias(self, client: TestClient) -> None:
        resp = client.get(
            "/security/c2/fingerprints", headers={"X-Snitch-Token": API_TOKEN}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["count"] >= 10

    def test_post_c2_fingerprints_reload(self, client: TestClient) -> None:
        resp = client.post(
            "/c2/fingerprints/reload", headers={"X-Snitch-Token": API_TOKEN}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["count"] >= 10

    def test_c2_fingerprints_requires_auth(self, client: TestClient) -> None:
        resp = client.get("/c2/fingerprints")
        assert resp.status_code == 401

    def test_alerts_rules_fields_include_ja3_and_ja4(self, client: TestClient) -> None:
        resp = client.get("/alerts/rules", headers={"X-Snitch-Token": API_TOKEN})
        assert resp.status_code == 200
        data = resp.json()
        fields = data.get("fields", [])
        assert "ja3" in fields
        assert "ja4" in fields

    def test_c2_suspect_explain_bilingual(self) -> None:
        from detection.explain import explain

        rec = explain("C2_SUSPECT")
        assert rec is not None
        assert "C2" in rec["title_en"]
        assert "C2" in rec["title_fr"]
        assert rec["what_en"] and rec["what_fr"]
        assert len(rec["actions_en"]) >= 3
        assert len(rec["actions_fr"]) >= 3
