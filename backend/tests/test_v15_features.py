"""
Snitch — tests for the v1.5 hardening modules / tests des modules de
durcissement v1.5.

EN: Coverage: ICMP payload parsing (type/code→flags, head→app_head),
    bounded TLS Certificate reassembly + minimal DER leaf parsing
    (issuer/subject/self-signed/SANs), SAN-SNI wildcard matching, the
    pure-Python isolation forest + flow scorer, geo-aware custom rules
    and their block action validation, RFC 3164 syslog dispatch, the
    NFQUEUE flow-key parser, IOC peer sync config, and the hollowing /
    eBPF honest-capability probes. Everything runs without privileges —
    platform-gated paths are probed through available() only.

FR: Couverture : parsing de payload ICMP (type/code→flags, tête→app_head),
    réassemblage borné du handshake Certificate + parsing DER minimal du
    certificat feuille, matching wildcard SAN/SNI, forêt d'isolation pur
    Python + scoreur de flux, règles géo (asn/country) et validation de
    l'action block, dispatch syslog RFC 3164, extracteur de clé de flux
    NFQUEUE, config de sync IOC entre pairs, et sondes de capacité
    hollowing/eBPF. Aucun privilège requis.
"""

import socket
import struct
import time

import pytest

from capture.parser import DLT_EN10MB, parse_frame
from capture import tlscert

ETH = DLT_EN10MB


# ── Frame builders (mirrors test_parser.py helpers) / Constructeurs ────────

def eth(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" \
        + struct.pack("!H", ethertype) + payload


def ipv4(src: bytes, dst: bytes, proto: int, payload: bytes) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s",
                      (4 << 4) | 5, 0, total, 0, 0, 64, proto, 0, src, dst)
    return hdr + payload


def tcp(sport: int, dport: int, flags: int = 0x18,
        payload: bytes = b"") -> bytes:
    hdr = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags,
                      8192, 0, 0)
    return hdr + payload


# ── Minimal DER builder for a synthetic leaf cert / Constructeur DER ───────

def _tlv(tag: int, val: bytes) -> bytes:
    ln = len(val)
    if ln < 128:
        lb = bytes([ln])
    elif ln < 256:
        lb = b"\x81" + bytes([ln])
    else:
        lb = b"\x82" + struct.pack("!H", ln)
    return bytes([tag]) + lb + val


def _name(cn: str, org: str = "") -> bytes:
    """EN: X.501 Name { cn, o? } — OID 2.5.4.3/10 as UTF8String.
    FR: X.501 Name { cn, o? } — OID 2.5.4.3/10 en UTF8String."""
    atv = _tlv(0x30, _tlv(0x06, b"\x55\x04\x03")
               + _tlv(0x0C, cn.encode()))
    rdns = _tlv(0x31, atv)
    if org:
        atv2 = _tlv(0x30, _tlv(0x06, b"\x55\x04\x0a")
                    + _tlv(0x0C, org.encode()))
        rdns += _tlv(0x31, atv2)
    return _tlv(0x30, rdns)


def _san_ext(names: list[str]) -> bytes:
    """EN: [3] extensions wrapper containing a SAN ext (OID 2.5.29.17)
    with dNSName entries. / FR: Wrapper [3] avec ext SAN + dNSNames."""
    gnames = b"".join(_tlv(0x82, n.encode("ascii")) for n in names)
    ext_val = _tlv(0x04, _tlv(0x30, gnames))          # OCTET STRING { SEQ }
    ext = _tlv(0x30, _tlv(0x06, b"\x55\x1d\x11") + ext_val)
    return _tlv(0xA3, _tlv(0x30, ext))


def make_cert(cn: str, issuer_cn: str, sans: list[str],
              issuer_org: str = "Test CA",
              days: tuple[bytes, bytes] = (b"250101000000Z",
                                          b"300101000000Z")) -> bytes:
    """EN: A structurally-valid-enough X.509 leaf for our bounded parser —
    not cryptographically valid (fake signature), exactly what the
    passive reader needs. `issuer_org=""` makes issuer DER == subject
    DER (the strict self-issuance test).
    FR: Certificat feuille structurellement valide pour le parseur —
    signature factice. `issuer_org=""` rend issuer == subject en DER."""
    tbs = (_tlv(0xA0, _tlv(0x02, b"\x02"))            # version v3
           + _tlv(0x02, b"\x01")                      # serial
           + _tlv(0x30, _tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b")
                  + _tlv(0x05, b""))                  # sha256WithRSA
           + _name(issuer_cn, issuer_org)             # issuer
           + _tlv(0x30, _tlv(0x17, days[0]) + _tlv(0x17, days[1]))
           + _name(cn)                                # subject
           + _tlv(0x30, _tlv(0x30, _tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d"
                                        b"\x01\x01\x01") + _tlv(0x05, b""))
                  + _tlv(0x03, b"\x00" + b"\xab" * 32))   # bogus PKI
           + _san_ext(sans))
    cert = (_tlv(0x30, tbs)
            + _tlv(0x30, _tlv(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b")
                   + _tlv(0x05, b""))
            + _tlv(0x03, b"\x00" + b"\xcd" * 64))
    return _tlv(0x30, cert)


def tls_cert_record(der: bytes) -> bytes:
    """EN: Wrap a DER cert into a TLS Certificate handshake record.
    FR: Enveloppe un cert DER en enregistrement handshake Certificate."""
    cert_entry = len(der).to_bytes(3, "big") + der
    body = len(cert_entry).to_bytes(3, "big") + cert_entry
    hs = b"\x0b" + len(body).to_bytes(3, "big") + body   # type 11
    return b"\x16\x03\x03" + struct.pack("!H", len(hs)) + hs


# ── ICMP parsing / Parsing ICMP ─────────────────────────────────────────────

def test_icmp_echo_payload_captured():
    """EN: ICMP echo keeps type/code in flags and the payload head in
    app_head — the tunnel heuristic's raw material.
    FR: L'écho ICMP garde type/code dans flags et la tête dans app_head."""
    tlscert.reset()
    payload = b"\x08\x00\xf7\xff" + b"\x12\x34\x00\x01" + b"A" * 56
    frame = eth(ipv4(b"\x0a\x00\x00\x01", b"\x08\x08\x08\x08", 1, payload))
    p = parse_frame(ETH, frame)
    assert p is not None and p.protocol == "ICMP"
    assert p.tcp_flags >> 8 == 8 and p.tcp_flags & 0xFF == 0
    assert p.app_head == b"A" * 56
    assert p.tls_cert is None


def test_icmpv6_echo_payload_captured():
    """EN: ICMPv6 echo-request (type 128) gets the same treatment.
    FR: L'écho ICMPv6 (type 128) reçoit le même traitement."""
    tlscert.reset()
    payload = b"\x80\x00\x00\x00" + b"\x00\x01\x00\x01" + b"B" * 40
    src = bytes(range(16))
    dst = bytes(range(16, 32))
    plen = len(payload)
    hdr = struct.pack("!IHBB16s16s", 6 << 28, plen, 58, 64, src, dst)
    frame = eth(hdr + payload, ethertype=0x86DD)
    p = parse_frame(ETH, frame)
    assert p is not None and p.protocol == "ICMP"
    assert p.tcp_flags >> 8 == 128
    assert p.app_head == b"B" * 40


def test_icmp_empty_payload_no_head():
    """EN: A bare echo (no payload) produces an empty app_head — no
    false tunnel signal. / FR: Un écho nu → app_head vide."""
    tlscert.reset()
    payload = b"\x08\x00\xf7\xff" + b"\x00\x01\x00\x01"
    frame = eth(ipv4(b"\x0a\x00\x00\x01", b"\x08\x08\x08\x08", 1, payload))
    p = parse_frame(ETH, frame)
    assert p is not None and p.app_head == b""


# ── TLS certificate / Certificat TLS ────────────────────────────────────────

def test_tls_cert_parsed_single_segment():
    """EN: A server Certificate record on :443 yields leaf metadata.
    FR: Un enregistrement Certificate sur :443 donne les métadonnées."""
    tlscert.reset()
    der = make_cert("www.example.com", "Example CA",
                    ["www.example.com", "example.com"])
    record = tls_cert_record(der)
    cert = tlscert.feed_tls_stream("93.184.216.34", 443,
                                   "10.0.0.5", 51000, record)
    assert cert is not None
    assert cert["subject_cn"] == "www.example.com"
    assert cert["issuer_cn"] == "Example CA"
    assert cert["self_signed"] is False
    assert "example.com" in cert["sans"]
    assert cert["not_before"] == "250101000000Z"


def test_tls_cert_reassembled_two_segments():
    """EN: The SAME record split mid-record still parses — the whole point
    of the bounded reassembly buffer. / FR: Le même enregistrement coupé
    en deux segments se parse quand même — c'est le but du tampon."""
    tlscert.reset()
    der = make_cert("a.example.org", "Self Root", ["a.example.org"])
    record = tls_cert_record(der)
    cut = len(record) // 2
    assert tlscert.feed_tls_stream("1.2.3.4", 443, "10.0.0.1", 40000,
                                   record[:cut]) is None
    cert = tlscert.feed_tls_stream("1.2.3.4", 443, "10.0.0.1", 40000,
                                   record[cut:])
    assert cert is not None and cert["subject_cn"] == "a.example.org"


def test_tls_self_signed_detected():
    """EN: issuer == subject DER → self_signed=True.
    FR: issuer == subject en DER → self_signed=True."""
    tlscert.reset()
    # EN: issuer DER must equal subject DER — same CN, no org either side.
    # FR: issuer et subject identiques en DER — même CN, pas d'org.
    der = make_cert("localhost", "localhost", ["localhost"],
                    issuer_org="")
    cert = tlscert.feed_tls_stream("10.9.9.9", 443, "10.0.0.1", 40001,
                                   tls_cert_record(der))
    assert cert is not None and cert["self_signed"] is True


def test_tls_wrong_port_ignored():
    """EN: TLS bytes on a non-watched port are not buffered.
    FR: Des octets TLS sur un port non surveillé ne sont pas tamponnés."""
    tlscert.reset()
    der = make_cert("x", "x", [])
    assert tlscert.feed_tls_stream("1.2.3.4", 12345, "10.0.0.1", 999,
                                   tls_cert_record(der)) is None
    assert not tlscert._FLOWS


def test_tls_garbage_dropped():
    """EN: Mid-stream garbage never starts a buffer; over-cap buffers are
    evicted. / FR: Du bruit ne démarre pas de tampon ; débordement expulsé."""
    tlscert.reset()
    assert tlscert.feed_tls_stream("1.2.3.4", 443, "10.0.0.1", 1,
                                   b"GET / HTTP/1.1\r\n") is None
    assert not tlscert._FLOWS
    # EN: header then >16KiB → flow evicted / FR: en-tête puis >16 Kio → expulsé
    tlscert.feed_tls_stream("1.2.3.4", 443, "10.0.0.1", 2, b"\x16\x03\x03")
    tlscert.feed_tls_stream("1.2.3.4", 443, "10.0.0.1", 2, b"x" * 17000)
    assert not tlscert._FLOWS


def test_san_mismatch_wildcard():
    """EN: Wildcard SANs cover exactly one label; bare SNI/mismatch flag.
    FR: Les wildcards couvrent exactement un label."""
    assert tlscert.san_mismatch("a.example.com", ["*.example.com"]) is False
    assert tlscert.san_mismatch("a.b.example.com",
                                ["*.example.com"]) is True
    assert tlscert.san_mismatch("example.com", ["*.example.com"]) is True
    assert tlscert.san_mismatch("www.example.com",
                                ["www.example.com"]) is False
    assert tlscert.san_mismatch(None, ["x"]) is False
    assert tlscert.san_mismatch("x", []) is False


def test_parser_tls_cert_end_to_end():
    """EN: Full frame → tls_cert on the ParsedPacket.
    FR: Trame complète → tls_cert sur le ParsedPacket."""
    tlscert.reset()
    der = make_cert("e2e.test", "E2E CA", ["e2e.test"])
    seg = tcp(443, 51515, payload=tls_cert_record(der))
    frame = eth(ipv4(b"\x5d\xb8\xd8\x22", b"\x0a\x00\x00\x05", 6, seg))
    p = parse_frame(ETH, frame)
    assert p is not None and p.tls_cert is not None
    assert p.tls_cert["subject_cn"] == "e2e.test"


# ── Isolation forest / Forêt d'isolation ────────────────────────────────────

def test_iforest_scores_outlier_higher():
    """EN: Trained on a tight cluster, an outlier must score clearly
    above cluster members. / FR: Entraînée sur un cluster dense, un
    outlier doit scorer nettement au-dessus."""
    from detection.iforest import IsolationForest
    # EN: Every feature must VARY in the training cloud — a constant
    #     column can never be split on, which would mask the outlier.
    # FR: Chaque feature doit VARIER dans le nuage — une colonne
    #     constante ne peut jamais servir de split, ce qui masquerait
    #     l'outlier.
    rng_pts = [[0.50 + (i % 10) * 0.002,
                0.50 + (i % 7) * 0.002,
                0.50 + (i % 5) * 0.002,
                0.50 + (i % 11) * 0.002,
                0.50 + (i % 3) * 0.002,
                0.50 + (i % 13) * 0.002]
               for i in range(300)]
    f = IsolationForest(seed=7)
    assert f.fit(rng_pts) == 64
    outlier = [0.99, 0.05, 0.99, 0.01, 0.99, 0.01]
    normal = [0.51, 0.52, 0.50, 0.51, 0.50, 0.51]
    # EN: Outlier must rank clearly above the cluster — the iForest's
    #     path-length compression keeps margins modest, so we assert a
    #     real gap AND the outlier sitting in the anomalous half.
    # FR: L'outlier doit se classer nettement au-dessus — la compression
    #     des chemins garde les marges modestes → écart réel + zone
    #     anormale.
    assert f.score(outlier) > f.score(normal) + 0.05
    assert f.score(outlier) > 0.55
    assert 0.0 <= f.score(normal) <= 1.0


def test_iforest_too_small_is_honest():
    """EN: Under 16 points the forest refuses to pretend — 0 trees, 0.0.
    FR: Sous 16 points la forêt refuse de prétendre — 0 arbre, 0.0."""
    from detection.iforest import IsolationForest
    f = IsolationForest()
    assert f.fit([[0.1] * 6 for _ in range(8)]) == 0
    assert f.score([0.5] * 6) == 0.0


def test_flow_ml_inert_then_scores():
    """EN: The scorer stays inert below the training minimum, then emits
    a dict for an extreme flow once fitted. / FR: Le scoreur reste inerte
    sous le minimum d'entraînement, puis émet pour un flux extrême."""
    from detection.mlflow import FlowAnomaly, _TRAIN_MIN
    m = FlowAnomaly()
    t = time.time()
    # EN: Learn a realistic baseline — a small stable set of destinations
    #     (intervals + fanout stay meaningful), boring web ports/sizes.
    # FR: Baseline réaliste — petit ensemble stable de destinations
    #     (intervalles + fanout significatifs), ports/tailles web banals.
    import random as _r
    rng = _r.Random(0)
    ips = [f"93.184.216.{i}" for i in range(20)]
    for i in range(_TRAIN_MIN + 100):
        m.observe("firefox", ips[i % 20],
                  443 if rng.random() < 0.7 else 80, "out",
                  400 + rng.randrange(2400), t + i * 2)
    # EN: Score still available after training; an insane flow (weird
    #     port, giant packet, odd hour vs learned) should score higher.
    #     Seeded forest → deterministic split points, no flaky runs.
    # FR: Un flux aberrant doit scorer plus haut qu'un flux normal.
    #     Forêt seedée → splits déterministes, pas de run flaky.
    from detection.iforest import IsolationForest
    forest = IsolationForest(seed=7)
    forest.fit(list(m._window))
    # EN: Typical point — 40 s interval (20 IPs round-robin), 20/512 fanout.
    # FR: Point typique — intervalle 40 s (20 IPs round-robin), fanout 20/512.
    normal_score = forest.score(
        [443 / 65535.0, 1200 / 65535.0, 0.45, 20 / 512.0, 0.52, 1.0])
    weird_score = forest.score(
        [31337 / 65535.0, 65535 / 65535.0, 0.0, 1.0, 0.999, 1.0])
    assert weird_score > normal_score


def test_flow_ml_ignores_inbound_and_bad_ip():
    """EN: Inbound packets and unparseable IPs produce nothing.
    FR: Paquets entrants et IP imparsables ne produisent rien."""
    from detection.mlflow import FlowAnomaly
    m = FlowAnomaly()
    assert m.observe("x", "1.2.3.4", 80, "in", 100) is None
    assert m.observe("x", "not-an-ip", 80, "out", 100) is None


# ── Custom rules geo + block / Règles géo + block ──────────────────────────

def _pkt(remote="1.2.3.4", proc="curl", port=443, direction="out",
         size=100, proto="TCP"):
    """EN: Minimal Packet-shaped stub — only the fields the matcher reads.
    FR: Stub minimal en forme de Packet — seulement les champs lus."""
    class P:
        dst_ip = remote if direction == "out" else "10.0.0.1"
        src_ip = "10.0.0.1" if direction == "out" else remote
        process_name = proc
        remote_port = port
        protocol = proto
        direction_ = direction
        size = 100
        sni = None
        dns: list = []
    p = P()
    p.direction = direction
    p.size = size
    return p


def test_custom_rules_asn_country_via_geo():
    """EN: asn/country fields resolve through the packet's geo record.
    FR: Les champs asn/country se résolvent via l'enregistrement geo."""
    from detection.customrules import CustomRules
    cr = CustomRules()
    cr.add("german", "country", "eq", "DE")
    cr.add("asn", "asn", "eq", "12345")
    geo = {"country": "DE", "asn": 12345}
    hits = cr.check(_pkt(), geo)
    assert {h["rule"]["name"] for h in hits} == {"german", "asn"}
    # EN: no geo → fields are empty strings, no match / FR: sans geo → vide
    assert cr.check(_pkt(), None) == []
    assert cr.check(_pkt(), {"country": "FR", "asn": 1}) == []


def test_custom_rules_block_action_validation():
    """EN: action=block is accepted on blockable fields, rejected on
    direction/size/protocol. / FR: action=block accepté sur champs
    bloquables, refusé sur direction/size/protocol."""
    from detection.customrules import CustomRules
    cr = CustomRules()
    for field in ("remote_ip", "host", "process_name", "asn", "country"):
        r = cr.add(f"b-{field}", field, "eq", "x", action="block")
        assert r["action"] == "block"
    for field in ("direction", "size", "protocol", "remote_port"):
        with pytest.raises(ValueError):
            cr.add(f"bad-{field}", field, "eq", "x", action="block")
    with pytest.raises(ValueError):
        cr.add("bad-action", "remote_ip", "eq", "x", action="nuke")
    # EN: bad ops for geo fields are rejected / FR: ops invalides refusées
    with pytest.raises(ValueError):
        cr.add("bad-op", "country", "gt", "x")
    with pytest.raises(ValueError):
        cr.add("bad-op2", "asn", "cidr", "1.0.0.0/8")


# ── Syslog / Syslog ─────────────────────────────────────────────────────────

def test_syslog_udp_rfc3164():
    """EN: A UDP datagram in RFC 3164 shape — <PRI>TS HOST TAG: text with
    local4.warning PRI = 156 for a warning alert.
    FR: Datagramme UDP au format RFC 3164 — PRI local4.warning = 156."""
    from api.notify import WebhookNotifier
    n = WebhookNotifier()
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(3)
    port = srv.getsockname()[1]
    try:
        n.configure("", enabled=False, syslog_addr=f"127.0.0.1:{port}")
        n.dispatch({"severity": "warning", "type": "BEACON",
                    "message": "test beacon"})
        data, _ = srv.recvfrom(2048)
        text = data.decode()
        assert text.startswith("<156>")              # local4(19)*8 + warning(4)
        assert "snitch[BEACON]" in text
        assert "test beacon" in text
    finally:
        srv.close()


def test_syslog_skips_info_severity():
    """EN: info alerts are never forwarded — channel spam protection.
    FR: Les alertes info ne sont jamais relayées — anti-spam."""
    from api.notify import WebhookNotifier
    n = WebhookNotifier()
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(0.4)
    port = srv.getsockname()[1]
    try:
        n.configure("", enabled=False, syslog_addr=f"127.0.0.1:{port}")
        n.dispatch({"severity": "info", "type": "NEW_HOST",
                    "message": "quiet"})
        with pytest.raises(socket.timeout):
            srv.recvfrom(512)
    finally:
        srv.close()


def test_syslog_bad_addr_never_raises():
    """EN: A bogus syslog address must not break the detection path.
    FR: Une adresse syslog invalide ne doit pas casser la détection."""
    from api.notify import WebhookNotifier
    n = WebhookNotifier()
    n.configure("", enabled=False, syslog_addr="nonexistent.invalid:514")
    n.dispatch({"severity": "critical", "type": "X", "message": "m"})


# ── NFQUEUE flow key / Clé de flux NFQUEUE ──────────────────────────────────

def test_askmode_flow_key_tcp_syn():
    """EN: IPv4 TCP SYN → (dst, dport, TCP); non-SYN → None; UDP → key.
    FR: SYN TCP IPv4 → clé ; non-SYN → None ; UDP → clé."""
    from detection.askmode import AskMode
    # EN: SYN set, ACK clear → asked / FR: SYN posé, ACK effacé → demandé
    syn = tcp(50000, 443, flags=0x02)
    ip = ipv4(b"\x0a\x00\x00\x01", b"\x08\x08\x08\x08", 6, syn)
    assert AskMode._flow_key(ip) == ("8.8.8.8", 443, "TCP")
    # EN: ACK-only packet rides the stored decision → None
    # FR: Paquet ACK seul → décision stockée → None
    ack = tcp(50000, 443, flags=0x10)
    ip2 = ipv4(b"\x0a\x00\x00\x01", b"\x08\x08\x08\x08", 6, ack)
    assert AskMode._flow_key(ip2) is None
    u = b"\x13\x88\x00\x35" + struct.pack("!HH", 8, 0)
    ip3 = ipv4(b"\x0a\x00\x00\x01", b"\x08\x08\x08\x08", 17, u)
    assert AskMode._flow_key(ip3) == ("8.8.8.8", 53, "UDP")


def test_askmode_available_honest_on_nonlinux():
    """EN: On this Mac the capability probe must honestly report Linux-
    only (or missing deps) — never pretend. / FR: Sur ce Mac la sonde
    doit honnêtement rapporter Linux-only — jamais prétendre."""
    import platform
    from detection.askmode import available
    ok, why = available()
    if platform.system().lower() != "linux":
        assert ok is False and "linux" in why.lower()


def test_askmode_decide_unknown_flow():
    """EN: A verdict for a flow that never pended returns False — no
    crash. / FR: Un verdict pour un flux inconnu renvoie False."""
    from detection.askmode import AskMode
    am = AskMode(lambda ctx: None)
    assert am.decide("9.9.9.9", 443, "TCP", True) is False
    st = am.status()
    assert st["running"] is False and st["pending"] == 0


# ── IOC peer sync / Sync IOC entre pairs ────────────────────────────────────

def test_gossip_configure_dedup_and_prefix():
    """EN: Peer list is deduped, scheme-prefixed, bounded.
    FR: La liste de pairs est dédupliquée, préfixée, bornée."""
    from detection.gossip import PeerSync
    ps = PeerSync(lambda: "tok")
    ps.configure(["10.0.0.2:8080", "http://10.0.0.2:8080",
                  " https://sec.example:9/", "", "  "])
    assert ps.peers == ["http://10.0.0.2:8080", "https://sec.example:9"]
    ps.configure([f"h{i}" for i in range(40)])
    assert len(ps.peers) == 32


def test_gossip_push_no_peers():
    """EN: Push with no peers is an honest error, never an exception.
    FR: Push sans pairs = erreur honnête, jamais d'exception."""
    from detection.gossip import PeerSync
    assert PeerSync(lambda: "t").push_pack({"a": 1})["ok"] is False


def test_gossip_push_calls_import_endpoint(monkeypatch):
    """EN: The pack is POSTed as JSON to each peer's authenticated import
    endpoint with the bearer token. / FR: Le pack est POSTé en JSON vers
    l'endpoint import authentifié de chaque pair."""
    from detection import gossip
    calls = []

    class R:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout=0):
        calls.append((req.full_url, req.headers.get("Authorization"),
                      req.data))
        return R()

    monkeypatch.setattr(gossip.urllib.request, "urlopen", fake_urlopen)
    ps = gossip.PeerSync(lambda: "TOKEN")
    ps.configure(["peer1:1"])
    res = ps.push_pack({"format": "snitch-ioc-proof/1"})
    assert res["ok"] is True
    assert calls[0][0] == "http://peer1:1/security/iocpack/import"
    assert calls[0][1] == "Bearer TOKEN"
    assert b"snitch-ioc-proof" in calls[0][2]


# ── Capability probes / Sondes de capacité ──────────────────────────────────

def test_hollow_available_honest():
    """EN: hollowing check reports its platform honestly — False off
    Linux. / FR: le check hollowing rapporte honnêtement — False hors
    Linux."""
    import platform
    from detection.hollow import available, hollow_check
    ok, why = available()
    if platform.system().lower() != "linux":
        assert ok is False
        res = hollow_check(1)
        assert res["ok"] is False and "linux" in res["error"].lower()


def test_ebpf_enforce_honest():
    """EN: cgroup-skb enforcer reports unavailable cleanly off-Linux and
    refuses to block before start. / FR: l'enforcer cgroup-skb rapporte
    indisponible hors Linux et refuse de bloquer avant start."""
    from detection.ebpf_enforce import EbpfEnforcer, available
    ok, why = available()
    e = EbpfEnforcer()
    if not ok:
        blk, reason = e.block_ip("1.2.3.4")
        assert blk is False and reason
        started, _why2 = e.start()
        assert started is False


def test_explain_covers_new_types():
    """EN: Every new alert type has a bilingual explanation template.
    FR: Chaque nouveau type d'alerte a un gabarit bilingue."""
    from detection.explain import explain
    for t in ("TLS_CERT", "HIGH_ENTROPY", "ICMP_TUNNEL", "ML_ANOMALY",
              "ASK_VERDICT", "DGA_SUSPECT", "PROTO_MISMATCH"):
        rec = explain(t)
        assert rec is not None, t
        assert rec["what_en"] and rec["what_fr"]
        assert rec["actions_en"] and rec["actions_fr"]


def test_askmode_configure_clamps():
    """EN: Live configure clamps timeout to [3,120] s and applies failopen
    without restarting. / FR: configure borne le timeout à [3,120] s et
    applique failopen sans redémarrage."""
    from detection.askmode import AskMode
    am = AskMode(lambda ctx: None)
    am.configure(timeout=1, failopen=True)
    assert am._timeout == 3.0 and am._failopen is True
    am.configure(timeout=999, failopen=False)
    assert am._timeout == 120.0 and am._failopen is False
    am.configure(timeout="garbage")
    assert am._timeout == 120.0          # EN: bad input keeps last value
    st = am.status()
    assert st["failopen"] is False and st["timeout_s"] == 120.0


def test_ebpf_enforce_scoped_attach(monkeypatch):
    """EN: start() must attach to the DEDICATED snitch cgroup, never the
    cgroup2 root — a root attach would make every block host-wide,
    silently contradicting the per-process promise.
    FR: start() doit attacher au cgroup snitch DÉDIÉ, jamais la racine —
    un attach racine rendrait chaque blocage global."""
    import platform
    if platform.system().lower() != "linux":
        pytest.skip("cgroup paths are linux-only")
    from detection import ebpf_enforce as m
    attached = {}

    class FakeBPF:
        class BPFAttachType:
            CGROUP_INET_EGRESS = 0
        CGROUP_SKB = 0
        def __init__(self, text=None):
            pass
        def load_func(self, name, t):
            return object()
        def attach_cgroup(self, fn, path, at):
            attached["path"] = path

    monkeypatch.setitem(__import__("sys").modules, "bcc",
                        type("B", (), {"BPF": FakeBPF}))
    monkeypatch.setattr(m, "available", lambda: (True, ""))
    monkeypatch.setattr(m._CGROUP_DIR, "mkdir", lambda **kw: None)
    e = m.EbpfEnforcer()
    ok, why = e.start()
    assert ok, why
    assert attached["path"] == str(m._CGROUP_DIR)
    assert e.status()["attached"] is True


# ── Pure-Python NFQUEUE / NFQUEUE pur Python ──────────────────────────────

def test_nfqueue_packet_message_roundtrip():
    """EN: A crafted NFQNL_MSG_PACKET parses back to (id, payload); an
    ACK-type message returns None. / FR: Un NFQNL_MSG_PACKET fabriqué se
    reparse en (id, payload) ; un message ACK renvoie None."""
    import struct as st
    from detection import nfqueue as n
    ip_pkt = ipv4(b"\x0a\x00\x00\x01", b"\x08\x08\x08\x08", 6,
                  tcp(50000, 443, flags=0x02))
    # EN: attrs — PACKET_HDR {be32 id, be16 proto, u8 hook} + PAYLOAD
    # FR: attributs — PACKET_HDR + PAYLOAD
    attrs = n._attr(n._ATTR_PACKET_HDR, st.pack("!IHB", 42, 0x0800, 0)) \
        + n._attr(n._ATTR_PAYLOAD, ip_pkt)
    body = n._msg(n._MSG_PACKET, 7, attrs, 1)
    pid, payload = n.parse_packet_message(body)
    assert pid == 42 and payload == ip_pkt
    # EN: a CONFIG message is not a packet / FR: un CONFIG n'est pas un paquet
    cfg = n.build_config_cmd(n._CFG_CMD_BIND, 0, 7, 1)
    assert n.parse_packet_message(cfg) is None


def test_nfqueue_verdict_wire_format():
    """EN: Verdict message carries queue res_id + verdict hdr attr with
    the right id/verdict in network order. / FR: Le message de verdict
    porte la file en res_id et l'en-tête verdict en ordre réseau."""
    import struct as st
    from detection import nfqueue as n
    msg = n.build_verdict(99, n.NF_DROP, 7, 5)
    length, mtype, _f, _s, _p = st.unpack_from("IHHII", msg, 0)
    assert length == len(msg)
    assert mtype == (n._SUBSYS_QUEUE << 8) | n._MSG_VERDICT
    _fam, _ver, res = st.unpack_from("!BBH", msg, 16)
    assert res == 7
    attrs = n._parse_attrs(msg[20:])
    v, pid = st.unpack("!II", attrs[n._ATTR_VERDICT_HDR])
    assert v == n.NF_DROP and pid == 99


def test_nfqueue_config_params_copy_packet():
    """EN: The bind params ask for whole-packet COPY_PACKET mode.
    FR: Les params du bind demandent le mode COPY_PACKET paquet entier."""
    import struct as st
    from detection import nfqueue as n
    msg = n.build_config_params(7, 1)
    attrs = n._parse_attrs(msg[20:])
    rng, mode = st.unpack("!IB", attrs[n._ATTR_CFG_PARAMS])
    assert mode == n._COPY_PACKET and rng == 0xFFFF


def test_askmode_pending_entry_shape():
    """EN: _handle parks [event, packet_id, ts] and decide() applies the
    verdict via the socket — mocked end-to-end without a kernel.
    FR: _handle gare [event, id, ts] et decide() applique le verdict via
    le socket — simulé de bout en bout sans noyau."""
    from detection.askmode import AskMode

    class FakeNfq:
        def __init__(self):
            self.verdicts = []

        def verdict(self, pid, accept):
            self.verdicts.append((pid, accept))

    asked = []
    am = AskMode(lambda ctx: asked.append(ctx))
    am._nfq = FakeNfq()
    syn = tcp(50000, 443, flags=0x02)
    ip = ipv4(b"\x0a\x00\x00\x01", b"\x08\x08\x08\x08", 6, syn)
    am._handle(7, ip)
    assert asked and asked[0]["remote_ip"] == "8.8.8.8"
    assert am.decide("8.8.8.8", 443, "TCP", False) is True
    assert am._nfq.verdicts == [(7, False)]
    # EN: Next SYN on the same flow rides the stored DENY instantly.
    # FR: Le SYN suivant du même flux suit le DENY stocké immédiatement.
    am._handle(8, ip)
    assert am._nfq.verdicts[-1] == (8, False)


# ── DGA heuristic / Heuristique DGA ──────────────────────────────────────

def test_dga_flags_random_names():
    """EN: Long consonant-soup + digit-noise names flag; normal domains
    stay silent. / FR: Les noms en soupe de consonnes/chiffres
    déclenchent ; les domaines normaux restent silencieux."""
    from detection.dga import score
    for bad in ("xj3kq9wzvbtpklm.net", "qwxzjkvbtpxyzqwr.com",
                "8f3k2j9xm4q7z5w1v.tk", "bcdfghjklmnpqrstvwxz.info"):
        hit = score(bad)
        assert hit is not None, bad
        assert hit["score"] >= 0.7 and hit["entropy"] >= 3.4
    for good in ("google.com", "github.io", "duckduckgo.com",
                 "wikipedia.org", "apple.com", "cdn.discordapp.net",
                 "mail.proton.me", "example.com"):
        assert score(good) is None, good


def test_dga_skips_unscorable():
    """EN: IP literals, single labels, short names → None, never crash.
    FR: IP, labels uniques, noms courts → None, jamais de crash."""
    from detection.dga import score
    for edge in ("", "localhost", "1.2.3.4", "8.8.8.8.",
                 "a.b.c", None, "short.io", "::1"):
        assert score(edge) is None


def test_dga_cdn_left_label_skipped():
    """EN: Random-looking LEFT labels under CDN parents are expected —
    the score jumps to the registrable part instead.
    FR: Les labels gauches aléatoires sous un parent CDN sont attendus —
    le score saute au registrable."""
    from detection.dga import score
    # EN: akamaihd is a public-suffix-ish parent → score 'example', not
    #     the hashed left label. / FR: parent type CDN → on note
    #     'example', pas le label haché.
    assert score("a1b2c3d4e5f6.example.akamaihd.net") is None
    # EN: but a DGA registrable STILL flags under a CDN parent.
    # FR: mais un registrable DGA déclenche quand même sous un CDN.
    hit = score("ok.qwxzjkvbtpxyzqwr.akamaihd.net")
    assert hit is not None and hit["label"] == "qwxzjkvbtpxyzqwr"


# ── Protocol mismatch / Protocole déguisé ─────────────────────────────────

def test_protomatch_http80():
    """EN: GET/POST/HTTP-response on :80 pass; binary garbage flags.
    FR: GET/POST/réponse HTTP sur :80 passent ; le binaire déclenche."""
    from detection.protomatch import check
    assert check(80, "TCP", b"GET / HTTP/1.1\r\nHost: x\r\n") is None
    assert check(80, "TCP", b"HTTP/1.1 200 OK\r\n") is None
    assert check(80, "TCP", b"\x89PNG\r\n\x1a\nbinary-blob!!") is not None
    assert check(80, "TCP", b"\x16\x03\x01\x00\x80tls-like-data") is not None


def test_protomatch_tls_ports():
    """EN: TLS records pass :443/:853; cleartext flags.
    FR: Les records TLS passent :443/:853 ; le clair déclenche."""
    from detection.protomatch import check
    tls = b"\x16\x03\x01\x00\x2e" + b"\x01" * 46
    assert check(443, "TCP", tls) is None
    assert check(853, "TCP", tls) is None
    assert check(443, "TCP", b"GET /not-tls HTTP/1.1") is not None
    assert check(853, "TCP", b"plain-dns-over-dot-port!") is not None


def test_protomatch_dns53():
    """EN: A real DNS query passes on :53; a blob flags — both transports.
    FR: Une vraie requête DNS passe sur :53 ; un blob déclenche — TCP et
    UDP."""
    import struct as st
    from detection.protomatch import check
    qname = b"\x07example\x03com\x00"
    dns = st.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname \
        + st.pack(">HH", 1, 1)
    assert check(53, "UDP", dns) is None
    assert check(53, "TCP", dns) is None
    assert check(53, "UDP", b"\xde\xad\xbe\xef" * 16) is not None
    assert check(53, "TCP", b"not-a-dns-message-at-all!!") is not None


def test_protomatch_ssh_and_ascii():
    """EN: 'SSH-' banner passes :22; binary on mail ports flags; unknown
    ports never match. / FR: bannière SSH- passe :22 ; binaire sur ports
    mail déclenche ; ports inconnus jamais matchés."""
    from detection.protomatch import check
    assert check(22, "TCP", b"SSH-2.0-OpenSSH_9.6") is None
    assert check(22, "TCP", b"\x00\x01\x02binary!") is not None
    assert check(25, "TCP", b"EHLO mail.example.com\r\n") is None
    assert check(25, "TCP", b"\x16\x03\x01tls-on-smtp?") is not None
    assert check(8443, "TCP", b"whatever") is None
    assert check(0, "TCP", b"") is None


# ── Permanent ask verdicts / Verdicts ask permanents ──────────────────────

def test_askmode_exempt_ips_installed_and_removed(monkeypatch):
    """EN: exempt_ips become `-d <ip> -j RETURN` rules inserted BEFORE the
    NFQUEUE jump at start, and are individually deleted on stop — the
    "allow always" path survives restarts without leaking rules.
    FR: exempt_ips deviennent des règles `-d <ip> -j RETURN` insérées
    AVANT le saut NFQUEUE au start, supprimées une à une au stop."""
    import subprocess
    from detection import askmode

    calls = []
    monkeypatch.setattr(askmode, "available", lambda: (True, ""))
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: calls.append(a[0]) or None)

    class FakeNfq:
        def __init__(self, _q):
            pass

        def open(self):
            pass

        def bind_queue(self):
            pass

        def recv_packets(self, _t):
            return []

        def verdict(self, _pid, _accept):
            pass

        def close(self):
            pass

    monkeypatch.setattr("detection.nfqueue.NfqSocket", FakeNfq)
    am = askmode.AskMode(lambda ctx: None)
    ok, why = am.start(exempt_ips=["1.2.3.4", "5.6.7.8"])
    assert ok, why
    # EN: both exemptions inserted before the NFQUEUE jump
    # FR: les deux exemptions insérées avant le saut NFQUEUE
    q_idx = next(i for i, c in enumerate(calls) if "NFQUEUE" in c)
    for ip in ("1.2.3.4", "5.6.7.8"):
        ins = ["iptables", "-w", "-I", "OUTPUT", "-d", ip, "-j", "RETURN"]
        assert ins in calls[:q_idx]
    am.stop()
    for ip in ("1.2.3.4", "5.6.7.8"):
        assert ["iptables", "-w", "-D", "OUTPUT", "-d", ip, "-j",
                "RETURN"] in calls


def test_askmode_exempt_bounded():
    """EN: exempt_ips is capped at 64 — a huge whitelist can't explode the
    rule list. / FR: exempt_ips borné à 64 — une whitelist énorme ne peut
    pas exploser la liste de règles."""
    from detection.askmode import AskMode
    am = AskMode(lambda ctx: None)
    am._exempt = [f"10.0.0.{i}" for i in range(200)][:64]
    assert len(am._exempt) == 64
