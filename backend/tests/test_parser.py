"""
Snitch — parser tests (synthetic packets, no real captures).

EN: Every frame below is built byte-by-byte in the test — no pcap files, no
    real traffic, no Scapy. Coverage: Ethernet/IPv4/TCP, IPv6 + extension
    headers, UDP, DNS answers (A/AAAA/CNAME), TLS ClientHello SNI, malformed
    inputs.

FR: Chaque trame ci-dessous est construite octet par octet dans le test — pas
    de fichiers pcap, pas de trafic réel, pas de Scapy. Couverture :
    Ethernet/IPv4/TCP, IPv6 + en-têtes d'extension, UDP, réponses DNS
    (A/AAAA/CNAME), SNI du ClientHello TLS, entrées malformées.
"""

import struct

from capture.parser import (
    DLT_EN10MB, DLT_LINUX_SLL, DLT_LINUX_SLL2, DLT_NULL, DLT_RAW,
    parse_frame, parse_dns, parse_tls_sni,
)

ETH = DLT_EN10MB


def eth(payload: bytes, ethertype: int = 0x0800) -> bytes:
    """EN: Ethernet II frame around a payload. / FR: Trame Ethernet II autour d'une charge."""
    return b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x11\x22\x33\x44\x55\x66" + struct.pack("!H", ethertype) + payload


def ipv4(src: bytes, dst: bytes, proto: int, payload: bytes,
         ihl_extra: bytes = b"") -> bytes:
    """EN: IPv4 packet. / FR: Paquet IPv4."""
    ihl = 5 + len(ihl_extra) // 4
    total = 20 + len(ihl_extra) + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s",
                      (4 << 4) | ihl, 0, total, 0, 0, 64, proto, 0, src, dst)
    return hdr + ihl_extra + payload


def ipv6(src: bytes, dst: bytes, next_header: int, payload: bytes,
         ext: bytes = b"") -> bytes:
    """EN: IPv6 packet. / FR: Paquet IPv6."""
    plen = len(ext) + len(payload)
    hdr = struct.pack("!IHBB16s16s", 6 << 28, plen, next_header, 64, src, dst)
    return hdr + ext + payload


def tcp(sport: int, dport: int, flags: int = 0x18, payload: bytes = b"") -> bytes:
    """EN: TCP segment (data offset 5). / FR: Segment TCP (data offset 5)."""
    hdr = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 8192, 0, 0)
    return hdr + payload


def udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    """EN: UDP datagram. / FR: Datagramme UDP."""
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_response(answers: list[tuple[str, int, bytes]], qname: str = "example.com") -> bytes:
    """
    EN: Minimal DNS response — header + one question + answer RRs. Each
        answer: (name, rtype, rdata). Names are written as label sequences.
    FR: Réponse DNS minimale — en-tête + une question + RR de réponse.
        Chaque réponse : (nom, rtype, rdata). Les noms sont en séquences de
        labels.
    """
    def name_to_wire(n: str) -> bytes:
        out = b""
        for label in n.split("."):
            out += bytes([len(label)]) + label.encode()
        return out + b"\x00"

    hdr = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, len(answers), 0, 0)
    question = name_to_wire(qname) + struct.pack("!HH", 1, 1)
    body = b""
    for name, rtype, rdata in answers:
        body += name_to_wire(name) + struct.pack("!HHIH", rtype, 1, 60, len(rdata)) + rdata
    return hdr + question + body


def tls_client_hello(sni_host: str) -> bytes:
    """
    EN: Minimal TLS record + ClientHello with a real SNI extension — the
        fixed-layout walk in parse_sni() must find it.
    FR: Enregistrement TLS minimal + ClientHello avec une vraie extension
        SNI — le parcours à layout fixe de parse_sni() doit la trouver.
    """
    host = sni_host.encode()
    # EN: ext = type(2) + len(2) + data; data = list_len(2) + type(1) +
    #     name_len(2) + name.
    # FR: ext = type(2) + longueur(2) + données ; données = longueur liste(2)
    #     + type(1) + longueur nom(2) + nom.
    name_entry = struct.pack("!BH", 0, len(host)) + host
    sni_data = struct.pack("!H", len(name_entry)) + name_entry
    sni_ext = struct.pack("!HH", 0, len(sni_data)) + sni_data

    ext_block = sni_ext
    hello_body = (
        b"\x03\x03"                    # client version
        + b"\x00" * 32                 # random
        + b"\x00"                      # session id len
        + struct.pack("!H", 2) + b"\x13\x01"   # cipher suites
        + b"\x01\x00"                  # compression: null
        + struct.pack("!H", len(ext_block)) + ext_block
    )
    handshake = b"\x01" + len(hello_body).to_bytes(3, "big") + hello_body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


# ── Ethernet / IPv4 / TCP ────────────────────────────────────────────────────

def test_ipv4_tcp_outbound():
    payload = tcp(54321, 443)
    ip = ipv4(b"\x0a\x00\x00\x01", b"\x5d\xb8\xd8\x22", 6, payload)
    p = parse_frame(ETH, eth(ip))
    assert p is not None
    assert p.src_ip == "10.0.0.1" and p.dst_ip == "93.184.216.34"
    assert p.protocol == "TCP"
    assert p.src_port == 54321 and p.dst_port == 443
    assert p.tcp_flags == 0x18


def test_ipv4_udp_dns():
    dns = dns_response([("example.com", 1, b"\x5d\xb8\xd8\x22")])
    p = parse_frame(ETH, eth(ipv4(b"\x08\x08\x08\x08", b"\x0a\x00\x00\x01", 17, udp(53, 5353, dns))))
    assert p.protocol == "UDP" and p.src_port == 53
    assert ("example.com", "93.184.216.34", 60) in p.dns


def test_ipv4_aaaa():
    dns = dns_response([("v6.example.com", 28, b"\x26\x06\x28\x00" + b"\x00" * 12)])
    p = parse_frame(ETH, eth(ipv4(b"\x08\x08\x08\x08", b"\x0a\x00\x00\x01", 17, udp(53, 5353, dns))))
    assert p.dns[0][0] == "v6.example.com"
    assert ":" in p.dns[0][1]


def test_tcp_sni_extracted():
    hello = tls_client_hello("www.example.org")
    p = parse_frame(ETH, eth(ipv4(b"\x0a\x00\x00\x01", b"\x5d\xb8\xd8\x22", 6,
                                  tcp(54321, 443, payload=hello))))
    assert p.sni == "www.example.org"


def test_sni_not_port_443():
    """EN: SNI parses on any port — the TLS record signature is what counts.
    FR: Le SNI se parse sur tout port — c'est la signature TLS qui compte."""
    hello = tls_client_hello("sneaky.example.net")
    p = parse_frame(ETH, eth(ipv4(b"\x0a\x00\x00\x01", b"\x5d\xb8\xd8\x22", 6,
                                  tcp(54321, 8443, payload=hello))))
    assert p.sni == "sneaky.example.net"


# ── IPv6 + extensions / IPv6 + extensions ────────────────────────────────────

def test_ipv6_tcp():
    src = bytes.fromhex("20010db8" + "00" * 12)
    dst = bytes.fromhex("2606" + "2800" + "00" * 12)
    p = parse_frame(ETH, eth(ipv6(src, dst, 6, tcp(1234, 443)), 0x86dd))
    assert p.protocol == "TCP" and p.dst_port == 443
    assert p.src_ip == "2001:db8::"


def test_ipv6_extension_header_skip():
    """EN: Hop-by-hop ext header (8 bytes) before TCP must be walked, not
    misparsed. / FR: L'en-tête hop-by-hop (8 o) avant TCP doit être sauté."""
    src = bytes.fromhex("20010db8" + "00" * 12)
    dst = bytes.fromhex("2606" + "2800" + "00" * 12)
    ext = bytes([6, 0]) + b"\x00" * 6   # next=tcp, len=0 → 8 bytes total
    p = parse_frame(ETH, eth(ipv6(src, dst, 0, tcp(1234, 443), ext), 0x86dd))
    assert p.protocol == "TCP" and p.dst_port == 443


# ── Alternate link types / Types de lien alternatifs ─────────────────────────

def test_dlt_raw():
    p = parse_frame(DLT_RAW, ipv4(b"\x0a\x00\x00\x01", b"\x5d\xb8\xd8\x22", 6, tcp(1, 2)))
    assert p is not None and p.dst_port == 2


def test_dlt_null_loopback():
    null_hdr = struct.pack("<I", 2)     # AF_INET
    p = parse_frame(DLT_NULL, null_hdr + ipv4(b"\x0a\x00\x00\x01", b"\x5d\xb8\xd8\x22", 6, tcp(1, 2)))
    assert p is not None and p.src_ip == "10.0.0.1"


def test_dlt_sll():
    sll = b"\x00" * 4 + struct.pack("!H", 0x0800) + b"\x00" * 8  # pkttype+arphrd+lladdrlen+addr+proto
    sll = struct.pack("!HHH8sH", 0, 1, 0, b"\x00" * 8, 0x0800)
    p = parse_frame(DLT_LINUX_SLL, sll + ipv4(b"\x0a\x00\x00\x01", b"\x5d\xb8\xd8\x22", 6, tcp(1, 2)))
    assert p is not None and p.dst_port == 2


def test_dlt_sll2():
    # EN: SLL2 header (20 bytes): proto(2) | rsvd(2) | if_index(4) |
    #     hatype(2) | pkttype(1) | halen(1) | addr(8).
    # FR: En-tête SLL2 (20 octets) : proto(2) | réservé(2) | if_index(4) |
    #     hatype(2) | pkttype(1) | halen(1) | adresse(8).
    sll2 = struct.pack("!HxxIHBB8s", 0x0800, 0, 0, 0, 0, b"\x00" * 8)
    p = parse_frame(DLT_LINUX_SLL2, sll2 + ipv4(b"\x0a\x00\x00\x01", b"\x5d\xb8\xd8\x22", 6, tcp(1, 2)))
    assert p is not None and p.dst_port == 2


# ── Malformed inputs / Entrées malformées ────────────────────────────────────

def test_empty_and_garbage():
    assert parse_frame(ETH, b"") is None
    assert parse_frame(ETH, b"\x00" * 10) is None
    assert parse_frame(9999, eth(ipv4(b"\x0a\x00\x00\x01", b"\x5d\xb8\xd8\x22", 6, tcp(1, 2)))) is None


def test_truncated_ip():
    p = parse_frame(ETH, eth(ipv4(b"\x0a\x00\x00\x01", b"\x5d\xb8\xd8\x22", 6, tcp(1, 2))[:18]))
    assert p is None


def test_dns_malformed():
    # EN: Malformed DNS never raises — empty list, not None.
    # FR: Un DNS malformé ne lève jamais — liste vide, pas None.
    assert parse_dns(b"\x00") == []
    assert parse_dns(b"\x00" * 12) == []


def test_sni_garbage():
    assert parse_tls_sni(b"\x16\x03\x01") is None
    assert parse_tls_sni(b"GET / HTTP/1.1\r\n\r\n") is None
