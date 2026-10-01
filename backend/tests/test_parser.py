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
    parse_frame, parse_dns, parse_mdns, parse_nbns, parse_dhcp,
    parse_tls_sni,
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


# ── mDNS / mDNS ──────────────────────────────────────────────────────────────

def mdns_frame(hostname: str, ip: bytes, section: str = "answer") -> bytes:
    """
    EN: Minimal mDNS message carrying "<hostname>.local → <ip>" — the A
        record can sit in the ANSWER or ADDITIONAL section (real devices put
        it in additional, e.g. under a PTR service answer).
    FR: Message mDNS minimal portant « <hostname>.local → <ip> » — le record
        A peut siéger dans la section ANSWER ou ADDITIONNELLE (les vrais
        appareils le mettent en additional, ex. sous une réponse PTR).
    """
    def name_to_wire(n: str) -> bytes:
        out = b""
        for label in n.split("."):
            out += bytes([len(label)]) + label.encode()
        return out + b"\x00"

    a_rec = name_to_wire(f"{hostname}.local") + struct.pack("!HHIH", 1, 1, 120, 4) + ip
    an, ar = (1, 0) if section == "answer" else (0, 1)
    # EN: when the A lives in ADDITIONAL, the answer section holds a dummy
    #     PTR record (name "ptr.local" → target "ptr.local") to stay realistic.
    # FR: quand le A vit en ADDITIONNELLE, la section réponses tient un
    #     enregistrement PTR factice (« ptr.local » → « ptr.local ») pour
    #     rester réaliste.
    answers = b"" if ar else a_rec
    if ar:
        ptr_name = name_to_wire("ptr.local")
        answers = ptr_name + struct.pack("!HHIH", 12, 1, 120, len(ptr_name)) + ptr_name
        an = 1
    hdr = struct.pack("!HHHHHH", 0, 0x8400, 0, an, 0, ar)
    return hdr + answers + (a_rec if ar else b"")


def test_mdns_answer_section():
    """EN: A record in ANSWER. / FR: Enregistrement A en ANSWER."""
    res = parse_mdns(mdns_frame("iPhone-de-Lisa", b"\xc0\xa8\x01\xc6", "answer"))
    assert res == [("iPhone-de-Lisa.local", "192.168.1.198", 120)]


def test_mdns_additional_section():
    """EN: A record in ADDITIONAL under a PTR answer — the common real case.
    FR: Enregistrement A en ADDITIONNELLE sous une réponse PTR — le cas réel
    le plus courant."""
    res = parse_mdns(mdns_frame("MacBook-Pro", b"\xc0\xa8\x01\x2a", "additional"))
    # EN: the PTR answer yields a sender-claimed name (empty ip) AND the
    #     additional A record yields the explicit binding.
    # FR: la réponse PTR donne un nom revendiqué par l'émetteur (ip vide) ET
    #     le A en additionnelle donne la liaison explicite.
    assert res == [("ptr.local", "", 0), ("MacBook-Pro.local", "192.168.1.42", 120)]


def test_mdns_udp_5353_flows_through_parser():
    """EN: A real UDP/5353 frame exposes dns tuples; port 53 still works and
        other ports stay empty.
    FR: Une vraie trame UDP/5353 expose des tuples dns ; le port 53 marche
        toujours et les autres ports restent vides."""
    mdns = mdns_frame("Nest-Mini", b"\xc0\xa8\x01\x63")
    ip = ipv4(b"\xc0\xa8\x01\x63", b"\xe0\x00\x00\xfb", 17, udp(5353, 5353, mdns))
    p = parse_frame(ETH, eth(ip))
    assert p is not None and p.dns == [("Nest-Mini.local", "192.168.1.99", 120)]

    plain = ipv4(b"\x0a\x00\x00\x01", b"\x5d\xb8\xd8\x22", 17, udp(5354, 8080, mdns))
    p2 = parse_frame(ETH, eth(plain))
    assert p2 is not None and p2.dns == []


def test_mdns_malformed():
    assert parse_mdns(b"\x00") == []
    assert parse_mdns(b"\x00" * 12) == []


# ── Device-name protocols: mDNS PTR / NBNS / DHCP ────────────────────────────
# ── Protocoles de nommage : PTR mDNS / NBNS / DHCP ────────────────────────────

def mdns_ptr_frame(instance: str) -> bytes:
    """EN: mDNS with a PTR answer: _device-info._tcp.local → instance.
    FR: mDNS avec réponse PTR : _device-info._tcp.local → instance."""
    def w(n):
        return b"".join(bytes([len(x)]) + x.encode() for x in n.split(".")) + b"\x00"
    rdata = w(instance)
    rec = w("_device-info._tcp.local") + struct.pack("!HHIH", 12, 1, 120, len(rdata)) + rdata
    return struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + rec


def test_mdns_ptr_instance_name():
    res = parse_mdns(mdns_ptr_frame("iPhone-de-Lisa._device-info._tcp.local"))
    assert res == [("iPhone-de-Lisa._device-info._tcp.local", "", 0)]


def nb_name_wire(name: str, suffix: int = 0x00) -> bytes:
    """EN: NetBIOS first-level encoding: 15-char padded name + suffix byte,
        each byte as two letters 'A'..'P'.
    FR: Encodage NetBIOS de premier niveau : nom sur 15 caractères + octet
        de suffixe, chaque octet en deux lettres 'A'..'P'."""
    raw = name.encode().ljust(15, b" ")[:15] + bytes([suffix])
    enc = b"".join(bytes([0x41 + (b >> 4), 0x41 + (b & 15)]) for b in raw)
    return b"\x20" + enc + b"\x00"


def test_nbns_registration():
    """EN: Name registration (QR=0, opcode 5) carries the sender's name.
    FR: L'enregistrement de nom (QR=0, opcode 5) porte le nom de l'émetteur."""
    q = nb_name_wire("PC-DE-LISA") + struct.pack("!HH", 0x20, 1)
    msg = struct.pack("!HHHHHH", 1, 5 << 11, 1, 0, 0, 0) + q
    assert parse_nbns(msg) == [("PC-DE-LISA", "", 0)]


def dhcp_request(hostname: str, req_ip: bytes, mac: bytes) -> bytes:
    """EN: Minimal BOOTP REQUEST: 236B header + cookie + options 12/50/end.
    FR: BOOTP REQUEST minimal : en-tête 236 o + cookie + options 12/50/fin."""
    hdr = struct.pack("!BBBBIHH", 1, 1, 6, 0, 0x1234, 0, 0x8000)
    hdr += b"\x00" * 4 * 4                     # ciaddr/yiaddr/siaddr/giaddr
    hdr += mac + b"\x00" * (16 - len(mac))     # chaddr
    hdr += b"\x00" * (64 + 128)                # sname + file
    opts = bytes([12, len(hostname)]) + hostname.encode()
    opts += bytes([50, 4]) + req_ip
    return hdr + b"\x63\x82\x53\x63" + opts + b"\xff"


def test_dhcp_hostname():
    res = parse_dhcp(dhcp_request("DESKTOP-ABC", b"\xc0\xa8\x01\xc6",
                                  b"\x58\xa0\x23\xe9\xe3\xb4"))
    assert res == ("DESKTOP-ABC", "192.168.1.198", "58:A0:23:E9:E3:B4")


def test_dhcp_server_reply_ignored():
    """EN: op=2 (server reply) returns None — no hostname to learn.
    FR: op=2 (réponse serveur) renvoie None — pas de nom à apprendre."""
    reply = bytearray(dhcp_request("X", b"\x0a\x00\x00\x01", b"\x01" * 6))
    reply[0] = 2
    assert parse_dhcp(bytes(reply)) is None
