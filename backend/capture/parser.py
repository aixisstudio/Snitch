"""
Snitch — packet parser (pure Python, no Scapy).

EN: Decodes raw link-layer frames into a normalized `ParsedPacket`. This is
    what frees Snitch from Scapy's GPL-2.0-only license and gives us IPv6,
    DNS answers and TLS SNI — all of which Scapy imports never actually used.

    Supported link types : Ethernet, BSD loopback (NULL), raw IP, Linux SLL
                           and SLL2.
    Network layers       : IPv4 (with fragment skip), IPv6 (walks extension
                           headers), TCP, UDP, ICMP.
    Payload extraction   : DNS responses (A / AAAA / CNAME → ip↔name with
                           TTL), TLS ClientHello SNI (single-segment case).

FR: Décode les trames de couche liaison brutes en `ParsedPacket` normalisé.
    C'est ce qui affranchit Snitch de la licence GPL-2.0-only de Scapy et nous
    donne IPv6, les réponses DNS et le SNI TLS — que les imports Scapy
    n'utilisaient jamais vraiment.

    Types de lien gérés  : Ethernet, loopback BSD (NULL), IP brut, SLL et
                           SLL2 Linux.
    Couches réseau       : IPv4 (fragments sautés), IPv6 (parcours des
                           extensions), TCP, UDP, ICMP.
    Extraction de charge : réponses DNS (A / AAAA / CNAME → ip↔nom avec TTL),
                           SNI du ClientHello TLS (cas d'un seul segment).
"""

import socket
import struct
from dataclasses import dataclass, field
from typing import Optional

# ── Link-layer types / Types de liaison ──────────────────────────────────────
DLT_NULL       = 0    # EN: BSD loopback / FR: loopback BSD
DLT_EN10MB     = 1    # EN: Ethernet / FR: Ethernet
DLT_RAW        = 12   # EN: raw IP, most platforms / FR: IP brut, plupart des plateformes
DLT_RAW_ALT    = 101  # EN: raw IP, OpenBSD numbering / FR: IP brut, numérotation OpenBSD
DLT_LINUX_SLL  = 113  # EN: Linux cooked v1 / FR: cooked v1 Linux
DLT_LINUX_SLL2 = 276  # EN: Linux cooked v2 / FR: cooked v2 Linux

# ── EtherTypes / EtherTypes ──────────────────────────────────────────────────
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100  # EN: 802.1Q tag — skip 4 bytes and re-read
                         # FR: tag 802.1Q — sauter 4 octets et relire

# ── IP protocol numbers / Numéros de protocole IP ────────────────────────────
IPPROTO_TCP  = 6
IPPROTO_UDP  = 17
IPPROTO_ICMP = 1
IPPROTO_ICMPV6 = 58
# EN: IPv6 extension headers that carry a length we can walk past.
# FR: En-têtes d'extension IPv6 dont la longueur permet de les sauter.
IPV6_EXT_HOPOPT = 0
IPV6_EXT_ROUTE  = 43
IPV6_EXT_FRAG   = 44
IPV6_EXT_AH     = 51
IPV6_EXT_DSTOPTS = 60
IPV6_EXT_NO_NEXT = 59
IPV6_EXT_CHAIN = {IPV6_EXT_HOPOPT, IPV6_EXT_ROUTE, IPV6_EXT_FRAG, IPV6_EXT_DSTOPTS}


@dataclass
class ParsedPacket:
    """
    EN: Normalized view of one frame — the single object the sniffer produces.
        `dns` holds answer tuples (name, ip, ttl) from DNS responses; `sni`
        holds the TLS ClientHello server name when observed.
    FR: Vue normalisée d'une trame — l'objet unique produit par le sniffer.
        `dns` contient des tuples de réponse (nom, ip, ttl) des réponses DNS ;
        `sni` contient le nom de serveur du ClientHello TLS quand observé.
    """
    src_ip: str
    dst_ip: str
    protocol: str                          # "TCP" | "UDP" | "ICMP" | "OTHER"
    size: int                              # EN: bytes on the wire / FR: octets sur le fil
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: int = 0
    dns: list[tuple[str, str, int]] = field(default_factory=list)
    sni: Optional[str] = None


def parse_frame(linktype: int, buf: bytes) -> Optional[ParsedPacket]:
    """
    EN: Entry point — decode one captured frame. Returns None for frames we
        can't or don't care to decode (non-IP, truncated, malformed).
        Never raises: a corrupt packet must not kill the capture loop.
    FR: Point d'entrée — décoder une trame capturée. Renvoie None pour les
        trames non décodables ou sans intérêt (non-IP, tronquées, malformées).
        Ne lève jamais d'exception : un paquet corrompu ne doit pas tuer la
        boucle de capture.
    """
    try:
        return _parse_frame(linktype, buf)
    except (IndexError, struct.error, ValueError):
        return None


def _parse_frame(linktype: int, buf: bytes) -> Optional[ParsedPacket]:
    """EN: Internal — may raise on malformed input; parse_frame guards it.
    FR: Interne — peut lever des exceptions sur entrée malformée ; parse_frame la protège."""
    total_len = len(buf)

    # ── Strip the link-layer header / Dépouiller l'en-tête de liaison ───────
    if linktype == DLT_EN10MB:
        if total_len < 14:
            return None
        ethertype = struct.unpack("!H", buf[12:14])[0]
        off = 14
        while ethertype == ETHERTYPE_VLAN:       # EN: stacked VLAN tags
            ethertype = struct.unpack("!H", buf[off + 2:off + 4])[0]
            off += 4
        if ethertype == ETHERTYPE_IPV4:
            return _parse_ipv4(buf[off:], total_len)
        if ethertype == ETHERTYPE_IPV6:
            return _parse_ipv6(buf[off:], total_len)
        return None

    if linktype == DLT_NULL:
        if total_len < 4:
            return None
        # EN: 4-byte family in HOST byte order: 2=IPv4, 24/28/30=IPv6.
        # FR: Famille sur 4 octets en ordre HÔTE : 2=IPv4, 24/28/30=IPv6.
        family = struct.unpack("=I", buf[:4])[0]
        if family == 2:
            return _parse_ipv4(buf[4:], total_len)
        if family in (24, 28, 30):
            return _parse_ipv6(buf[4:], total_len)
        return None

    if linktype in (DLT_RAW, DLT_RAW_ALT):
        # EN: First nibble is the IP version. / FR: Le premier quartet est la version IP.
        if total_len < 1:
            return None
        version = buf[0] >> 4
        if version == 4:
            return _parse_ipv4(buf, total_len)
        if version == 6:
            return _parse_ipv6(buf, total_len)
        return None

    if linktype == DLT_LINUX_SLL:
        # EN: 16-byte header, protocol at offset 14 (network byte order).
        # FR: En-tête de 16 octets, protocole à l'offset 14 (ordre réseau).
        if total_len < 16:
            return None
        proto = struct.unpack("!H", buf[14:16])[0]
        if proto == ETHERTYPE_IPV4:
            return _parse_ipv4(buf[16:], total_len)
        if proto == ETHERTYPE_IPV6:
            return _parse_ipv6(buf[16:], total_len)
        return None

    if linktype == DLT_LINUX_SLL2:
        # EN: 20-byte header, protocol at offset 0.
        # FR: En-tête de 20 octets, protocole à l'offset 0.
        if total_len < 20:
            return None
        proto = struct.unpack("!H", buf[0:2])[0]
        if proto == ETHERTYPE_IPV4:
            return _parse_ipv4(buf[20:], total_len)
        if proto == ETHERTYPE_IPV6:
            return _parse_ipv6(buf[20:], total_len)
        return None

    return None


# ── IPv4 / IPv6 ──────────────────────────────────────────────────────────────

def _parse_ipv4(buf: bytes, wire_len: int) -> Optional[ParsedPacket]:
    """
    EN: IPv4 header — variable IHL, fragment-aware (non-first fragments are
        dropped since their ports aren't present).
    FR: En-tête IPv4 — IHL variable, gestion des fragments (les fragments non
        premiers sont ignorés car leurs ports ne sont pas présents).
    """
    if len(buf) < 20:
        return None
    ihl = (buf[0] & 0x0F) * 4
    if ihl < 20 or len(buf) < ihl:
        return None
    proto = buf[9]
    frag = struct.unpack("!H", buf[6:8])[0]
    # EN: Fragment offset in low 13 bits — non-zero means a later fragment.
    # FR: Offset de fragment sur 13 bits bas — non nul = fragment ultérieur.
    if frag & 0x1FFF:
        return None
    src = socket.inet_ntop(socket.AF_INET, buf[12:16])
    dst = socket.inet_ntop(socket.AF_INET, buf[16:20])
    return _parse_transport(buf[ihl:], proto, src, dst, wire_len)


def _parse_ipv6(buf: bytes, wire_len: int) -> Optional[ParsedPacket]:
    """
    EN: IPv6 — fixed 40-byte header, then walk the extension-header chain
        (hop-by-hop / routing / dest-opts have a len field; fragment header is
        fixed 8 bytes; non-first fragments are dropped).
    FR: IPv6 — en-tête fixe de 40 octets, puis parcours de la chaîne
        d'extensions (hop-by-hop / routing / dest-opts ont un champ de
        longueur ; l'en-tête fragment fait 8 octets ; les fragments non
        premiers sont ignorés).
    """
    if len(buf) < 40:
        return None
    nxt = buf[6]
    src = socket.inet_ntop(socket.AF_INET6, buf[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, buf[24:40])
    off = 40

    while nxt in IPV6_EXT_CHAIN:
        if nxt == IPV6_EXT_FRAG:
            if off + 8 > len(buf):
                return None
            frag_field = struct.unpack("!H", buf[off + 2:off + 4])[0]
            if (frag_field >> 3) != 0:        # EN: non-first fragment
                return None                   # FR: fragment non premier
            nxt = buf[off]
            off += 8
            continue
        if off + 2 > len(buf):
            return None
        hdr_len = (buf[off + 1] + 1) * 8
        nxt = buf[off]
        off += hdr_len

    if nxt == IPV6_EXT_NO_NEXT:
        return None
    return _parse_transport(buf[off:], nxt, src, dst, wire_len)


def _parse_transport(payload: bytes, proto: int, src: str, dst: str,
                     wire_len: int) -> Optional[ParsedPacket]:
    """
    EN: TCP/UDP/ICMP dispatch. TCP extracts flags + SNI attempt; UDP extracts
        DNS answers on port 53.
    FR: Répartition TCP/UDP/ICMP. TCP extrait les flags + tente le SNI ; UDP
        extrait les réponses DNS sur le port 53.
    """
    if proto == IPPROTO_TCP:
        if len(payload) < 20:
            return None
        sport, dport = struct.unpack("!HH", payload[:4])
        data_off = (payload[12] >> 4) * 4
        flags = payload[13]
        tcp_payload = payload[data_off:] if data_off <= len(payload) else b""

        sni = None
        # EN: Cheap gate: TLS record starts 0x16 0x03 xx on port 443 (or SNI on
        #     any port — be liberal, check both endpoints' payload anyway).
        # FR: Filtre rapide : un enregistrement TLS commence par 0x16 0x03 xx
        #     sur le port 443 (ou SNI sur tout port — rester souple).
        if tcp_payload[:2] == b"\x16\x03":
            sni = parse_tls_sni(tcp_payload)

        dns = []
        if sport == 53 or dport == 53:
            # EN: DNS-over-TCP has a 2-byte length prefix. / FR: DNS sur TCP a un préfixe de longueur de 2 octets.
            dns = parse_dns(tcp_payload[2:]) if len(tcp_payload) > 2 else []

        return ParsedPacket(src, dst, "TCP", wire_len, sport, dport, flags, dns, sni)

    if proto == IPPROTO_UDP:
        if len(payload) < 8:
            return None
        sport, dport = struct.unpack("!HH", payload[:4])
        udp_payload = payload[8:]
        dns = parse_dns(udp_payload) if (sport == 53 or dport == 53) else []
        return ParsedPacket(src, dst, "UDP", wire_len, sport, dport, 0, dns, None)

    if proto in (IPPROTO_ICMP, IPPROTO_ICMPV6):
        return ParsedPacket(src, dst, "ICMP", wire_len)

    return ParsedPacket(src, dst, "OTHER", wire_len)


# ── DNS / DNS ────────────────────────────────────────────────────────────────

def _dns_name(buf: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    """
    EN: Decode a possibly-compressed DNS name. Returns (name, offset_after).
        Compression pointers (0xC0) may jump backwards — depth-capped to avoid
        loops in malformed packets.
    FR: Décoder un nom DNS éventuellement compressé. Renvoie (nom, offset_après).
        Les pointeurs de compression (0xC0) peuvent sauter en arrière — profondeur
        plafonnée pour éviter les boucles dans les paquets malformés.
    """
    labels = []
    jumped = False
    end = off
    while off < len(buf):
        length = buf[off]
        if length == 0:
            off += 1
            if not jumped:
                end = off
            break
        if length & 0xC0 == 0xC0:            # EN: compression pointer / FR: pointeur de compression
            if off + 1 >= len(buf):
                break
            ptr = ((length & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                end = off + 2
                jumped = True
            off = ptr
            depth += 1
            if depth > 20:
                break
            continue
        off += 1
        labels.append(buf[off:off + length].decode("ascii", errors="replace"))
        off += length
        if not jumped:
            end = off
    return ".".join(labels), end


def parse_dns(payload: bytes) -> list[tuple[str, str, int]]:
    """
    EN: Parse a DNS message; returns [(name, ip, ttl)] for A/AAAA answers —
        empty for queries or failures. Errors are non-fatal (return []).
    FR: Analyser un message DNS ; renvoie [(nom, ip, ttl)] pour les réponses
        A/AAAA — vide pour les requêtes ou les échecs. Les erreurs sont non
        fatales (renvoie []).
    """
    try:
        if len(payload) < 12:
            return []
        _, flags, qdcount, ancount = struct.unpack("!HHHH", payload[:8])
        if not (flags & 0x8000):             # EN: QR bit — responses only
            return []                        # FR: bit QR — réponses seulement

        off = 12
        for _ in range(qdcount):             # EN: skip question section / FR: sauter la section questions
            _, off = _dns_name(payload, off)
            off += 4

        answers = []
        for _ in range(ancount):
            name, off = _dns_name(payload, off)
            if off + 10 > len(payload):
                break
            rtype, _, ttl, rdlen = struct.unpack("!HHIH", payload[off:off + 10])
            rdata_off = off + 10
            rdata = payload[rdata_off:rdata_off + rdlen]
            if rtype == 1 and rdlen == 4:                    # EN: A record / FR: enregistrement A
                answers.append((name, socket.inet_ntop(socket.AF_INET, rdata), ttl))
            elif rtype == 28 and rdlen == 16:                # EN: AAAA / FR: AAAA
                answers.append((name, socket.inet_ntop(socket.AF_INET6, rdata), ttl))
            off = rdata_off + rdlen
        return answers
    except (IndexError, struct.error, ValueError):
        return []


# ── TLS SNI / SNI TLS ────────────────────────────────────────────────────────

def parse_tls_sni(payload: bytes) -> Optional[str]:
    """
    EN: Extract the SNI hostname from a TLS ClientHello when the whole
        handshake fits in one segment — the overwhelmingly common case.
        Layout: record header (5) | handshake type+len (4) | version (2) |
        random (32) | session_id (1+n) | ciphers (2+n) | compression (1+n) |
        extensions len (2) | extensions… — we look for ext type 0.
    FR: Extraire le nom d'hôte SNI d'un ClientHello TLS quand tout le
        handshake tient dans un seul segment — le cas très majoritaire.
        Structure : en-tête d'enregistrement (5) | type+longueur handshake (4) |
        version (2) | aléa (32) | session_id (1+n) | chiffrements (2+n) |
        compression (1+n) | longueur extensions (2) | extensions… — on cherche
        l'extension type 0.
    """
    try:
        if len(payload) < 9 or payload[0] != 0x16 or payload[1] != 0x03:
            return None
        hs = 5
        if payload[hs] != 0x01:              # EN: ClientHello / FR: ClientHello
            return None
        hs_len = struct.unpack("!I", b"\x00" + payload[hs + 1:hs + 4])[0]
        body = payload[hs + 4:hs + 4 + hs_len]
        if len(body) < 34:
            return None
        off = 2 + 32                         # EN: version + random / FR: version + aléa
        sid_len = body[off]
        off += 1 + sid_len
        cs_len = struct.unpack("!H", body[off:off + 2])[0]
        off += 2 + cs_len
        cm_len = body[off]
        off += 1 + cm_len
        if off + 2 > len(body):
            return None
        ext_total = struct.unpack("!H", body[off:off + 2])[0]
        off += 2
        ext_end = min(off + ext_total, len(body))

        while off + 4 <= ext_end:
            etype, elen = struct.unpack("!HH", body[off:off + 4])
            edata = body[off + 4:off + 4 + elen]
            if etype == 0 and len(edata) >= 5:   # EN: server_name ext / FR: ext server_name
                # EN: list_len(2) | type(1) | name_len(2) | name
                # FR: longueur liste (2) | type (1) | longueur nom (2) | nom
                if edata[2] == 0:
                    nlen = struct.unpack("!H", edata[3:5])[0]
                    raw = edata[5:5 + nlen].decode("ascii", errors="strict")
                    # EN: IDNA → unicode when possible; the "idna" codec does
                    #     not accept an errors= argument.
                    # FR: IDNA → unicode quand possible ; le codec « idna »
                    #     n'accepte pas d'argument errors=.
                    try:
                        return raw.encode("ascii").decode("idna")
                    except UnicodeError:
                        return raw
            off += 4 + elen
        return None
    except (IndexError, struct.error, ValueError):
        return None
