"""
Snitch — protocol/port mismatch classifier / classifieur protocole↔port.

EN: "Disguised protocol" detection for the classic well-known ports —
    when the first payload bytes on a socket do NOT look like the protocol
    the port advertises, someone is riding a friendly port to sneak a
    tunnel past firewalls (HTTP/80, DNS/53, SSH/22, TLS/443, mail…).

    Checks are cheap signature tests on the ≤64-byte app head only — no
    payload is stored, matching Snitch's privacy model:

      tcp/80    expects an HTTP method or "HTTP/" status line
      udp+tcp/53 expects a plausible DNS header (id, flags, qdcount>0,
                labels that fit)
      tcp/22    expects the "SSH-" banner
      tcp/443   expects a TLS record (\\x16\\x03) — cleartext on the
                HTTPS port is itself the anomaly
      tcp/853   expects a TLS record (DNS-over-TLS)
      tcp/21,25,110,143,587 expects printable ASCII commands

    Honest limits: HEURISTIC, one alert per (ip, port) per cooldown —
    exotic-but-legit protocols (WebSocket pre-GET, MQTT on 443) may
    false-positive once, then stay quiet. The classifier flags the
    MISMATCH, it does not identify what the traffic really is.

FR: Détection de « protocole déguisé » sur les ports bien connus — quand
    les premiers octets ne ressemblent pas au protocole annoncé par le
    port, quelqu'un fait passer un tunnel sous un port amical (HTTP/80,
    DNS/53, SSH/22, TLS/443, mail…). Tests de signature bon marché sur la
    tête ≤64 o uniquement. HEURISTIQUE — une alerte par (ip, port) par
    fenêtre de cooldown ; les protocoles exotiques légitimes peuvent
    déclencher une fois puis se taire.
"""

from __future__ import annotations

import struct
from typing import Optional

_HTTP_METHODS = (b"GET ", b"POST", b"HEAD", b"PUT ", b"DELE", b"OPTI",
                 b"PATC", b"TRAC", b"CONN")
_ASCII_PORTS = {21: "FTP", 25: "SMTP", 110: "POP3", 143: "IMAP",
                587: "SMTP-submission"}


def _looks_dns(payload: bytes) -> bool:
    """EN: Plausible DNS message — ≥12B header, qdcount in 1..32, and the
    first QNAME's label walk must terminate inside the packet (a random
    blob almost never walks cleanly).
    FR: Message DNS plausible — en-tête ≥12 o, qdcount 1..32 et la
    marche des labels du premier QNAME doit se terminer dans le paquet."""
    if len(payload) < 14:                        # 12B hdr + minimal QNAME
        return False
    _id, _flags, qd = struct.unpack_from(">HHH", payload, 0)
    if not (1 <= qd <= 32):
        return False
    # EN: Walk labels — each byte must be a length ≤63 followed by data,
    #     ending on 0 or a pointer (0xC0). / FR: Marche des labels.
    off = 12
    for _ in range(64):
        if off >= len(payload):
            return False
        length = payload[off]
        if length == 0:
            return True                          # EN: clean terminator
        if length & 0xC0 == 0xC0:
            return True                          # EN: compression ptr
        if length > 63 or off + 1 + length > len(payload):
            return False
        off += 1 + length
    return False


def check(port: int, proto: str, app_head: bytes) -> Optional[str]:
    """EN: Mismatch reason when app_head doesn't fit `port`'s protocol,
    else None. Caller owns the cooldown/dedup policy.
    FR: Raison du mismatch quand app_head ne colle pas au port, sinon
    None. Cooldown/dédup à la charge de l'appelant."""
    if not app_head or not port:
        return None
    head = app_head[:64]
    proto = (proto or "").upper()

    if proto == "TCP":
        if port == 80:
            if not (head.startswith(_HTTP_METHODS)
                    or head.startswith(b"HTTP/")):
                return "non-HTTP payload on tcp/80"
        elif port == 443:
            if not head.startswith(b"\x16\x03"):
                return "non-TLS payload on tcp/443 (HTTPS port)"
        elif port == 853:
            if not head.startswith(b"\x16\x03"):
                return "cleartext on tcp/853 (DNS-over-TLS port)"
        elif port == 22:
            if not head.startswith(b"SSH-"):
                return "non-SSH payload on tcp/22"
        elif port in _ASCII_PORTS:
            if not all(32 <= b < 127 or b in (9, 10, 13) for b in head):
                return (f"non-{_ASCII_PORTS[port]} payload on "
                        f"tcp/{port} (expected printable commands)")
        elif port == 53:
            if not _looks_dns(head):
                return "non-DNS payload on tcp/53"
    elif proto == "UDP":
        if port == 53 and not _looks_dns(head):
            return "non-DNS payload on udp/53"
    return None
