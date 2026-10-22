"""
Snitch — pure-Python NFQUEUE client (Linux AF_NETLINK) / client NFQUEUE
pur Python (AF_NETLINK Linux).

EN: Zero-dependency implementation of the netfilter-queue userspace
    protocol — the feature that makes ask-on-first-connect REAL on Linux
    without `pip install NetfilterQueue` or libnetfilter_queue.so. An
    AF_NETLINK socket of family NETLINK_NETFILTER speaks nfnetlink_queue
    directly:

      * bind    — nfqnl config commands (PF_UNBIND/PF_BIND/BIND +
                  COPY_PACKET params), each verified by an nlmsg ACK so a
                  failed bind surfaces honestly instead of timing out
      * recv    — NFQNL_MSG_PACKET messages carrying the diverted IP
                  packet in NFQA_PAYLOAD plus its verdict id
      * verdict — NFQNL_MSG_VERDICT with NF_ACCEPT / NF_DROP

    Protocol reference: linux/netfilter/nfnetlink_queue.h and
    libnetfilter_queue's message layout. Everything here is host byte
    order except fields documented __be16/__be32.

FR: Implémentation zéro-dépendance du protocole netfilter-queue —
    l'ask-on-connect réel sous Linux sans `pip install NetfilterQueue`.
    Socket AF_NETLINK famille NETLINK_NETFILTER parlant nfnetlink_queue
    directement : bind via commandes de config vérifiées par ACK, réception
    NFQNL_MSG_PACKET (payload IP + id de verdict), verdict NF_ACCEPT/NF_DROP.
"""

from __future__ import annotations

import os
import socket
import struct
from typing import Optional

# EN: netlink + nfnetlink_queue constants / FR: constantes netlink
NETLINK_NETFILTER = 12
NLMSG_ERROR = 2
NLM_F_REQUEST = 0x0001
NLM_F_ACK = 0x0004

_SUBSYS_QUEUE = 3                                # NFNL_SUBSYS_QUEUE
_MSG_PACKET = 0                                  # NFQNL_MSG_PACKET
_MSG_VERDICT = 1                                 # NFQNL_MSG_VERDICT
_MSG_CONFIG = 3                                  # NFQNL_MSG_CONFIG

_CFG_CMD_BIND = 1                                # NFQNL_CFG_CMD_BIND
_CFG_CMD_PF_BIND = 3                             # NFQNL_CFG_CMD_PF_BIND
_CFG_CMD_PF_UNBIND = 4                           # NFQNL_CFG_CMD_PF_UNBIND
_COPY_PACKET = 2                                 # NFQNL_COPY_PACKET

_ATTR_CFG_CMD = 1                                # NFQA_CFG_CMD
_ATTR_CFG_PARAMS = 2                             # NFQA_CFG_PARAMS
_ATTR_PACKET_HDR = 1                             # NFQA_PACKET_HDR
_ATTR_VERDICT_HDR = 2                            # NFQA_VERDICT_HDR
_ATTR_PAYLOAD = 10                               # NFQA_PAYLOAD
_ATTR_TYPE_MASK = 0x3FFF                         # NLA_TYPE_MASK

NF_ACCEPT = 1
NF_DROP = 0

_AF_UNSPEC = 0
_AF_INET = 2
_AF_INET6 = 10


def _attr(atype: int, payload: bytes) -> bytes:
    """EN: One nfattr TLV — 2-byte len + 2-byte type, 4-aligned.
    FR: Un TLV nfattr — len + type sur 2 octets, aligné 4."""
    length = 4 + len(payload)
    out = struct.pack("HH", length, atype) + payload
    return out + b"\x00" * ((4 - length % 4) % 4)


def _msg(mtype: int, res_id: int, payload: bytes, seq: int,
         flags: int = NLM_F_REQUEST) -> bytes:
    """EN: nlmsghdr + nfgenmsg + attribute payload. nlmsg_type is
    (subsys<<8)|msg_type in HOST order; nfgenmsg.res_id carries the queue
    number in network order.
    FR: nlmsghdr + nfgenmsg + attributs. type = (subsys<<8)|msg en ordre
    hôte ; res_id porte le numéro de file en ordre réseau."""
    nfgen = struct.pack("!BBH", _AF_UNSPEC, 0, res_id)
    total = 16 + 4 + len(payload)
    return (struct.pack("IHHII", total, (_SUBSYS_QUEUE << 8) | mtype,
                        flags, seq, 0) + nfgen + payload)


def _parse_attrs(body: bytes) -> dict[int, bytes]:
    """EN: Split an nfattr list into {type: payload}; malformed tails are
    dropped quietly. / FR: Découpe la liste nfattr ; queue malformée
    ignorée silencieusement."""
    out: dict[int, bytes] = {}
    off = 0
    while off + 4 <= len(body):
        length, atype = struct.unpack_from("HH", body, off)
        if length < 4 or off + length > len(body):
            break
        out[atype & _ATTR_TYPE_MASK] = body[off + 4: off + length]
        off += (length + 3) & ~3                   # EN: NFA_ALIGN / FR: NFA_ALIGN
    return out


def parse_packet_message(data: bytes) -> Optional[tuple[int, bytes]]:
    """EN: Extract (packet_id, ip_payload) from one NFQNL_MSG_PACKET
    netlink message. Returns None for non-packet messages (ACKs etc.).
    Exposed for unit tests. / FR: Extrait (id, payload IP) d'un message
    NFQNL_MSG_PACKET ; None pour les autres types."""
    if len(data) < 20:
        return None
    _length, mtype, _flags, _seq, _pid = struct.unpack_from(
        "IHHII", data, 0)
    if mtype != (_SUBSYS_QUEUE << 8) | _MSG_PACKET:
        return None
    attrs = _parse_attrs(data[20:])                # EN: skip nfgenmsg
    hdr = attrs.get(_ATTR_PACKET_HDR)
    payload = attrs.get(_ATTR_PAYLOAD)
    if hdr is None or len(hdr) < 5 or payload is None:
        return None
    pkt_id, _hwproto, _hook = struct.unpack("!IHB", hdr[:7])
    return pkt_id, payload


def build_verdict(packet_id: int, verdict: int, queue: int,
                  seq: int = 0) -> bytes:
    """EN: A complete NFQNL_MSG_VERDICT netlink message accepting or
    dropping the held packet. / FR: Message NFQNL_MSG_VERDICT complet
    acceptant ou droppant le paquet retenu."""
    vh = _attr(_ATTR_VERDICT_HDR, struct.pack("!II", verdict, packet_id))
    return _msg(_MSG_VERDICT, queue, vh, seq)


def build_config_cmd(command: int, pf: int, queue: int,
                     seq: int = 0) -> bytes:
    """EN: NFQNL_MSG_CONFIG carrying one NFQA_CFG_CMD (bind/unbind family
    or queue). / FR: NFQNL_MSG_CONFIG portant une NFQA_CFG_CMD."""
    cmd = _attr(_ATTR_CFG_CMD, struct.pack("!BBH", command, 0, pf))
    return _msg(_MSG_CONFIG, queue, cmd, seq)


def build_config_params(queue: int, seq: int = 0,
                        copy_range: int = 0xFFFF) -> bytes:
    """EN: NFQNL_MSG_CONFIG with NFQA_CFG_PARAMS — whole-packet copy mode.
    FR: NFQNL_MSG_CONFIG avec NFQA_CFG_PARAMS — copie du paquet entier."""
    par = _attr(_ATTR_CFG_PARAMS,
                struct.pack("!IB", copy_range, _COPY_PACKET))
    return _msg(_MSG_CONFIG, queue, par, seq)


class NfqSocket:
    """EN: One bound NFQUEUE — open(), bind_queue(), recv_packet(),
    verdict(), close(). Verdicts for packets never touched by iptables
    are no-ops, so the class stays safe to construct anywhere.
    FR: Une file NFQUEUE liée. Les verdicts pour des paquets jamais
    détournés sont sans effet — la construction est sûre partout."""

    def __init__(self, queue: int = 7):
        self.queue = queue
        self._fd: Optional[socket.socket] = None
        self._seq = 0

    # ── lifecycle / cycle de vie ────────────────────────────────────────

    def open(self) -> None:
        """EN: Create + bind the netlink socket. Needs CAP_NET_ADMIN.
        FR: Crée et lie le socket netlink. Exige CAP_NET_ADMIN."""
        if self._fd is not None:
            return
        fd = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW,
                           NETLINK_NETFILTER)
        try:
            fd.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
            fd.bind((0, 0))                        # EN: kernel assigns pid
        except Exception:
            fd.close()
            raise
        self._fd = fd

    def bind_queue(self, timeout: float = 2.0) -> None:
        """EN: PF_UNBIND (cleanup), PF_BIND, BIND and COPY_PACKET for
        AF_INET + AF_INET6 — every step ACK-verified so failures raise a
        real error, not silence. / FR: PF_UNBIND, PF_BIND, BIND et
        COPY_PACKET v4+v6 — chaque étape vérifiée par ACK."""
        if self._fd is None:
            self.open()
        for pf in (_AF_INET, _AF_INET6):
            self._send_checked(build_config_cmd(
                _CFG_CMD_PF_UNBIND, pf, self.queue, self._next()),
                timeout, tolerate=True)
        for pf in (_AF_INET, _AF_INET6):
            self._send_checked(build_config_cmd(
                _CFG_CMD_PF_BIND, pf, self.queue, self._next()), timeout)
        self._send_checked(build_config_cmd(
            _CFG_CMD_BIND, _AF_UNSPEC, self.queue, self._next()), timeout)
        self._send_checked(build_config_params(
            self.queue, self._next()), timeout)

    def close(self) -> None:
        try:
            if self._fd is not None:
                self._fd.close()
        finally:
            self._fd = None

    def _next(self) -> int:
        self._seq = (self._seq + 1) & 0x7FFFFFFF
        return self._seq

    # ── protocol / protocole ────────────────────────────────────────────

    def _send_checked(self, msg: bytes, timeout: float,
                      tolerate: bool = False) -> None:
        """EN: Send one message then wait for its NLMSG_ERROR ack —
        error 0 means accepted. `tolerate` swallows failures (the initial
        PF_UNBIND legitimately fails when nothing is bound).
        FR: Envoie puis attend l'ACK NLMSG_ERROR — erreur 0 = accepté.
        `tolerate` avale les échecs (PF_UNBIND échoue normalement)."""
        assert self._fd is not None
        self._fd.send(msg)
        self._fd.settimeout(timeout)
        try:
            while True:
                data = self._fd.recv(65535)
                off = 0
                while off + 16 <= len(data):
                    (length, mtype, _f, _s, _p) = struct.unpack_from(
                        "IHHII", data, off)
                    if mtype == NLMSG_ERROR and length >= 20:
                        err = struct.unpack_from("i", data, off + 16)[0]
                        if err and not tolerate:
                            raise OSError(
                                -err, f"nfqueue config refused: "
                                      f"{os.strerror(-err)}")
                        return
                    off += (length + 3) & ~3 if length else len(data)
        except socket.timeout:
            # EN: No ACK back within the window — the kernel answered
            #     nothing; treat tolerated steps as silent success.
            # FR: Pas d'ACK dans la fenêtre — étape tolérée = succès muet.
            if not tolerate:
                raise OSError("nfqueue config timed out — kernel did "
                              "not acknowledge the bind")

    def recv_packets(self, timeout: Optional[float] = None) \
            -> list[tuple[int, bytes]]:
        """EN: All diverted packets in the next datagram as
        [(id, raw IP payload), ...] — a single recv() can carry several
        queued messages. [] on timeout. / FR: Tous les paquets du prochain
        datagramme — un recv() peut porter plusieurs messages."""
        assert self._fd is not None
        self._fd.settimeout(timeout)
        try:
            data = self._fd.recv(65535)
        except socket.timeout:
            return []
        out = []
        off = 0
        while off + 16 <= len(data):
            res = parse_packet_message(data[off:])
            if res is not None:
                out.append(res)
            length = struct.unpack_from("I", data, off)[0]
            if length < 16:
                break
            off += (length + 3) & ~3
        return out

    def verdict(self, packet_id: int, accept: bool) -> None:
        """EN: NF_ACCEPT/NF_DROP verdict for one held packet.
        FR: Verdict NF_ACCEPT/NF_DROP pour un paquet retenu."""
        if self._fd is None:
            return
        try:
            self._fd.send(build_verdict(
                packet_id, NF_ACCEPT if accept else NF_DROP,
                self.queue, self._next()))
        except OSError:
            pass                                   # EN: packet may be gone
