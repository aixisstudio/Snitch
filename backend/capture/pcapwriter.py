"""
Snitch — libpcap (.pcap) file writer / écrivain de fichiers pcap.

EN: Classic libpcap savefile format, written in pure Python — the same
    byte layout tcpdump/Wireshark expects, produced from the frames the
    capture thread already holds. No libpcap handle needed for writing:
    the format is a fixed global header followed by per-packet records.

    Byte layout (little-endian, magic 0xa1b2c3d4):
      global header  : magic u32, ver_major u16, ver_minor u16,
                       thiszone i32, sigfigs u32, snaplen u32, network u32
      per packet     : ts_sec u32, ts_usec u32, incl_len u32, orig_len u32,
                       raw frame bytes (incl_len of them)

FR: Format savefile libpcap classique, écrit en Python pur — le même
    layout d'octets qu'attendent tcpdump/Wireshark, produit depuis les
    trames que le thread de capture détient déjà. Pas besoin de handle
    libpcap pour écrire : l'en-tête global fixe est suivi des enregistrements
    par paquet.
"""

from __future__ import annotations

import io
import struct
from typing import BinaryIO, Iterable

# EN: Classic magic — little-endian variant (microsecond timestamps).
# FR: Magic classique — variante little-endian (timestamps microseconde).
_MAGIC = 0xA1B2C3D4
_SNAPLEN = 65535           # EN: capture whole frames / FR: trames entières

_GLOBAL_HDR = struct.Struct("<IHHiIII")
_PACKET_HDR = struct.Struct("<IIII")


def write_pcap(dest: BinaryIO, linktype: int,
               frames: Iterable[tuple[float, bytes, int]]) -> int:
    """
    EN: Serialize `frames` to `dest` in libpcap format.

        frames : iterable of (unix_ts, frame_bytes, wire_len) — a frame
                 longer than _SNAPLEN is truncated honestly (incl_len <
                 orig_len, exactly like a live capture would store it).
        dest   : binary file object (open(path,'wb') or io.BytesIO).
        returns: number of packet records written.

    FR: Sérialiser `frames` dans `dest` au format libpcap. Une trame plus
        longue que _SNAPLEN est tronquée honnêtement (incl_len < orig_len,
        comme une capture live). Renvoie le nombre de paquets écrits.
    """
    dest.write(_GLOBAL_HDR.pack(_MAGIC, 2, 4, 0, 0, _SNAPLEN, linktype))
    n = 0
    for ts, buf, wire_len in frames:
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        incl = min(len(buf), _SNAPLEN)
        dest.write(_PACKET_HDR.pack(sec, usec, incl, max(wire_len, incl)))
        dest.write(buf[:incl])
        n += 1
    return n


def pcap_bytes(linktype: int,
               frames: Iterable[tuple[float, bytes, int]]) -> bytes:
    """EN: Convenience — whole savefile in memory (rings stay small).
    FR: Confort — le savefile entier en mémoire (les anneaux restent petits)."""
    buf = io.BytesIO()
    write_pcap(buf, linktype, frames)
    return buf.getvalue()
