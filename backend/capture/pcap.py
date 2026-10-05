"""
Snitch — ctypes binding to libpcap / wpcap.

EN: Minimal, dependency-free binding to the system packet-capture library:
      - Windows : wpcap.dll, shipped by Npcap (user-installed — NOT bundled;
                  the free Npcap license does not allow external redistribution)
      - Linux   : libpcap.so (apt install libpcap0.8)
      - macOS   : libpcap.dylib (ships with the OS)

    ctypes is stdlib, so this adds zero compiled dependencies and zero GPL
    contamination (libpcap/Npcap are BSD-style licensed).

    Capture rights are still required: admin on Windows, root or
    cap_net_raw/cap_net_admin on Linux, /dev/bpf* access on macOS.

FR: Liaison ctypes minimale et sans dépendance vers la bibliothèque système de
    capture :
      - Windows : wpcap.dll, fournie par Npcap (installé par l'utilisateur —
                  PAS embarqué ; la licence gratuite de Npcap interdit la
                  redistribution externe)
      - Linux   : libpcap.so (apt install libpcap0.8)
      - macOS   : libpcap.dylib (livré avec l'OS)

    ctypes fait partie de la bibliothèque standard : zéro dépendance compilée,
    zéro contamination GPL (libpcap/Npcap sont sous licences de type BSD).

    Les droits de capture restent nécessaires : admin sous Windows, root ou
    cap_net_raw/cap_net_admin sous Linux, accès /dev/bpf* sous macOS.
"""

import ctypes
import ctypes.util
import logging
import socket
import sys
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("snitch.capture.pcap")


class PcapError(Exception):
    """EN: Raised when libpcap is missing or a call fails.
    FR: Levée quand libpcap est absente ou qu'un appel échoue."""
    pass


# ── Structures / Structures ──────────────────────────────────────────────────

class _TimeVal(ctypes.Structure):
    """EN: struct timeval. / FR: struct timeval."""
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class PcapPkthdr(ctypes.Structure):
    """EN: struct pcap_pkthdr — timestamp + captured/wire lengths.
    FR: struct pcap_pkthdr — timestamp + longueurs capturée/fil."""
    _fields_ = [
        ("ts", _TimeVal),
        ("caplen", ctypes.c_uint32),
        ("len", ctypes.c_uint32),
    ]


class PcapAddr(ctypes.Structure):
    """EN: struct pcap_addr (linked list of interface addresses).
    FR: struct pcap_addr (liste chaînée des adresses d'interface)."""
    pass


PcapAddr._fields_ = [
    ("next", ctypes.POINTER(PcapAddr)),
    ("addr", ctypes.c_void_p),
    ("netmask", ctypes.c_void_p),
    ("broadaddr", ctypes.c_void_p),
    ("dstaddr", ctypes.c_void_p),
]


class PcapIf(ctypes.Structure):
    """EN: struct pcap_if — device list node. / FR: struct pcap_if — nœud de la liste de périphériques."""
    pass


PcapIf._fields_ = [
    ("next", ctypes.POINTER(PcapIf)),
    ("name", ctypes.c_char_p),
    ("description", ctypes.c_char_p),
    ("addresses", ctypes.POINTER(PcapAddr)),
    ("flags", ctypes.c_uint32),
]


class BpfInsn(ctypes.Structure):
    """EN: struct bpf_insn. / FR: struct bpf_insn."""
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class BpfProgram(ctypes.Structure):
    """EN: struct bpf_program. / FR: struct bpf_program."""
    _fields_ = [
        ("bf_len", ctypes.c_uint),
        ("bf_insns", ctypes.POINTER(BpfInsn)),
    ]


# ── Library loading / Chargement de la bibliothèque ─────────────────────────

_lib = None


def _load_lib() -> ctypes.CDLL:
    """
    EN: Locate and load libpcap for the current platform, once. On Windows,
        Npcap installs wpcap.dll under System32\\Npcap — add it to the DLL
        search path explicitly (required since Python 3.8 no longer searches
        PATH for ctypes loads).
    FR: Localiser et charger libpcap pour la plateforme courante, une fois.
        Sous Windows, Npcap installe wpcap.dll dans System32\\Npcap — l'ajouter
        explicitement au chemin de recherche DLL (Python 3.8+ ne consulte plus
        PATH pour les chargements ctypes).
    """
    global _lib
    if _lib is not None:
        return _lib

    candidates: list[str] = []
    if sys.platform == "win32":
        import os
        npcap_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                 "System32", "Npcap")
        if os.path.isdir(npcap_dir):
            try:
                os.add_dll_directory(npcap_dir)
            except OSError:
                pass
        candidates = ["wpcap.dll"]
    elif sys.platform == "darwin":
        candidates = ["libpcap.dylib", "libpcap.A.dylib"]
    else:
        found = ctypes.util.find_library("pcap")
        candidates = [found] if found else []
        candidates += ["libpcap.so.0.8", "libpcap.so.1", "libpcap.so"]

    last_err: Optional[Exception] = None
    for name in candidates:
        if not name:
            continue
        try:
            _lib = ctypes.CDLL(name)
            _configure(_lib)
            return _lib
        except OSError as exc:
            last_err = exc

    raise PcapError(_missing_msg(last_err))


def _missing_msg(err: Optional[Exception]) -> str:
    """EN: Human-readable install guidance per platform.
    FR: Conseils d'installation lisibles selon la plateforme."""
    if sys.platform == "win32":
        return ("Npcap not found — install it from https://npcap.com "
                "(Npcap n'est pas installé — téléchargez-le sur https://npcap.com)")
    if sys.platform == "darwin":
        return "libpcap not found (unexpected on macOS) / libpcap introuvable"
    return ("libpcap not found — install it (apt install libpcap0.8 / dnf install libpcap) "
            "/ libpcap introuvable — installez-la")


def _configure(lib: ctypes.CDLL) -> None:
    """EN: Declare argtypes/restypes for the functions we bind.
    FR: Déclarer les argtypes/restypes des fonctions liées."""
    lib.pcap_findalldevs.argtypes = [ctypes.POINTER(ctypes.POINTER(PcapIf)), ctypes.c_char_p]
    lib.pcap_findalldevs.restype = ctypes.c_int
    lib.pcap_freealldevs.argtypes = [ctypes.POINTER(PcapIf)]
    lib.pcap_freealldevs.restype = None

    lib.pcap_open_live.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int,
                                   ctypes.c_int, ctypes.c_char_p]
    lib.pcap_open_live.restype = ctypes.c_void_p

    lib.pcap_datalink.argtypes = [ctypes.c_void_p]
    lib.pcap_datalink.restype = ctypes.c_int

    lib.pcap_compile.argtypes = [ctypes.c_void_p, ctypes.POINTER(BpfProgram),
                                 ctypes.c_char_p, ctypes.c_int, ctypes.c_uint32]
    lib.pcap_compile.restype = ctypes.c_int

    lib.pcap_setfilter.argtypes = [ctypes.c_void_p, ctypes.POINTER(BpfProgram)]
    lib.pcap_setfilter.restype = ctypes.c_int

    lib.pcap_freecode.argtypes = [ctypes.POINTER(BpfProgram)]
    lib.pcap_freecode.restype = None

    lib.pcap_next_ex.argtypes = [ctypes.c_void_p,
                                 ctypes.POINTER(ctypes.POINTER(PcapPkthdr)),
                                 ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte))]
    lib.pcap_next_ex.restype = ctypes.c_int

    lib.pcap_geterr.argtypes = [ctypes.c_void_p]
    lib.pcap_geterr.restype = ctypes.c_char_p

    lib.pcap_close.argtypes = [ctypes.c_void_p]
    lib.pcap_close.restype = None

    lib.pcap_lib_version.restype = ctypes.c_char_p


def is_available() -> bool:
    """EN: True when libpcap/wpcap loads. / FR: True si libpcap/wpcap se charge."""
    try:
        _load_lib()
        return True
    except PcapError:
        return False


@dataclass
class PcapDevice:
    """EN: One capture-capable interface. / FR: Une interface capturable."""
    name: str
    description: str
    loopback: bool = False
    # EN: IPv4/IPv6 addresses owned by the device, as reported by libpcap.
    #     Needed on Windows, where Npcap names (\Device\NPF_{GUID}) never
    #     match psutil's friendly names ("Ethernet 2").
    # FR: Adresses IPv4/IPv6 du périphérique, telles que rapportées par
    #     libpcap. Indispensable sous Windows, où les noms Npcap
    #     (\Device\NPF_{GUID}) ne correspondent jamais aux noms
    #     conviviaux de psutil (« Ethernet 2 »).
    addresses: tuple[str, ...] = ()


def _sockaddr_ip(ptr: Optional[int]) -> Optional[str]:
    """
    EN: Decode a `struct sockaddr *` into an IP string (IPv4/IPv6 only).
        BSD/macOS start with a 1-byte sa_len then a 1-byte family; Windows
        and Linux use a 2-byte little-endian family.
    FR: Décoder un `struct sockaddr *` en chaîne IP (IPv4/IPv6 seulement).
        BSD/macOS commencent par sa_len sur 1 octet puis la famille sur 1
        octet ; Windows et Linux utilisent une famille sur 2 octets LE.
    """
    if not ptr:
        return None
    raw = ctypes.string_at(ptr, 24)
    family = raw[1] if sys.platform == "darwin" else int.from_bytes(raw[0:2], "little")
    if family == socket.AF_INET:
        return socket.inet_ntop(socket.AF_INET, raw[4:8])
    if family == socket.AF_INET6:
        return socket.inet_ntop(socket.AF_INET6, raw[8:24])
    return None


def list_devices() -> list[PcapDevice]:
    """
    EN: Enumerate capture interfaces via pcap_findalldevs.
    FR: Énumérer les interfaces de capture via pcap_findalldevs.
    """
    lib = _load_lib()
    devs = ctypes.POINTER(PcapIf)()
    errbuf = ctypes.create_string_buffer(256)
    try:
        if lib.pcap_findalldevs(ctypes.byref(devs), errbuf) != 0:
            raise PcapError(f"pcap_findalldevs: {errbuf.value.decode(errors='replace')}")
        out = []
        cur = devs
        while cur:
            d = cur.contents
            name = d.name.decode(errors="replace") if d.name else ""
            desc = d.description.decode(errors="replace") if d.description else ""
            addrs = []
            a = d.addresses
            while a:
                ip = _sockaddr_ip(a.contents.addr)
                if ip:
                    addrs.append(ip)
                a = a.contents.next
            out.append(PcapDevice(name=name, description=desc,
                                  loopback=bool(d.flags & 0x1),
                                  addresses=tuple(addrs)))
            cur = d.next
        return out
    finally:
        lib.pcap_freealldevs(devs)


class PcapSession:
    """
    EN: One live capture session on a device. `next_packet()` blocks up to
        `timeout_ms` (set at open) and returns (bytes, wire_len) or None on
        timeout — the caller loop polls and stays interruptible.
    FR: Une session de capture live sur un périphérique. `next_packet()`
        bloque jusqu'à `timeout_ms` (fixé à l'ouverture) et renvoie
        (octets, longueur_fil) ou None en cas de timeout — la boucle appelante
        sonde et reste interruptible.
    """

    def __init__(self, device: str, snaplen: int = 65535, promisc: bool = True,
                 timeout_ms: int = 100, bpf_filter: Optional[str] = None):
        self._lib = _load_lib()
        errbuf = ctypes.create_string_buffer(256)
        self._handle = self._lib.pcap_open_live(
            device.encode(), snaplen, 1 if promisc else 0, timeout_ms, errbuf)
        if not self._handle:
            raise PcapError(
                f"pcap_open_live({device}): {errbuf.value.decode(errors='replace')}")
        self.device = device
        self.linktype = self._lib.pcap_datalink(self._handle)
        self._closed = False

        if bpf_filter:
            prog = BpfProgram()
            try:
                if self._lib.pcap_compile(self._handle, ctypes.byref(prog),
                                          bpf_filter.encode(), 1, 0) != 0:
                    raise PcapError(f"pcap_compile({bpf_filter!r}): {self._err()}")
                if self._lib.pcap_setfilter(self._handle, ctypes.byref(prog)) != 0:
                    raise PcapError(f"pcap_setfilter: {self._err()}")
            finally:
                self._lib.pcap_freecode(ctypes.byref(prog))

    def _err(self) -> str:
        """EN: Last libpcap error string. / FR: Dernière erreur libpcap."""
        raw = self._lib.pcap_geterr(self._handle)
        return raw.decode(errors="replace") if raw else "unknown error"

    def next_packet(self) -> Optional[tuple[bytes, int]]:
        """
        EN: Next packet — (payload, wire_length) or None on timeout. Raises
            PcapError on capture failure or EOF.
        FR: Paquet suivant — (charge utile, longueur fil) ou None au timeout.
            Lève PcapError en cas d'échec de capture ou de fin de fichier.
        """
        hdr = ctypes.POINTER(PcapPkthdr)()
        data = ctypes.POINTER(ctypes.c_ubyte)()
        rc = self._lib.pcap_next_ex(self._handle, ctypes.byref(hdr), ctypes.byref(data))
        if rc == 1:
            return ctypes.string_at(data, hdr.contents.caplen), hdr.contents.len
        if rc == 0:
            return None                    # EN: timeout / FR: timeout
        if rc == -2:
            return None                    # EN: EOF (offline dumps) / FR: fin de fichier (dumps hors ligne)
        raise PcapError(f"pcap_next_ex: {self._err()}")

    def close(self) -> None:
        """EN: Release the capture handle. / FR: Libérer le handle de capture."""
        if not self._closed and self._handle:
            self._lib.pcap_close(self._handle)
            self._closed = True
