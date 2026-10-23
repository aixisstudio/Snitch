"""
Snitch — capture interface selection tests (no libpcap, no real traffic).

EN: Covers sockaddr decoding of libpcap device addresses and the default
    interface choice: the device owning the default-route IP must win over
    virtual adapters listed first (WSL/Hyper-V on Windows).
FR: Couvre le décodage sockaddr des adresses de périphériques libpcap et le
    choix de l'interface par défaut : le périphérique qui possède l'IP de la
    route par défaut doit l'emporter sur les cartes virtuelles listées en
    premier (WSL/Hyper-V sous Windows).
"""

import ctypes
import socket
import struct
import sys

import capture.pcap as pcap
import capture.sniffer as sniffer
from capture.pcap import PcapDevice


def _sockaddr_in(ip: str) -> ctypes.Array:
    """EN: Platform-shaped sockaddr_in buffer. / FR: Buffer sockaddr_in au format de la plateforme."""
    if sys.platform == "darwin":
        head = bytes([16, socket.AF_INET])
    else:
        head = struct.pack("<H", socket.AF_INET)
    raw = head + bytes(2) + socket.inet_aton(ip) + bytes(16)
    return ctypes.create_string_buffer(raw, len(raw))


def _sockaddr_in6(ip: str) -> ctypes.Array:
    """EN: Platform-shaped sockaddr_in6 buffer. / FR: Buffer sockaddr_in6 au format de la plateforme."""
    if sys.platform == "darwin":
        head = bytes([28, socket.AF_INET6])
    else:
        head = struct.pack("<H", socket.AF_INET6)
    raw = head + bytes(6) + socket.inet_pton(socket.AF_INET6, ip) + bytes(4)
    return ctypes.create_string_buffer(raw, len(raw))


def test_sockaddr_ipv4():
    buf = _sockaddr_in("192.168.1.42")
    assert pcap._sockaddr_ip(ctypes.addressof(buf)) == "192.168.1.42"


def test_sockaddr_ipv6():
    buf = _sockaddr_in6("2001:db8::7")
    assert pcap._sockaddr_ip(ctypes.addressof(buf)) == "2001:db8::7"


def test_sockaddr_null():
    assert pcap._sockaddr_ip(None) is None


def test_default_iface_prefers_default_route(monkeypatch):
    devs = [
        PcapDevice(r"\Device\NPF_{WSL}", "vEthernet (WSL)", addresses=("172.20.0.1",)),
        PcapDevice(r"\Device\NPF_{ETH}", "Ethernet 2", addresses=("10.0.0.5",)),
        PcapDevice(r"\Device\NPF_Loopback", "Loopback", loopback=True,
                   addresses=("127.0.0.1",)),
    ]
    monkeypatch.setattr(sniffer, "list_devices", lambda: devs)
    monkeypatch.setattr(sniffer, "_default_route_ip", lambda: "10.0.0.5")
    assert sniffer.PacketSniffer._default_iface() == r"\Device\NPF_{ETH}"


def test_default_iface_falls_back_without_route(monkeypatch):
    devs = [
        PcapDevice("lo0", "", loopback=True),
        PcapDevice("en0", "", addresses=("192.168.1.2",)),
    ]
    monkeypatch.setattr(sniffer, "list_devices", lambda: devs)
    monkeypatch.setattr(sniffer, "_default_route_ip", lambda: None)
    monkeypatch.setattr(sniffer.psutil, "net_if_addrs", lambda: {})
    assert sniffer.PacketSniffer._default_iface() == "en0"


def test_pcap_open_failure_is_reported(monkeypatch):
    """EN: pcap_open_live failing (no privileges / missing Npcap) must set
        last_error and fire on_error — the old code logged and died silently,
        which is how users got "devices but no traffic" with no explanation.
    FR: Un échec de pcap_open_live (droits manquants / Npcap absent) doit
        remplir last_error et déclencher on_error — l'ancien code logguait
        puis mourrait silencieusement, d'où le « appareils mais pas de
        trafic » sans explication vu par les utilisateurs."""
    monkeypatch.setattr(sniffer, "PCAP_AVAILABLE", True)

    def boom(*_a, **_k):
        raise sniffer.PcapError("you don't have permission to capture")
    monkeypatch.setattr(sniffer, "PcapSession", boom)

    s = sniffer.PacketSniffer(callback=lambda p: None, iface="en0")
    errors = []
    s.on_error = errors.append
    s._running = True
    s._run()
    assert s.last_error and "permission" in s.last_error
    assert errors == [s.last_error]


def test_missing_libpcap_is_reported(monkeypatch):
    """EN: No libpcap at all must also surface via last_error + on_error.
    FR: L'absence totale de libpcap doit aussi remonter via last_error +
        on_error."""
    monkeypatch.setattr(sniffer, "PCAP_AVAILABLE", False)
    s = sniffer.PacketSniffer(callback=lambda p: None, iface="en0")
    errors = []
    s.on_error = errors.append
    s.start()
    assert s.last_error
    assert errors == [s.last_error]
