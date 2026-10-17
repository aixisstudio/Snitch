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
