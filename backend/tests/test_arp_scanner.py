"""
Snitch — ARP scanner parsing tests.

EN: macOS `arp -a` drops leading zeros in MAC octets ("be:18:9d:a0:c1:3") —
    a strict two-digit regex silently skips whole devices (this actually
    hid the user's phone). Regression coverage for _norm_mac / MAC_RE.

FR: `arp -a` de macOS supprime les zéros de tête dans les octets MAC
    (« be:18:9d:a0:c1:3 ») — une regex stricte à deux chiffres ignorait
    silencieusement des appareils entiers (ça a réellement caché le
    téléphone de l'utilisateur). Couverture de régression pour
    _norm_mac / MAC_RE.
"""

from scanner.arp_scanner import MAC_RE, _norm_mac


def test_norm_mac_macos_unpadded():
    """EN: Single-digit octets get zero-padded. / FR: Octets à un chiffre complétés à zéro."""
    assert _norm_mac("be:18:9d:a0:c1:3") == "BE:18:9D:A0:C1:03"
    assert _norm_mac("ea:d5:e:80:3b:cf") == "EA:D5:0E:80:3B:CF"


def test_norm_mac_canonical_and_windows():
    assert _norm_mac("70:FC:8F:57:31:FB") == "70:FC:8F:57:31:FB"
    assert _norm_mac("00-e0-4c-12-34-56") == "00:E0:4C:12:34:56"   # EN: '-' separator / FR: séparateur « - »


def test_mac_re_matches_unpadded_line():
    line = "? (192.168.1.25) at be:18:9d:a0:c1:3 on en1 ifscope [ethernet]"
    assert MAC_RE.search(line)


def test_mac_re_rejects_incomplete():
    line = "? (192.168.1.9) at incomplete on en1 ifscope [ethernet]"
    assert not MAC_RE.search(line)
