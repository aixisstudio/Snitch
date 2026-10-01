"""
Snitch — OUI lookup tests.

EN: MAC normalization (colons/dashes/case) and the unknown-prefix fallback.
FR: Normalisation des MAC (deux-points/tirets/casse) et le repli pour préfixe
    inconnu.
"""

from scanner.oui import lookup


def test_known_apple_prefix():
    vendor, dev_type = lookup("A4:C1:38:12:34:56")
    assert vendor == "Apple"
    assert dev_type == "phone"


def test_normalization_dashes_and_lowercase():
    vendor, _ = lookup("a4-c1-38-aa-bb-cc")
    assert vendor == "Apple"


def test_short_prefix_input():
    vendor, _ = lookup("B827EB")
    assert vendor == "Raspberry Pi"


def test_unknown_prefix():
    vendor, dev_type = lookup("ZZ:ZZ:ZZ:00:11:22")
    assert vendor == ""          # EN: empty — UI falls back to the IP and
                                 #     shows an "unidentified" badge instead
                                 # FR: vide — l'UI retombe sur l'IP et
                                 #     affiche un badge « non identifié »
    assert dev_type == "unknown"


def test_local_mac_detection():
    """EN: Randomized/locally-administered MACs are detected (U/L bit).
    FR: Les MAC aléatoires/administrées localement sont détectées (bit U/L)."""
    from scanner.oui import is_local_mac
    assert is_local_mac("BE:18:9D:A0:C1:3F")     # EN: iOS private MAC
    assert is_local_mac("ea:d5:0e:80:3b:cf")     # FR: MAC privée Android
    assert not is_local_mac("70:FC:8F:57:31:FB") # EN: real OUI (Freebox)
    assert not is_local_mac("58:A0:23:E9:E3:B4") # EN: real OUI (Intel)


def test_ieee_registry_fallback():
    """EN: Curated table wins; IEEE registry covers the long tail; unknown
        prefixes still return ("", "unknown").
    FR: La table choisie gagne ; le registre IEEE couvre le reste ; les
        préfixes inconnus renvoient toujours ("", "unknown")."""
    vendor, _ = lookup("70:FC:8F:57:31:FB")      # EN: in curated table → router
    assert vendor == "Freebox"
