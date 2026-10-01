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
