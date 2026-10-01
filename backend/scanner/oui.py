"""
Snitch — OUI lookup table.

EN: Maps the first 6 hex chars of a MAC address (the Organizationally Unique
    Identifier) to a (vendor, device_type) pair. This is a partial,
    hand-picked table covering the most common home-network devices — extend
    it freely.

FR: Associe les 6 premiers caractères hex d'une adresse MAC (l'Organizationally
    Unique Identifier) à un couple (fabricant, type d'appareil). Table
    partielle et choisie couvrant les appareils domestiques les plus courants —
    à enrichir librement.
"""

# EN: Partial OUI table — key = first 6 hex chars of MAC (uppercase, no colons).
# FR: Table OUI partielle — clé = 6 premiers caractères hex de la MAC (majuscules, sans « : »).
OUI_TABLE: dict[str, tuple[str, str]] = {
    # Apple
    "A4C138": ("Apple", "phone"), "F0DCE2": ("Apple", "phone"),
    "3C0754": ("Apple", "phone"), "8C8590": ("Apple", "phone"),
    "ACBC32": ("Apple", "phone"), "F82793": ("Apple", "phone"),
    # Samsung
    "8CCE4E": ("Samsung", "phone"), "A0CBFD": ("Samsung", "phone"),
    "5425EA": ("Samsung", "phone"), "D87D76": ("Samsung", "tv"),
    # Cisco / Linksys
    "000C29": ("Cisco", "router"), "001A2F": ("Cisco", "router"),
    "1C1B0D": ("Cisco", "router"), "44D9E7": ("Cisco", "router"),
    # Netgear
    "20E52A": ("Netgear", "router"), "A021B7": ("Netgear", "router"),
    "C03F0E": ("Netgear", "router"),
    # TP-Link
    "50C7BF": ("TP-Link", "router"), "B0487A": ("TP-Link", "router"),
    "E894F6": ("TP-Link", "router"), "F4F26D": ("TP-Link", "router"),
    # ASUS
    "10BF48": ("ASUS", "router"), "107B44": ("ASUS", "router"),
    "2C4D54": ("ASUS", "router"),
    # Raspberry Pi
    "B827EB": ("Raspberry Pi", "iot"), "DC8E95": ("Raspberry Pi", "iot"),
    "E45F01": ("Raspberry Pi", "iot"),
    # Intel — EN: usually PC/laptop / FR: généralement PC/portable
    "8086F2": ("Intel", "pc"), "A4C3F0": ("Intel", "pc"),
    # Realtek — EN: PC NICs / FR: cartes réseau de PC
    "00E04C": ("Realtek", "pc"),
    # Google — Chromecast, Home, etc.
    "54600A": ("Google", "iot"), "F88FCA": ("Google", "iot"),
    "A47733": ("Google", "iot"),
    # Amazon — Echo, Fire TV
    "A002DC": ("Amazon", "iot"), "FC65DE": ("Amazon", "iot"),
    "B47C9C": ("Amazon", "iot"),
    # Sonos
    "5CAAFD": ("Sonos", "iot"), "B8E937": ("Sonos", "iot"),
    # Microsoft — Xbox, Surface
    "7C1E52": ("Microsoft", "pc"), "28184D": ("Microsoft", "pc"),
    # Sony — PlayStation, TVs
    "00D9D1": ("Sony", "iot"), "F8D0AC": ("Sony", "iot"),
}


# EN: UI color per device type — matches the legend in the frontend.
# FR: Couleur UI par type d'appareil — correspond à la légende du frontend.
DEVICE_TYPE_COLORS: dict[str, str] = {
    "router":  "#f97316",
    "phone":   "#a855f7",
    "pc":      "#06b6d4",
    "tv":      "#ec4899",
    "iot":     "#84cc16",
    "unknown": "#64748b",
}


def lookup(mac: str) -> tuple[str, str]:
    """
    EN: Return (vendor, device_type) for a MAC address string. Unknown OUIs
        return ("Unknown", "unknown").
    FR: Renvoyer (fabricant, type d'appareil) pour une adresse MAC. Les OUI
        inconnus renvoient ("Unknown", "unknown").
    """
    key = mac.upper().replace(":", "").replace("-", "")[:6]
    return OUI_TABLE.get(key, ("Unknown", "unknown"))
