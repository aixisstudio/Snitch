"""
Snitch — OUI lookup table.

EN: Maps the first 6 hex chars of a MAC address (the Organizationally Unique
    Identifier) to a (vendor, device_type) pair.

    Two layers:
      1. OUI_TABLE — hand-picked prefixes that also carry a device_type guess
         (home routers, phones, TVs, IoT). These always win.
      2. oui_table.txt.gz — the full IEEE MA-L registry (~40k vendors,
         ~390 KB compressed), loaded lazily from package data. Gives a vendor
         name for almost every real MAC; device_type stays "unknown" since
         the registry doesn't tell you what the device IS.

    Locally-administered MACs (bit 1 of the first octet set) are private/
    randomized addresses — iOS/Android default to them. is_local_mac()
    detects them so the UI can explain why no vendor shows.

FR: Associe les 6 premiers caractères hex d'une adresse MAC (l'Organizationally
    Unique Identifier) à un couple (fabricant, type d'appareil).

    Deux couches :
      1. OUI_TABLE — préfixes choisis qui portent aussi une estimation de type
         d'appareil (routeurs, téléphones, TV, IoT). Toujours prioritaires.
      2. oui_table.txt.gz — le registre IEEE MA-L complet (~40 000 fabricants,
         ~390 Ko compressé), chargé paresseusement depuis les données du
         package. Donne un nom de fabricant pour presque toute MAC réelle ;
         le type reste « unknown » car le registre ne dit pas ce qu'est
         l'appareil.

    Les MAC locales (bit 1 du premier octet levé) sont des adresses privées/
    aléatoires — iOS/Android les utilisent par défaut. is_local_mac() les
    détecte pour que l'UI explique l'absence de fabricant.
"""

import gzip
import sys
from pathlib import Path

# EN: Curated OUI table — key = first 6 hex chars of MAC (uppercase, no colons).
#     Value = (vendor, device_type). Takes precedence over the IEEE registry.
# FR: Table OUI choisie — clé = 6 premiers caractères hex de la MAC (majuscules,
#     sans « : »). Valeur = (fabricant, type). Prioritaire sur le registre IEEE.
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
    "58A023": ("Intel", "pc"),
    # Realtek — EN: PC NICs / FR: cartes réseau de PC
    "00E04C": ("Realtek", "pc"),
    # French ISP boxes — EN: gate the gateway check anyway, these are belts
    # FR: Box d'opérateurs français — la détection de passerelle reste active,
    #     ce ne sont que des indices supplémentaires
    "70FC8F": ("Freebox", "router"), "001D19": ("Freebox", "router"),
    "F4CAE5": ("Freebox", "router"), "14A9E3": ("Orange", "router"),
    "A09169": ("Orange", "router"), "449F51": ("Bouygues", "router"),
    "EC43E6": ("SFR", "router"), "2485B5": ("SFR", "router"),
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


# EN: Full IEEE registry, loaded lazily on first lookup miss: prefix → vendor.
#     The .gz sits in package data (works in dev AND under sys._MEIPASS).
# FR: Registre IEEE complet, chargé paresseusement au premier échec de lookup :
#     préfixe → fabricant. Le .gz est embarqué dans les données du package
#     (fonctionne en dev ET sous sys._MEIPASS).
_IEEE_TABLE: dict[str, str] | None = None


def _ieee_table() -> dict[str, str]:
    """
    EN: One-shot loader for oui_table.txt.gz — lines "HHHHHH|Vendor Name".
        Empty dict on any failure; lookup then falls back to "unknown".
    FR: Chargeur unique de oui_table.txt.gz — lignes « HHHHHH|Nom fabricant ».
        Dictionnaire vide sur erreur ; le lookup retombe alors sur « unknown ».
    """
    global _IEEE_TABLE
    if _IEEE_TABLE is not None:
        return _IEEE_TABLE
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    candidates = [
        base / "scanner" / "oui_table.txt.gz" if getattr(sys, "_MEIPASS", None)
            else base / "oui_table.txt.gz",
        base / "oui_table.txt.gz",
    ]
    table: dict[str, str] = {}
    for path in candidates:
        try:
            if path.exists():
                with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        prefix, _, vendor = line.strip().partition("|")
                        if prefix and vendor:
                            table[prefix] = vendor
                break
        except OSError:
            continue
    _IEEE_TABLE = table
    return table


def is_local_mac(mac: str) -> bool:
    """
    EN: True for locally-administered addresses (U/L bit = bit 1 of the first
        octet). iOS, Android and modern Windows randomize MACs this way on
        Wi-Fi — no OUI will ever match, and the UI should say so.
    FR: Vrai pour les adresses administrées localement (bit U/L = bit 1 du
        premier octet). iOS, Android et Windows récents randomisent ainsi les
        MAC en Wi-Fi — aucun OUI ne correspondra, l'UI doit le dire.
    """
    try:
        first = int(mac.replace(":", "").replace("-", "")[:2], 16)
        return bool(first & 0x02)
    except ValueError:
        return False


def lookup(mac: str) -> tuple[str, str]:
    """
    EN: Return (vendor, device_type) for a MAC address string.
        Resolution order: curated table → IEEE registry → ("", "unknown").
    FR: Renvoyer (fabricant, type d'appareil) pour une adresse MAC.
        Ordre : table choisie → registre IEEE → ("", "unknown").
    """
    key = mac.upper().replace(":", "").replace("-", "")[:6]
    if key in OUI_TABLE:
        return OUI_TABLE[key]
    vendor = _ieee_table().get(key, "")
    return (vendor, "unknown") if vendor else ("", "unknown")
