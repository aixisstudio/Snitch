"""
Snitch — traffic classifier.

EN: Assigns each connection a label (HTTPS, DNS, SSH…), a category
    (safe / tracking / cdn / dns / admin / unknown), a risk level and a UI
    color. Classification is heuristic: known tracker/CDN domain suffixes
    first, then well-known ports.

FR: Attribue à chaque connexion un label (HTTPS, DNS, SSH…), une catégorie
    (safe / tracking / cdn / dns / admin / unknown), un niveau de risque et
    une couleur pour l'UI. Classification heuristique : d'abord les suffixes
    de domaines trackers/CDN connus, puis les ports bien connus.
"""

from dataclasses import dataclass
from typing import Optional

# EN: Well-known tracker / analytics domains — flagged "tracking" (amber).
# FR: Domaines de tracking / analytics connus — signalés « tracking » (ambre).
KNOWN_TRACKERS = {
    "doubleclick.net", "googlesyndication.com", "facebook.com",
    "fbcdn.net", "amazon-adsystem.com", "scorecardresearch.com",
    "quantserve.com", "hotjar.com", "mixpanel.com", "segment.io",
}

# EN: Major CDN providers — flagged "cdn" (indigo). Not dangerous, but useful
#     to distinguish infrastructure from real endpoints.
# FR: Grands fournisseurs CDN — signalés « cdn » (indigo). Pas dangereux, mais
#     utile pour distinguer l'infrastructure des vrais endpoints.
KNOWN_CDN = {
    "cloudflare.com", "akamaiedge.net", "fastly.net",
    "cloudfront.net", "edgekey.net",
}

# EN: Human-readable service names for common destination ports.
# FR: Noms de service lisibles pour les ports de destination courants.
PORT_LABELS: dict[int, str] = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    22: "SSH",
    21: "FTP",
    25: "SMTP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}

RISK_LEVELS = ("safe", "tracking", "cdn", "unknown", "suspicious")


@dataclass
class TrafficCategory:
    """
    EN: Result of classification — everything the UI needs to render a node.
    FR: Résultat de la classification — tout ce qu'il faut à l'UI pour
        afficher un nœud.
    """
    label: str        # EN: "HTTPS", "DNS", "SSH"… / FR: « HTTPS », « DNS », « SSH »…
    category: str     # EN: "tracking", "cdn", "safe", "unknown"… / FR: idem
    risk: str         # EN: "low" | "medium" | "high" / FR: « low » | « medium » | « high »
    color: str        # EN: hex color for the graph / FR: couleur hex pour le graphe


def classify(
    hostname: Optional[str],
    dst_port: Optional[int],
    protocol: str,
) -> TrafficCategory:
    """
    EN: Classify one connection. Priority order:
          1. hostname contains a known tracker domain  -> tracking
          2. hostname contains a known CDN domain      -> cdn
          3. well-known destination port               -> safe/dns/admin
          4. fallback                                  -> unknown
    FR: Classifier une connexion. Ordre de priorité :
          1. hostname contient un domaine tracker connu -> tracking
          2. hostname contient un domaine CDN connu     -> cdn
          3. port de destination bien connu             -> safe/dns/admin
          4. repli                                      -> unknown
    """
    label = PORT_LABELS.get(dst_port or 0, protocol)

    if hostname:
        h = hostname.lower()
        for tracker in KNOWN_TRACKERS:
            if tracker in h:
                return TrafficCategory(label, "tracking", "medium", "#f59e0b")
        for cdn in KNOWN_CDN:
            if cdn in h:
                return TrafficCategory(label, "cdn", "low", "#6366f1")

    if dst_port == 443:
        return TrafficCategory(label, "safe", "low", "#22c55e")
    if dst_port == 80:
        return TrafficCategory(label, "safe", "low", "#84cc16")
    if dst_port == 53:
        return TrafficCategory(label, "dns", "low", "#38bdf8")
    if dst_port == 22:
        return TrafficCategory(label, "admin", "medium", "#fb923c")

    return TrafficCategory(label, "unknown", "low", "#94a3b8")
