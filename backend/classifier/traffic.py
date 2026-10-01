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

import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from paths import data_dir

logger = logging.getLogger("snitch.classifier")


def _list_dir() -> Path:
    """EN: Bundled classifier/lists/ directory — works in dev AND inside the
    PyInstaller bundle (sys._MEIPASS). / FR: Dossier classifier/lists/
    embarqué — fonctionne en dev ET dans le bundle PyInstaller
    (sys._MEIPASS)."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / "classifier" / "lists" if getattr(sys, "_MEIPASS", None) else base / "lists"


def _load_domain_list(name: str, fallback: set[str]) -> set[str]:
    """
    EN: Load a domain list. Priority: <data_dir>/lists/<name> (user override)
        → bundled classifier/lists/<name> → hardcoded fallback. Blank lines
        and '#' comments are skipped; everything is lowercased.
    FR: Charger une liste de domaines. Priorité : <data_dir>/lists/<name>
        (surcharge utilisateur) → classifier/lists/<name> embarqué → repli
        codé en dur. Lignes vides et commentaires '#' ignorés ; tout en
        minuscules.
    """
    candidates = [data_dir() / "lists" / name, _list_dir() / name]
    for path in candidates:
        try:
            if path.exists():
                domains = {
                    line.strip().lower()
                    for line in path.read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.strip().startswith("#")
                }
                if domains:
                    logger.debug("loaded %d domains from %s", len(domains), path)
                    return domains
        except OSError as exc:
            logger.warning("cannot read %s: %s", path, exc)
    return set(fallback)


# EN: Last-resort in-code lists if the data files are missing entirely.
# FR: Listes de dernier recours si les fichiers de données manquent.
_FALLBACK_TRACKERS = {"doubleclick.net", "googlesyndication.com", "facebook.com"}
_FALLBACK_CDNS = {"cloudflare.com", "akamaiedge.net", "fastly.net", "cloudfront.net"}

# EN: Well-known tracker / analytics domains — flagged "tracking" (amber).
#     Loaded from data/lists/ so the community can extend them without code.
# FR: Domaines de tracking / analytics connus — signalés « tracking » (ambre).
#     Chargés depuis data/lists/ pour que la communauté puisse les étendre
#     sans toucher au code.
KNOWN_TRACKERS = _load_domain_list("trackers.txt", _FALLBACK_TRACKERS)

# EN: Major CDN providers — flagged "cdn" (indigo). Not dangerous, but useful
#     to distinguish infrastructure from real endpoints.
# FR: Grands fournisseurs CDN — signalés « cdn » (indigo). Pas dangereux, mais
#     utile pour distinguer l'infrastructure des vrais endpoints.
KNOWN_CDN = _load_domain_list("cdns.txt", _FALLBACK_CDNS)


def _domain_match(hostname: str, domains: set[str]) -> bool:
    """
    EN: Registrable-domain SUFFIX match — "cdn.api.example.com" matches
        "example.com" but "notexample.com" does NOT (the old `in` substring
        test produced exactly that kind of false positive).
    FR: Correspondance par SUFFIXE de domaine enregistrable —
        « cdn.api.example.com » correspond à « example.com » mais
        « notexample.com » NON (l'ancien test par sous-chaîne produisait
        exactement ce genre de faux positif).
    """
    h = hostname.lower().rstrip(".")
    for d in domains:
        if h == d or h.endswith("." + d):
            return True
    return False

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
          1. hostname ends with a known tracker domain -> tracking
          2. hostname ends with a known CDN domain     -> cdn
          3. well-known destination port               -> safe/dns/admin
          4. fallback                                  -> unknown
    FR: Classifier une connexion. Ordre de priorité :
          1. hostname finit par un domaine tracker connu -> tracking
          2. hostname finit par un domaine CDN connu     -> cdn
          3. port de destination bien connu              -> safe/dns/admin
          4. repli                                       -> unknown
    """
    label = PORT_LABELS.get(dst_port or 0, protocol)

    if hostname:
        if _domain_match(hostname, KNOWN_TRACKERS):
            return TrafficCategory(label, "tracking", "medium", "#f59e0b")
        if _domain_match(hostname, KNOWN_CDN):
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
