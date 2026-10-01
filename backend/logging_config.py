"""
Snitch — logging configuration.

EN: Central logging setup. Logs go to stdout AND a rotating file in the data
    directory (<data>/logs/snitch.log, 3 × 1 MB). Called once from
    run_backend.py; library modules just do `logging.getLogger("snitch.x")`.
    Replaces the old `except Exception: pass` pattern with real, debuggable
    diagnostics.

FR: Configuration centralisée des logs. Sortie vers stdout ET un fichier
    rotatif dans le dossier de données (<data>/logs/snitch.log, 3 × 1 Mo).
    Appelé une fois depuis run_backend.py ; les modules utilisent simplement
    `logging.getLogger("snitch.x")`. Remplace l'ancien motif
    `except Exception: pass` par de vrais diagnostics exploitables.
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from paths import data_dir


def setup_logging(level: int = logging.INFO) -> Path:
    """
    EN: Configure the root "snitch" logger. Returns the log file path.
        Idempotent — safe to call twice.
    FR: Configurer le logger racine « snitch ». Renvoie le chemin du fichier
        de log. Idempotent — appelable plusieurs fois sans effet.
    """
    log_dir = data_dir() / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "snitch.log"

    root = logging.getLogger("snitch")
    if root.handlers:
        return log_file  # EN: already configured / FR: déjà configuré

    root.setLevel(level)
    fmt = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")

    console = logging.StreamHandler()
    console.setFormatter(fmt)
    root.addHandler(console)

    try:
        file_handler = RotatingFileHandler(
            log_file, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)
    except OSError as exc:
        root.warning("File logging unavailable (%s) — console only", exc)

    return log_file
