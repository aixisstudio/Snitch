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
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


def _data_dir() -> Path:
    """
    EN: Same resolution as api.security / storage.db — duplicated here so this
        module has zero internal dependencies (it must be importable first).
    FR: Même résolution que api.security / storage.db — dupliquée ici pour que
        ce module n'ait aucune dépendance interne (il doit être importable en
        premier).
    """
    env_dir = os.environ.get("SNITCH_DATA_DIR")
    if env_dir:
        d = Path(env_dir)
    elif getattr(sys, "frozen", False):
        d = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Snitch"
    else:
        d = Path(__file__).parent.parent / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def setup_logging(level: int = logging.INFO) -> Path:
    """
    EN: Configure the root "snitch" logger. Returns the log file path.
        Idempotent — safe to call twice.
    FR: Configurer le logger racine « snitch ». Renvoie le chemin du fichier
        de log. Idempotent — appelable plusieurs fois sans effet.
    """
    log_dir = _data_dir() / "logs"
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
