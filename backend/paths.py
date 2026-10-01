"""
Snitch — filesystem paths.

EN: Single source of truth for the writable data directory — shared by the
    DB, the API token file and the log file (each used to duplicate this
    logic). Resolution order:
      1. SNITCH_DATA_DIR env var            (tests, custom deployments)
      2. per-OS user data dir               (frozen/Electron installs)
           Windows : %LOCALAPPDATA%\\Snitch
           macOS   : ~/Library/Application Support/Snitch
           Linux   : $XDG_DATA_HOME/snitch or ~/.local/share/snitch
      3. <repo>/data                        (dev / Docker)

    NOTE: PyInstaller bundles are read-only — Path(__file__)-relative data
    dirs land inside the bundle and silently lose writes. Rule 2 exists for
    exactly that reason.

FR: Source de vérité unique pour le dossier de données inscriptible — partagée
    par la BDD, le fichier de jeton API et le fichier de log (chacun dupliquait
    cette logique). Ordre de résolution :
      1. variable SNITCH_DATA_DIR            (tests, déploiements personnalisés)
      2. dossier de données utilisateur par OS (installations figées/Electron)
           Windows : %LOCALAPPDATA%\\Snitch
           macOS   : ~/Library/Application Support/Snitch
           Linux   : $XDG_DATA_HOME/snitch ou ~/.local/share/snitch
      3. <dépôt>/data                        (dev / Docker)

    ATTENTION : les bundles PyInstaller sont en lecture seule — un dossier de
    données relatif à Path(__file__) atterrit dans le bundle et perd les
    écritures silencieusement. La règle 2 existe exactement pour ça.
"""

import os
import sys
from pathlib import Path


def data_dir() -> Path:
    """
    EN: Resolve (and create) the writable data directory.
    FR: Résoudre (et créer) le dossier de données inscriptible.
    """
    env_dir = os.environ.get("SNITCH_DATA_DIR")
    if env_dir:
        d = Path(env_dir)
    elif getattr(sys, "frozen", False) or os.environ.get("SNITCH_USER_DATA") == "1":
        if sys.platform == "win32":
            d = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / "Snitch"
        elif sys.platform == "darwin":
            d = Path.home() / "Library" / "Application Support" / "Snitch"
        else:
            d = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "snitch"
    else:
        d = Path(__file__).parent.parent / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d
