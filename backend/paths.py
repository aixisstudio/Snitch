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


def _real_owner() -> tuple[int, int] | None:
    """
    EN: (uid, gid) of the desktop user who launched the app — passed via
        SNITCH_OWNER_UID/SNITCH_OWNER_GID by the Electron launcher when it
        elevates the backend (osascript/pkexec). None when not elevated or
        not told — chown is then skipped.
    FR: (uid, gid) de l'utilisateur qui a lancé l'app — transmis via
        SNITCH_OWNER_UID/SNITCH_OWNER_GID par le lanceur Electron quand il
        élève le backend (osascript/pkexec). None si non élevé ou non
        renseigné — le chown est alors sauté.
    """
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return None
    try:
        return int(os.environ["SNITCH_OWNER_UID"]), int(os.environ["SNITCH_OWNER_GID"])
    except (KeyError, ValueError):
        return None


def chown_to_user(path: Path) -> None:
    """
    EN: Hand a file/dir we just created back to the real desktop user.
        Without this, an ELEVATED backend leaves root-owned files inside
        ~/Library/Application Support/Snitch (or ~/.local/share/snitch) —
        the next unprivileged launch then dies with EACCES because
        Chromium/the launcher can no longer write there.
    FR: Rendre un fichier/dossier qu'on vient de créer au vrai utilisateur.
        Sans ça, un backend ÉLEVÉ laisse des fichiers possédés par root dans
        ~/Library/Application Support/Snitch (ou ~/.local/share/snitch) —
        le lancement non privilégié suivant meurt en EACCES car
        Chromium/le lanceur ne peut plus y écrire.
    """
    owner = _real_owner()
    if owner is not None:
        try:
            os.chown(path, *owner)
        except OSError:
            pass


def chown_tree(root: Path) -> None:
    """
    EN: Recursively chown the whole data dir back to the desktop user —
        called on shutdown so files created DURING this elevated run
        (logs, db, token) don't brick the next launch.
    FR: chown récursif de tout le dossier de données vers l'utilisateur —
        appelé à l'arrêt pour que les fichiers créés PENDANT ce run élevé
        (logs, db, jeton) ne briquent pas le lancement suivant.
    """
    owner = _real_owner()
    if owner is None:
        return
    try:
        os.chown(root, *owner)
        for p in root.rglob("*"):
            try:
                os.chown(p, *owner)
            except OSError:
                pass
    except OSError:
        pass


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
    chown_to_user(d)
    return d
