"""
Snitch backend entry point.

EN: Single entry point — used both in development (`python run_backend.py`)
    and by PyInstaller for the standalone `snitch-backend` binary that
    Electron spawns. `app` is imported as an object (not a string) so
    PyInstaller traces the full import chain.

    Binds to 127.0.0.1 by default in ALL modes — the API holds sensitive
    traffic data and must never be network-exposed without an explicit
    SNITCH_BIND override (token auth is always enforced regardless).

FR: Point d'entrée unique — utilisé en développement (`python run_backend.py`)
    et par PyInstaller pour le binaire autonome `snitch-backend` que lance
    Electron. `app` est importé comme objet (pas une chaîne) pour que
    PyInstaller suive toute la chaîne d'imports.

    Écoute sur 127.0.0.1 par défaut dans TOUS les modes — l'API contient des
    données de trafic sensibles et ne doit jamais être exposée au réseau sans
    override explicite de SNITCH_BIND (le jeton reste de toute façon exigé).
"""

import logging
import os
import sys

# EN: When frozen by PyInstaller, all modules live inside sys._MEIPASS.
# FR: Quand l'app est figée par PyInstaller, tous les modules sont dans sys._MEIPASS.
if getattr(sys, 'frozen', False):
    bundle_dir = sys._MEIPASS
    if bundle_dir not in sys.path:
        sys.path.insert(0, bundle_dir)

# EN: console=False PyInstaller builds on Windows have no stdout/stderr (None),
#     which crashes uvicorn's log formatter (isatty) at startup.
# FR: Les builds PyInstaller console=False sous Windows n'ont pas de
#     stdout/stderr (None), ce qui fait planter le formateur de uvicorn (isatty).
if sys.stdout is None:
    sys.stdout = open(os.devnull, 'w', encoding='utf-8')
if sys.stderr is None:
    sys.stderr = open(os.devnull, 'w', encoding='utf-8')

# EN: Configure logging BEFORE importing app modules so they inherit handlers.
# FR: Configurer les logs AVANT d'importer les modules pour qu'ils héritent des handlers.
from logging_config import setup_logging  # noqa: E402

setup_logging(logging.INFO)

# EN: Direct import — PyInstaller follows this chain and bundles every
#     backend package (api, capture, classifier, detection, resolver,
#     scanner, storage) automatically.
# FR: Import direct — PyInstaller suit cette chaîne et embarque tous les
#     paquets backend (api, capture, classifier, detection, resolver,
#     scanner, storage) automatiquement.
from api.main import app  # noqa: E402
import uvicorn             # noqa: E402

if __name__ == '__main__':
    # EN: Optional --port/--bind argv flags — needed by the Windows elevated
    #     spawn path, where environment variables cannot cross the UAC
    #     boundary. Env vars still take precedence when both are present.
    # FR: Drapeaux argv optionnels --port/--bind — nécessaires pour le
    #     lancement élevé Windows, où les variables d'environnement ne
    #     traversent pas la frontière UAC. Les variables d'env gardent la
    #     priorité quand les deux sont présentes.
    argv_port = argv_bind = None
    args = sys.argv[1:]
    for i, a in enumerate(args):
        if a == '--port' and i + 1 < len(args):
            argv_port = args[i + 1]
        elif a == '--bind' and i + 1 < len(args):
            argv_bind = args[i + 1]

    # EN: Loopback-only by default everywhere — Electron AND Docker/dev.
    #     Set SNITCH_BIND=0.0.0.0 to expose (token auth still applies).
    # FR: Loopback uniquement par défaut partout — Electron ET Docker/dev.
    #     Poser SNITCH_BIND=0.0.0.0 pour exposer (le jeton reste exigé).
    uvicorn.run(
        app,
        host=os.environ.get('SNITCH_BIND') or argv_bind or '127.0.0.1',
        port=int(os.environ.get('SNITCH_PORT') or argv_port or '8000'),
        log_level='warning',
    )
