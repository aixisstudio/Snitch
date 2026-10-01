"""
Snitch backend entry point.

EN: This script is the single entry point for the Snitch backend.
    It is used both in development (`python run_backend.py`) and by
    PyInstaller when producing the standalone `snitch-backend` binary
    launched by the Electron wrapper as a child process.
    `app` is imported as an object (not a string) so PyInstaller can trace
    the full import chain and bundle api, capture, classifier, etc.

FR: Point d'entrée unique du backend Snitch.
    Utilisé à la fois en développement (`python run_backend.py`) et par
    PyInstaller pour produire le binaire autonome `snitch-backend` lancé
    par le conteneur Electron comme processus enfant.
    `app` est importé comme objet (pas comme chaîne) pour que PyInstaller
    suive toute la chaîne d'imports et embarque api, capture, classifier, etc.
"""

import os
import sys

# EN: When frozen by PyInstaller, all modules live inside sys._MEIPASS.
#     Make sure that directory is importable.
# FR: Quand l'app est figée par PyInstaller, tous les modules sont dans
#     sys._MEIPASS. On s'assure que ce dossier est importable.
if getattr(sys, 'frozen', False):
    bundle_dir = sys._MEIPASS
    if bundle_dir not in sys.path:
        sys.path.insert(0, bundle_dir)

# EN: Direct import — PyInstaller follows this chain and includes every
#     backend package (api, capture, classifier, detection, resolver,
#     scanner, storage) automatically.
# FR: Import direct — PyInstaller suit cette chaîne et inclut automatiquement
#     tous les paquets backend (api, capture, classifier, detection, resolver,
#     scanner, storage).
from api.main import app  # noqa: E402
import uvicorn             # noqa: E402

if __name__ == '__main__':
    # EN: In the frozen (Electron) build, bind to localhost only — the UI is
    #     a local app, there is no reason to expose the API on the network.
    #     In Docker/dev we default to all interfaces so the UI is reachable.
    # FR: Dans le build figé (Electron), on n'écoute que sur localhost — l'UI
    #     est une app locale, aucune raison d'exposer l'API sur le réseau.
    #     En Docker/dev on écoute sur toutes les interfaces.
    default_bind = '127.0.0.1' if getattr(sys, 'frozen', False) else '0.0.0.0'
    uvicorn.run(
        app,
        host=os.environ.get('SNITCH_BIND', default_bind),
        port=int(os.environ.get('SNITCH_PORT', '8000')),
        log_level='warning',
    )
