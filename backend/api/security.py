"""
Snitch — API security layer.

EN: Three complementary protections:
      1. Bearer-style token. Generated at startup (or taken from the
         SNITCH_TOKEN env var, which is how the Electron wrapper injects
         it), persisted to <data>/api_token.txt (0600) and printed once to
         stdout so Docker/dev users can pass ?token=… in the browser.
         Every REST endpoint and the WebSocket require it.
      2. CORS allowlist — no more `*`. Only the Vite dev server, the
         backend's own origin and `null` (file:// pages under Electron).
      3. Origin check on the WebSocket handshake — blocks Cross-Site
         WebSocket Hijacking even if a browser somehow skips CORS.

FR: Trois protections complémentaires :
      1. Jeton d'authentification. Généré au démarrage (ou pris de la variable
         SNITCH_TOKEN, ce que fait le conteneur Electron), persisté dans
         <data>/api_token.txt (0600) et affiché une fois sur stdout pour que
         les utilisateurs Docker/dev passent ?token=… dans le navigateur.
         Chaque endpoint REST et le WebSocket l'exigent.
      2. Liste blanche CORS — plus de `*`. Seulement le serveur de dev Vite,
         l'origine du backend lui-même et `null` (pages file:// sous Electron).
      3. Vérification d'Origin sur le handshake WebSocket — bloque le
         Cross-Site WebSocket Hijacking même si un navigateur contourne CORS.
"""

import logging
import os
import secrets
import sys
from pathlib import Path

from fastapi import HTTPException, Request, WebSocket, status

logger = logging.getLogger("snitch.api.security")

# EN: Origins allowed to reach the API. `null` covers file:// pages (Electron
#     renderer) — browsers send Origin: null for local files.
# FR: Origines autorisées à joindre l'API. `null` couvre les pages file://
#     (renderer Electron) — les navigateurs envoient Origin: null pour les
#     fichiers locaux.
ALLOWED_ORIGINS = {
    "http://localhost:5173",   # EN: Vite dev / FR: dev Vite
    "http://127.0.0.1:5173",
    "http://localhost:8000",   # EN: backend serving its own frontend
    "http://127.0.0.1:8000",   # FR: le backend servant son propre frontend
    "null",                    # EN: file:// (Electron) / FR: file:// (Electron)
}

ALLOWED_ORIGINS_LIST = sorted(ALLOWED_ORIGINS)


def _data_dir() -> Path:
    """
    EN: Resolve the writable data directory — same rules as storage.db:
        SNITCH_DATA_DIR env override, LOCALAPPDATA\\Snitch when frozen by
        PyInstaller, otherwise <repo>/data.
    FR: Résoudre le dossier de données inscriptible — mêmes règles que
        storage.db : SNITCH_DATA_DIR en priorité, LOCALAPPDATA\\Snitch quand
        figé par PyInstaller, sinon <dépôt>/data.
    """
    env_dir = os.environ.get("SNITCH_DATA_DIR")
    if env_dir:
        d = Path(env_dir)
    elif getattr(sys, "frozen", False):
        d = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "Snitch"
    else:
        d = Path(__file__).parent.parent.parent / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _load_or_create_token() -> str:
    """
    EN: Token resolution order:
          1. SNITCH_TOKEN env var   — set by the Electron wrapper
          2. existing api_token.txt — survives backend restarts so an open
             UI doesn't get logged out
          3. freshly generated 48-hex secret
        The token file is created with 0600 permissions where supported.
    FR: Ordre de résolution du jeton :
          1. variable SNITCH_TOKEN  — posée par le conteneur Electron
          2. api_token.txt existant — survit aux redémarrages du backend pour
             ne pas déconnecter une UI déjà ouverte
          3. secret hexadécimal de 48 caractères fraîchement généré
        Le fichier est créé en 0600 quand le système le permet.
    """
    token = os.environ.get("SNITCH_TOKEN", "").strip()
    if token:
        return token

    token_file = _data_dir() / "api_token.txt"
    try:
        if token_file.exists():
            existing = token_file.read_text().strip()
            if len(existing) >= 32:
                return existing
    except OSError:
        pass

    token = secrets.token_hex(24)
    try:
        token_file.write_text(token)
        try:
            os.chmod(token_file, 0o600)   # EN: owner-only / FR: propriétaire seul
        except OSError:
            pass                          # EN: Windows has no chmod semantics
                                          # FR: Windows n'a pas de sémantique chmod
    except OSError as exc:
        logger.warning("Could not persist API token to %s: %s", token_file, exc)

    # EN: Printed once so Docker/browser users can complete the ?token= URL.
    # FR: Affiché une fois pour que les utilisateurs Docker/navigateur complètent l'URL ?token=.
    print(f"[snitch] API token: {token}", flush=True)
    return token


# EN: Resolved once at import — the token is stable for the process lifetime.
# FR: Résolu une fois à l'import — le jeton est stable pour la vie du processus.
API_TOKEN = _load_or_create_token()


def _extract_token(request: Request) -> str | None:
    """
    EN: Accept `X-Snitch-Token` header (preferred) or `?token=` query param
        (needed by the WebSocket, which can't set headers in the browser API).
    FR: Accepter l'en-tête `X-Snitch-Token` (préféré) ou le paramètre `?token=`
        (nécessaire pour le WebSocket, qui ne peut pas poser d'en-têtes dans
        l'API navigateur).
    """
    return request.headers.get("x-snitch-token") or request.query_params.get("token")


def require_token(request: Request) -> None:
    """
    EN: FastAPI dependency — 401 unless a valid token is presented.
        Applies to ALL endpoints: even GET /graph leaks sensitive traffic data.
    FR: Dépendance FastAPI — 401 sans jeton valide.
        S'applique à TOUS les endpoints : même GET /graph divulgue des données
        de trafic sensibles.
    """
    token = _extract_token(request)
    if not token or not secrets.compare_digest(token, API_TOKEN):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API token")


def origin_allowed(origin: str | None) -> bool:
    """
    EN: An absent Origin header means a non-browser client (curl, Electron's
        main process) — allowed. Present origins must be in the allowlist.
    FR: Un en-tête Origin absent signifie un client non-navigateur (curl,
        processus principal d'Electron) — autorisé. Les origines présentes
        doivent figurer dans la liste blanche.
    """
    return origin is None or origin in ALLOWED_ORIGINS


async def ws_authorized(websocket: WebSocket) -> bool:
    """
    EN: WebSocket gate — validates Origin (anti-CSWSH) and the ?token= param.
        Closes with 4401/4403 and returns False on failure so callers bail out.
    FR: Barrière WebSocket — valide Origin (anti-CSWSH) et le paramètre
        ?token=. Ferme avec 4401/4403 et renvoie False en cas d'échec pour
        que l'appelant abandonne.
    """
    if not origin_allowed(websocket.headers.get("origin")):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return False
    token = websocket.query_params.get("token") or websocket.headers.get("x-snitch-token")
    if not token or not secrets.compare_digest(token, API_TOKEN):
        await websocket.close(code=4401)
        return False
    return True
