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

from fastapi import HTTPException, Request, WebSocket, status

from paths import data_dir

logger = logging.getLogger("snitch.api.security")

# EN: Origins allowed to reach the API. `null` covers file:// pages (Electron
#     renderer) — browsers send Origin: null for local files.
# FR: Origines autorisées à joindre l'API. `null` couvre les pages file://
#     (renderer Electron) — les navigateurs envoient Origin: null pour les
#     fichiers locaux.
# EN: The port is dynamic now (free-port selection), so the allowlist is a
#     RULE, not a literal set: loopback hosts on any port + `null` (file://
#     Electron). A loopback origin can only come from a local process/page —
#     remote origins always fail. Token auth applies on top regardless.
# FR: Le port est désormais dynamique (choix de port libre), donc la liste
#     blanche est une RÈGLE, pas un ensemble littéral : hôtes loopback sur tout
#     port + `null` (file:// Electron). Une origine loopback ne peut venir que
#     d'une page/processus local — les origines distantes échouent toujours.
#     L'authentification par jeton s'applique de toute façon par-dessus.
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}

def _is_loopback_origin(origin: str) -> bool:
    """EN: True when the origin's hostname is loopback (any scheme/port).
    FR: True quand le nom d'hôte de l'origine est loopback (schéma/port quelconques)."""
    try:
        from urllib.parse import urlparse
        host = urlparse(origin).hostname or ""
        return host.lower() in _LOOPBACK_HOSTS
    except Exception:
        return False


def origin_allowed(origin: str | None) -> bool:
    """
    EN: An absent Origin header means a non-browser client (curl, Electron's
        main process) — allowed. Present origins must be loopback or `null`.
    FR: Un en-tête Origin absent signifie un client non-navigateur (curl,
        processus principal d'Electron) — autorisé. Les origines présentes
        doivent être loopback ou `null`.
    """
    if origin is None:
        return True
    return origin == "null" or _is_loopback_origin(origin)


# EN: CORS needs literal strings/regex — a loopback regex mirrors the rule.
# FR: CORS exige des chaînes/regex littérales — une regex loopback reflète la règle.
ALLOWED_ORIGIN_REGEX = r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$"
ALLOWED_ORIGINS_LIST = ["null"]


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

    token_file = data_dir() / "api_token.txt"
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


def get_token() -> str:
    """EN: Public accessor — the CLI needs the token to build the open-URL.
    FR: Accesseur public — la CLI a besoin du jeton pour construire l'URL."""
    return API_TOKEN


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
