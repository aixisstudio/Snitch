"""
Snitch — API security layer.

EN: Three complementary protections:
      1. Bearer-style token. Generated at startup (or taken from the
         SNITCH_TOKEN env var, which is how the Electron wrapper injects
         it), persisted to <data>/api_token.txt (0600) and printed once to
         stdout so Docker/dev users can pass ?token=… in the browser
         (disable that print with SNITCH_PRINT_TOKEN=0). REST endpoints
         require the X-Snitch-Token header; ?token= is honoured on the
         WebSocket handshake only.
      2. CORS allowlist — no more `*`. Only the Vite dev server, the
         backend's own origin and `null` (file:// pages under Electron).
      3. Origin check on the WebSocket handshake — blocks Cross-Site
         WebSocket Hijacking even if a browser somehow skips CORS.

FR: Trois protections complémentaires :
      1. Jeton d'authentification. Généré au démarrage (ou pris de la variable
         SNITCH_TOKEN, ce que fait le conteneur Electron), persisté dans
         <data>/api_token.txt (0600) et affiché une fois sur stdout pour que
         les utilisateurs Docker/dev passent ?token=… dans le navigateur
         (désactivable via SNITCH_PRINT_TOKEN=0). Les endpoints REST exigent
         l'en-tête X-Snitch-Token ; ?token= n'est honoré qu'au handshake
         WebSocket.
      2. Liste blanche CORS — plus de `*`. Seulement le serveur de dev Vite,
         l'origine du backend lui-même et `null` (pages file:// sous Electron).
      3. Vérification d'Origin sur le handshake WebSocket — bloque le
         Cross-Site WebSocket Hijacking même si un navigateur contourne CORS.
"""

import logging
import os
import secrets
import threading
import time

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
        main process) — allowed. Present origins must be loopback, `null`,
        or `file://` — Chromium inside Electron serialises the WebSocket
        Origin of a file:// page as literally `file://` (not `null` like a
        browser does), so without this the packaged app's own renderer was
        rejected with 403 and the UI stayed "Disconnected". A file:// origin
        can only come from a local page, and the token check still applies.
    FR: Un en-tête Origin absent signifie un client non-navigateur (curl,
        processus principal d'Electron) — autorisé. Les origines présentes
        doivent être loopback, `null` ou `file://` — Chromium sous Electron
        sérialise l'Origin WebSocket d'une page file:// littéralement en
        `file://` (pas `null` comme un navigateur), donc sans cela le renderer
        de l'app empaquetée était rejeté en 403 et l'UI restait « Déconnecté ».
        Une origine file:// ne peut venir que d'une page locale, et le
        contrôle du jeton s'applique toujours.
    """
    if origin is None:
        return True
    if origin == "null" or origin.startswith("file:"):
        return True
    return _is_loopback_origin(origin)


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
    #     Hardened deployments can suppress it with SNITCH_PRINT_TOKEN=0 —
    #     the token remains readable from api_token.txt (0600).
    # FR: Affiché une fois pour que les utilisateurs Docker/navigateur
    #     complètent l'URL ?token=. Les déploiements durcis peuvent le
    #     supprimer via SNITCH_PRINT_TOKEN=0 — le jeton reste lisible dans
    #     api_token.txt (0600).
    if os.environ.get("SNITCH_PRINT_TOKEN", "1") != "0":
        print(f"[snitch] API token: {token}", flush=True)
    return token


# EN: Resolved once at import — the token is stable for the process lifetime.
# FR: Résolu une fois à l'import — le jeton est stable pour la vie du processus.
API_TOKEN = _load_or_create_token()


def get_token() -> str:
    """EN: Public accessor — the CLI needs the token to build the open-URL.
    FR: Accesseur public — la CLI a besoin du jeton pour construire l'URL."""
    return API_TOKEN


# ── Brute-force guard / Garde anti-force brute ───────────────────────────────
# EN: The 48-hex token is not realistically brute-forceable, but when the
#     API is bound to a LAN address (opt-in SNITCH_BIND) failed attempts
#     are cheap to spray. Track failures per client IP: after
#     _AUTH_MAX_FAILS within _AUTH_WINDOW_S the source is rejected with
#     429/4401 for _AUTH_BAN_S. Loopback keeps the same rules — a rogue
#     local process should not get unlimited guesses either.
# FR: Le jeton hex de 48 caractères n'est pas réalistement brute-forçable,
#     mais quand l'API écoute sur une adresse LAN (SNITCH_BIND opt-in) les
#     tentatives ratées ne coûtent rien. Suivre les échecs par IP cliente :
#     après _AUTH_MAX_FAILS dans _AUTH_WINDOW_S la source est rejetée en
#     429/4401 pendant _AUTH_BAN_S. Loopback suit les mêmes règles — un
#     processus local malveillant ne doit pas avoir d'essais illimités non plus.
_AUTH_MAX_FAILS = 20
_AUTH_WINDOW_S = 300.0
_AUTH_BAN_S = 60.0
_AUTH_FAILS_CAP = 512          # EN: bound the tracker dict / FR: borne du suivi
_fail_lock = threading.Lock()
_fail_track: dict[str, list[float]] = {}
_banned_until: dict[str, float] = {}


def _client_ip(request: Request | WebSocket) -> str:
    """EN: Client source for the ban tracker. / FR: Source cliente pour le suivi."""
    return request.client.host if request.client else "unknown"


def _check_banned(ip: str) -> bool:
    """EN: True while `ip` is inside its ban window.
    FR: True tant qu'`ip` est dans sa fenêtre de bannissement."""
    with _fail_lock:
        until = _banned_until.get(ip, 0.0)
        if until > time.time():
            return True
        _banned_until.pop(ip, None)
        return False


def _record_failure(ip: str) -> None:
    """EN: Count a failed auth; ban at the threshold. Prunes stale entries
        so a long-running instance can't grow the tracker unboundedly.
    FR: Compter un échec d'auth ; bannir au seuil. Épure les entrées
        périmées pour ne pas laisser le suivi grossir indéfiniment."""
    now = time.time()
    with _fail_lock:
        fails = _fail_track.setdefault(ip, [])
        fails.append(now)
        fresh = [t for t in fails if now - t < _AUTH_WINDOW_S]
        if len(fresh) >= _AUTH_MAX_FAILS:
            _banned_until[ip] = now + _AUTH_BAN_S
            _fail_track.pop(ip, None)
            logger.warning("auth failures: %s banned for %ds", ip,
                           int(_AUTH_BAN_S))
            return
        _fail_track[ip] = fresh
        # EN: Bound the dict — evict the oldest-seen sources beyond the cap.
        # FR: Borner le dict — évincer les sources les plus anciennes au-delà du plafond.
        if len(_fail_track) > _AUTH_FAILS_CAP:
            for k in sorted(_fail_track,
                            key=lambda k: _fail_track[k][0])[:64]:
                _fail_track.pop(k, None)


def _extract_token(request: Request) -> str | None:
    """
    EN: `X-Snitch-Token` header ONLY. The `?token=` query param is honoured
        on the WebSocket handshake (browser API can't set headers) but not
        on REST — URLs end up in browser history and access logs.
    FR: En-tête `X-Snitch-Token` UNIQUEMENT. Le paramètre `?token=` est
        honoré au handshake WebSocket (l'API navigateur ne peut pas poser
        d'en-têtes) mais pas sur REST — les URLs finissent dans l'historique
        navigateur et les access logs.
    """
    return request.headers.get("x-snitch-token")


def require_token(request: Request) -> None:
    """
    EN: FastAPI dependency — 401 unless a valid token is presented.
        Applies to ALL endpoints: even GET /graph leaks sensitive traffic data.
        Repeated failures earn the source a 429 ban.
    FR: Dépendance FastAPI — 401 sans jeton valide.
        S'applique à TOUS les endpoints : même GET /graph divulgue des données
        de trafic sensibles. Les échecs répétés valent un bannissement 429.
    """
    ip = _client_ip(request)
    if _check_banned(ip):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="too many failed auth attempts")
    token = _extract_token(request)
    if not token or not secrets.compare_digest(token, API_TOKEN):
        _record_failure(ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid or missing API token")


async def ws_authorized(websocket: WebSocket) -> bool:
    """
    EN: WebSocket gate — validates Origin (anti-CSWSH) and the ?token= param.
        Closes with 4401/4403 and returns False on failure so callers bail out.
    FR: Barrière WebSocket — valide Origin (anti-CSWSH) et le paramètre
        ?token=. Ferme avec 4401/4403 et renvoie False en cas d'échec pour
        que l'appelant abandonne.
    """
    ip = _client_ip(websocket)
    if _check_banned(ip):
        await websocket.close(code=4401)
        return False
    if not origin_allowed(websocket.headers.get("origin")):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return False
    token = websocket.query_params.get("token") or websocket.headers.get("x-snitch-token")
    if not token or not secrets.compare_digest(token, API_TOKEN):
        _record_failure(ip)
        await websocket.close(code=4401)
        return False
    return True
