"""
Snitch — API security tests.

EN: Verifies the token gate (401 without / wrong token, 200 with header;
    ?token= is WebSocket-only and now 401 on REST), the per-IP brute-force
    ban, and the Origin allowlist used by CORS and the WebSocket handshake.
FR: Vérifie la barrière à jeton (401 sans jeton / mauvais jeton, 200 avec
    en-tête ; ?token= réservé au WebSocket et désormais 401 sur REST), le
    bannissement anti-force brute par IP et la liste blanche d'Origin
    utilisée par CORS et le handshake WebSocket.
"""

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from api.security import API_TOKEN, origin_allowed, require_token

_test_app = FastAPI()


@_test_app.get("/protected", dependencies=[Depends(require_token)])
def _protected():
    return {"ok": True}


client = TestClient(_test_app)


def test_missing_token_is_401():
    assert client.get("/protected").status_code == 401


def test_wrong_token_is_401():
    r = client.get("/protected", headers={"X-Snitch-Token": "0" * 48})
    assert r.status_code == 401


def test_valid_header_token_passes():
    r = client.get("/protected", headers={"X-Snitch-Token": API_TOKEN})
    assert r.status_code == 200


def test_query_token_rejected_on_rest():
    """EN: ?token= is honoured on /ws only — on REST it must 401 so the
        credential cannot linger in URLs, history or access logs.
    FR: ?token= n'est honoré que sur /ws — sur REST il doit renvoyer 401
        pour que la crédence ne persiste pas dans URLs, historique ou logs."""
    r = client.get(f"/protected?token={API_TOKEN}")
    assert r.status_code == 401


@pytest.mark.parametrize("origin", [
    "http://localhost:5173",
    "http://127.0.0.1:8000",
    "http://localhost:9999",   # EN: dynamic backend port / FR: port dynamique du backend
    "http://[::1]:4242",
    "null",          # EN: file:// pages under Electron / FR: pages file:// sous Electron
])
def test_allowed_origins(origin):
    assert origin_allowed(origin)


@pytest.mark.parametrize("origin", [
    "http://evil.example.com",
    "https://attacker.invalid",
    "http://localhost.evil.com",   # EN: subdomain trick — NOT loopback
                                   # FR: astuce sous-domaine — PAS loopback
    "http://127.0.0.1.evil.com",
    "null://evil.com",
])
def test_foreign_origins_rejected(origin):
    assert not origin_allowed(origin)


def test_absent_origin_allowed():
    """EN: No Origin header = non-browser client (curl, Electron main) — allowed.
    FR: Pas d'en-tête Origin = client non-navigateur (curl, main Electron) — autorisé."""
    assert origin_allowed(None)


def test_bruteforce_triggers_ban():
    """EN: After _AUTH_MAX_FAILS bad tokens the source gets 429 instead of
        another 401 — and the ban window then rejects even valid tokens.
    FR: Après _AUTH_MAX_FAILS mauvais jetons la source obtient 429 au lieu
        d'un 401 — et la fenêtre de bannissement rejette même les bons jetons."""
    import api.security as sec
    ip = "10.66.0.1"
    with sec._fail_lock:
        sec._fail_track.clear()
        sec._banned_until.clear()
    for _ in range(sec._AUTH_MAX_FAILS):
        sec._record_failure(ip)
    assert sec._check_banned(ip)
    # EN: A banned source stays banned until the window expires.
    # FR: Une source bannie le reste jusqu'à l'expiration de la fenêtre.
    assert sec._check_banned(ip)
    # EN: Simulate expiry — the ban lifts cleanly.
    # FR: Simuler l'expiration — le bannissement se lève proprement.
    with sec._fail_lock:
        sec._banned_until[ip] = 0.0
    assert not sec._check_banned(ip)


def test_fail_tracker_stays_bounded():
    """EN: Spraying failures from many distinct sources must not grow the
        tracker dict past _AUTH_FAILS_CAP.
    FR: Arroser des échecs depuis de nombreuses sources distinctes ne doit
        pas faire grossir le suivi au-delà de _AUTH_FAILS_CAP."""
    import api.security as sec
    with sec._fail_lock:
        sec._fail_track.clear()
        sec._banned_until.clear()
    for i in range(sec._AUTH_FAILS_CAP + 200):
        sec._record_failure(f"192.0.2.{i % 250}")
    with sec._fail_lock:
        assert len(sec._fail_track) <= sec._AUTH_FAILS_CAP
