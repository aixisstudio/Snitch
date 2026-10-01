"""
Snitch — API security tests.

EN: Verifies the token gate (401 without / wrong token, 200 with header or
    ?token=) and the Origin allowlist used by both CORS and the WebSocket
    handshake.
FR: Vérifie la barrière à jeton (401 sans jeton / mauvais jeton, 200 avec
    en-tête ou ?token=) et la liste blanche d'Origin utilisée par CORS et le
    handshake WebSocket.
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


def test_valid_query_token_passes():
    r = client.get(f"/protected?token={API_TOKEN}")
    assert r.status_code == 200


@pytest.mark.parametrize("origin", [
    "http://localhost:5173",
    "http://127.0.0.1:8000",
    "null",          # EN: file:// pages under Electron / FR: pages file:// sous Electron
])
def test_allowed_origins(origin):
    assert origin_allowed(origin)


@pytest.mark.parametrize("origin", [
    "http://evil.example.com",
    "http://localhost:9999",
    "https://attacker.invalid",
])
def test_foreign_origins_rejected(origin):
    assert not origin_allowed(origin)


def test_absent_origin_allowed():
    """EN: No Origin header = non-browser client (curl, Electron main) — allowed.
    FR: Pas d'en-tête Origin = client non-navigateur (curl, main Electron) — autorisé."""
    assert origin_allowed(None)
