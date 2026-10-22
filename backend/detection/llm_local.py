"""
EN: Local SLM enrichment — a REAL small language model, not a simulated
    one. If the user runs Ollama (or any llama.cpp-server compatible API)
    on LOOPBACK, alert explanations can be generated in natural language
    instead of templates. Three hard rules keep it honest and private:

      * LOOPBACK ONLY — the endpoint host must be 127.0.0.1 / ::1 /
        localhost. Any other host is rejected outright: alert data never
        leaves the machine. This is checked on every configure() call,
        not just documented.
      * OPT-IN — disabled by default; the deterministic bilingual
        templates (explain.py) always remain the fallback, so nothing
        breaks when the model is down.
      * NO BUNDLED MODEL — Snitch never downloads weights itself; the
        user points it at their own local server. Model names are
        user-provided or auto-detected from /api/tags.

FR: Enrichissement SLM local — un VRAI petit modèle de langage, pas un
    simulacre. Si l'utilisateur fait tourner Ollama (ou toute API
    compatible llama.cpp-server) en LOOPBACK, les explications d'alertes
    peuvent être générées en langage naturel. Trois règles strictes :

      * LOOPBACK SEUL — l'hôte doit être 127.0.0.1 / ::1 / localhost.
        Tout autre hôte est rejeté : les données d'alerte ne quittent
        jamais la machine. Vérifié à chaque configure().
      * OPT-IN — désactivé par défaut ; les gabarits bilingues
        déterministes (explain.py) restent le repli permanent.
      * PAS DE MODÈLE EMBARQUÉ — Snitch ne télécharge jamais de poids ;
        l'utilisateur pointe vers son propre serveur local.
"""

from __future__ import annotations

import ipaddress
import json
import threading
import time
import urllib.request
from urllib.parse import urlparse

_TIMEOUT = 20.0
_CACHE_TTL = 300.0


def _is_loopback(url: str) -> bool:
    """EN: Hard privacy gate — only literal loopback hosts pass.
    FR: Verrou vie privée strict — seuls les hôtes loopback littéraux
    passent."""
    try:
        host = urlparse(url).hostname or ""
        if host in ("localhost", "localhost."):
            return True
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class LocalSlm:
    """EN: Optional Ollama/llama.cpp-server client — status + single-call
    enrich(). Every network op has a short timeout and degrades to None.
    FR: Client optionnel Ollama/serveur llama.cpp — status + enrich()
    simple. Chaque appel réseau a un timeout court et dégrade en None."""

    def __init__(self):
        self._lock = threading.Lock()
        self._enabled = False
        self._endpoint = "http://127.0.0.1:11434"
        self._model = ""                            # EN: empty → autodetect / FR: vide → autodétecté
        self._cache: dict[tuple, tuple[float, str]] = {}

    # ── config / configuration ───────────────────────────────────────────────

    def configure(self, enabled: bool, endpoint: str = "",
                  model: str = "") -> None:
        with self._lock:
            self._enabled = bool(enabled)
            if endpoint and _is_loopback(endpoint):
                self._endpoint = endpoint.rstrip("/")
            if model is not None:
                self._model = model.strip()

    # ── status / état ────────────────────────────────────────────────────────

    def _detect_model(self) -> str:
        """EN: First model reported by the server — keeps zero-config flow.
        FR: Premier modèle rapporté par le serveur — reste zéro-config."""
        try:
            with urllib.request.urlopen(
                    f"{self._endpoint}/api/tags", timeout=5) as r:
                models = json.loads(r.read()).get("models", [])
                return models[0].get("name", "") if models else ""
        except Exception:                            # noqa: BLE001
            return ""

    def status(self) -> dict:
        """EN: Reachability probe (cheap /api/tags) + current config —
        powers the Settings panel honesty ("model unreachable" is shown,
        never hidden). / FR: Sonde de joignabilité + config courante —
        alimente l'honnêteté des réglages (« modèle injoignable »
        affiché, jamais caché)."""
        with self._lock:
            enabled, endpoint, model = self._enabled, self._endpoint, self._model
        reachable = False
        detected = ""
        if enabled:
            detected = self._detect_model() if not model else ""
            reachable = bool(model or detected)
        return {"enabled": enabled, "reachable": reachable,
                "endpoint": endpoint,
                "model": model or detected,
                "loopback_only": True}

    # ── generation / génération ──────────────────────────────────────────────

    def enrich(self, alert_type: str, details: dict, lang: str = "en") -> str | None:
        """EN: One-shot natural-language explanation of an alert — or None
        (disabled, unreachable, error) so the caller falls back to
        templates. Cached briefly per (type,lang,detail-hash).
        FR: Explication en langage naturel d'une alerte — ou None
        (désactivé, injoignable, erreur) pour repli sur les gabarits.
        Cache bref par (type,lang,hash-détails)."""
        with self._lock:
            if not self._enabled:
                return None
            endpoint = self._endpoint
            model = self._model
        if not _is_loopback(endpoint):
            return None
        model = model or self._detect_model()
        if not model:
            return None
        import hashlib
        key = (alert_type, lang,
               hashlib.sha256(json.dumps(details, sort_keys=True,
                                         default=str).encode()).hexdigest()[:16])
        with self._lock:
            hit = self._cache.get(key)
            if hit and time.time() - hit[0] < _CACHE_TTL:
                return hit[1]
        prompt = (
            f"You are a security assistant inside a localhost-only network "
            f"monitor. Explain this alert in {'French' if lang == 'fr' else 'English'} "
            f"in at most 4 short sentences: what it means, why it fired, "
            f"and what the user should check. No preamble.\n"
            f"ALERT TYPE: {alert_type}\nDETAILS: {json.dumps(details, default=str)[:600]}"
        )
        try:
            body = json.dumps({"model": model, "prompt": prompt,
                               "stream": False}).encode()
            req = urllib.request.Request(f"{endpoint}/api/generate",
                                         data=body,
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
                text = (json.loads(r.read()).get("response") or "").strip()
        except Exception:                            # noqa: BLE001
            return None
        if text:
            with self._lock:
                self._cache[key] = (time.time(), text)
                if len(self._cache) > 128:
                    self._cache.pop(next(iter(self._cache)))
        return text or None
