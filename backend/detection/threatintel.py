"""
EN: Threat-intel reputation checks — strictly OPT-IN. Disabled by default;
    when the user provides a personal API key, outbound IPs are checked
    against the chosen provider and malicious verdicts raise THREAT_HIT
    alerts. This IS an outbound network call (documented in PRIVACY.md):
    only the remote IP is sent to the provider, nothing else.

    Providers:
      * abuseipdb → https://api.abuseipdb.com/api/v2/check  (abuseConfidenceScore)
      * otx       → https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general
                    (pulse_info.count)
      * virustotal → https://www.virustotal.com/api/v3/ip_addresses/{ip}
                    (last_analysis_stats.malicious/suspicious)

    Results are cached in a bounded LRU map — one provider call per IP per
    session, negative/errored results cached too so a flaky network can't
    stall the capture loop.

FR: Vérification de réputation threat-intel — strictement OPT-IN. Désactivé
    par défaut ; avec une clé API personnelle, les IP sortantes sont
    vérifiées auprès du fournisseur choisi et les verdicts malveillants
    lèvent des alertes THREAT_HIT. C'est un appel sortant (documenté dans
    PRIVACY.md) : seule l'IP distante est envoyée au fournisseur.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.request
from collections import OrderedDict
from typing import Optional

# EN: Cache bounds + verdict TTL (re-check daily at most).
# FR: Bornes du cache + durée de vie d'un verdict (revérif max 1×/jour).
_MAX_CACHE = 4_000
_TTL_S = 86_400
_TIMEOUT_S = 8

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_OTX_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
_VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

# EN: abuseConfidenceScore threshold treated as malicious.
# FR: Seuil abuseConfidenceScore considéré malveillant.
_MALICIOUS_SCORE = 50


class ThreatIntel:
    """EN: Provider-agnostic reputation client with bounded LRU cache.
    FR: Client de réputation agnostique avec cache LRU borné."""

    def __init__(self):
        self._lock = threading.Lock()
        self._provider = "none"          # 'abuseipdb' | 'otx' | 'virustotal' | 'none'
        self._api_key = ""
        self._cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self._inflight: set[str] = set()

    def configure(self, provider: str, api_key: str) -> None:
        """EN: Point the client at a provider ('none' disables checks).
        Changing provider/key clears the cache so verdicts refresh.
        FR: Pointer le client vers un fournisseur (« none » désactive).
        Changer fournisseur/clé vide le cache pour rafraîchir les verdicts."""
        provider = (provider or "none").lower()
        api_key = (api_key or "").strip()
        with self._lock:
            if provider != self._provider or api_key != self._api_key:
                self._cache.clear()
            self._provider = provider if provider in (
                "abuseipdb", "otx", "virustotal") else "none"
            self._api_key = api_key

    @property
    def enabled(self) -> bool:
        return self._provider != "none" and bool(self._api_key)

    def config(self) -> dict:
        """EN: Settings surface — api_key is masked for display.
        FR: Surface de réglages — la clé API est masquée pour l'affichage."""
        k = self._api_key
        return {
            "enabled": self.enabled,
            "provider": self._provider,
            "api_key_masked": (k[:4] + "…" + k[-4:]) if len(k) > 8 else ("…" if k else ""),
            "cached": len(self._cache),
        }

    def begin_check(self, ip: str) -> bool:
        """EN: Dedup guard — caller should spawn check() in an executor only
        if this returns True. / FR: Garde anti-doublon — ne lancer check()
        dans un executor que si True."""
        if not self.enabled:
            return False
        with self._lock:
            if ip in self._inflight:
                return False
            if ip in self._cache:
                ts, verdict = self._cache[ip]
                if time.time() - ts < _TTL_S:
                    return False
            self._inflight.add(ip)
        return True

    def check(self, ip: str) -> Optional[dict]:
        """EN: Synchronous provider call — run inside an executor, never on
        the event loop. Returns the verdict dict (or None on hard failure),
        caches it, clears the inflight mark.
        FR: Appel fournisseur synchrone — à lancer dans un executor, jamais
        sur la boucle. Retourne le verdict (ou None), le cache, lève la
        marque inflight."""
        # EN: Serve a fresh cached verdict first — callers like the manual
        #     /security/threat_check may call check() without begin_check().
        # FR: Servir d'abord un verdict en cache frais — des appelants comme
        #     /security/threat_check peuvent appeler check() sans begin_check().
        with self._lock:
            cached = self._cache.get(ip)
        if cached and time.time() - cached[0] < _TTL_S:
            return cached[1]
        try:
            verdict = self._fetch(ip)
        finally:
            with self._lock:
                self._inflight.discard(ip)
        if verdict:
            with self._lock:
                self._cache[ip] = (time.time(), verdict)
                self._cache.move_to_end(ip)
                while len(self._cache) > _MAX_CACHE:
                    self._cache.popitem(last=False)
        return verdict

    def _fetch(self, ip: str) -> Optional[dict]:
        """EN: One HTTP call to the configured provider. Returns a verdict
        dict: {ip, provider, verdict: malicious|suspicious|clean, score, detail}.
        FR: Un appel HTTP au fournisseur configuré → verdict dict."""
        if self._provider == "abuseipdb":
            req = urllib.request.Request(
                f"{_ABUSEIPDB_URL}?ipAddress={ip}&maxAgeInDays=90",
                headers={"Key": self._api_key, "Accept": "application/json"},
            )
            try:
                with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as r:
                    data = json.loads(r.read(1 << 20))
            except Exception as e:                      # noqa: BLE001
                return {"ip": ip, "provider": "abuseipdb", "verdict": "error",
                        "score": 0, "detail": str(e)[:200]}
            d = data.get("data", {})
            score = int(d.get("abuseConfidenceScore", 0))
            verdict = "malicious" if score >= _MALICIOUS_SCORE else \
                      "suspicious" if score >= 25 else "clean"
            return {"ip": ip, "provider": "abuseipdb", "verdict": verdict,
                    "score": score,
                    "detail": f"confidence {score}%, {d.get('totalReports', 0)} reports, "
                              f"{d.get('countryCode') or '?'}, {d.get('usageType') or ''}"}

        if self._provider == "otx":
            req = urllib.request.Request(
                _OTX_URL.format(ip=ip),
                headers={"X-OTX-API-KEY": self._api_key, "Accept": "application/json"},
            )
            try:
                with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as r:
                    data = json.loads(r.read(1 << 20))
            except Exception as e:                      # noqa: BLE001
                return {"ip": ip, "provider": "otx", "verdict": "error",
                        "score": 0, "detail": str(e)[:200]}
            pulses = data.get("pulse_info", {}).get("count", 0)
            verdict = "malicious" if pulses >= 3 else \
                      "suspicious" if pulses >= 1 else "clean"
            names = [p.get("name", "") for p in data.get("pulse_info", {}).get("pulses", [])][:3]
            return {"ip": ip, "provider": "otx", "verdict": verdict,
                    "score": pulses,
                    "detail": f"{pulses} pulses" + (f" — {', '.join(names)}" if names else "")}

        # EN: VirusTotal v3 — free public API (4 req/min) still needs the
        #     user's own key. last_analysis_stats counts engines flagging
        #     the IP; a couple of hits already deserve a suspicious mark.
        # FR: VirusTotal v3 — l'API publique gratuite (4 req/min) exige la
        #     clé de l'utilisateur. last_analysis_stats compte les moteurs
        #     signalant l'IP ; quelques signalements méritent déjà un
        #     verdict suspect.
        if self._provider == "virustotal":
            req = urllib.request.Request(
                _VT_URL.format(ip=ip),
                headers={"x-apikey": self._api_key, "Accept": "application/json"},
            )
            try:
                with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as r:
                    data = json.loads(r.read(1 << 20))
            except Exception as e:                      # noqa: BLE001
                return {"ip": ip, "provider": "virustotal", "verdict": "error",
                        "score": 0, "detail": str(e)[:200]}
            stats = data.get("data", {}).get("attributes", {}) \
                      .get("last_analysis_stats", {})
            hits = int(stats.get("malicious", 0))
            sus = int(stats.get("suspicious", 0))
            verdict = "malicious" if hits >= 3 else \
                      "suspicious" if hits >= 1 or sus >= 2 else "clean"
            total = sum(int(v) for v in stats.values())
            return {"ip": ip, "provider": "virustotal", "verdict": verdict,
                    "score": hits,
                    "detail": f"{hits} malicious / {sus} suspicious of {total} engines"}

        return None
