"""
EN: External alert webhooks — OPT-IN. When the user configures a webhook URL
    (Discord channel webhook, Slack incoming webhook, Telegram bot URL or any
    generic endpoint), warning/critical alerts are POSTed there in real time.
    This is an outbound network call made ONLY when explicitly configured —
    documented in PRIVACY.md.

    Payloads are auto-shaped:
      * Discord/Slack → {"content": "**[warning]** BEACON — …"}
      * Telegram      → {"chat_id": <from `telegram_chat_id` setting>, "text": "…"}
      * generic       → full alert JSON {"alert": {...}, "source": "snitch"}

FR: Webhooks d'alerte externes — OPT-IN. Quand l'utilisateur configure une
    URL (webhook de canal Discord, incoming webhook Slack, URL de bot
    Telegram ou endpoint générique), les alertes warning/critical y sont
    POSTées en temps réel. C'est un appel sortant fait UNIQUEMENT si
    explicitement configuré — documenté dans PRIVACY.md.
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.request
from typing import Optional

logger = logging.getLogger("snitch.notify")

# EN: Only these severities are forwarded — info alerts would spam channels.
# FR: Seules ces sévérités sont relayées — les infos spammeraient les canaux.
_FORWARD = {"warning", "critical"}
_TIMEOUT_S = 8


class WebhookNotifier:
    """EN: Holds webhook settings + dispatches alert payloads.
    FR: Définit les réglages webhook + envoie les payloads d'alerte."""

    def __init__(self):
        self._lock = threading.Lock()
        self._url = ""
        self._enabled = False
        self._chat_id = ""

    def configure(self, url: str, enabled: bool, chat_id: str = "") -> None:
        with self._lock:
            self._url = (url or "").strip()
            self._enabled = bool(enabled)
            self._chat_id = (chat_id or "").strip()

    def config(self) -> dict:
        with self._lock:
            return {"enabled": self._enabled,
                    "url_set": bool(self._url),
                    "url_masked": (self._url[:32] + "…") if len(self._url) > 32 else self._url,
                    "chat_id_set": bool(self._chat_id)}

    def dispatch(self, alert: dict) -> None:
        """EN: Synchronous POST — must run in an executor, never on the event
        loop. Silent on failure: alerting must never break detection.
        FR: POST synchrone — à lancer dans un executor, jamais sur la boucle.
        Silencieux en échec : l'alerting ne doit jamais casser la détection."""
        with self._lock:
            url, enabled, chat_id = self._url, self._enabled, self._chat_id
        if not enabled or not url or alert.get("severity") not in _FORWARD:
            return
        text = f"[{alert.get('severity','').upper()}] {alert.get('type')}: {alert.get('message')}"
        if "discord.com" in url or "slack.com" in url:
            payload = {"content": f"**{text}**"}
        elif "api.telegram.org" in url:
            payload = {"text": text}
            if chat_id:
                payload["chat_id"] = chat_id
        else:
            payload = {"alert": alert, "source": "snitch", "text": text}
        try:
            req = urllib.request.Request(
                url, data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(req, timeout=_TIMEOUT_S).read()
        except Exception as e:                          # noqa: BLE001
            logger.debug("webhook dispatch failed: %s", e)


notifier = WebhookNotifier()
