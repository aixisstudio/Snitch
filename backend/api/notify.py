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
      * syslog        → `syslog_addr` setting ("host:port" or
                        "tcp://host:port") sends RFC 3164 datagrams —
                        <PRI>TIME HOST TAG: MSG — the SIEM/Wazuh path.

FR: Webhooks d'alerte externes — OPT-IN. Quand l'utilisateur configure une
    URL (webhook de canal Discord, incoming webhook Slack, URL de bot
    Telegram ou endpoint générique), les alertes warning/critical y sont
    POSTées en temps réel. C'est un appel sortant fait UNIQUEMENT si
    explicitement configuré — documenté dans PRIVACY.md.
"""

from __future__ import annotations

import json
import logging
import socket as _socket
import threading
import urllib.request
from datetime import datetime

logger = logging.getLogger("snitch.notify")

# EN: Only these severities are forwarded — info alerts would spam channels.
# FR: Seules ces sévérités sont relayées — les infos spammeraient les canaux.
_FORWARD = {"warning", "critical"}
_TIMEOUT_S = 8

# EN: RFC 3164 severity mapping — local4 facility (19) so Snitch alerts can
#     be routed/filtered inside a SIEM: warning→4, critical→2.
# FR: Mapping de sévérité RFC 3164 — facilité local4 (19) pour router les
#     alertes Snitch dans un SIEM : warning→4, critical→2.
_SEV_TO_SYSLOG = {"warning": 4, "critical": 2}


class WebhookNotifier:
    """EN: Holds webhook settings + dispatches alert payloads.
    FR: Définit les réglages webhook + envoie les payloads d'alerte."""

    def __init__(self):
        self._lock = threading.Lock()
        self._url = ""
        self._enabled = False
        self._chat_id = ""
        self._syslog = ""

    def configure(self, url: str, enabled: bool, chat_id: str = "",
                  syslog_addr: str = "") -> None:
        with self._lock:
            self._url = (url or "").strip()
            self._enabled = bool(enabled)
            self._chat_id = (chat_id or "").strip()
            self._syslog = (syslog_addr or "").strip()

    def config(self) -> dict:
        with self._lock:
            return {"enabled": self._enabled,
                    "url_set": bool(self._url),
                    "url_masked": (self._url[:32] + "…") if len(self._url) > 32 else self._url,
                    "chat_id_set": bool(self._chat_id),
                    "syslog_set": bool(self._syslog)}

    def dispatch(self, alert: dict) -> None:
        """EN: Synchronous POST — must run in an executor, never on the event
        loop. Silent on failure: alerting must never break detection.
        FR: POST synchrone — à lancer dans un executor, jamais sur la boucle.
        Silencieux en échec : l'alerting ne doit jamais casser la détection."""
        with self._lock:
            url, enabled, chat_id = \
                self._url, self._enabled, self._chat_id
            syslog_addr = self._syslog
        if alert.get("severity") not in _FORWARD:
            return
        text = f"[{alert.get('severity','').upper()}] {alert.get('type')}: {alert.get('message')}"
        # EN: Syslog path is independent of webhook_enabled — a SIEM user
        #     may want ONLY syslog. UDP by default, tcp:// for TCP.
        # FR: Le chemin syslog est indépendant du webhook — UDP par
        #     défaut, tcp:// pour TCP.
        if syslog_addr:
            self._send_syslog(syslog_addr, alert, text)
        if not enabled or not url:
            return
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

    @staticmethod
    def _send_syslog(addr: str, alert: dict, text: str) -> None:
        """EN: RFC 3164 datagram — <PRI>Mmm dd HH:MM:SS host tag: msg.
        `addr` is "host:port" (UDP, default) or "tcp://host:port".
        Never raises. / FR: Datagramme RFC 3164 — ne lève jamais."""
        try:
            tcp = addr.startswith("tcp://")
            target = addr[6:] if tcp else addr
            target = target.removeprefix("udp://")
            host, _, port_s = target.rpartition(":")
            port = int(port_s) if port_s.isdigit() else 514
            sev = _SEV_TO_SYSLOG.get(alert.get("severity"), 5)
            pri = 19 * 8 + sev                          # EN: local4.<sev>
            ts = datetime.now().strftime("%b %d %H:%M:%S")
            msg = f"<{pri}>{ts} {_socket.gethostname()} " \
                  f"snitch[{alert.get('type','?')}]: {text}".encode(
                      "utf-8", "replace")
            if tcp:
                with _socket.create_connection(
                        (host, port), timeout=_TIMEOUT_S) as s:
                    s.sendall(msg + b"\n")
            else:
                with _socket.socket(_socket.AF_INET,
                                    _socket.SOCK_DGRAM) as s:
                    s.sendto(msg, (host, port))
        except Exception as e:                          # noqa: BLE001
            logger.debug("syslog dispatch failed: %s", e)


notifier = WebhookNotifier()
