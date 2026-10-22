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
import urllib.parse
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

# EN: CEF (ArcSight Common Event Format) 0–10 scale — SIEM connectors
#     (Wazuh, Graylog, Splunk UF, Elastic Agent) parse it natively.
# FR: Échelle CEF 0–10 — les connecteurs SIEM le parsent nativement.
_SEV_TO_CEF = {"warning": 5, "critical": 8}


def _cef_escape(s: str, header: bool = False) -> str:
    """EN: CEF escaping — `\\` everywhere, `|` in header fields,
    `=`+newlines in extension values. / FR: Échappement CEF."""
    s = str(s).replace("\\", "\\\\")
    if header:
        return s.replace("|", "\\|")
    return s.replace("=", "\\=").replace("\n", "\\n").replace("\r", "")


def to_cef(alert: dict, version: str) -> str:
    """EN: One alert as a CEF:0 line — vendor/product/version/signature/
    name/severity then the extension. `details.ip/process` map to the
    standard dst/sproc slots so SIEM correlation works out of the box.
    FR: Une alerte en ligne CEF:0 — `details.ip/process` mappent les
    champs standard dst/sproc pour la corrélation SIEM directe."""
    sev = _SEV_TO_CEF.get(alert.get("severity"), 3)
    det = alert.get("details") or {}
    ext = {
        "rt": alert.get("timestamp") or "",
        "dst": det.get("ip") or alert.get("node_id") or "",
        "sproc": det.get("process") or "",
        "cs1Label": "alertType", "cs1": alert.get("type") or "",
        "cs2Label": "reasons", "cs2": ",".join(det.get("reasons") or []),
    }
    ext_s = " ".join(f"{k}={_cef_escape(v)}" for k, v in ext.items() if v)
    return "CEF:0|Cognition|Snitch|{}|{}|{}|{}|{}".format(
        _cef_escape(version, True), _cef_escape(alert.get("type"), True),
        _cef_escape(alert.get("message"), True), sev, ext_s)


class WebhookNotifier:
    """EN: Holds webhook settings + dispatches alert payloads.
    FR: Définit les réglages webhook + envoie les payloads d'alerte."""

    def __init__(self):
        self._lock = threading.Lock()
        self._url = ""
        self._enabled = False
        self._chat_id = ""
        self._syslog = ""
        self._syslog_format = "rfc3164"
        self._version = "?"

    def configure(self, url: str, enabled: bool, chat_id: str = "",
                  syslog_addr: str = "", syslog_format: str = "rfc3164",
                  version: str = "?") -> None:
        with self._lock:
            self._url = (url or "").strip()
            self._enabled = bool(enabled)
            self._chat_id = (chat_id or "").strip()
            self._syslog = (syslog_addr or "").strip()
            # EN: "cef" wraps the message in ArcSight CEF inside the
            #     syslog envelope — anything else keeps plain RFC 3164.
            # FR: « cef » enveloppe le message en CEF ArcSight dans
            #     l'enveloppe syslog — sinon RFC 3164 brut.
            self._syslog_format = "cef" if syslog_format == "cef" else "rfc3164"
            self._version = version

    def config(self) -> dict:
        with self._lock:
            return {"enabled": self._enabled,
                    "url_set": bool(self._url),
                    "url_masked": (self._url[:32] + "…") if len(self._url) > 32 else self._url,
                    "chat_id_set": bool(self._chat_id),
                    "syslog_set": bool(self._syslog),
                    "syslog_format": self._syslog_format}

    def dispatch(self, alert: dict) -> None:
        """EN: Synchronous POST — must run in an executor, never on the event
        loop. Silent on failure: alerting must never break detection.
        FR: POST synchrone — à lancer dans un executor, jamais sur la boucle.
        Silencieux en échec : l'alerting ne doit jamais casser la détection."""
        with self._lock:
            url, enabled, chat_id = \
                self._url, self._enabled, self._chat_id
            syslog_addr = self._syslog
            syslog_format = self._syslog_format
            version = self._version
        if alert.get("severity") not in _FORWARD:
            return
        text = f"[{alert.get('severity','').upper()}] {alert.get('type')}: {alert.get('message')}"
        # EN: Syslog path is independent of webhook_enabled — a SIEM user
        #     may want ONLY syslog. UDP by default, tcp:// for TCP. The
        #     body is RFC 3164 text or a CEF:0 payload per syslog_format.
        # FR: Le chemin syslog est indépendant du webhook — UDP par
        #     défaut. Le corps est du texte RFC 3164 ou un payload CEF:0
        #     selon syslog_format.
        if syslog_addr:
            body = to_cef(alert, version) if syslog_format == "cef" else text
            self._send_syslog(syslog_addr, alert, body)
        if not enabled or not url:
            return
        # EN: Host-matched provider detection — a substring check would
        #     misclassify `discord.com.evil.example` as Discord. Compare
        #     the parsed hostname (+ subdomain suffix), not the raw URL.
        # FR: Détection du fournisseur par hôte — un test de sous-chaîne
        #     classerait `discord.com.evil.example` comme Discord. On
        #     compare le hostname parsé (+ suffixe de sous-domaine).
        host = (urllib.parse.urlparse(url).hostname or "").lower()
        if host == "discord.com" or host.endswith(".discord.com") \
                or host == "slack.com" or host.endswith(".slack.com"):
            payload = {"content": f"**{text}**"}
        elif host == "api.telegram.org":
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
