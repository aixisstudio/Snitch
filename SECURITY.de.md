# Sicherheitsrichtlinie

[English](SECURITY.md) | [Français](SECURITY.md) | [Español](SECURITY.es.md) | **Deutsch** | [Русский](SECURITY.ru.md) | [日本語](SECURITY.ja.md) | [Português](SECURITY.pt-BR.md) | [中文](SECURITY.zh-CN.md)

## Meldung von Schwachstellen

Melde Schwachstellen bitte privat über GitHubs Funktion „Report a
vulnerability“ (Reiter Security) oder per E-Mail an die im Repository-Profil
genannten Maintainer. Öffne keine öffentlichen Issues für
Sicherheitsprobleme.

## Lokale Angriffsfläche

Die API legt deinen kompletten Verkehrsgraph offen — sie ist by design
geschützt:

- **Token-Authentifizierung** auf jedem REST-Endpoint und dem WebSocket
  (`X-Snitch-Token` oder `?token=`). Unter Electron pro Start generiert,
  sonst mit 0600 persistiert.
- **Loopback-Bind** (`127.0.0.1`) standardmäßig in allen Modi.
- **Origin-Allowlist** beim WebSocket-Handshake (Loopback-Hosts + `null`),
  um Cross-Site-WebSocket-Hijacking zu blockieren.
- **Restriktives CORS** — nur Loopback-Origins, keine Credentials.
- **Tokens pro Agent** — `POST /ingest/enroll` stellt dedizierte `sagt_…`-Tokens für Flotten-Agents aus; nur der Hash wird gespeichert, jedes ist via `/ingest/revoke` widerrufbar. Agent-Tokens dürfen nur eigene Events senden — kein Lesezugriff, kein Identitätswechsel.

## Privilegien

Paket-Capture erfordert erhöhte Rechte — aber nur das Backend besitzt sie.
Die gepackte Electron-App lässt die UI auf jedem OS unprivilegiert laufen
und erhöht NUR das Backend über den nativen Prompt der Plattform:

- **Windows:** `Start-Process -Verb RunAs` (eine UAC-Abfrage pro Start) + Npcap (von dir installiert, npcap.com)
- **macOS:** `osascript … with administrator privileges` (nativer Passwort-Dialog)
- **Linux:** `pkexec` (Polkit-Dialog); fällt ohne Polkit auf unprivilegiert zurück

Das erhöhte Kind wird über den authentifizierten `/shutdown`-Endpoint
gestoppt, da ein unprivilegierter Prozess es nicht signalisieren kann.
Ablehnen des Prompts bietet Wiederholen / Ohne-Capture-Fortfahren statt
eines harten Abbruchs.

## Abhängigkeiten

Scapy wurde entfernt (GPL-2.0-only + große Angriffsfläche). Die Capture ist
ein minimales ctypes-Binding auf libpcap plus unser eigener begrenzter
Parser. Abhängigkeiten sind gepinnt und werden von Dependabot überwacht.
