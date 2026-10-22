# Threat Model

[English](threat-model.md) | [Français](threat-model.md) | [Español](threat-model.es.md) | **Deutsch** | [Русский](threat-model.ru.md) | [日本語](threat-model.ja.md) | [Português](threat-model.pt-BR.md) | [中文](threat-model.zh-CN.md)

## Was Snitch ist

Ein Local-first-Visualizer für Netzwerkverkehr. Er erfasst Pakete auf dem
Host, ordnet sie Prozessen zu, reichert sie **offline** an (lokale
`.mmdb`-Geolokalisierung, lokale DNS/SNI-Karten) und rendert sie in einer
Web-UI, die vom selben Prozess ausgeliefert wird. **Keine
Cloud-Komponente, keine Telemetrie.**

## Assets

- Deine Verkehrs-Metadaten (Ziel-IPs, Ports, Volumen, Prozessnamen).
- Das API-Token (pro Start in Electron, pro Installation in CLI/Docker).
- Die lokale SQLite-DB (`traffic`, `alerts_log`, Historien, Einstellungen).
- Die Integrität der Maschine selbst (ein kompromittiertes Snitch könnte
  dich belügen).

## Vertrauensgrenzen

| Grenze | Bedrohung | Mitigation |
|---|---|---|
| Browser/Remote-Client → REST | Ein LAN-Angreifer oder eine bösartige Webseite liest/steuert deine Verkehrsansicht | Token auf **jedem** Endpoint (`Authorization: Bearer`). Bind `127.0.0.1` standardmäßig. In Docker erfordert `0.0.0.0` ein explizites `SNITCH_TOKEN`. |
| Webseite → `/ws` | Cross-Site-WebSocket-Hijacking (CSWSH) | Token **und** `Origin`-Allowlist (Loopback + Electron `null`-Origin). |
| Host → Dritte | Privacy-Leak | Null ausgehende Aufrufe standardmäßig. GeoIP-Download, Threat Intel, Webhooks und Updates sind **Opt-in** und in PRIVACY.md dokumentiert. |
| Capture-Treiber → Parser | Malformed Frames crashen den Prozess | Der Parser prüft jeden Offset; malformed Pakete liefern `None` und werfen nie in die Capture-Schleife. |
| Renderer ↔ Main (Electron) | Token-Exfiltration aus der Seite | `contextIsolation` + `sandbox`; das Token kreuzt nur via `ipcRenderer.invoke`, landet nie im DOM oder einer URL. |
| Lokaler Angreifer mit FS-Zugriff | Token-/Historien-Diebstahl | Token-Datei `0600`; Datenverzeichnis im User-Verzeichnis; DB unverschlüsselt — Festplattenverschlüsselung ist OS-Aufgabe. |

## Bekannte Grenzen

- **Capture erfordert Admin-/Root-Rechte**, aber begrenzt aufs Backend:
  die Electron-UI läuft unprivilegiert, während das Backend über den
  Plattform-Prompt erhöht startet (`Start-Process -Verb RunAs` auf Windows,
  `osascript` auf macOS, `pkexec` auf Linux) und via authentifiziertem
  `/shutdown`-Endpoint gestoppt wird.
- Das Token schützt HTTP/WS, aber **nicht** gegen einen anderen lokalen
  Prozess unter deinem Account, der `data/api_token.txt` oder die
  Electron-IPC lesen kann.
- SQLite-Daten im Ruhezustand sind unverschlüsselt.
- Alarm-Unterdrückung ist lokal und still — ein Angreifer mit Schreibzugriff
  auf die DB kann Alarme stumm schalten (Abwehr: FS-Rechte).

## Out of scope

Bösartige Paket-Payloads (nur Header werden geparst), Kernel-/Treiber-
Kompromittierung, bösartiger Administrator.
