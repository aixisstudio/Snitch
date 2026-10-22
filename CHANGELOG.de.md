# Änderungsprotokoll

[English](CHANGELOG.md) | [Français](CHANGELOG.md) | [Español](CHANGELOG.es.md) | **Deutsch** | [Русский](CHANGELOG.ru.md) | [日本語](CHANGELOG.ja.md) | [Português](CHANGELOG.pt-BR.md) | [中文](CHANGELOG.zh-CN.md)

Alle nennenswerten Änderungen an Snitch.

Das Format folgt [Keep a Changelog](https://keepachangelog.com/).

## [1.5.0] — 2026-10-22

### Hinzugefügt

- **Passive TLS-Zertifikatsinspektion** — `capture/tlscert.py` reassembliert die Server-`Certificate`-Nachricht über TCP-Segmente (begrenzt 16 KiB/Flow) und liest den Blatt-DER: Issuer/Subject, Self-Signed-Flag, SANs, Validität → `TLS_CERT` bei Self-Signed oder SAN/SNI-Mismatch. TLS 1.3 wird ehrlich als unbeobachtbar gemeldet — kein MITM, keine Entschlüsselung.
- **ICMP-Tunnel-Heuristik** — wiederholte große Echo-Payloads (≥24 B, 3+ in 5 Min) → `ICMP_TUNNEL` (ptunnel/icmpsh-Signatur).
- **High-Entropy-Erkennung** — quasi-zufällige Payload-Köpfe (≥4,7 Bit/Byte) auf Klartext-Sockets → `HIGH_ENTROPY` (verdeckte Krypto/Stego-Hinweis).
- **Isolation Forest (pur Python)** — `detection/iforest.py` + `mlflow.py` scoren Ausgangsflüsse auf 6 Features; `ML_ANOMALY` ab Score 0,62, inert unter 384 gelernten Flüssen.
- **Ask-on-Connect (Linux NFQUEUE, opt-in)** — `ask_enabled` hält neue Ausgangsflüsse in Queue 7 bis zu `POST /security/ask/verdict` — echte Verdict-Macht, Timeout droppt standardmäßig.
- **eBPF-Egress-Enforcement** — `detection/ebpf_enforce.py` + `POST /security/ebpf/isolate|block` — Kernel-Drops nur für Prozesse im snitch-Cgroup.
- **Hollowing-Beweis** — `POST /security/hollow` diff't ausführbare RAM-Seiten gegen die Disk-Datei (Linux, `/proc`).
- **IOC-Peer-Sync** — `gossip_peers` + `gossip_enabled`: gesalzene Merkle-Pakete alle 5 Min an explizit gelistete Peers — nur Hash-Commitments, keine Discovery.
- **Syslog** — `syslog_addr` (UDP oder `tcp://`) leitet warning/critical-Alarme als RFC 3164 weiter — SIEM/Wazuh-Pfad.
- **Geo-Regeln + Auto-Block** — Custom Rules mit `asn`/`country` (lokale mmdb) und `action:"block"` installieren echte Firewall-Regeln pro gematchter IP.
- **Actionable Alerts + Settings-UI** — Block IP / Kill / Suspend / Allow-Deny pro Alarm; neue Regler in den Einstellungen (syslog, ask, peers).
- **nftables-Backend + firejail** — `nft` wenn iptables fehlt (eigene `inet snitch`-Tabelle); `firejail --net=none` als Sandbox-Fallback.

## [Unreleased]

### Hinzugefügt

- **Orchestrierung der Ausgangs-Firewall** — Benutzerregeln (`ip`, `cidr`, `domain`, `process`, `port`) best-effort auf die native OS-Firewall angewendet: `netsh advfirewall` unter Windows, `iptables` unter Linux, generierter `pf`-Anker unter macOS. Persistiert, beim Start erneut angewendet, ehrliches `applied=False` ohne Rechte (Matching + `BLOCKED_ATTEMPT`-Zähler laufen weiter).
- **Lockdown** — Panik-Schalter, der ausgehenden Verkehr zu öffentlichen IPs droppt, aber Loopback/LAN erhält (Linux-`SNITCH_LOCK`-Chain, `netsh`-Regeln, `pf`-Anker).
- **Prozess-Aktionen** — `POST /processes/kill` und `POST /processes/suspend` (per PID, verweigert PIDs ≤ 3 und Snitch selbst); Kill-/Suspend-Buttons in der Prozessliste.
- **Threat Intelligence (Opt-in)** — Reputationsprüfungen gegen AbuseIPDB, AlienVault OTX oder VirusTotal mit eigenem API-Key; standardmäßig aus, ein Aufruf pro neu gesehener öffentlicher IP, begrenzter LRU-Cache + Dedup, `THREAT_HIT`-Alarme bei verdächtigen/bösartigen Urteilen.
- **Externe Webhooks (Opt-in)** — warning/critical-Alarme live per POST an Discord, Slack, Telegram (mit Chat-ID) oder beliebige Endpunkte; standardmäßig aus.
- **Neue Erkennungen** — `DNS_TUNNEL` (überlange DNS-Namen/-Labels), `CLEARTEXT` (FTP/Telnet/HTTP/Klartext-Mail-Ausgang), `BASELINE_DEVIATION` (gelerntes Länderprofil pro Prozess, persistiert).
- **Security-Audit** — `GET /security/audit` berechnet einen 0–100-Score plus Empfehlungen in Klartext aus aktuellen Alarmen und dem Live-Graphen; im Firewall-Panel sichtbar.
- **Forensik-Export** — `GET /forensics/export?format=json|csv|stix` bündelt Prozessbaum, SHA-256 der Executable, passende Alarme und Verlauf; STIX ist ein minimales 2.1-Bundle (indicators + observed-data) für SIEM-Import.
- **Firewall- & Security-UI** — dediziertes Panel: Lockdown-Schalter, Regeln erstellen/umschalten/löschen, Blockzähler pro Regel, ehrliche Plattform-Unterstützung, Audit-Bericht, Forensik-Downloads; Block-Aktion pro Verbindung in der Sidebar.
- **Fünf neue UI-Locales** — de, ru, ja, pt-BR, zh-CN (8 gesamt, 280-Key-Parität geprüft); Wörterbücher nach `frontend/src/locales/*.js` verschoben — neue Sprache = Ein-Datei-PR.

## [1.1.0] — 2026-10-22

### Hinzugefügt

- **Auto-Update** — die Desktop-App prüft GitHub Releases beim Start und alle 6 h via electron-updater (die `latest-*.yml`-Feeds wurden schon veröffentlicht). Downloads installieren beim Neustart; Tray und Einstellungen zeigen den Live-Status. Opt-out in Einstellungen oder per `SNITCH_NO_UPDATE=1`.
- **QUIC / HTTP/3-Sichtbarkeit** — UDP/443-Flows werden als `QUIC/HTTP3` gelabelt statt in HTTPS oder unbekannt zu landen. Das SNI des QUIC-Initial ist verschlüsselt und wird nie gelesen — das Label ist ehrlich über das Beobachtbare.
- **Watchlist** — IPs oder Domain-Suffixe pinnen (`example.com` matcht auch `api.example.com`); ein dedizierter `WATCHLIST_HIT`-Alarm feuert beim ersten Kontakt, rate-limitiert pro (Eintrag, Host). Persistiert, in Einstellungen verwaltet.
- **Upload-Alarm pro Prozess** — `UPLOAD_SPIKE` warnt, wenn ein Prozess eine konfigurierbare MB/min-Grenze überschreitet (Standard 50, 0 = aus) — deckt Exfiltration ab, die das baseline-relative `VOLUME_SPIKE` bei frisch gestarteten Prozessen verpasst.
- **Capture-Interface-Auswahl** — `GET/POST /capture/interfaces` + Dropdown in Einstellungen mit libpcap-Geräten; Wechsel startet die Capture sofort neu. Ersetzt die `SNITCH_IFACE`-Variable für Desktop-Nutzer.
- **WLAN-Kontext** — die Toolbar zeigt die aktuelle SSID (oder das Interface ohne WLAN). Best-effort pro OS, 60-s-Cache.
- **Spanische UI** — vollständiges `es`-Wörterbuch (194 Keys, Parität geprüft); der Sprachwähler wird EN/FR/ES.
- **Snap-Paket** — electron-builder erzeugt jetzt ein `.snap` in strict confinement (mit `network-observe`-Plug für AF_PACKET-Capture). Flatpak bewusst nicht ausgeliefert — die Sandbox kann rohe Capture nicht freigeben (dokumentiert in `docs/PACKAGING.md`).
- **Kostenloser Codesigning-Weg** — optionale SignPath-Foundation-OSS-Integration in CI (`vars.SIGNPATH_*` + `secrets.SIGNPATH_API_TOKEN`): der Windows-Installer wird nach Annahme des Projekts automatisch Authenticode-signiert. Vollständig dokumentiert in `docs/SIGNING.md`, inklusive ehrlicher macOS-Lage (keine kostenlose Notarisierung).

## [1.0.8] — 2026-10-22

### Geändert

- **Echtes natives Light-Theme** — ersetzt den Invert-Filter von v1.0.7 durch ein vollständiges Design-Token-System: jede Fläche, jeder Text, jede Border und Akzentfarbe wird über CSS-Custom-Properties mit handgewählter heller Palette gezeichnet. Karte, Force-Graph, Timeline und WebGL-Aurora folgen dem Theme, und der Toggle persistiert die Wahl.

## [1.0.7] — 2026-10-22

### Hinzugefügt

- **Light-Theme** — respektiert `prefers-color-scheme` out of the box und lässt sich per Sonne/Mond-Toggle in der Toolbar überschreiben; die Wahl wird in `localStorage` persistiert. Als farbton-erhaltende Invertierung der Dark-Palette umgesetzt, damit Graphen, Karte und Aurora kohärent bleiben.

### Behoben

- **AppImage-Katalog-Konformität** — das Linux-Asset heißt jetzt `Snitch-x86_64.AppImage` (korrekte Architektur-Benennung) und electron-builder publiziert GitHub-Update-Metadaten (`latest-linux.yml` + `.zsync`), wodurch Auto-Update über AppImageUpdate-kompatible Werkzeuge möglich wird.

## [1.0.6] — 2026-10-21

### Hinzugefügt

- **Ein Download pro OS** — jeder Tag liefert startfertige Apps aus der CI:
  - **Windows** — `Snitch Setup <Version>.exe` (Electron + NSIS: natives Fenster, Tray, eingebaute Npcap-Prüfung, UAC-Prompt beim Backend-Start) und `Snitch-Lite-Setup-<Version>-windows-x64.exe` (Inno Setup: nur Backend, UI öffnet im Browser).
  - **macOS (Apple Silicon)** — `Snitch-<Version>-macos-arm64.zip` + `.dmg` in CI gebaut (zuvor manuell).
  - **Linux** — `Snitch-<Version>.AppImage` + `.deb` — kein Docker-Zwang mehr für die Desktop-App.
- **Backend-Modus `--launcher`** — wählt freien Loopback-Port, berechnet den API-Token und öffnet den Browser; vom Lite-Installer-Shortcut genutzt.

### Behoben

- **Standalone-Backend-Bundles liefern jetzt die UI mit** — `frontend_dist` wird auf allen OSen ins PyInstaller-Bundle gepackt; das nackte Tarball servierte vorher nur die API.

### Geändert

- Der CI-Job `package` baut die Electron-Installer auf allen drei OSen und ein `release`-Job publiziert jedes Artefakt automatisch auf das GitHub-Release.

## [1.0.5] — 2026-10-17

### Hinzugefügt

- **Windows-Support** — die paketierte App bootet und captured unter Windows (Npcap).
- **Prozess-Icons** — Lucide-Icons pro Prozess in der Apps-Tabelle (externe Contribution).
- **24 neue Tracker-Domains** in der Classifier-Blocklist (externe Contribution).

### Behoben

- Backend-Crash bei `console=False`-PyInstaller-Builds (`sys.stdout`/`sys.stderr` = None) — Issue #25.
- Capture-Interface-Auswahl unter Windows — Snitch wählt jetzt das Interface mit der Default-Route statt `vEthernet (WSL)`.
- `NaNh ago` bei Alarm-Timestamps mit Zeitzonen-Offsets.
- Der Electron-Splash verdeckt keine Fehlerdialoge mehr; die Timeout-Meldung listet Ursachen + Log-Ordner.
- Vier übrig gebliebene englische Strings im französischen Wörterbuch übersetzt (externe Contribution).
- Version jetzt single-sourced aus `backend/version.py`.

### Geändert

- React 18 → 19, uvicorn 0.30 → 0.54, fastapi → 0.143, psutil → 7.2, websockets → 17.2, maxminddb → 3.2, aiofiles → 25.1, lucide-react → 1.55, vite → 8.3.4, electron → 44.7 (+ dev deps).

## [1.0.4] — 2026-10-05

- Erste öffentliche Veröffentlichung.
