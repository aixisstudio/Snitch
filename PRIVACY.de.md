# Datenschutz

[English](PRIVACY.md) | [Français](PRIVACY.md) | [Español](PRIVACY.es.md) | **Deutsch** | [Русский](PRIVACY.ru.md) | [日本語](PRIVACY.ja.md) | [Português](PRIVACY.pt-BR.md) | [中文](PRIVACY.zh-CN.md)

Snitch ist ein Datenschutz-Werkzeug — es darf niemals genau die Daten
verlieren, deren Überwachung es dir ermöglicht.

**Telemetrie: keine.** Keine Analytics, kein Crash-Reporting, keinerlei
„Phone-Home“.

**Ausgehende Netzwerkaufrufe von Snitch: alle optional, alle standardmäßig
aus.** Alles andere ist passive Beobachtung oder von dir ausgelöst — es
gibt keinen stillen Traffic:

- Paket-Capture auf deinen lokalen Interfaces (passive Beobachtung),
- Lesen der System-ARP-/Nachbartabelle (kein aktives Scannen),
- Reverse-DNS über den OS-Resolver — Standard-PTR-Lookups, die bei jeder
  Netzwerkaktivität ohnehin implizit passieren (`SNITCH_DISABLE_PTR=1`
  deaktiviert sie komplett),
- Bereitstellen einer Web-UI auf `127.0.0.1` für deinen eigenen Browser.

**Die Desktop-App prüft github.com auf neue Releases** beim Start und alle
6 h (electron-updater, liest die öffentlichen `latest-*.yml`). Das ist der
einzige periodische ausgehende Aufruf. Abschaltbar in *Einstellungen →
Updates → Automatisch prüfen* (persistiert) oder via `SNITCH_NO_UPDATE=1`.
Docker-Build und Backend prüfen nie.

**Der GeoIP-Datenbank-Download** (*Einstellungen → Geolokalisierung*) holt
~50 MB von db-ip.com — nur auf deinen Klick, mit expliziter Einwilligung.

**Threat Intelligence (Opt-in, standardmäßig aus).** Wenn du einen Anbieter
(AbuseIPDB, AlienVault OTX oder VirusTotal) konfigurierst *und* deinen
eigenen API-Key in den Einstellungen einträgst, fragt Snitch den Anbieter
nach der Reputation neu gesehener öffentlicher Hosts — es wird nur die
abgefragte IP gesendet. Urteile werden lokal gecacht; der Key liegt in
`snitch.db` (nie geloggt, in der UI maskiert). Ohne Anbieter oder Key:
null Lookups — `ti.check()` ist ein No-Op.

**Externe Webhooks (Opt-in, standardmäßig aus).** Wenn du eine Webhook-URL
einträgst (Discord, Slack, Telegram-Bot-Endpoint oder beliebige URL) und
den Schalter umlegst, werden Warn-/Kritik-Alarmtexte in Echtzeit an diesen
Endpoint gePOSTet. Bei ausgeschaltetem Schalter geht nichts raus.

**Lokale LLM-Anreicherung (Opt-in, standardmäßig aus).** Bei
`slm_enabled` können Alarm-*Metadaten* (Typ, Prozess, Ziel) an ein
Ollama-kompatibles Modell gehen — **ausschließlich Loopback**: der
Backend lehnt jeden Endpunkt ab, der nicht nach 127.0.0.1 / ::1
auflöst. Deterministische Vorlagen bleiben der Standard.

**IOC-Pakete werden von Snitch nie übertragen.** `GET /security/iocpack`
kodiert deine Indikatoren als Bloom-Filter + randomized response
(ε≈4,6) und übergibt dir die Datei — du entscheidest, ob und wohin.
Ein Import liefert nur probabilistische Hinweise; nie Auto-Blocking.

**Inspektionssonden bleiben lesend und lokal.** Die eBPF-Sonde, die
Frida-Inspektion, `perf_event_open`-Zähler, Modul-Integritätsscans und
der Sinkhole-Responder *lesen* nur lokalen Zustand und lauschen auf
127.0.0.1 — keiner sendet Daten.

**Geolokalisierung ist zu 100 % offline.** Liegt eine `.mmdb` von DB-IP
Lite oder MaxMind GeoLite2 in `<data_dir>/geo/`, laufen Lookups lokal. Ohne
Datenbank zeigen IPs schlicht keinen Ort. Es gibt keinen HTTP-Geodienst —
ip-api.com wurde gerade deshalb entfernt, weil es besuchte IPs im Klartext
an Dritte schickte.

**Was lokal gespeichert wird:**

| Daten | Ort | Aufbewahrung |
|---|---|---|
| Pro-Minute-Traffic-Aggregate | `snitch.db` | 24 h (einstellbar: `retention_hours`) |
| Alarm-Historie | `snitch.db` | gleiches Fenster |
| Einstellungen (Filter, Whitelist, Sprache…) | `snitch.db` | bis du sie änderst |
| API-Token | `api_token.txt` (0600) | unter Electron pro Start neu |
| Logs | `logs/snitch.log` (rotierend) | max. ~5 MB |

Datenverzeichnis: `data/` in Dev/Docker, `%LOCALAPPDATA%\Snitch` unter
Windows, `~/Library/Application Support/Snitch` unter macOS,
`~/.local/share/snitch` unter Linux bei installierter Nutzung.
