# Sicherheitsfunktionen

[English](FIREWALL.md) | [Français](FIREWALL.md) | [Español](FIREWALL.es.md) | **Deutsch** | [Русский](FIREWALL.ru.md) | [日本語](FIREWALL.ja.md) | [Português](FIREWALL.pt-BR.md) | [中文](FIREWALL.zh-CN.md)

Snitch bringt eine Threat-Hunting-Schicht über der passiven Beobachtung.
**Was sie tut — und ebenso wichtig, was sie nicht tut:**

## Orchestrierung der Ausgangs-Firewall

Snitch filtert **keine** Pakete im User-Space. Regeln werden best-effort
an die OS-native Firewall übergeben:

| OS | Mechanismus |
|---|---|
| Windows | ausgehende Blockregeln via `netsh advfirewall` |
| Linux | `iptables -A OUTPUT -j DROP` (eigene `SNITCH_LOCK`-Chain für Lockdown) |
| macOS | generierter `pf`-Anchor, geladen mit `pfctl` |

Regelarten: `ip`, `cidr`, `domain` (einmalig beim Anwenden aufgelöst),
`process`, `port`. Regeln persistieren in `snitch.db` und werden beim
Start erneut angewendet.

**Ehrliche Grenzen:**

- Das Anwenden braucht dieselben Privilegien wie die Capture. Ohne
  Erhöhung wird `applied=False` auf der Regel vermerkt — die UI zeigt
  „nur Sichtbarkeit“. Das Matching läuft trotzdem: Pakete, die eine
  Regel verletzen, lösen `BLOCKED_ATTEMPT`-Alarme mit Zählern pro Regel.
- `pf` auf macOS kann keinen *Prozess* matchen — Prozessregeln sind dort
  bewusst nur Sichtbarkeit.
- `domain`-Regeln lösen den Namen einmalig auf; eine CDN mit wechselnden
  IPs entkommt der Regel bis zur Neuanlage.
- **Lockdown** unterbricht Ausgangstraffic nur zu *öffentlichen* IPs —
  Loopback und LAN bleiben offen, damit die UI erreichbar bleibt.

## Incident Response

- `POST /processes/kill` / `POST /processes/suspend` — per PID, lehnt
  PIDs ≤ 3 und Snitch selbst ab. Übliche OS-Privilegien gelten.
- `POST /firewall/rules`, `DELETE /firewall/rules/{id}`,
  `POST /firewall/rules/{id}/toggle`, `POST /firewall/lockdown` —
  authentifiziert wie jeder Endpoint.
- `GET /forensics/export?process=<name>&ip=<ip>` — Ermittlungspaket:
  Prozessbaum (bis 8 Ahnen), SHA-256 der Exe, Kommandozeile, passende
  Alarme, Minuten-Historie. `format=json|csv|stix` wählt die Ausgabe
  (STIX = minimales 2.1-Bundle für SIEM). Nur lokale Daten; Export ist
  ein Download, nie ein Upload.

## Threat Intelligence — Opt-in, standardmäßig aus

*Einstellungen → Threat Intelligence* akzeptiert einen Anbieter
(`abuseipdb`, `otx`, `virustotal`) plus **deinen eigenen API-Key**.
Aktiviert wird jede neue öffentliche IP einmal pro 24-h-TTL geprüft;
Urteile werden gecacht und `suspicious`/`malicious` löst `THREAT_HIT`
aus. Ohne Anbieter oder Key: **null ausgehende Aufrufe**.
`GET /security/ti` zeigt die maskierte Konfiguration;
`POST /security/threat_check` startet eine manuelle Prüfung (ebenfalls
cache-bewusst).

## Webhooks — Opt-in, standardmäßig aus

*Einstellungen → Externer Webhook* nimmt URL + Schalter. Warn- und
Kritik-Alarme werden live gePOSTet: Discord/Slack `{content}`, Telegram
`{chat_id, text}` (Chat-ID-Feld bei Telegram-URL), sonstige Endpoints
bekommen `{alert, source, text}`. Fehler werden geloggt, nie fatal.

## Erkennungs-Neuerungen

- `DNS_TUNNEL` — überlange DNS-Namen/-Labels (>60 Zeichen / Label >40),
  klassisches Exfiltrationsmuster; einmal pro Host pro 10 min.
- `CLEARTEXT` — ausgehendes TCP zu natürlich unverschlüsselten Ports
  (80, 21, 23, 25, 110, 143…), Stufe INFO, speist das Audit.
- `BASELINE_DEVIATION` — jeder Prozess lernt in den ersten Paketen seine
  üblichen Zielländer, danach warnt er einmalig bei einem neuen.
  Baselines persistieren (`app_baselines`).
- `BEACON` — bereits geliefert: Regelintervall-Erkennung (CV der
  Inter-Arrival-Zeiten) auch bei minimalem Traffic.
- `BLOCKED_ATTEMPT`, `LOCKDOWN`, `THREAT_HIT` — neue Alarmtypen aus den
  Modulen oben.

## Security-Audit

`GET /security/audit` berechnet einen Score 0–100 aus den letzten 500
Alarmen und dem Live-Graphen: Zählungen pro Typ, Kontakte in
Risikoländer, unaufgelöste Hosts, Firewall-Haltung — plus Empfehlungen
in Klartext. Ein *Befundbericht*, keine Zertifizierung.
