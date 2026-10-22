Dein Computer spricht gerade jetzt mit dem Internet. Wahrscheinlich dutzende Verbindungen — Sync, Telemetrie, Update-Checks, deine offenen Tabs, das Hintergrund-Geplapper deiner Apps. Die Frage "was macht meine Maschine eigentlich?" klingt banal, aber versuch sie zu beantworten und du merkst: die Tools sind entweder mikroskopisch (Wireshark) oder hinter einer Paywall.

Hier ein praktischer Guide, um es wirklich zu sehen — inklusive des Tools, das ich dafür gebaut habe, [Snitch](https://github.com/aixisstudio/Snitch) (Open Source, AGPL — Offenlegung, es ist meins).

## Die 60-Sekunden-Version

```bash
# macOS / Linux — klassisch aber roh
sudo tcpdump -i any -n | head -50        # jedes Paket, kein Kontext
netstat -anp tcp | grep ESTABLISHED      # nur aktuelle Verbindungen
lsof -i -nP | head                       # Prozess → Socket-Mapping

# Windows
netstat -ano | findstr ESTABLISHED
Get-NetTCPConnection -State Established  # PowerShell
```

Die beantworten "welche Verbindungen existieren gerade". Sie sagen dir nicht welche App, wo der Server steht oder ob es verdächtig ist. Genau diese Lücke füllt ein Visualisierer.

## Der Visualisierungs-Ansatz

Snitch rendert jede Verbindung als Live-Graph + Weltkarte:

- **Knoten = deine Maschine** im Zentrum, Linien zu jedem Remote-Endpoint
- **Jeder Endpoint beschriftet**: Hostname (via Reverse-DNS + TLS-SNI), geolokalisiertes Land/Stadt — alles offline aus einer lokalen MaxMind/DB-IP-Datei
- **Pro-App-Attribution**: die Verbindung wird zum *Prozess* gezeichnet, der sie geöffnet hat
- **Timeline**: 15/30/60-min-Traffic-Volumen, 24 h Verlauf in lokalem SQLite

Was ihn von tcpdump unterscheidet: die Daten sind *bereits aufbereitet*. Nicht "Paket an 142.250.74.78" — sondern "Chrome → google.com → Frankfurt".

## Die Karte lesen: normal vs verdächtig

So sieht eine normale Karte aus: Speichen zu Apple/Google/Microsoft/CDNs deiner Tabs, dein Router, andere LAN-Geräte.

Was heraussticht:

- **Beaconing** — eine Verbindung, die in regelmäßigen Intervallen feuert (Snitch flaggt die; klassisches C2-Muster)
- **Lang laufende Uploads zu fremden Endpoints** — Daten, die stetig irgendwohin fließen, das du nicht kennst
- **Portscans** — ein LAN-Host, der viele Ports deiner Maschine anfasst, wird geflaggt
- **Apps, die mit Ländern reden**, die für ihre Funktion keinen Sinn ergeben
- **Tracker** — Snitch gleicht Hostnamen mit editierbaren Tracker-Suffix-Listen ab und verrechnet sie in einen Privacy Score
- **DNS-Tunneling** — DNS-Queries mit abnormal langen Namen oder ungewöhnlicher Frequenz

Die eingebaute **Anomalie-Erkennung** wacht über all das automatisch, und Alarme lassen sich pro Regel stummschalten, sobald ein Muster verifiziert ist.

## Installation (2 Minuten)

```bash
# macOS: App von Releases laden, oder brew
# Windows: Npcap installieren → snitch-backend.exe als Admin ausführen
# Linux / Docker:
docker run --network host ghcr.io/aixisstudio/snitch

# Keine Admin-Rechte? Der Demo-Modus zeigt die volle UI mit synthetischem Traffic:
SNITCH_DEMO=1 snitch-backend
```

Alles bleibt lokal — token-authentifizierte API auf Loopback, null Telemetrie, kein Account, und jeder ausgehende Aufruf (GeoIP, Updates, Threat Intel, Webhooks) ist Opt-in. Das ist keine Marketingzeile; es ist eine AGPL-Codebase, du kannst den Netzwerkpfad selbst verifizieren.

Und wenn etwas falsch aussieht, kannst du handeln — seit v1.2 pushed Snitch Block-Regeln in die OS-Firewall (netsh / iptables / pf), hat einen Ein-Klick-Lockdown, Kill/Suspend-Buttons und Forensik-Export (JSON/CSV/STIX) für das, was du gefangen hast.

## Und dann?

Sobald du den Traffic *sehen* kannst, fängt das Interessante an — das Lieblingshobby der Community ist der ["Was hast du gefangen?"-Thread](https://github.com/aixisstudio/Snitch/discussions/39): Drucker, die um 3 Uhr nachts mit Cloud-Servern reden, TV-Telemetrie, das volle Programm.

Repo: https://github.com/aixisstudio/Snitch — ⭐ wenn es die Frage beantwortet, die es sich stellte.
