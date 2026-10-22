Dein Computer spricht täglich mit hunderten Servern. Unter Linux sind die klassischen Antworten `tcpdump`, `ss`, `netstat` oder Wireshark — mächtig, aber sie beantworten "zeig mir Pakete", nicht "mit wem redet meine Maschine, und sollte ich mir Sorgen machen?".

Dafür habe ich [Snitch](https://github.com/aixisstudio/Snitch) gebaut — einen Open-Source-Echtzeit-Netzwerkvisualisierer (AGPL), unter Linux voll unterstützt via Docker oder Release-Binary. Volle Transparenz: Ich bin der Autor, also hier der ehrliche Überblick, was es gibt und wo Snitch reinpasst.

## Die Linux-Landschaft

| Tool | Was es tut | Was es nicht tut |
|---|---|---|
| **tcpdump / ss / netstat** | Rohe Verbindungsdaten | Keine UI, kein Verlauf, keine Geolocation, kein App-Mapping |
| **Wireshark** | Tiefe Paket-Dissektion | Overkill für "wer ruft nach Hause" — Mikroskop, kein Dashboard |
| **OpenSnitch** | Application Firewall (Block/Allow-Prompts) | Minimale Visualisierung — block-first, nur Linux |
| **iftop / nethogs / nload** | Bandbreite pro Interface oder Prozess | Keine Weltkarte, keine Anomalie-Erkennung, keine Persistenz |
| **Snitch** | Live-Karte jeder Verbindung: App → Server → Land, Anomalie-Erkennung, 24-h-Verlauf, Opt-in-Blocking via OS-Firewall | OS-Regelanwendung best-effort (braucht Rechte); keine volle interaktive Firewall |

OpenSnitch und Snitch sind komplementär, keine Konkurrenten: OpenSnitch ist eine reife interaktive Application Firewall, Snitch zeigt dir, *was* deine Maschine tut — und kann seit v1.2 auch Regeln (`ip`/`cidr`/`domain`/`process`/`port`) in `iptables` pushen plus einen Lockdown-Schalter, best-effort.

## Was Snitch dir unter Linux gibt

- **Live-Weltkarte** jeder ausgehenden Verbindung mit Prozess-Attribution — welche App sie geöffnet hat, nicht nur welche IP
- **Offline-Geolocation** via lokaler MaxMind/DB-IP-Datenbank — deine IPs verlassen die Maschine nie
- **Anomalie-Erkennung**: Portscans im LAN, Beaconing (Callbacks in regelmäßigen Intervallen, klassisches C2-Muster), ungewöhnliches Ausgangsvolumen, DNS-Tunneling, pro-Prozess-Baseline-Abweichungen
- **Privacy Score** + Tracker-Erkennung aus editierbaren Suffix-Listen
- **Pro-App-Bandbreite**, Timeline, 24-h-SQLite-Retention, Alarm-Suppression-Regeln
- **Passiver LAN-Scan** via System-ARP-Tabelle — jedes Gerät im Netz, null injizierte Pakete
- **Outbound-Firewall-Regeln + Lockdown** — IP, CIDR, Domain, Prozess oder Port via OS-Firewall (`iptables` unter Linux) blockieren, Prozesse killen/suspendieren, Forensik-Bundle exportieren (JSON/CSV/STIX)
- **Opt-in Threat Intel** — Reputation via AbuseIPDB / AlienVault OTX / VirusTotal mit eigenem API-Key
- UI und Docs in 8 Sprachen (EN/FR/ES/DE/RU/JA/PT-BR/中文)

## Der Privacy-Teil

Das prüfen Linux-Nutzer meist zuerst, also: Die API bindet an **127.0.0.1** und verlangt einen Token. **Keine Telemetrie, kein Account**, und jeder ausgehende Aufruf — GeoIP-Download, Update-Checks, Threat Intel, Webhooks — ist unabhängig Opt-in. Traffic-Daten leben in einer lokalen SQLite-Datei, die dir gehört.

## Installation

```bash
# Docker (Host-Networking für Capture nötig)
docker run --network host ghcr.io/aixisstudio/snitch

# oder das Release-Tarball — braucht root/cap_net_raw wie tcpdump
sudo ./snitch-backend
```

Dann die ausgegebene URL öffnen. Es gibt auch einen Demo-Modus (`SNITCH_DEMO=1`), der synthetischen Traffic durch die echte Pipeline schickt — zum Reinschauen, bevor du Capture-Rechte gibst.

## Unter der Haube (für Neugierige)

Reines Python + ctypes → libpcap für die Capture — kein Scapy. Das IPv4/IPv6/TCP/UDP/DNS/TLS-SNI-Parsing ist handgeschrieben, ~2K Zeilen für die ganze Pipeline. FastAPI + WebSocket-Backend, React + D3-Frontend, Electron-Shell auf Desktops.

Wenn du unter Linux eine Antwort auf "redet meine Maschine um 3 Uhr nachts mit komischen Orten?" willst, ohne eine Firewall zu bezahlen oder tagelang Pakete mitzuschneiden — genau dafür ist es. ⭐ auf [GitHub](https://github.com/aixisstudio/Snitch) wenn verdient, und in Discussions gibt es einen "Was hast du gefangen?"-Thread — Screenshots willkommen.
