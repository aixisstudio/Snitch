Wer unter Windows einen Netzwerkmonitor gesucht hat, stieß auf GlassWire. Es ist poliert, sieht gut aus — und dann tauchen die Paywalls auf: Verlauf hinter Abo, Firewall-Features hinter Tiers, ein Account, der ständig angeboten wird, Cloud-"Elite"-Sync.

Nichts gegen bezahlte Software. Aber "zeig mir, womit mein Computer verbunden ist" ist Basishygiene — sollte wohl kaum gesperrt sein. Ich bin der Autor von [Snitch](https://github.com/aixisstudio/Snitch), einer kostenlosen Open-Source-Alternative (AGPL) — hier also der ehrliche Vergleich statt eines Verkaufsgesprächs.

## Snitch vs GlassWire, Feature für Feature

| | **Snitch** | **GlassWire** |
|---|---|---|
| Preis | Kostenlos, für immer | Freemium — Kernfeatures hinter Paywall |
| Lizenz | AGPL Open Source | Proprietär |
| Account | **Keiner — niemals** | Account/Cloud-Tier beworben |
| Telemetrie | **Kein ausgehender Aufruf ohne Opt-in** (GeoIP, Updates, Threat Intel, Webhooks standardmäßig aus) | Phone-home für Sync/Features |
| Datenort | Lokales SQLite, deins | Cloud-verknüpfte Features existieren |
| Live-Weltkarte der Verbindungen | ✅ offline geolokalisiert | ✅ (Paid-Tiers) |
| Pro-App-Traffic & Bandbreite | ✅ | ✅ (teilweise gratis) |
| Verlauf | 24 h gratis (SQLite-Ringbuffer) | Limitiert im Free-Tier |
| Anomalie-Alarme (Portscans, Beaconing, Exfil, DNS-Tunneling) | ✅ | ✅ (meist paid) |
| LAN-Geräte-Scan | ✅ passiv, via ARP | ✅ (paid) |
| Firewall / Blocking | ✅ OS-Firewall-Orchestrierung + Lockdown (best-effort, braucht Rechte) | ✅ (GlassWires Firewall ist reifer) |
| Threat-Intel-Reputation | ✅ Opt-in (AbuseIPDB / OTX / VirusTotal, eigener Key) | ❌ |
| Prozess killen / suspendieren | ✅ eingebaut | ✅ |
| Forensik-Export | ✅ JSON / CSV / STIX | ❌ |
| Plattformen | macOS, Windows, Linux | Windows, Android |
| Privacy Score / Tracker-Erkennung | ✅ editierbare Listen | ❌ |

## Wo GlassWire weiterhin gewinnt

Fairerweise:

- **Blocking-Reife.** GlassWires Application Firewall wurde ein Jahrzehnt verfeinert — Snitchs Outbound-Blocking (seit v1.2) orchestriert die OS-Firewall best-effort und braucht Capture-Rechte, um Regeln wirklich anzuwenden. Wenn interaktive "App verweigern"-Prompts dein Kernbedarf sind, bleibt GlassWire (oder das kostenlose Portmaster) die poliertere Wahl.
- **Polish.** GlassWire hatte ein Jahrzehnt UI-Arbeit. Snitch ist viel jünger — der Graph ist stark, die Einstellungen funktional, Ecken erwarten.
- **Lange Verlaufs-Aufbewahrung** — Snitch hält 24 h by design (Privacy-first heißt auch, deinen Traffic *nicht* zu horten).

## Der Architektur-Unterschied, der zählt

GlassWires Modell ist das der Branche: Free-Tier → Ärgernis → Abo → Cloud-Features. Snitchs Modell ist das Gegenteil: Das Binary, das du startest, ist das ganze Produkt. Nichts freizuschalten, weil nichts gesperrt ist. Dein Verlauf lebt in einer lokalen SQLite-Datei — und der Code ist AGPL, er kann also nicht heimlich anfangen nach Hause zu telefonieren, ohne dass der Diff öffentlich wäre.

Konkret: API auf Loopback mit Token-Auth, null Telemetrie-Endpoints, kein Analytics-SDK irgendwo im Code (grep es — es ist Open Source).

## Probier es

```bash
# Windows: Npcap installieren, dann Release-exe als Administrator ausführen
# Linux/Docker:
docker run --network host ghcr.io/aixisstudio/snitch
# macOS: paketierte App oder brew
# Demo-Modus ohne Admin: SNITCH_DEMO=1
```

Repo: https://github.com/aixisstudio/Snitch — Issues und Feature-Requests willkommen, der Windows-Port selbst war Community-Beitrag. Wenn es ein Abo ersetzt, das du nicht wolltest — genau dafür ist es da. ⭐ wenn ja.
