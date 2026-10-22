# Roadmap

[English](ROADMAP.md) | [Français](ROADMAP.md) | [Español](ROADMAP.es.md) | **Deutsch** | [Русский](ROADMAP.ru.md) | [日本語](ROADMAP.ja.md) | [Português](ROADMAP.pt-BR.md) | [中文](ROADMAP.zh-CN.md)

> Feature-Vorschläge und Votes in [GitHub Discussions](https://github.com/aixisstudio/Snitch/discussions) — Kategorie *Ideas*. Für konkrete Bugs die [Issues](https://github.com/aixisstudio/Snitch/issues) nutzen.

## ✅ Ausgeliefert

| Version | Was kam |
|---|---|
| **v1.0.4** | Erste öffentliche Release — Echtzeit-Graph + Weltkarte, Prozess-Attribution, Offline-Geolokalisierung (.mmdb), Anomalie-Alarme, Privacy Score, passive LAN-Erkennung (ARP/OUI), Mikro/Kamera-Monitoring (Windows/Linux), Demo-Modus, UI EN/FR |
| **v1.0.5** | **Windows-Support** (Npcap, gepacktes Backend), Prozess-Icons, +24 Tracker-Domains, Fixes |
| **v1.2 (main, ohne Tag)** | **Security- & Threat-Hunting-Suite** — OS-Firewall-Orchestrierung (Regeln IP/CIDR/Domain/Prozess/Port via `netsh`/`iptables`/`pf`, best-effort), Lockdown-Schalter, Kill/Suspend-Aktionen, Opt-in Threat Intel (AbuseIPDB/OTX/VirusTotal), Opt-in Webhooks (Discord/Slack/Telegram/generisch), DNS-Tunnel-/Klartext-/Länderabweichungs-Erkennung, Security-Audit, Forensik-Export (Prozessbaum + SHA-256, JSON/CSV/STIX), UI in 8 Sprachen |

Außerdem live: Docker-Image auf GHCR, Homebrew-Tap (`brew install --cask aixisstudio/tap/snitch`), winget-Paket [eingereicht](https://github.com/microsoft/winget-pkgs/pull/455520), README in 8 Sprachen, GitHub Discussions.

## 🚧 v1.x — in Arbeit

- [x] **Signierter Windows-Installer** — CI auf [SignPath](https://signpath.org) OSS vorbereitet (kostenloses Authenticode für genehmigte Projekte); aktiv sobald der Antrag angenommen wird — siehe `docs/SIGNING.md`
- [ ] **Signierter & notarisierter macOS-Build** — braucht Apple-Developer-Account (99 $/Jahr), es gibt keinen Gratisweg. Bis dahin entfernt der [Tap](https://github.com/aixisstudio/homebrew-tap) die Quarantäne
- [ ] **Homebrew-Upstream** (`brew install --cask snitch`) — blockiert: der Name `snitch` ist von einem anderen Projekt belegt; erneut prüfen sobald Developer-ID-Signatur existiert
- [ ] **winget-Veröffentlichung** — [PR #455520](https://github.com/microsoft/winget-pkgs/pull/455520) offen, wartet auf Microsoft-Review
- [x] **Windows-Ein-Klick-Installer** — Electron-NSIS + Inno Lite, gebaut in CI pro Tag; seit v1.0.6
- [x] **Linux-Pakete** — .deb / AppImage / **snap** zusätzlich zu Docker (kein Flatpak: die Sandbox kann keine Paket-Capture freigeben)
- [x] **Auto-Update** — electron-updater auf den `latest-*.yml`-Feeds, abwählbar in Einstellungen
- [x] **Exportformate** — Graph + Alarme als JSON/CSV in der UI
- [ ] **Breitere Tracker-Abdeckung** — community-editierbare Listen in `backend/classifier/lists/`
- [ ] **PCAP-Export** — pro Host oder Session

## 💭 In Erwägung

- Eigene Alarmregeln in der UI
- Optionales Remote-Pairing für headless Hosts — consent-gated, token-geschützt
- Karten-Layer: ASN-/Organisationsansicht
- Blocklist-Imports (StevenBlack hosts, EasyList) — braucht vorher Privacy-/Lizenz-Review
- Firewall-Profile (strikt/Reise vs Entwickler/permissiv)

## 🔬 Forschung — dokumentiert, nicht implementiert

Ideen, die Snitch Richtung Desktop-EDR/XDR führen würden. Ehrlich gelistet —
**keine davon ist implementiert**; jede braucht eigenes Design, native
Komponenten und oft ein zweites Binär-Artefakt:

- **eBPF-Sonden (Linux)** — Kernel-Space-Capture von `sys_enter_connect`/`accept`, umgehungssicher; braucht kompiliertes BPF-Programm + Root
- **WFP-Callout (Windows)** — echtes Kernel-Paketfiltering statt `netsh`-Orchestrierung; braucht signierten Kernel-Treiber
- **NetworkExtension (macOS)** — `NEFilterProvider` für Bundle-Filterung; braucht Apple Developer ID + Entitlements
- **Speicher-/Fluss-Korrelation** — Inspektion unsignierter DLLs / `PAGE_EXECUTE_READWRITE`-Regionen, gekreuzt mit verdächtigen Verbindungen
- **Dynamic Taint Analysis** — Exfiltration byte-genau beweisen; schwere Forschung
- **Lokales SecOps-SLM** — 1–3-B-Parameter-Modell, das Alarme in natürlicher Sprache erklärt
- **ZKP-Flotten-Intel** — Erkennungen flottenweit teilen, ohne Endpunkte preiszugeben
- **PMU-/Hardware-Counter** — Ransomware-Signale unterhalb des OS (Speculation, Crypto-Bursts)
- **Merkle-Integrität geladener Module** — hot-gepatchte DLLs vor dem ersten Paket erkennen
- **Sinkholing / Micro-Containment** — verdächtige Flüsse in einen lokalen Honeypot umleiten statt zu killen
- **PCAP-Export** bleibt oben im Scope

## 🚫 Out of scope

Bewusst, by design:

- **Telemetrie, Analytics, Konten, Cloud-Sync** — niemals.
- **Passives IDS auf Netzwerkebene** — Snitch beobachtet *diesen* Rechner, nicht das ganze Netz.
- **User-Space-Paketfilterung** — Blockieren wird an die OS-native Firewall delegiert (oder künftige Kernel-Komponenten), nie neu implementiert.

## 🤝 Mitmachen

Gute Einstiegspunkte: `good first issue`-Labels, Tracker-Listen-PRs (`backend/classifier/lists/`), Übersetzungen (i18n fertig, eine Datei pro Sprache), Packaging (Linux .deb/.rpm). Siehe [CONTRIBUTING.md](CONTRIBUTING.md).
