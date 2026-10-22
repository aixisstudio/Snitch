# Launch-Entwürfe — alles kopierbar

[English](drafts-launch.md) | [Français](drafts-launch.md) | [Español](drafts-launch.es.md) | **Deutsch** | [Русский](drafts-launch.ru.md) | [日本語](drafts-launch.ja.md) | [Português](drafts-launch.pt-BR.md) | [中文](drafts-launch.zh-CN.md)

> **Hinweis:** die einzufügenden Texte bleiben auf Englisch — HN und Reddit sind englischsprachige Plattformen. Die vollständige kanonische EN/FR-Version steht in `drafts-launch.md`; hier die operative Zusammenfassung.

## Show HN — das « Buzz »-Paket

**Timing: Dienstag 14:30-15:00 Paris** (= 8:30-9:00 New York, Werktag = bester Slot der Woche). NICHT früher: die US-Frontpage muss aktiv sein.

**URL:** `https://github.com/aixisstudio/Snitch`

### Titel — Option A (Data-Hook, empfohlen)

`Show HN: Snitch – my Mac talked to 347 servers in one idle hour, so I built this`

### Titel — Option B (Story-Hook, falls A schon genutzt)

`Show HN: I open-sourced a network monitor — strangers shipped the Windows port`

### Autor-Erstkommentar — INNERHALB von 60 Sekunden posten

Den vollständigen Autorkommentar aus `drafts-launch.md` nutzen — Stack-Details: ctypes→libpcap, psutil-Attribution, .mmdb offline, FastAPI 127.0.0.1 + Token, `SNITCH_DEMO=1`, die Story des Community-Windows-Ports.

## Reddit — r/privacy + r/selfhosted am selben Tag

**Titel:** `Snitch — open-source app that shows every connection your PC makes (world map + process names, 100% local)`

**Body:** siehe `drafts-launch.md` — Ehrlichkeit zuerst (« I'm the author »), Feature-Bullets, Demo ohne Admin, Repo-Link. Karten-Screenshot dazu, wenn der Sub es erlaubt.

## r/netsec — wöchentlicher Show-Thread

Technischer Winkel: ctypes→libpcap-Pipeline ohne Scapy, eigener ~2K-Zeilen-Parser, psutil-Attribution, Beaconing-/DNS-Tunnel-Erkennung, OS-Firewall-Orchestrierung. SOC-/Analysten-Ton, kein Marketing.

## Vorbereitete Antworten (FAQ-Defensive)

Vollständige Antworten in `drafts-launch.md` auf: « und GlassWire/Portmaster/OpenSnitch? », « warum Python statt Rust? », « braucht Capture root? », « ausgehende Calls? » (alle Opt-in: GeoIP, Updates, TI, Webhooks), « Code-Signing? » (SignPath pending + publizierte Hashes).
