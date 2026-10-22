---
title: "Eine kostenlose Open-Source-Alternative zu Little Snitch für Windows (ja, sie existiert)"
description: "Little Snitch ist macOS-only. Wenn du unter Windows oder Linux sehen willst, mit welchen Servern dein Computer spricht — hier ein ehrlicher Vergleich der echten Alternativen."
tags: [opensource, privacy, windows, networking]
canonical_url: https://aixisstudio.github.io/Snitch/
---

Dein Computer spricht täglich mit hunderten Servern. Das meiste ist okay — Updates, Sync, Telemetrie, der du zugestimmt hast. Manches nicht. Die Frage "mit wem redet meine Maschine wirklich?" ist der Grund, warum Little Snitch seit 15 Jahren ein macOS-Grundnahrungsmittel ist.

Das Problem: **Little Snitch existiert nicht auf Windows oder Linux.** Und die meisten Windows-"Alternativen" sind entweder kostenpflichtig, brauchen einen Account oder sind firewall-first, obwohl du nur Sichtbarkeit wolltest.

Ich bin der Autor von [Snitch](https://github.com/aixisstudio/Snitch), einem Open-Source-Echtzeit-Netzwerkvisualisierer (AGPL) mit Windows-Port — also volle Transparenz vorab. Hier der ehrliche Stand der Optionen.

## Zuerst: Visualisierer vs Blocker

Es lohnt sich, präzise zu sein, weil man das verwechselt:

- **Sichtbarkeit** = "zeig mir, mit wem meine Maschine redet" (Karte, Pro-App-Attribution, Verlauf)
- **Blocking** = "lass mich entscheiden, was erlaubt ist" (Firewall-Regeln, Prompts)

Little Snitch macht beides. Manche Alternativen nur eins. Snitch kann heute beides — die Sichtbarkeit ist seine Stärke, das Blocking orchestriert die OS-Firewall.

## Der ehrliche Vergleich

| Tool | OS | Blockt? | Gratis? | Account? | Notizen |
|---|---|---|---|---|---|
| **Little Snitch** | macOS | ✅ | bezahlt (~59 $) | nein | Die Referenz. Nichts Vergleichbares außerhalb macOS. |
| **Snitch** | macOS, Windows, Linux | ✅ OS-Firewall-Regeln + Lockdown (best-effort) | ✅ AGPL | nein | Live-Weltkarte, Anomalie-Erkennung, Privacy Score, Opt-in-Threat-Intel, Forensik-Export. 100 % lokal. |
| **Portmaster** | Win, Linux, macOS | ✅ | ✅ Kern gratis | nein | DNS-level-Blocking + App-Regeln. Schwerer — läuft als Systemdienst. |
| **OpenSnitch** | Linux | ✅ | ✅ GPL | nein | Das nächste Linux-Äquivalent — Application Firewall mit Prompts. |
| **GlassWire** | Windows, Android | ✅ | freemium | drängt Account/Cloud | Polierte UI, aber Kernfeatures + Verlauf hinter Paywall, und das Cloud-Tier wird beworben. |
| **Wireshark** | alle | ❌ | ✅ | nein | Goldstandard für *tiefe* Paketanalyse — aber zum Dissezieren, nicht für "wer telefoniert gerade nach Hause". |
| **LuLu** | macOS | ✅ | ✅ | nein | Tolle gratis macOS-Firewall — aber nur macOS, block-first, minimale Visualisierung. |

## Was Snitch wirklich tut

Ein Satz: **eine Live-Karte jeder Verbindung, die dein Computer aufbaut — welche App, welcher Server, welches Land.**

- Force-Graph + Weltkarte in Echtzeit, offline geolokalisiert (MaxMind/DB-IP — keine IP verlässt deine Maschine)
- Prozess-Attribution: welche *App* die Verbindung öffnete, nicht nur die IP
- Anomalie-Erkennung: Portscans, Beaconing-Muster, Exfil-Volumen, DNS-Tunneling
- Privacy Score + Tracker-Erkennung aus editierbaren Listen
- Pro-App-Traffic, Timeline (15/30/60 min), 24-h-SQLite-Verlauf
- Passiver LAN-Scanner (liest die ARP-Tabelle — zeigt jedes Gerät im Netz)
- **Outbound-Regeln + Lockdown**: IP/CIDR/Domain/Prozess/Port in der OS-Firewall blocken (`netsh advfirewall` unter Windows), Prozesse killen/suspendieren, Forensik-Export JSON/CSV/STIX
- **Opt-in Threat Intel**: AbuseIPDB / OTX / VirusTotal mit eigenem API-Key

Der Teil, der Privacy-Leute interessiert: **alles ist lokal.** Kein Account, keine Telemetrie, und jeder ausgehende Aufruf — GeoIP, Updates, Threat Intel, Webhooks — ist Opt-in. Die API ist token-authentifiziert und standardmäßig an Loopback gebunden.

## Was Snitch NICHT tut

Ehrlichkeits-Sektion, weil HN/Reddit ohnehin fragt:

- **Sein Blocking ist Orchestrierung, kein Treiber.** Seit v1.2 pushed Snitch `ip`/`cidr`/`domain`/`process`/`port`-Regeln in die OS-Firewall (`netsh advfirewall` unter Windows, `iptables` unter Linux, `pf` unter macOS) plus Lockdown-Schalter — best-effort: Regeln brauchen dieselben Rechte wie die Capture, um wirklich anzuwenden, und `pf` kann keine Prozesse matchen. Die UI sagt ehrlich, wenn eine Regel nicht angewendet werden konnte. Für eine reife interaktive Application Firewall bleiben Portmaster (oder Little Snitch auf macOS) die Referenz.
- **Braucht Admin/root** für Paket-Capture (unvermeidbar — wie Wireshark).
- **Tiefe Paket-Dissektion** — da gewinnt Wireshark weiterhin. Snitch ist die 10.000-Fuß-Ansicht.

## Installation unter Windows

1. [Npcap](https://npcap.com) installieren (der Windows-Capture-Treiber — Pflicht, dieselbe Abhängigkeit wie Wireshark)
2. `Snitch Setup <Version>.exe` vom [letzten Release](https://github.com/aixisstudio/Snitch/releases) laden — native Electron-App mit Tray — oder den Lite-Backend-only-Installer
3. Als Administrator ausführen (der Installer handled den UAC-Prompt beim Backend-Start)
4. Die UI öffnet sich von selbst — im Electron-Fenster oder im Browser bei Lite

Linux: `docker run --network host ghcr.io/aixisstudio/snitch` — oder das Release-Tarball. macOS: paketierte App oder `brew`.

## Wie der Windows-Port entstand

Ich maintaine das Projekt solo. Der Windows-Port war nicht ich — Nutzer meldeten Bugs mit Root-Cause-Analyse, dann schickte ein Fremder drei PRs, die Capture + Interface + Start-Crash fixten. Open Source wie erwartet. v1.0.5 erschien letzte Woche.

Wenn du es testest und etwas Interessantes fängst, gibt es eine ["Was hast du gefangen?"-Discussion](https://github.com/aixisstudio/Snitch/discussions/39) im Repo. Und wenn es dir nützt, hilft ein ⭐ auf [GitHub](https://github.com/aixisstudio/Snitch) wirklich bei der Sichtbarkeit.

**Repo:** https://github.com/aixisstudio/Snitch — AGPL, UI und Docs in 8 Sprachen (EN/FR/ES/DE/RU/JA/PT-BR/中文).
