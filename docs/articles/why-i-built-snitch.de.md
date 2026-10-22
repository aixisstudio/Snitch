Vor drei Wochen wollte ich eine lächerlich einfache Frage beantworten: **Mit wem redet mein Computer?**

Nicht "kann ich Pakete mitschneiden" (Wireshark kann das — ein Mikroskop, wo ich eine Windschutzscheibe wollte). Nicht "Verbindungen blockieren" (Little Snitch kann das auf macOS, 59 $, unter Windows gab es nichts Vergleichbares). Nur: eine live, visuelle Antwort. Welche App, welcher Server, welches Land — jetzt gerade.

Also baute ich [Snitch](https://github.com/aixisstudio/Snitch). Open Source, AGPL, UI in 8 Sprachen, ~400 Stars in drei Wochen. Was ich gelernt habe — und der Teil, wo Fremde meinen Windows-Port schrieben.

## Der Bau

Meine selbst gesetzte Bedingung: **keine schweren Abhängigkeiten, keine Telemetrie, niemals.**

- Capture: `ctypes → libpcap` auf macOS/Linux, Npcap auf Windows. Kein Scapy — direkte Bindings sind leichter und geben exakte Feldkontrolle.
- Parsing: handgeschriebene IPv4/IPv6/TCP/UDP/DNS/TLS-SNI-Decoder. ~2K Zeilen für die ganze Pipeline.
- Backend: FastAPI + WebSockets + SQLite-Ringbuffer (24 h Aufbewahrung, dann löscht es sich selbst — Datenschutz heißt auch *nicht* horten).
- Frontend: React + D3-Force-Graph + TopoJSON-Weltkarte.
- Geolocation: lokale MaxMind/DB-IP-Datei. IPs verlassen die Maschine nie.

Sicherheitslage als Feature: API nur auf Loopback, token-authentifiziert, und jeder ausgehende Aufruf ist Opt-in — GeoIP-Download, Update-Checks, Threat Intel und Webhooks sind alle standardmäßig aus. Bei einem Privacy-Tool *ist* der Code das Versprechen — AGPL macht ihn auditierbar.

## Was ich nicht geplant hatte

Ich lieferte zuerst macOS aus und taggte das Repo "help wanted" für Windows. Innerhalb von Tagen:

- Nutzer meldeten Bugs **mit Root-Cause-Analyse** — nicht "geht nicht", sondern echte Stacktraces und der fehlerhafte Capture-Pfad identifiziert
- Ein Fremder, mit dem ich nie gesprochen hatte, schickte drei PRs: Npcap-Capture, Interface-Auswahl, ein Start-Crash
- Jemand anderes öffnete den [winget-Paket-PR](https://github.com/microsoft/winget-pkgs/pull/455520)

v1.0.5 erschien letzte Woche mit voll funktionierendem Windows-Port. Der stärkste Distributionskanal war kein Marketingtrick — es war "ein echtes Problem öffentlich stellen, dann kommen die Leute mit demselben Problem".

## Was die Traffic-Daten sagten

Lustiger Meta-Moment: Snitchs eigener Referral-Traffic erzählte die Geschichte. Ein chinesischer Tech-Newsletter (ruanyifeng.com) featured das Projekt — plötzlich waren ~20 % der Leser Chinesen vor einem englischen README. Jetzt gibt es ein vollständiges [README 中文](https://github.com/aixisstudio/Snitch/blob/main/README.zh-CN.md) — und insgesamt Übersetzungen in 8 Sprachen. Die Daten entscheiden; ich höre nur zu.

## Was ich jedem Dev-Tool-Bauer sagen würde

1. **Löse ein gespürtes Problem.** "Mit wem redet meine Maschine" ist viszeral — alle fragen sich das, keiner kann es sehen.
2. **Local-first ist jetzt ein Differenzierer.** "Kein Account, keine Telemetrie" ist keine Einschränkung, sondern die Botschaft.
3. **Mehrsprachige Docs sind keine Wohltätigkeit** — sie sind Distribution an Zielgruppen ohne Konkurrenz.
4. **Issues und Discussions konvertieren.** Schnelle Antworten machten aus Bug-Reportenden Contributor. So entstand mein Windows-Port.

## Probier es

```bash
docker run --network host ghcr.io/aixisstudio/snitch   # Linux
# macOS/Windows: Releases-Seite — SNITCH_DEMO=1 läuft ohne Admin
```

Repo: https://github.com/aixisstudio/Snitch — AGPL, UI + Docs in EN/FR/ES/DE/RU/JA/PT-BR/中文, und v1.2 brachte das meistgewünschte Feature: Outbound-Blocking über die OS-Firewall, Opt-in-Threat-Intel und Forensik-Export per Klick. Der ["Was hast du gefangen?"-Thread](https://github.com/aixisstudio/Snitch/discussions/39) ist offen, und ein ⭐ hilft echt, wenn es ihn verdient.
