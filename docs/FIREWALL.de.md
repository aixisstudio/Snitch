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

### Neu in v1.2 / Nouveautés v1.2

- **Aktion `sinkhole`** — `domain`-/`ip`-Regeln können auf Loopback umleiten statt blockieren: Domains über einen markierten `# snitch-sinkhole`-Block in der hosts-Datei (alle OS), IPs/CIDRs über iptables-`DNAT` (nur Linux). `sinkhole` bei `process`/`port` wird abgelehnt; nicht unterstützte Plattformen → ehrliches `applied=False`.
- **Domain-Re-Auflösung** — `domain`-Regeln werden alle ~10 Min neu aufgelöst; das IP-Delta wird je OS angewendet, damit CDN-Rotation einen Namen nicht stillschweigend freigibt.
- **Integritätswache** (standardmäßig an, schreibgeschützt, lokal) — SHA-256-Baselines vernetzter Executables (`BINARY_CHANGED`), Name/Exe-Mismatches (`NAME_MISMATCH`), `rwxp`-Scan nur Linux (`MEM_RWX`, Info-Stufe für bekannte JIT-Apps). `GET /security/integrity`, `POST /security/integrity/check`.
- **Alert-Erklärungen** — `GET /security/explain?type=X` liefert handgeschriebene zweisprachige (EN/FR) Erklärungen; deterministisch und offline — kein Modell. Die UI zeigt sie hinter der „Warum?“-Schaltfläche.

### Optionale Sonden (v1.3)

Alle sind **standardmäßig aus oder selbstlimitierend**, degradieren ehrlich und senden nie Daten von der Maschine:

- **eBPF-Connect-Sonde** (Linux, `ebpf_probe`) — BCC-`tcpconnect`-Kprobe ordnet `connect()` zu kurzlebiger Prozesse zu. Braucht `python3-bcc` + root; mehrdeutige Ziele werden nie geraten. `GET /security/ebpf`.
- **Frida-Inspektion** — `POST /security/deep_inspect {pid,seconds}` hängt ≤60 s an EINEN pid und meldet, welches geladene Modul jedes `connect()` auslöste. Staging-Pfade → `INJECT_SUSPECT`.
- **Sinkhole-Responder** — bei aktiver `sinkhole`-Regel verwandeln Loopback-Listener auf :80/:443 jeden Versuch in einen `SINKHOLE_HIT`-Alarm mit Host/URI oder SNI + Prozess.
- **Modul-Integrität** — Merkle-Wurzel über ausführbare Mappings → `MODULE_CHANGED`; Pfade unter `/tmp`/memfd → `MODULE_SUSPECT`.
- **Mining-Erkennung** — Stratum-JSON im Payload-Kopf → `MINING_STRATUM`; Pool-Ports + anhaltende CPU → `MINING_SUSPECT`.
- **Hardware-Zähler** — `POST /security/perf` sampelt Zyklen/Instruktionen via `perf_event_open` (Linux).
- **Lokales LLM** — opt-in (`slm_enabled`): `/security/explain` ruft einen Ollama-Endpunkt **nur Loopback** — Remote-Endpunkte abgelehnt.
- **IOC-Pakete** — `GET /security/iocpack` exportiert Bloom + randomized response (nie Klartext); `POST /security/iocpack/import` prüft Ziele probabilistisch.

### Policy- & Reaktions-Neuerungen (v1.4)

- **Benannte Profile** — `POST /firewall/profile`: `permissive` (sauberer Tisch), `balanced` (vorsichtige Egress-Basis) oder `strict` (Basis + Lockdown); werden mit Dedup in gewöhnliche Regeln ausgerollt.
- **Eigene Alarmregeln** — `GET/POST/DELETE /alerts/rules`: Feld + Operator + Wert → `CUSTOM_RULE`-Alarme (nur Alarm, nie Blockierung).
- **Blocklisten-Import** — `POST /firewall/blocklist`: lokale Datei (rein lokal) oder opt-in URL (HTTPS-Fetch ≤4 MiB, als `remote_fetch` markiert) → `domain`-Regeln, dedupliziert, Limit 500–5000.
- **PCAP-Export** — `GET /forensics/pcap` (Filter `ip`/`process`): ~4-MiB-Ringpuffer als Wireshark-`.pcap`.
- **Fernkopplung** — `POST /remote/pairing` persistiert `lan_bind` für den nächsten Start; Token bleibt Pflicht. `GET /remote/pairing` meldet Bind + LAN-IPs.
- **Sandbox ohne Netzwerk** — `POST /security/sandbox` führt Binärdateien mit null Egress aus (`unshare -n` Linux, `sandbox-exec` macOS; `contrib/snitch-contain` manuell).
- **Eingebettetes Modell** — `slm_mode=embedded` lädt ein Nutzer-`.gguf` via `llama-cpp-python` — null Netzwerk.
- **Native Skelette** — `contrib/wfp-callout/` (WFP-Callout in C + Signierung) und `contrib/macos-filter/` (`NEFilterDataProvider` Swift + Entitlements): Forschungs-Scaffolding, nicht ausgeliefert.
- **ASN** — mit `GeoLite2-ASN.mmdb`/`dbip-asn-lite.mmdb` tragen Knoten `asn` neben `org`.

## v1.5 — Passive Inspektion, Kernel-Verdicts & Flotten-Sync

- **Passive TLS-Zertifikatsinspektion** — begrenzte TCP-Reassembly (≤16 KiB/Flow, 30 s TTL) liest die `Certificate`-Nachricht: Issuer/Subject CN+O, Self-Signed, SANs, Validität, `san_mismatch` → `TLS_CERT`. **TLS 1.3 bleibt opak** — ehrlich unbeobachtbar statt geraten.
- **High-Entropy-Wache** — Payloads ≥48 B auf Nicht-TLS-Kanälen mit ≥4,7 Bit/Byte → `HIGH_ENTROPY`; 10-Min-Cooldown pro Host.
- **ICMP-Tunnel-Heuristik** — Echo-Typen mit ≥24 B Payload, ≥3× in 5 Min → `ICMP_TUNNEL`.
- **ML-Flow-Anomalie** — Isolation Forest pur Python (64 Bäume, null Deps) über eigene Flow-Summaries; inert <384 Flows, `ML_ANOMALY` ab 0,62. Baseline-Abweichung, **kein** Malware-Klassifikator.
- **Ask-on-Connect (Linux, opt-in)** — `ask_enabled` + root + `python-netfilterqueue`: neue Ausgangsflüsse werden auf NFQUEUE 7 gehalten bis `POST /security/ask/verdict`; Timeout 15 s, fail-closed (`ask_failopen=1` umgekehrt). Windows/macOS brauchen die signierten Callout-/NetworkExtension-Skelette aus `contrib/`.
- **eBPF-Cgroup-Enforcement (Linux, opt-in)** — `POST /security/ebpf/isolate {pid}` + `/security/ebpf/block {ip}`: Programm an den snitch-Cgroup attachiert — Kernel-Drops gelten NUR für isolierte Prozesse.
- **Hollowing-Check (Linux)** — `POST /security/hollow {pid}` diff't ausführbare file-backed Seiten aus `/proc/<pid>/mem` gegen Disk.
- **IOC-Peer-Sync (opt-in)** — `gossip_peers` ≤32 + `gossip_enabled`: Merkle-Proof-Pakete alle 5 Min per authentifiziertem HTTP(S) — kein Discovery, kein ZK-Protokoll.
- **Syslog (opt-in)** — `syslog_addr` (`host:port` UDP oder `tcp://`) → RFC 3164 `local4`.
- **Firejail-Containment** — `firejail --net=none` bevorzugt, `unshare` als Fallback.
- **nftables-Backend** — eigene `inet snitch`-Tabelle statt iptables, wo `nft` existiert.
- **Actionable Alerts** — strukturierte `actions` (Block IP, Kill/Suspend, Ask-Verdict) als Ein-Klick-Buttons.
- **`asn`/`country` in Custom Rules** — lokale Geo-DB, kombinierbar mit `action=block` als Geo-Fence.
