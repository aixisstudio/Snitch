# Snitch — Architektur

[English](architecture.md) | [Français](architecture.md) | [Español](architecture.es.md) | **Deutsch** | [Русский](architecture.ru.md) | [日本語](architecture.ja.md) | [Português](architecture.pt-BR.md) | [中文](architecture.zh-CN.md)

```
┌──────────────────────────────────────────────────────────────┐
│  Browser / Electron renderer (React + D3)                    │
│  WS ◄──── batch (250 ms) ──── REST (token: X-Snitch-Token)   │
└───────────────────────────▲──────────────────────────────────┘
                            │ 127.0.0.1 only
┌───────────────────────────┴──────────────────────────────────┐
│  FastAPI (api/main.py)                                       │
│    _pkt_queue (bounded) → _drain_loop → _process_batch       │
│      filters → LAN accounting → graph aggregates → detector  │
│      enrichment: fire-and-forget, dedup per IP               │
│      settings ←→ SQLite settings table                       │
├──────────────────────────────────────────────────────────────┤
│  capture/sniffer.py  — PacketSniffer thread                  │
│    capture/pcap.py   — ctypes → wpcap.dll / libpcap.so       │
│    capture/parser.py — own parser: Ethernet, IPv4/IPv6,      │
│                        TCP/UDP, DNS answers, TLS SNI         │
│    ConnectionTable   — psutil snapshot every ~1.5 s          │
│                        (proto, local_port) → (pid, name)     │
├──────────────────────────────────────────────────────────────┤
│  scanner/arp_scanner.py — system ARP table (passive)         │
│  capture/media_monitor.py — mic/camera (win/linux; macOS:    │
│                             explicitly unsupported)          │
│  detection/anomaly.py   — NEW_HOST, SUSPICIOUS_PROCESS/PORT, │
│                           PORT_SCAN, BEACON (regularity),    │
│                           VOLUME_SPIKE (window vs baseline), │
│                           MEDIA_EXFIL, LAN device rules      │
│  detection/firewall.py  — OS-firewall orchestration +        │
│                           lockdown + blocked counters        │
│  detection/threatintel.py — opt-in reputation lookups        │
│  resolver/dns_geo.py    — observed DNS/SNI map > reverse DNS │
│                           > offline .mmdb (DB-IP/GeoLite2)   │
│  storage/db.py          — SQLite: traffic, alerts, settings  │
└──────────────────────────────────────────────────────────────┘
```

**Zentrale Invarianten**

- Keine per-Paket-Coroutines oder -Broadcasts — eine Queue, ein Drain-Task,
  eine `batch`-WS-Nachricht pro ~250 ms.
- `remote_port` ist überall richtungsbewusst; `dst_port` wird nie zur
  Klassifikation genutzt (eingehend ist es ein *lokaler* Port).
- Kein Drittanbieter-Aufruf existiert im Code ohne explizites Opt-in.
- Der Detector hält einen Lock um allen veränderlichen Zustand; jeder
  Container ist größenbeschränkt.
- macOS: Media-Monitoring meldet `supported: false`; die UI blendet das
  Badge aus.

**Schichten im Überblick**

- **Capture**: `pcap.py` (ctypes → libpcap/Npcap) + eigener `parser.py`
  (Ethernet, IPv4/IPv6 mit Extensionen, TCP/UDP, DNS-Antworten, TLS-SNI).
- **Pipeline**: begrenzte Queue → ein Drain-Task (~4 Hz) → eine
  `batch`-WS-Nachricht pro Tick.
- **Klassifikation**: immer über `remote_port` (richtungsbewusst).
- **Anreicherung**: beobachtetes DNS/SNI > Reverse-DNS > lokale .mmdb;
  deduplizierte Tasks, Fehler nie dauerhaft gecacht.
- **Sicherheit**: `firewall.py` orchestriert die OS-Firewall
  (netsh/iptables/pf) mit persistierten Regeln, Lockdown und
  Blockzählern; `threatintel.py` macht Opt-in-Reputationsabfragen mit
  LRU-Cache.
- **Persistenz**: Traffic-Aggregate, Alarme und Einstellungen in SQLite;
  Flush beim Stoppen; konfigurierbare Aufbewahrung.
