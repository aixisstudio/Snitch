# Snitch — Архитектура

[English](architecture.md) | [Français](architecture.md) | [Español](architecture.es.md) | [Deutsch](architecture.de.md) | **Русский** | [日本語](architecture.ja.md) | [Português](architecture.pt-BR.md) | [中文](architecture.zh-CN.md)

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

**Ключевые инварианты**

- Никаких корутин и рассылок на пакет — одна очередь, одна задача
  выгрузки, одно WS-сообщение `batch` раз в ~250 мс.
- `remote_port` везде учитывает направление; `dst_port` никогда не
  используется для классификации (на входе это *локальный* порт).
- Ни одного вызова к третьим сторонам в коде без явного opt-in.
- Детектор держит lock вокруг всего изменяемого состояния; каждый
  контейнер ограничен по размеру.
- macOS: медиа-мониторинг сообщает `supported: false`; UI прячет значок.

**Слои вкратце**

- **Захват**: `pcap.py` (ctypes → libpcap/Npcap) + собственный
  `parser.py` (Ethernet, IPv4/IPv6 с расширениями, TCP/UDP, ответы DNS,
  TLS SNI).
- **Конвейер**: ограниченная очередь → одна задача выгрузки (~4 Гц) →
  одно WS-сообщение `batch` за тик.
- **Классификация**: всегда по `remote_port` (с учётом направления).
- **Обогащение**: наблюдаемые DNS/SNI > обратный DNS > локальная .mmdb;
  задачи дедуплицированы, ошибки не кэшируются навсегда.
- **Безопасность**: `firewall.py` оркестрирует фаервол ОС
  (netsh/iptables/pf) с персистентными правилами, lockdown и счётчиками
  блокировок; `threatintel.py` делает opt-in проверки репутации с
  LRU-кэшем.
- **Хранение**: агрегаты трафика, тревоги и настройки в SQLite; flush при
  остановке; настраиваемое хранение.
