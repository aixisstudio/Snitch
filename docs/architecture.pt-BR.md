# Snitch — Arquitetura

[English](architecture.md) | [Français](architecture.md) | [Español](architecture.es.md) | [Deutsch](architecture.de.md) | [Русский](architecture.ru.md) | [日本語](architecture.ja.md) | **Português** | [中文](architecture.zh-CN.md)

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

**Invariantes-chave**

- Sem corrotinas ou broadcasts por pacote — uma fila, uma tarefa de
  drenagem, uma mensagem WS `batch` a cada ~250 ms.
- `remote_port` é consciente da direção em todo lugar; `dst_port` nunca é
  usado para classificar (é uma porta *local* no tráfego de entrada).
- Nenhuma chamada a terceiros existe no código sem opt-in explícito.
- O detector segura um lock em todo estado mutável e cada contêiner tem
  tamanho limitado.
- macOS: o monitoramento de mídia reporta `supported: false`; a UI oculta
  o selo.

**Camadas em resumo**

- **Captura**: `pcap.py` (ctypes → libpcap/Npcap) + `parser.py` próprio
  (Ethernet, IPv4/IPv6 com extensões, TCP/UDP, respostas DNS, SNI TLS).
- **Pipeline**: fila limitada → tarefa de drenagem única (~4 Hz) → uma
  mensagem WS `batch` por tick.
- **Classificação**: sempre sobre `remote_port` (consciente da direção).
- **Enriquecimento**: DNS/SNI observados > DNS reverso > .mmdb local;
  tarefas deduplicadas, falhas nunca cacheadas para sempre.
- **Segurança**: `firewall.py` orquestra o firewall do SO
  (netsh/iptables/pf) com regras persistidas, lockdown e contadores de
  bloqueio; `threatintel.py` faz consultas de reputação opt-in com cache
  LRU.
- **Persistência**: agregados de tráfego, alertas e configurações em
  SQLite; flush ao parar; retenção configurável.
