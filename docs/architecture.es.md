# Snitch — Arquitectura

[English](architecture.md) | [Français](architecture.md) | **Español** | [Deutsch](architecture.de.md) | [Русский](architecture.ru.md) | [日本語](architecture.ja.md) | [Português](architecture.pt-BR.md) | [中文](architecture.zh-CN.md)

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

**Invariantes clave**

- Ni corrutinas ni broadcasts por paquete — una cola, una tarea de vaciado,
  un mensaje WS `batch` cada ~250 ms.
- `remote_port` es consciente de la dirección en todas partes; `dst_port`
  nunca se usa para clasificar (es un puerto *local* en tráfico entrante).
- Ninguna llamada a terceros existe en el código sin opt-in explícito.
- El detector protege todo estado mutable con un lock y cada contenedor
  está acotado en tamaño.
- macOS: el monitoreo de media reporta `supported: false`; la UI oculta
  el badge.

**Resumen por capas**

- **Captura**: `pcap.py` (ctypes hacia libpcap/Npcap) + `parser.py` propio
  (Ethernet, IPv4/IPv6 con extensiones, TCP/UDP, respuestas DNS, SNI TLS).
- **Pipeline**: cola acotada → tarea de vaciado única (~4 Hz) → un
  mensaje WS `batch` por tick.
- **Clasificación**: siempre sobre `remote_port` (consciente de dirección).
- **Enriquecimiento**: DNS/SNI observados > DNS inverso > .mmdb local;
  tareas deduplicadas, fallos nunca cacheados para siempre.
- **Seguridad**: `firewall.py` orquesta el firewall del SO (netsh/iptables/
  pf) con reglas persistidas, lockdown y contadores de bloqueo;
  `threatintel.py` hace lookups de reputación opt-in con caché LRU.
- **Persistencia**: agregados de tráfico, alertas y ajustes en SQLite;
  flush al apagar; retención configurable.
