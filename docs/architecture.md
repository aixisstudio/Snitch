# Snitch — Architecture / Architecture

## English

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
│  resolver/dns_geo.py    — observed DNS/SNI map > reverse DNS │
│                           > offline .mmdb (DB-IP/GeoLite2)   │
│  storage/db.py          — SQLite: traffic, alerts, settings  │
└──────────────────────────────────────────────────────────────┘
```

**Key invariants**

- No per-packet coroutines or broadcasts — one queue, one drain task, one
  `batch` WS message per ~250 ms.
- `remote_port` is direction-aware everywhere; `dst_port` is never used for
  classification (it's a *local* port on inbound traffic).
- No third-party network call exists in the codebase.
- The detector holds a lock around all mutable state and every container is
  size-bounded.
- macOS: media monitoring reports `supported: false`; the UI hides the badge.

## Français

Le schéma ci-dessus s'applique tel quel — l'architecture est :

- **Capture** : `pcap.py` (ctypes vers libpcap/Npcap) + `parser.py` maison
  (Ethernet, IPv4/IPv6 avec extensions, TCP/UDP, réponses DNS, SNI TLS).
- **Pipeline** : file bornée → tâche de vidage unique (~4 Hz) → un message
  WS `batch` par tick. Aucune coroutine ni diffusion par paquet.
- **Classification** : toujours sur `remote_port` (direction-aware) — le bug
  `dst_port` sur le trafic entrant est corrigé.
- **Enrichissement** : DNS/SNI observés > DNS inverse > .mmdb local ; tâches
  dédupliquées, échecs jamais cachés définitivement.
- **Persistance** : agrégats trafic, alertes et réglages dans SQLite ;
  flush à l'arrêt ; rétention configurable.
