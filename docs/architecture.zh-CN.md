# Snitch — 架构

[English](architecture.md) | [Français](architecture.md) | [Español](architecture.es.md) | [Deutsch](architecture.de.md) | [Русский](architecture.ru.md) | [日本語](architecture.ja.md) | [Português](architecture.pt-BR.md) | **中文**

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

**关键不变量**

- 没有逐包协程或广播——一个队列、一个排空任务、每 ~250 ms 一条
  `batch` WS 消息。
- `remote_port` 处处感知方向；`dst_port` 绝不用于分类（入站时它是
  *本地*端口）。
- 代码中不存在未经明确 opt-in 的第三方调用。
- 检测器用锁保护所有可变状态，每个容器都有大小上限。
- macOS：媒体监控返回 `supported: false`，UI 隐藏徽标。

**分层概述**

- **捕获**：`pcap.py`（ctypes → libpcap/Npcap）＋自研 `parser.py`
  （Ethernet、带扩展的 IPv4/IPv6、TCP/UDP、DNS 应答、TLS SNI）。
- **管线**：有界队列 → 单一排空任务（~4 Hz）→ 每 tick 一条
  `batch` WS 消息。
- **分类**：始终基于 `remote_port`（方向感知）。
- **富化**：观测到的 DNS/SNI > 反向 DNS > 本地 .mmdb；任务去重，
  失败不永久缓存。
- **安全**：`firewall.py` 编排 OS 防火墙（netsh/iptables/pf）——
  持久规则、lockdown、拦截计数；`threatintel.py` 做带 LRU 缓存的
  opt-in 信誉查询。
- **持久化**：流量聚合、告警和设置存 SQLite；停止时落盘；保留期可调。
