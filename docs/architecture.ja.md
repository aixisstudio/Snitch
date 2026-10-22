# Snitch — アーキテクチャ

[English](architecture.md) | [Français](architecture.md) | [Español](architecture.es.md) | [Deutsch](architecture.de.md) | [Русский](architecture.ru.md) | **日本語** | [Português](architecture.pt-BR.md) | [中文](architecture.zh-CN.md)

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

**主要な不変条件**

- パケットごとのコルーチンやブロードキャストなし — キュー 1 本、ドレイン
  タスク 1 本、~250 ms ごとの `batch` WS メッセージ 1 本。
- `remote_port` は常に方向を考慮；`dst_port` は分類に使わない
  （受信では*ローカル*ポートのため）。
- 明示的オプトインなしの第三者呼び出しはコード中に存在しない。
- 検出器は全ての可変状態をロックで保護し、全コンテナはサイズ上限付き。
- macOS: メディア監視は `supported: false` を返し、UI はバッジを隠す。

**レイヤ概要**

- **キャプチャ**: `pcap.py`（ctypes → libpcap/Npcap）＋独自 `parser.py`
  （Ethernet、拡張付き IPv4/IPv6、TCP/UDP、DNS 応答、TLS SNI）。
- **パイプライン**: 上限付きキュー → 単一ドレインタスク（~4 Hz）→
  ティックごとの `batch` WS メッセージ。
- **分類**: 常に `remote_port`（方向考慮）。
- **エンリッチ**: 観測 DNS/SNI > 逆引き DNS > ローカル .mmdb；タスクは
  重複排除、失敗は恒久的にキャッシュしない。
- **セキュリティ**: `firewall.py` が OS ファイアウォール
  （netsh/iptables/pf）を連携 — 永続ルール、lockdown、ブロックカウンタ；
  `threatintel.py` が LRU キャッシュ付きオプトイン評判照会。
- **永続化**: トラフィック集計、アラート、設定を SQLite に；停止時に
  フラッシュ；保持期間は設定可。
