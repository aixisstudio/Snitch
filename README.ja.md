<div align="center">

# Snitch

**隠れたネットワーク接続をすべて追跡。**

[English](README.md#english) | [Français](README.md#français) | [Español](README.es.md) | [Deutsch](README.de.md) | [Русский](README.ru.md) | **日本語** | [Português](README.pt-BR.md) | [中文](README.zh-CN.md)

⭐ **Snitch が役に立ったら、スターをいただけると嬉しいです！** ⭐

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Platform: macOS](https://img.shields.io/badge/Platform-macOS-blue.svg)]()
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue.svg)]()
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux%20(Docker)-blue.svg)]()
[![GitHub release](https://img.shields.io/github/v/release/aixisstudio/Snitch?include_prereleases&label=release)](https://github.com/aixisstudio/Snitch/releases/latest)
[![GitHub stars](https://img.shields.io/github/stars/aixisstudio/Snitch?style=flat-square&logo=github)](https://github.com/aixisstudio/Snitch/stargazers)

<!-- JA: デモモード (SNITCH_DEMO=1) のライブキャプチャ — 合成トラフィックのみ。 -->
![Snitch live graph — LAN perimeter, geolocated hosts, alerts](docs/assets/demo.gif)

</div>

---

**Snitch** はリアルタイムのネットワークトラフィック・ビジュアライザです。
コンピュータの全接続が見えます — 誰と通信しているか、相手はどこか、どのアプリが原因か。

UI 全体は **English、Français、Español、Deutsch、Русский、日本語、Português (BR)、简体中文** で利用可能。右上ツールバーの言語セレクタを使ってください。

### なぜ Snitch？

- **vs Little Snitch / Lulu** — 同じ発想（アプリ別可視化＋外向きブロックルール）ですが、Snitch はクロスプラットフォーム・無料・オープンソース。ブロックは OS ネイティブファイアウォール（`netsh` / `iptables` / `pf`）でオーケストレート — ユーザースペースでのフィルタリングはしません。
- **vs GlassWire** — Snitch は無料・オープンソース（AGPL）・アカウント不要で、オプトインなしの**外向き呼び出しはゼロ**。ジオロケーションさえオフライン。
- **vs Wireshark** — 生のパケット解析ではなく、誰でも読めるライブな高レベル概要を提供。
- **vs クラウド監視** — すべて `127.0.0.1` でトークン認証の内側。トラフィックデータはマシンから出ません。

### 機能

| 機能 | 説明 |
|---|---|
| フォースグラフ | ライブノードグラフ — 中央にあなたのマシン、各接続がノード |
| ワールドマップ | ジオロケーション済み IP をインタラクティブ地球儀上にアニメーションアークで表示 |
| 15/30/60分タイムライン | SQLite ローカルのスライディング履歴（保持 24 時間） |
| 異常検知 | ポートスキャン、ビーコニング（定期間隔 C2）、潜在的な流出を検出 |
| 高度な検知 | DNS トンネルヒューリスティック、平文ポート、アプリ別国ベースライン逸脱 |
| ファイアウォール連携 | ブロックルール（IP/CIDR/ドメイン/プロセス/ポート）を OS ファイアウォールへ適用 — `netsh`/`iptables`/`pf`、永続化、ルール別ブロックカウンタ |
| ロックダウンモード | パニックスイッチ — 公開向け送信トラフィックをすべて検出＆ブロック、LAN は維持 |
| インシデント対応 | プロセスの kill / サスペンド、IP ブロック — 接続詳細からワンクリック |
| Threat Intelligence | **オプトイン**の評判チェック（AbuseIPDB / AlienVault OTX / VirusTotal）、自分の API キー使用 — デフォルト OFF、結果はキャッシュ |
| セキュリティ監査 | 組み込みハードニングレポート — スコア、検出結果、平易な推奨事項 |
| フォレンジックエクスポート | ワンクリック調査バンドル — プロセスツリー＋バイナリ SHA-256、履歴＆関連アラート（JSON/CSV/STIX） |
| Webhook アラート | warning/critical アラートを Discord・Slack・Telegram・任意 endpoint へ **オプトイン**転送 |
| プロセス帰属 | どのアプリがどのトラフィックを生成するか（接続ごとトップ 5） |
| LAN スキャナ | システム ARP テーブルによる受動的検出（ブロードキャストスキャンなし） |
| プライバシースコア | 送信トラフィック露出度のリアルタイムスコア |
| アプリ別ビュー | プロセス別の宛先・容量・60 分履歴 |
| アラート抑制 | 永続化された「ホスト/種類を無視」ルール、UI で管理 |
| 設定パネル | 言語、保持期間、フィルタ、同意制 GeoIP ダウンロード、診断 |
| トラッカー検出 | サフィックスマッチのドメインリストを編集可能なデータファイルで同梱（`backend/classifier/lists/`） |
| 帯域モニタ | ライブ MB/s スパークライン |
| 8 言語 UI | EN · FR · ES · DE · RU · JA · PT-BR · ZH-CN — ワンクリック切替、ロケールは `frontend/src/locales/` |
| ライト/ダークテーマ | デフォルトで OS 設定に追従、手動切替は永続化 |
| 自動更新 | デスクトップアプリが GitHub Releases を確認（設定で無効化可；`SNITCH_NO_UPDATE=1`） |
| QUIC / HTTP/3 | UDP/443 フローを正直にラベル付け — QUIC の SNI は暗号化され読みません |
| ウォッチリスト | IP/ドメインをピン留め — 接触した瞬間に専用アラート |
| アップロードスパイク警報 | プロセス別 MB/分上限、閾値調整可 |
| インターフェース選択 | どのアダプタを傍受するか — 環境変数不要 |
| Wi-Fi コンテキスト | 現在の SSID をツールバーに表示 |
| エクスポート | グラフ＋アラートを JSON/CSV にワンクリック |

### ダウンロード

| プラットフォーム | パッケージ |
|---|---|
| **macOS (Apple Silicon)** | `brew install --cask aixisstudio/tap/snitch` — または [最新リリース](https://github.com/aixisstudio/Snitch/releases/latest) の **Snitch.app** zip/dmg |
| **Linux** | [最新リリース](https://github.com/aixisstudio/Snitch/releases/latest) の **Snitch AppImage / .deb / .snap** — または `sudo docker compose up --build`（[Docker (Linux)](#docker-linux) 参照） |
| **Windows** | **Snitch Setup** `.exe` — ワンクリック NSIS インストーラ（ネイティブアプリ、起動時 UAC、Npcap チェック内蔵）。[最新リリース](https://github.com/aixisstudio/Snitch/releases/latest) から。Lite 代替: `Snitch-Lite-Setup`（バックエンド＋ブラウザ UI）。[Npcap](https://npcap.com/) が必要 |
| **すべて (1 クリック)** | [Pinokio](https://pinokio.co/apps/github-com-aixisstudio-snitch) — 依存関係をインストール、バックエンド起動、UI を開く |

最新リリースはこちら: **[github.com/aixisstudio/Snitch/releases](https://github.com/aixisstudio/Snitch/releases)**

> **macOS 初回起動** — Snitch は ad-hoc 署名で、ノータライズされていません（有償 Apple Developer ID なし）。`brew install --cask` は quarantine フラグを自動で除去します。手動 zip の場合：右クリック → **開く**、または `xattr -dr com.apple.quarantine /Applications/Snitch.app`。初回起動時に管理者パスワードを**一度だけ**聞きます — tcpdump/Wireshark と同様、パケットキャプチャに必要です。UI 自体は非特権のまま。
>
> **Windows コード署名** — Windows ビルドは [SignPath Foundation](https://signpath.org) 提供の無料 OSS 証明書で [SignPath.io](https://signpath.io) 経由の Authenticode 署名予定（申請済み・承認待ち）。署名ビルド公開までは SmartScreen が警告する場合があります — **詳細 → 実行** をクリック。

### 技術スタック

| レイヤ | 技術 |
|---|---|
| パケットキャプチャ | ctypes → libpcap — Npcap (Windows) / libpcap (Linux/macOS) — 独自パーサ（IPv4/IPv6/TCP/UDP/DNS/TLS-SNI） |
| バックエンド API | FastAPI — WebSockets — SQLite |
| フロントエンド | React 19 — Vite — D3.js v7 — TopoJSON |
| デスクトップ | Electron 44 |
| ジオロケーション | **オフラインのみ** — DB-IP Lite (CC BY 4.0) を gzip 同梱 `backend/data/geo/`、初回起動時に展開。MaxMind GeoLite2 `.mmdb` も対応 |

### セキュリティとプライバシー

- **API トークン** — 全 REST エンドポイントと WebSocket がトークン必須。Electron は起動ごとに生成；Docker/ブラウザではバックエンドログに一度だけ表示され `data/api_token.txt` に保存。`http://localhost:8000/?token=<TOKEN>` で UI を開く。
- **デフォルト loopback のみ** — API は全モードで `127.0.0.1` にバインド。LAN アクセスが必要な場合のみ `SNITCH_BIND=0.0.0.0`（トークンは依然必須）。
- **CORS/WebSocket Origin 許可リスト** — `localhost:5173`、バックエンド自身の origin、Electron の `file://` ページのみ接続可。
- **ジオロケーションは 100% オフライン** — オンライン参照は*一切なし*。DB-IP Lite ([CC BY 4.0](https://db-ip.com/db/lite.php)) は `<data_dir>/geo/` へ自動展開。新しい `.mmdb` を置くか設定から DB-IP Lite をダウンロード可（明示的同意；他のオプトイン外向き呼び出し — threat intel・webhook・更新確認 — は [PRIVACY.md](PRIVACY.md) に記載）。
- **すべてのデータはローカル** — `snitch.db`（24 時間スライディング、`retention_hours`）と `data/logs/snitch.log` はマシンから出ません。テレメトリなし。外向き呼び出しはすべてオプトイン。
- **設定の永続化** — ポートフィルタ、除外プロセス、IP ホワイトリスト、ファイアウォールルール、言語、保持期間は SQLite に保存され再起動時に復元。
- **ファイアウォールルールは best-effort** — バックエンドが OS ファイアウォール（`netsh advfirewall`、`iptables`、`pf` アンカー）を駆動。権限不足時はルールを保持し*可視化*のためにマッチング（BLOCKED_ATTEMPT アラート）＋「未適用」と正直に表示。ロックダウン中も loopback＋LAN は維持。
- **Threat intel・webhook はオプトイン** — デフォルト無効。有効化すると外向き呼び出しが追加されます（[PRIVACY.md](PRIVACY.md)）。
- **アラート抑制** — 各アラートに「この種類/ホストを無視」；ルールは永続化（`alert_suppressions`）、`POST|DELETE|GET /alerts/ignore` で管理。
- **履歴** — 分単位のホスト別・プロセス別バイト/パケット集計を SQLite（`host_history`、`process_history`）に保持、アプリ別ビューと `GET /history/*` を駆動。
- **診断** — `GET /diagnostics` は秘密情報を含まないランタイム JSON スナップショット；設定パネルからエクスポート可。
- **LAN デバイス** — システム ARP テーブルから受動的検出、アクティブスキャンなし。名前はデバイス自身が発信するものから学習：mDNS `*.local`、LLMNR/NetBIOS、DHCP hostname、完全オフライン IEEE OUI テーブル。ゲートウェイはルーターとして自動検出。
- 完全な脅威モデルは [docs/threat-model.md](docs/threat-model.md)、セキュリティスイートは [docs/FIREWALL.md](docs/FIREWALL.md) を参照。

### Docker (Linux)

Docker デプロイは Docker 以外何もインストールしたくない Linux ユーザー向けです。
`network_mode: host` によりコンテナはホストの実トラフィックを見ます。

**ビルド済みイメージ** — クローン・ビルド不要:

```bash
sudo docker run --network host --cap-add NET_ADMIN --cap-add NET_RAW \
  -v snitch-data:/app/data ghcr.io/aixisstudio/snitch
```

> **注意:** Mac/Windows の Docker Desktop は VM 内で動作しホストトラフィックをキャプチャできません。これらのプラットフォームでは Electron アプリを使用。

API トークン（起動時に一度表示、または `cat data/api_token.txt`）を取得し、ブラウザで **http://localhost:8000/?token=TOKEN** を開く。
バックグラウンド: `sudo docker compose up -d --build`

Docker の制限: プロセス帰属はコンテナ内プロセスのみ；LAN スキャナはネットワーク構成により利用不可の場合あり。

### 開発

要件: Python 3.11+、Node.js 18+、[Npcap](https://npcap.com/)（Windows のみ）、バックエンド用管理者ターミナル。

> **デモモード** — `SNITCH_DEMO=1` で合成トラフィックを実パイプラインに流す：root 不要、libpcap 不要、実パケット不問。スクリーンショットやテストに最適。

```bash
cd backend && pip install -r requirements.txt && python run_backend.py
cd frontend && npm install && npm run dev   # http://localhost:5173/?token=TOKEN
cd electron && npm install && VITE_DEV=1 npx electron .
```

テスト:

```bash
cd backend && pip install -r requirements-dev.txt && python -m pytest tests/ -v
cd frontend && npm test
```

### プロジェクト構成

```
snitch/
├── backend/       FastAPI + libpcap キャプチャ（ctypes、独自パーサ）
├── frontend/      React + D3.js UI（8 言語）
├── electron/      Electron ラッパー（main、splash、preload）
├── data/          実行時データ（SQLite、geo/ 内 .mmdb）
└── dist/          ビルド成果物（バックエンド exe、インストーラ）
```

---

## ライセンス

AGPL v3 — [LICENSE](LICENSE) 参照。自由に使用・学習・改変可；派生物は AGPL v3 のオープンソースを維持する必要があります。

## スター履歴

[![Star History Chart](https://api.star-history.com/svg?repos=aixisstudio/Snitch&type=Date)](https://star-history.com/#aixisstudio/Snitch&Date)
