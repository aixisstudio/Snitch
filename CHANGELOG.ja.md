# 変更履歴

[English](CHANGELOG.md) | [Français](CHANGELOG.md) | [Español](CHANGELOG.es.md) | [Deutsch](CHANGELOG.de.md) | [Русский](CHANGELOG.ru.md) | **日本語** | [Português](CHANGELOG.pt-BR.md) | [中文](CHANGELOG.zh-CN.md)

Snitch の全ての注目すべき変更。

フォーマットは [Keep a Changelog](https://keepachangelog.com/) に準拠。

## [1.5.0] — 2026-10-22

### 追加

- **パッシブTLS証明書インスペクション** — `capture/tlscert.py` がサーバーの `Certificate` メッセージをTCPセグメント越しに再構成（16 KiB/フロー上限）し、リーフDERを読み取り：発行者/サブジェクト、自己署名フラグ、SAN、有効期限 → 自己署名やSAN/SNI不一致で `TLS_CERT`。TLS 1.3は正直に「観測不可」と報告 — MITMも復号もなし。
- **ICMPトンネル検知** — 大きなエコーペイロードの繰り返し（≥24B、5分で3回以上）→ `ICMP_TUNNEL`（ptunnel/icmpshシグネチャ）。
- **高エントロピー検知** — 平文ソケット上のほぼランダムなペイロード先頭（≥4.7ビット/バイト）→ `HIGH_ENTROPY`（秘匿暗号/ステガノの兆候）。
- **Isolation Forest（純Python）** — `detection/iforest.py` + `mlflow.py` が送信フローを6特徴量でスコアリング；スコア0.62以上で `ML_ANOMALY`、学習384フロー未満では不活性。
- **Ask-on-Connect（Linux NFQUEUE、オプトイン）** — `ask_enabled` が新規送信フローをキュー7に保留し `POST /security/ask/verdict` まで保持 — 本物の判定権、タイムアウトは既定でdrop。
- **eBPF egressエンフォースメント** — `detection/ebpf_enforce.py` + `POST /security/ebpf/isolate|block` — snitch cgroup内のプロセスのみカーネルdrop。
- **ハロウィング証拠** — `POST /security/hollow` が実行可能RAMページとディスク上ファイルを比較（Linux、`/proc`）。
- **IOCピア同期** — `gossip_peers` + `gossip_enabled`：塩付きMerkleパックを5分毎に明示リストのピアへ — ハッシュコミットメントのみ、探索なし。
- **Syslog** — `syslog_addr`（UDPまたは `tcp://`）が警告/重大アラートをRFC 3164で転送 — SIEM/Wazuh経路。
- **ジオルール + 自動ブロック** — カスタムルールの `asn`/`country`（ローカルmmdb）と `action:"block"` が一致IPへ実ファイアウォールルールを追加。
- **アクション可能アラート + 設定UI** — アラート毎にIPブロック/強制終了/一時停止/許可・拒否；設定画面に新コントロール（syslog、ask、ピア）。
- **nftablesバックエンド + firejail** — iptables不在時は `nft`（専用 `inet snitch` テーブル）；`firejail --net=none` をサンドボックスのフォールバックに。

## [Unreleased]

### 追加

- **送信ファイアウォール連携** — ユーザールール（`ip`、`cidr`、`domain`、`process`、`port`）を OS ネイティブのファイアウォールへ best-effort で適用: Windows は `netsh advfirewall`、Linux は `iptables`、macOS は生成した `pf` アンカー。永続化・起動時に再適用、権限不足時は正直に `applied=False`（マッチングと `BLOCKED_ATTEMPT` カウンタは継続動作）。
- **Lockdown** — パブリック IP への送信トラフィックを遮断しつつ loopback/LAN を維持するパニックスイッチ（Linux の `SNITCH_LOCK` チェーン、`netsh` ルール、`pf` アンカー）。
- **プロセス操作** — `POST /processes/kill` と `POST /processes/suspend`（PID 指定、PID ≤ 3 と Snitch 自身は拒否）；プロセス一覧に kill/suspend ボタン。
- **脅威インテリジェンス（オプトイン）** — 自分の API キーで AbuseIPDB、AlienVault OTX または VirusTotal の評判照会；デフォルト無効、新規パブリック IP ごとに 1 コール、上限付き LRU キャッシュ＋重複排除、疑わしい/悪性の判定で `THREAT_HIT` アラート。
- **外部 Webhook（オプトイン）** — warning/critical アラートを Discord、Slack、Telegram（chat ID 付き）または任意エンドポイントへライブ POST；デフォルト無効。
- **検知追加** — `DNS_TUNNEL`（異常に長い DNS 名/ラベル）、`CLEARTEXT`（FTP/Telnet/HTTP/平文メールの送信）、`BASELINE_DEVIATION`（プロセス毎に学習した国プロファイル、永続化）。
- **セキュリティ監査** — `GET /security/audit` が直近のアラートとライブグラフから 0–100 スコアと平易な推奨を算出；ファイアウォールパネルに表示。
- **フォレンジックエクスポート** — `GET /forensics/export?format=json|csv|stix` がプロセスツリー、実行ファイル SHA-256、該当アラート、トラフィック履歴を同梱；STIX は SIEM インポート用の最小 2.1 バンドル（indicators + observed-data）。
- **ファイアウォール＆セキュリティ UI** — 専用パネル: lockdown スイッチ、ルール作成/切替/削除、ルール別ブロックカウンタ、プラットフォーム対応の正直な表示、監査レポート、フォレンジックダウンロードボタン；サイドバーの接続毎ブロックアクション。
- **新 UI ロケール 5 件** — de, ru, ja, pt-BR, zh-CN（計 8、280 キーのパリティ検証済）；辞書は `frontend/src/locales/*.js` へ移動 — 新言語は 1 ファイルの PR で追加可能。

## [1.1.0] — 2026-10-22

### 追加

- **自動更新** — デスクトップアプリが起動時と 6 時間毎に electron-updater で GitHub Releases を確認（`latest-*.yml` フィードは公開済）。ダウンロードは再起動時にインストール；トレイと設定にステータスをライブ表示。設定または `SNITCH_NO_UPDATE=1` で無効化可。
- **QUIC / HTTP/3 の可視化** — UDP/443 フローを HTTPS や不明にまとめず `QUIC/HTTP3` とラベル付け。QUIC Initial の SNI は暗号化され一切読まない — 観測可能な範囲に正直なラベル。
- **Watchlist** — IP やドメイン接尾辞をピン留め（`example.com` は `api.example.com` にも一致）；専用 `WATCHLIST_HIT` アラートが初回接触で発火、（エントリ, ホスト）毎にレート制限。永続化、設定で管理。
- **プロセス別アップロードアラート** — `UPLOAD_SPIKE` はプロセスが設定可能な MB/分上限（デフォルト 50、0 = 無効）を超えると警告 — 起動直後のプロセスでベースライン相対の `VOLUME_SPIKE` が逃す exfiltration をカバー。
- **キャプチャインターフェース選択** — `GET/POST /capture/interfaces` ＋設定内の libpcap デバイス一覧ドロップダウン；切替でキャプチャ即時再起動。デスクトップユーザー向けに `SNITCH_IFACE` 環境変数を置き換え。
- **Wi-Fi コンテキスト** — ツールバーに現在の SSID（Wi-Fi 非接続時はキャプチャインターフェース）を表示。OS 毎に best-effort、60 秒キャッシュ。
- **スペイン語 UI** — `es` 辞書完備（194 キー、パリティ検証済）；言語切替は EN/FR/ES に。
- **Snap パッケージ** — electron-builder が strict confinement の `.snap` を出力（AF_PACKET キャプチャ用 `network-observe` プラグ付き）。Flatpak は意図的に未提供 — サンドボックスが生キャプチャを公開できないため（`docs/PACKAGING.md` に記載）。
- **無料コード署名の道** — CI に SignPath Foundation OSS 連携をオプション追加（`vars.SIGNPATH_*` + `secrets.SIGNPATH_API_TOKEN`）：プロジェクト受理後、Windows インストーラは Authenticode 自動署名。macOS の正直な状況（無料公証なし）含め `docs/SIGNING.md` に完全文書化。

## [1.0.8] — 2026-10-22

### 変更

- **真のネイティブライトテーマ** — v1.0.7 の反転フィルタを完全なデザイントークンシステムに置換：全サーフェス・テキスト・ボーダー・アクセント色が手選定のライトパレットで CSS カスタムプロパティ経由で描画。マップ、フォースグラフ、タイムライン、WebGL オーロラ全てがテーマ追従し、トグルは選択を永続化。

## [1.0.7] — 2026-10-22

### 追加

- **ライトテーマ** — `prefers-color-scheme` を標準で尊重しツールバーの太陽/月トグルで上書き可能；選択は `localStorage` に永続化。作製済ダークパレットの色相保持反転で実装し、グラフ・マップ・オーロラの一貫性を維持。

### 修正

- **AppImage カタログ準拠** — Linux アセットは `Snitch-x86_64.AppImage`（正しいアーキ命名）に改名し、electron-builder が GitHub 更新メタデータ（`latest-linux.yml` + `.zsync`）を公開 — AppImageUpdate 互換ツールでの自動更新が可能に。

## [1.0.6] — 2026-10-21

### 追加

- **OS 毎のダウンロード 1 本** — 各タグで CI ビルドの即実行アプリを提供：
  - **Windows** — `Snitch Setup <version>.exe`（Electron + NSIS: ネイティブウィンドウ、トレイ、Npcap チェック内蔵、バックエンド起動時 UAC）と `Snitch-Lite-Setup-<version>-windows-x64.exe`（Inno Setup: バックエンドのみ、UI はブラウザ）。
  - **macOS (Apple Silicon)** — `Snitch-<version>-macos-arm64.zip` + `.dmg` を CI でビルド（以前は手動）。
  - **Linux** — `Snitch-<version>.AppImage` + `.deb` — デスクトップアプリに Docker 不要に。
- **`--launcher` バックエンドモード** — 空き loopback ポートを選択し API トークンを算出してブラウザを開く；Lite インストーラのショートカットが使用。

### 修正

- **スタンドアロン backend バンドルが UI を同梱** — `frontend_dist` を全 OS で PyInstaller バンドル内に配置；従来の tarball は API のみを提供していた。

### 変更

- CI の `package` ジョブが 3 OS 全てで Electron インストーラをビルドし、`release` ジョブが全アーティファクトを GitHub リリースへ自動公開。

## [1.0.5] — 2026-10-17

### 追加

- **Windows サポート** — パッケージ版アプリが Windows で起動・キャプチャ可能に（Npcap）。
- **プロセスアイコン** — アプリ一覧にプロセス毎の Lucide アイコン（外部コントリビューション）。
- **トラッカードメイン 24 件追加** — クラシファイアのブロックリストへ（外部コントリビューション）。

### 修正

- `console=False` PyInstaller ビルドでの backend クラッシュ（`sys.stdout`/`sys.stderr` = None）— issue #25。
- Windows でのキャプチャインターフェース選択 — `vEthernet (WSL)` ではなくデフォルトルートを持つインターフェースを選択するように。
- タイムゾーンオフセット付きアラート時刻の `NaNh ago`。
- Electron スプラッシュがエラーダイアログを隠さなくなった；タイムアウトメッセージに原因とログフォルダを列挙。
- フランス語辞書に残っていた英語文字列 4 件を翻訳（外部コントリビューション）。
- バージョンを `backend/version.py` の単一ソース化。

### 変更

- React 18 → 19、uvicorn 0.30 → 0.54、fastapi → 0.143、psutil → 7.2、websockets → 17.2、maxminddb → 3.2、aiofiles → 25.1、lucide-react → 1.55、vite → 8.3.4、electron → 44.7（+ dev deps）。

## [1.0.4] — 2026-10-05

- 初の公開リリース。
