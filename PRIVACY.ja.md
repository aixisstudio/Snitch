# プライバシー

[English](PRIVACY.md) | [Français](PRIVACY.md) | [Español](PRIVACY.es.md) | [Deutsch](PRIVACY.de.md) | [Русский](PRIVACY.ru.md) | **日本語** | [Português](PRIVACY.pt-BR.md) | [中文](PRIVACY.zh-CN.md)

Snitch はプライバシーツールです — 監視を手伝うデータそのものを決して
漏らしません。

**テレメトリ：なし。** アナリティクスもクラッシュレポートも、いかなる
「ホーム呼び出し」もありません。

**Snitch が行う外向きネットワーク呼び出し：すべてオプション、すべて
デフォルト OFF。** 以下は受動的観察かユーザー操作のみ — 静かな
トラフィックはありません:

- ローカルインターフェースでのパケットキャプチャ（受動的観察）、
- システム ARP/近隣テーブルの読み取り（アクティブスキャンなし）、
- OS リゾルバ経由の逆引き DNS — あらゆるネットワーク活動で暗黙に
  発生する標準 PTR ルックアップ（`SNITCH_DISABLE_PTR=1` で完全無効化）、
- `127.0.0.1` 上の Web UI 提供（あなた自身のブラウザ用）。

**デスクトップアプリは github.com で新リリースを確認** — 起動時と
6 時間ごと（electron-updater、公開 `latest-*.yml` を読む）。これが
唯一の定期的な外向き呼び出しです。*設定 → 更新 → 自動で確認*（永続化）
または `SNITCH_NO_UPDATE=1` で無効化。Docker ビルドとバックエンドは
確認しません。

**GeoIP データベースのダウンロード**（*設定 → ジオロケーション*）は
db-ip.com から約 50 MB を取得 — あなたがクリックした時だけ、明示的な
同意付き。

**Threat intelligence（オプトイン、デフォルト OFF）。** プロバイダ
（AbuseIPDB、AlienVault OTX、VirusTotal）を設定し*かつ*自分の API キーを
設定に貼った場合のみ、Snitch は新たに現れた公開ホストの評判をその
プロバイダに問い合わせます — 送信されるのは照会 IP のみ。判定はローカル
にキャッシュ；キーは `snitch.db` に保存（ログ出力なし、UI ではマスク）。
プロバイダやキーが無ければ照会ゼロ — `ti.check()` は no-op。

**外部 Webhook（オプトイン、デフォルト OFF）。** Webhook URL（Discord、
Slack、Telegram ボットエンドポイント、任意 URL）を貼りスイッチを入れると、
warning/critical アラートのテキストがそのエンドポイントへリアルタイム
POST されます。スイッチ OFF の間は一切送信しません。

**ローカル LLM エンリッチ（オプトイン、デフォルト OFF）。**
`slm_enabled` 有効時、アラートの*メタデータ*（種別・プロセス・宛先）は
Ollama 互換モデルへ送られる場合があります — **loopback アドレスのみ**：
127.0.0.1 / ::1 に解決しないエンドポイントはバックエンドが拒否します。
決定的テンプレートが引き続きデフォルトです。

**IOC パックは Snitch が送信することはありません。**
`GET /security/iocpack` はローカル指標を Bloom フィルター +
randomized response（ε≈4.6）でエンコードしてファイルを渡します —
共有するかはあなた次第。インポートは確率的ヒントのみで、自動
ブロックしません。

**検査プローブは読み取り専用・ローカル。** eBPF プローブ、Frida
インスペクション、`perf_event_open` カウンタ、モジュール整合性
スキャン、シンクホールレスポンダはローカル状態を*読む*だけで
127.0.0.1 で待ち受けます — データを送るものはありません。

**ジオロケーションは 100% オフライン。** DB-IP Lite または MaxMind
GeoLite2 の `.mmdb` が `<data_dir>/geo/` にあれば、ルックアップはローカル
で完結。DB が無ければ IP は単に位置を表示しません。HTTP ジオロケーション
サービスは存在しません — ip-api.com は訪問 IP を平文で第三者に送って
いたため削除されました。

**ローカルに保存されるもの:**

| データ | 場所 | 保持期間 |
|---|---|---|
| 分単位のトラフィック集計 | `snitch.db` | 24 時間（`retention_hours` で変更可） |
| アラート履歴 | `snitch.db` | 同じ保持期間 |
| 設定（フィルタ、ホワイトリスト、言語…） | `snitch.db` | 変更するまで |
| API トークン | `api_token.txt` (0600) | Electron では起動ごとに再生成 |
| ログ | `logs/snitch.log`（ローテーション） | 最大 ~5 MB |

データディレクトリ: dev/Docker は `data/`、Windows は
`%LOCALAPPDATA%\Snitch`、macOS は `~/Library/Application Support/Snitch`、
Linux はインストール時 `~/.local/share/snitch`。
