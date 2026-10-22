# 脅威モデル

[English](threat-model.md) | [Français](threat-model.md) | [Español](threat-model.es.md) | [Deutsch](threat-model.de.md) | [Русский](threat-model.ru.md) | **日本語** | [Português](threat-model.pt-BR.md) | [中文](threat-model.zh-CN.md)

## Snitch とは

ローカルファーストのネットワークトラフィック・ビジュアライザ。ホスト上で
パケットをキャプチャし、プロセスへ帰属させ、**オフライン**でエンリッチ
（ローカル `.mmdb` ジオロケーション、ローカル DNS/SNI マップ）して、
同一プロセスが提供する Web UI に描画します。**クラウドコンポーネント
なし、テレメトリなし。**

## 資産

- あなたのトラフィックメタデータ（宛先 IP、ポート、容量、プロセス名）。
- API トークン（Electron では起動ごと、CLI/Docker ではインストールごと）。
- ローカル SQLite DB（`traffic`、`alerts_log`、履歴、設定）。
- マシン自体の完全性（侵害された Snitch はあなたに嘘をつき得る）。

## 信頼境界

| 境界 | 脅威 | 緩和策 |
|---|---|---|
| ブラウザ/リモートクライアント → REST | LAN 上の攻撃者や悪意あるページがトラフィックビューを読み/操作する | **全** endpoint でトークン必須（`Authorization: Bearer`）。デフォルト `127.0.0.1` バインド。Docker で `0.0.0.0` は `SNITCH_TOKEN` 明示設定必須。 |
| Web ページ → `/ws` | クロスサイト WebSocket ハイジャック（CSWSH） | トークン**＋**`Origin` 許可リスト（loopback＋Electron の `null` origin のみ）。 |
| ホスト → 第三者 | プライバシー漏洩 | デフォルトで外向き呼び出しゼロ。GeoIP ダウンロード、threat intel、webhook、更新確認はすべて **オプトイン**で PRIVACY.md に記載。 |
| キャプチャドライバ → パーサ | 不正フレームでプロセスが落ちる | パーサは全オフセットを境界チェック；不正パケットは `None` を返し、キャプチャループに例外を投げない。 |
| Renderer ↔ main（Electron） | ページからのトークン流出 | `contextIsolation`＋`sandbox`；トークンは `ipcRenderer.invoke` 経由のみで、DOM や URL には乗らない。 |
| FS アクセスを持つローカル攻撃者 | トークン/履歴の窃取 | トークンファイル `0600`；データディレクトリはユーザーディレクトリ配下；DB は非暗号化 — ディスク暗号化は OS の役割。 |

## 既知の限界

- **キャプチャには admin/root が必要** — ただしバックエンドのみに限定：
  Electron UI は非特権で動作し、バックエンドのみプラットフォームの
  プロンプト経由で昇格（Windows は `Start-Process -Verb RunAs`、macOS は
  `osascript`、Linux は `pkexec`）、認証済み `/shutdown` で停止。
- トークンは HTTP/WS を守るが、同じアカウントで動く他のローカル
  プロセスが `data/api_token.txt` や Electron IPC を読むことは**防げない**。
- 保存時の SQLite データは暗号化されていない。
- アラート抑制はローカルかつサイレント — DB に書き込める攻撃者は
  アラートを消音できる（防御： FS パーミッション）。

## 対象外

悪意あるペイロード（ヘッダのみ解析）、カーネル/ドライバ侵害、悪意ある
管理者。
