# セキュリティポリシー

[English](SECURITY.md) | [Français](SECURITY.md) | [Español](SECURITY.es.md) | [Deutsch](SECURITY.de.md) | [Русский](SECURITY.ru.md) | **日本語** | [Português](SECURITY.pt-BR.md) | [中文](SECURITY.zh-CN.md)

## 脆弱性の報告

脆弱性は GitHub の「Report a vulnerability」機能（Security タブ）または
リポジトリプロフィールに記載のメンテナへのメールで非公開に報告して
ください。セキュリティ問題を公開 issue で報告しないでください。

## ローカル攻撃対象面

API はあなたのトラフィックグラフ全体を公開します — 設計上保護されて
います:

- **トークン認証** — すべての REST エンドポイントと WebSocket で必須
  （`X-Snitch-Token` または `?token=`）。Electron では起動ごとに生成、
  それ以外では 0600 で永続化。
- **loopback バインド**（`127.0.0.1`）が全モードでデフォルト。
- **Origin 許可リスト** — WebSocket ハンドシェイクで（loopback ホスト
  ＋ `null` のみ）、クロスサイト WebSocket ハイジャックを防止。
- **制限付き CORS** — loopback origin のみ、クレデンシャルなし。
- **エージェント専用トークン** — `POST /ingest/enroll` がフリートエージェント向けに専用 `sagt_…` トークンを発行。ハッシュのみ保存、`/ingest/revoke` で失効可能。エージェントトークンは自分名義のイベント送信のみ可能 — 読み取り・なりすまし不可。

## 権限

パケットキャプチャには昇格した権限が必要です — ただしバックエンド
だけが保持します。パッケージ版 Electron アプリは全 OS で UI を非特権で
実行し、プラットフォームのネイティブプロンプトでバックエンドのみを
昇格させます:

- **Windows:** `Start-Process -Verb RunAs`（起動ごとに 1 回 UAC）＋ Npcap（npcap.com から自分で導入）
- **macOS:** `osascript … with administrator privileges`（ネイティブのパスワードダイアログ）
- **Linux:** `pkexec`（polkit ダイアログ）；polkit が無ければ非特権にフォールバック

昇格した子プロセスは非特権プロセスからシグナルを送れないため、認証済み
`/shutdown` エンドポイントで停止します。プロンプトを拒否した場合は
強制終了ではなく、再試行 / キャプチャなしで続行を提示します。

## 依存関係

Scapy は除去済み（GPL-2.0-only ＋ 広大な攻撃対象面のため）。キャプチャは
libpcap への最小限 ctypes バインディングと独自の境界チェック付きパーサ
です。依存はピン留めされ Dependabot が監視しています。
