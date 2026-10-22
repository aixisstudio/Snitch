# ロードマップ

[English](ROADMAP.md) | [Français](ROADMAP.md) | [Español](ROADMAP.es.md) | [Deutsch](ROADMAP.de.md) | [Русский](ROADMAP.ru.md) | **日本語** | [Português](ROADMAP.pt-BR.md) | [中文](ROADMAP.zh-CN.md)

> 機能の提案・投票は [GitHub Discussions](https://github.com/aixisstudio/Snitch/discussions) の *Ideas* カテゴリへ。具体的なバグは [Issues](https://github.com/aixisstudio/Snitch/issues) へ。

## ✅ リリース済み

| バージョン | 内容 |
|---|---|
| **v1.0.4** | 初公開リリース — リアルタイムグラフ＋世界地図、プロセス帰属、オフラインジオロケーション（.mmdb）、異常アラート、プライバシースコア、パッシブ LAN 検出（ARP/OUI）、マイク/カメラ監視（Windows/Linux）、デモモード、UI EN/FR |
| **v1.0.5** | **Windows 対応**（Npcap、パッケージ済みバックエンド）、プロセスアイコン、トラッカードメイン +24、修正 |
| **v1.2（main、タグなし）** | **セキュリティ＆スレットハンティングスイート** — OS ファイアウォール連携（IP/CIDR/ドメイン/プロセス/ポートのルールを `netsh`/`iptables`/`pf` へ、best-effort）、ロックダウンスイッチ、kill/suspend アクション、オプトイン threat intel（AbuseIPDB/OTX/VirusTotal）、オプトイン webhook（Discord/Slack/Telegram/汎用）、DNS トンネル/平文/国ベースライン逸脱検知、セキュリティ監査、フォレンジックエクスポート（プロセスツリー＋SHA-256、JSON/CSV/STIX）、8 言語 UI |

その他稼働中： GHCR の Docker イメージ、Homebrew tap（`brew install --cask aixisstudio/tap/snitch`）、winget パッケージ[提出済み](https://github.com/microsoft/winget-pkgs/pull/455520)、8 言語 README、GitHub Discussions。

## 🚧 v1.x — 進行中

- [x] **署名付き Windows インストーラ** — CI は [SignPath](https://signpath.org) OSS 用に配線済み（承認プロジェクトに無料 Authenticode）；申請受理で有効化 — `docs/SIGNING.md` 参照
- [ ] **署名＋公証済み macOS ビルド** — Apple Developer アカウント（年 $99）が必要で無料ルートなし。それまでは [tap](https://github.com/aixisstudio/homebrew-tap) が quarantine を除去
- [ ] **Homebrew 本家**（`brew install --cask snitch`）— ブロック中：`snitch` 名は別プロジェクトが使用中；Developer ID 署名後に再検討
- [ ] **winget 公開** — [PR #455520](https://github.com/microsoft/winget-pkgs/pull/455520) オープン、Microsoft レビュー待ち
- [x] **Windows ワンクリックインストーラ** — Electron NSIS＋Inno Lite、タグごとに CI ビルド；v1.0.6 から
- [x] **Linux パッケージ** — .deb / AppImage / **snap** に加え Docker（Flatpak なし：サンドボックスはパケットキャプチャを公開不可）
- [x] **自動更新** — `latest-*.yml` フィードの electron-updater、設定で無効化可
- [x] **エクスポート形式** — UI でグラフ＋アラートを JSON/CSV に
- [ ] **トラッカー網羅の拡大** — `backend/classifier/lists/` のコミュニティ編集リスト
- [ ] **PCAP エクスポート** — ホスト/セッション単位

## 💭 検討中

- UI でのカスタムアラートルール
- ヘッドレスホスト向けオプションのリモートペアリング — 同意制＋トークン保護
- マップレイヤ： ASN / 組織ビュー
- ブロックリストインポート（StevenBlack hosts、EasyList）— プライバシー/ライセンス審査が先
- ファイアウォールプロファイル（厳格/旅行 vs 開発者/寛容）

## 🔬 研究 — 記録のみ、未実装

Snitch をデスクトップ EDR/XDR へ向かわせるアイデア群。正直に記載 —
**いずれも未実装**；それぞれ固有の設計・ネイティブコンポーネント・
多くは第二のバイナリ成果物が必要：

- **eBPF プローブ（Linux）** — `sys_enter_connect`/`accept` のカーネル空間キャプチャ、回避耐性；コンパイル済み BPF＋root が必要
- **WFP コールアウト（Windows）** — `netsh` 連携ではなく本物のカーネルフィルタ；署名済みドライバが必要
- **NetworkExtension（macOS）** — バンドル別フィルタの `NEFilterProvider`；Apple Developer ID＋entitlements が必要
- **メモリ/フロー相関** — 未署名 DLL・`PAGE_EXECUTE_READWRITE` 領域の検査と不審接続のクロス
- **Dynamic Taint Analysis** — バイト単位での流出証明；重量級の研究
- **ローカル SecOps SLM** — アラートを自然言語で説明する 1–3 B パラメータモデル
- **ZKP フリートインテル** — endpoint を明かさず検知をピアフリートへ共有
- **PMU/ハードウェアカウンタ** — OS の下のランサムウェア兆候（投機実行、暗号バースト）
- **ロード済みモジュールの Merkle 完全性** — ホットパッチ DLL を最初のパケット前に検出
- **Sinkholing / マイクロ封じ込め** — 不審フローを kill せずローカル honeypot へ誘導
- **PCAP エクスポート** は上記スコープ内

## 🚫 対象外

意図的に、設計上：

- **テレメトリ、アナリティクス、アカウント、クラウド同期** — 決して。
- **ネットワーク全体のパッシブ IDS** — Snitch は*この*マシンを見る。ネットワーク全体ではない。
- **ユーザースペースのパケットフィルタ** — ブロックは OS ネイティブファイアウォール（または将来のカーネルコンポーネント）へ委譲。再実装しない。

## 🤝 貢献

入りやすい場所： `good first issue` ラベル、トラッカーリスト PR（`backend/classifier/lists/`）、翻訳（i18n 準備済み、1 言語 = 1 ファイル）、パッケージング（Linux .deb/.rpm）。[CONTRIBUTING.md](CONTRIBUTING.md) 参照。
