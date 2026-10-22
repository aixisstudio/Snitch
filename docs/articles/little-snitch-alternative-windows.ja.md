---
title: "Windows 向け無料オープンソース Little Snitch 代替（本当に存在する）"
description: "Little Snitch は macOS 専用。Windows や Linux で自分の PC がどのサーバーと話しているか見たい人向けに、実際の代替案を正直に比較する。"
tags: [opensource, privacy, windows, networking]
canonical_url: https://aixisstudio.github.io/Snitch/
---

あなたのコンピュータは毎日何百ものサーバーと通信している。大半は問題ない — 更新、同期、同意したテレメトリ。一部は違う。「自分のマシンは実際誰と話しているのか?」という問いこそ、Little Snitch が 15 年間 macOS の定番であり続ける理由だ。

問題は: **Little Snitch は Windows や Linux に存在しない。** そして Windows の「代替」の多くは有料か、アカウント必須か、可視化だけ欲しいのに firewall-first だ。

私は [Snitch](https://github.com/aixisstudio/Snitch) の作者 — Windows 移植を持つオープンソース（AGPL）リアルタイムネットワークビジュアライザ — なので最初に完全開示しておく。以下が選択肢の正直な現状だ。

## まず: ビジュアライザ vs ブロッカー

混同されがちなので正確に:

- **可視化** =「マシンが誰と話しているか見せて」（マップ、アプリ別帰属、履歴）
- **ブロッキング** =「許可を自分で決めたい」（ファイアウォールルール、プロンプト）

Little Snitch は両方やる。代替品の中には片方しかないものもある。Snitch は今や両方 — 可視化が強みで、ブロッキングは OS ファイアウォールを連携する。

## 正直な比較

| ツール | OS | ブロック? | 無料? | アカウント? | 備考 |
|---|---|---|---|---|---|
| **Little Snitch** | macOS | ✅ | 有料（~$59） | 不要 | リファレンス。macOS 以外に同等なし。 |
| **Snitch** | macOS、Windows、Linux | ✅ OS-FW ルール＋lockdown（best-effort） | ✅ AGPL | 不要 | ライブ世界地図、異常検知、プライバシースコア、オプトイン脅威インテル、フォレンジック出力。100% ローカル。 |
| **Portmaster** | Win、Linux、macOS | ✅ | ✅ コア無料 | 不要 | DNS レベルブロッキング＋アプリルール。重め — システムサービスとして動作。 |
| **OpenSnitch** | Linux | ✅ | ✅ GPL | 不要 | 最も近い Linux 相当品 — プロンプト型アプリケーションファイアウォール。 |
| **GlassWire** | Windows、Android | ✅ | freemium | アカウント/クラウド推奨 | 洗練された UI だが、主要機能＋履歴は paywall、クラウドティアを推してくる。 |
| **Wireshark** | 全 OS | ❌ | ✅ | 不要 | *深い*パケット解析の金標準 — ただしパケット解剖用で「今誰が phone-home してる?」向けではない。 |
| **LuLu** | macOS | ✅ | ✅ | 不要 | 優れた無料 macOS ファイアウォール — ただし macOS のみ、block-first で可視化最小。 |

## Snitch が実際にやること

一文で: **あなたのコンピュータが張る全接続のライブマップ — どのアプリ、どのサーバー、どの国。**

- フォースグラフ＋世界地図のリアルタイム表示、オフライン測位（MaxMind/DB-IP — IP はマシンから出ない）
- プロセス帰属: 接続を開いたのはどの*アプリ*か、IP だけでなく
- 異常検知: ポートスキャン、ビーコニングパターン、流出ボリューム、DNS トンネリング
- プライバシースコア＋編集可能リストのトラッカー検出
- アプリ別トラフィック、タイムライン（15/30/60 分）、24 時間 SQLite 履歴
- パッシブ LAN スキャナ（ARP テーブル読み取り — ネットワーク上の全デバイス表示）
- **送信ルール＋lockdown**: OS ファイアウォールで IP/CIDR/ドメイン/プロセス/ポートをブロック（Windows は `netsh advfirewall`）、プロセス kill/suspend、JSON/CSV/STIX フォレンジック出力
- **オプトイン脅威インテル**: AbuseIPDB / OTX / VirusTotal を自分の API キーで

プライバシー重視の人に大事な点: **全てローカル。** アカウント無し、テレメトリ無し、そして全ての外部呼び出し — GeoIP、更新、脅威インテル、Webhook — はオプトイン。API はトークン認証でデフォルト loopback バインド。

## Snitch がやらないこと

HN/Reddit がどうせ聞くので正直に:

- **ブロッキングはドライバではなく連携。** v1.2 から Snitch は `ip`/`cidr`/`domain`/`process`/`port` ルールを OS ネイティブファイアウォール（Windows は `netsh advfirewall`、Linux は `iptables`、macOS は `pf`）にプッシュし lockdown スイッチもある — best-effort: 実際の適用にはキャプチャと同じ権限が必要で、`pf` はプロセスをマッチできない。適用失敗時は UI が正直に伝える。成熟した対話型アプリ FW なら Portmaster（macOS なら Little Snitch）が依然リファレンス。
- **admin/root が必要** — パケットキャプチャのため（不可避、Wireshark と同じ）。
- **深いパケット解剖** — それには Wireshark が依然優位。Snitch は 1 万フィートの眺め。

## Windows でのインストール

1. [Npcap](https://npcap.com) をインストール（Windows パケットキャプチャドライバ — 必須、Wireshark と同じ依存）
2. [最新リリース](https://github.com/aixisstudio/Snitch/releases)から `Snitch Setup <version>.exe` — トレイ付きネイティブ Electron アプリ — または Lite バックエンドのみインストーラを取得
3. 管理者として実行（インストーラがバックエンド起動時の UAC プロンプトを処理）
4. UI は自動で開く — Electron ウィンドウ、または Lite ならブラウザ

Linux: `docker run --network host ghcr.io/aixisstudio/snitch` — またはリリース tarball。macOS: パッケージ版アプリまたは `brew`。

## Windows 移植がどう生まれたか

プロジェクトは一人でメンテしている。Windows 移植は私ではない — ユーザーが根本原因分析付きのバグ報告を出し、見知らぬ人がキャプチャ＋正しい NIC＋起動クラッシュを直す PR を 3 本送った。宣伝通りのオープンソース。v1.0.5 は先週リリース。

試して面白いものを捕まえたら、リポジトリに[「何を捕まえた?」Discussion](https://github.com/aixisstudio/Snitch/discussions/39) がある。役に立ったなら [GitHub](https://github.com/aixisstudio/Snitch) の ⭐ がプロジェクトの発見に本当に効く。

**Repo:** https://github.com/aixisstudio/Snitch — AGPL、UI とドキュメントは 8 言語（EN/FR/ES/DE/RU/JA/PT-BR/中文）。
