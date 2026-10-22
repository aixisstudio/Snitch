あなたのコンピュータは一日に何百ものサーバーと通信している。Linux での古典的な答えは `tcpdump`、`ss`、`netstat`、Wireshark — 強力だが、答えるのは「パケットを見せて」であって「誰と話していて、心配すべきか?」ではない。

その二番目の問いのために [Snitch](https://github.com/aixisstudio/Snitch) を作った — オープンソース（AGPL）のリアルタイムネットワークビジュアライザで、Linux では Docker かリリースバイナリで完全対応。完全な開示: 私は作者なので、既存の選択肢と Snitch の位置づけを正直に紹介する。

## Linux の状況

| ツール | できること | できないこと |
|---|---|---|
| **tcpdump / ss / netstat** | 生の接続データ | UI 無し、履歴無し、測位無し、アプリマッピング無し |
| **Wireshark** | 深いパケット解剖 | 「誰が phone-home してる?」には過剰 — 顕微鏡であってダッシュボードではない |
| **OpenSnitch** | アプリケーションファイアウォール（block/allow プロンプト） | 最小限の可視化 — block-first、Linux のみ |
| **iftop / nethogs / nload** | インターフェース別・プロセス別帯域 | 世界地図無し、異常検知無し、永続化無し |
| **Snitch** | 全接続のライブマップ: app → server → 国、異常検知、24 時間履歴、OS ファイアウォール経由のオプトインブロッキング | OS ルール適用は best-effort（権限必要）; 完全な対話型 FW ではない |

OpenSnitch と Snitch は競合ではなく補完関係: OpenSnitch は成熟した対話型アプリケーションファイアウォール、Snitch はマシンが*何を*しているかを見せる — そして v1.2 以降はルール（`ip`/`cidr`/`domain`/`process`/`port`）を `iptables` へプッシュし lockdown スイッチもある、best-effort で。

## Snitch が Linux で提供するもの

- **ライブ世界地図** — 全送信接続をプロセス帰属付きで: どのアプリが開いたか、IP だけでなく
- **オフライン測位** — ローカル MaxMind/DB-IP データベース経由、IP はマシンから出ない
- **異常検知**: LAN 内ポートスキャン、ビーコニング（定間隔コールバック、典型的 C2 パターン）、異常な送信量、DNS トンネリング、プロセス別ベースライン乖離
- **プライバシースコア** + 編集可能サフィックスリストによるトラッカー検出
- **アプリ別帯域**、タイムライン、24 時間 SQLite 保持、アラート抑制ルール
- **パッシブ LAN スキャン** — システム ARP テーブル経由、パケット注入ゼロで全デバイス表示
- **送信ファイアウォールルール＋lockdown** — IP、CIDR、ドメイン、プロセス、ポートを OS ファイアウォール（Linux は `iptables`）でブロック、プロセスの kill/suspend、フォレンジックバンドル（JSON/CSV/STIX）エクスポート
- **オプトイン脅威インテル** — AbuseIPDB / AlienVault OTX / VirusTotal を自分の API キーで評判照会
- UI とドキュメントは 8 言語（EN/FR/ES/DE/RU/JA/PT-BR/中文）

## プライバシーの部分

Linux ユーザーが最初に確認しがちな点なので: API は **127.0.0.1** にバインドしトークン必須。**テレメトリ無し、アカウント無し**、そして全ての外部呼び出し — GeoIP ダウンロード、更新チェック、脅威インテル、Webhook — は独立してオプトイン。トラフィックデータはあなたのローカル SQLite ファイルに住む。

## インストール

```bash
# Docker（パケットキャプチャには host networking が必要）
docker run --network host ghcr.io/aixisstudio/snitch

# またはリリース tarball — tcpdump 同様 root/cap_net_raw が必要
sudo ./snitch-backend
```

出力される URL を開く。キャプチャ権限を与える前に見たいなら、合成トラフィックを実パイプラインに流すデモモード（`SNITCH_DEMO=1`）もある。

## 中身（好奇心のある人向け）

純粋な Python + ctypes → libpcap でキャプチャ — Scapy 依存無し。IPv4/IPv6/TCP/UDP/DNS/TLS-SNI パースは手書きでパイプライン全体 ~2K 行。FastAPI + WebSocket バックエンド、React + D3 フロントエンド、デスクトップでは Electron シェル。

「夜中の 3 時に変な場所と話していないか?」という答えを Linux で、ファイアウォールを買わず一日中キャプチャもせずに得たいなら — まさにそのためのツール。[GitHub](https://github.com/aixisstudio/Snitch) で ⭐ いただければ。Discussions の「何を捕まえた？」スレッドでスクリーンショットもお待ちしている。
