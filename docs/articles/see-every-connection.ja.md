あなたのコンピュータは今この瞬間もインターネットと話している。おそらく何十もの接続 — 同期、テレメトリ、更新チェック、開いているタブ、アプリのバックグラウンド通信。「自分のマシンは実際何をしているのか?」という問いは基本的に聞こえるが、答えようとすると、ツールは顕微鏡的（Wireshark）か paywall だらけだ。

ここに実際に見るための実践ガイド — そのために作ったツール [Snitch](https://github.com/aixisstudio/Snitch)（オープンソース、AGPL — 開示: 私の作）を含む。

## 60 秒バージョン

```bash
# macOS / Linux — 古典だが生
sudo tcpdump -i any -n | head -50        # 全パケット、文脈なし
netstat -anp tcp | grep ESTABLISHED      # 現在の接続のみ
lsof -i -nP | head                       # プロセス → ソケット対応

# Windows
netstat -ano | findstr ESTABLISHED
Get-NetTCPConnection -State Established  # PowerShell
```

これらは「今どんな接続があるか」に答える。だがどのアプリか、サーバーはどこか、不審かは教えてくれない。その隙間を埋めるのがビジュアライザだ。

## 可視化アプローチ

Snitch は全接続をライブグラフ＋世界地図として描画:

- **ノード = あなたのマシン**が中心、各リモートエンドポイントへの線
- **各エンドポイントにラベル**: ホスト名（逆引き DNS＋TLS SNI 経由）、測位された国/都市 — 全てオフライン、ローカル MaxMind/DB-IP から
- **アプリ別帰属**: 接続は開いた*プロセス*へ描かれる
- **タイムライン**: 15/30/60 分のトラフィック量、ローカル SQLite に 24 時間の履歴

tcpdump と違うのは、データが*既に処理済み*なこと。「142.250.74.78 へのパケット」ではなく「Chrome → google.com → フランクフルト」。

## マップの読み方: 正常 vs 不審

正常なマップの様子: Apple/Google/Microsoft/タブの CDN へのスポーク、ルーター、他の LAN デバイス。

目立つもの:

- **ビーコニング** — 定間隔で発火する接続（Snitch がフラグ; 典型的 C2 パターン）
- **見知らぬエンドポイントへの長期アップロード** — 認識しない場所へデータが出続ける
- **ポートスキャン** — あなたのマシンの多くのポートに触れる LAN ホストはフラグされる
- **アプリの役割に合わない国**と話すアプリ
- **トラッカー** — Snitch はホスト名を編集可能なトラッカーサフィックスリストと照合し、プライバシースコアに反映
- **DNS トンネリング** — 異常に長い名前や不自然な頻度の DNS クエリ

内蔵の**異常検知**がこれら全てを自動で監視し、検証済みのパターンはルール毎にアラート抑制できる。

## インストール（2 分）

```bash
# macOS: releases からアプリを、または brew
# Windows: Npcap インストール → snitch-backend.exe を管理者実行
# Linux / Docker:
docker run --network host ghcr.io/aixisstudio/snitch

# 管理者権限なし? デモモードが合成トラフィックで全 UI を表示:
SNITCH_DEMO=1 snitch-backend
```

全てローカル — loopback のトークン認証 API、テレメトリゼロ、アカウント無し、そして全ての外部呼び出し（GeoIP、更新、脅威インテル、Webhook）はオプトイン。マーケティング文句ではない; AGPL のコードベースで、ネットワーク経路を自分で検証できる。

そして何かおかしければ行動できる — v1.2 から Snitch はブロックルールを OS ネイティブファイアウォール（netsh / iptables / pf）にプッシュし、ワンクリック lockdown、kill/suspend ボタン、捕まえたもののフォレンジック出力（JSON/CSV/STIX）を備える。

## それから?

トラフィックが*見える*ようになると面白いことが始まる — コミュニティの定番は[「何を捕まえた?」スレッド](https://github.com/aixisstudio/Snitch/discussions/39): 深夜 3 時にクラウドサーバーと話すプリンタ、TV テレメトリ、などなど。

Repo: https://github.com/aixisstudio/Snitch — 掲げた問いに答えたなら ⭐ を。
