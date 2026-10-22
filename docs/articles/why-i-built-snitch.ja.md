三週間前、バカみたいに単純な質問に答えたくなった: **自分のコンピュータは誰と話しているのか?**

「パケットをキャプチャできるか」ではなく（Wireshark ならできる — でも欲しかったのは顕微鏡ではなくフロントガラス）。「接続をブロックしたい」でもなく（macOS の Little Snitch が $59 でやるが、Windows には同等品が無かった）。ただ: ライブで視覚的な答え。どのアプリが、どのサーバーと、どの国と — 今まさに。

そこで [Snitch](https://github.com/aixisstudio/Snitch) を作った。オープンソース、AGPL、8 言語の UI、三週間で ~400 スター。学んだこと — そして見知らぬ人々が Windows 移植を書いてくれた話。

## ビルド

自ら課した制約: **重い依存無し、テレメトリ無し、絶対に。**

- キャプチャ: macOS/Linux は `ctypes → libpcap`、Windows は Npcap。Scapy 無し — 直接バインディングの方が軽くフィールドを正確に制御できる。
- パース: 手書きの IPv4/IPv6/TCP/UDP/DNS/TLS-SNI デコーダ。パイプライン全体で ~2K 行。
- バックエンド: FastAPI + WebSockets + SQLite リングバッファ（保持 24 時間、その後自己削除 — プライバシーとは溜め込ま*ない*ことでもある）。
- フロントエンド: React + D3 フォースグラフ + TopoJSON 世界地図。
- ジオロケーション: ローカル MaxMind/DB-IP ファイル。IP はマシンから出ない。

機能としてのセキュリティ: API は loopback のみ、トークン認証、外部呼び出しは全てオプトイン — GeoIP ダウンロード、更新チェック、脅威インテル、Webhook は全てデフォルト無効。プライバシーツールにとってコード*こそが*約束 — AGPL はそれを監査可能にする。

## 計画していなかったこと

まず macOS 版を出し、リポジトリに Windows 向け「help wanted」タグを付けた。数日以内に:

- ユーザーが**根本原因分析付き**のバグ報告を提出 — 「動かない」ではなく、本物のスタックトレースと特定済みの不良キャプチャパス
- 話したこともない見知らぬ人が PR を 3 本: Npcap キャプチャ、NIC 選択、起動クラッシュ
- 別の誰かが [winget パッケージ PR](https://github.com/microsoft/winget-pkgs/pull/455520) をオープン

先週出た v1.0.5 で Windows 移植が完全動作。このプロジェクトが見つけた最強の流通チャネルはマーケティングの技ではなく、「本物の問題を公開すれば、同じ問題を持つ人が現れる」だった。

## トラフィックデータが語ったこと

面白いメタな瞬間: Snitch 自身のリファラルが物語を語った。中国の tech ニュースレター（ruanyifeng.com）がプロジェクトを紹介 — 突如 ~20% のトラフィックが英語 README を見る中国の読者に。今では完全な [README 中文](https://github.com/aixisstudio/Snitch/blob/main/README.zh-CN.md) があり、合計 8 言語の翻訳がある。データが決める; 私は聞くだけ。

## dev tools を作る人へ伝えたいこと

1. **感じられる問題を解け。**「自分のマシンは誰と話しているか」は本能的 — 誰もが思い、誰も見えない。
2. **local-first は今や差別化要因。**「アカウント無し、テレメトリ無し」は制限ではなく売り文句。
3. **多言語ドキュメントは慈善ではない** — 競合ゼロの読者への流通経路。
4. **Issues と Discussions はコンバートする。**速い回答がバグ報告者をコントリビュータに変えた。私の Windows 移植はそう生まれた。

## 試してみる

```bash
docker run --network host ghcr.io/aixisstudio/snitch   # Linux
# macOS/Windows: releases ページ — SNITCH_DEMO=1 で管理者権限無しに実行可
```

Repo: https://github.com/aixisstudio/Snitch — AGPL、UI とドキュメントは EN/FR/ES/DE/RU/JA/PT-BR/中文、v1.2 で最も要望の多かった機能: OS ファイアウォール経由の送信ブロック、オプトイン脅威インテル、ワンクリックフォレンジックエクスポートを追加。[「何を捕まえた？」スレッド](https://github.com/aixisstudio/Snitch/discussions/39)は開いている。⭐ は本当に助けになる — 値するなら。
