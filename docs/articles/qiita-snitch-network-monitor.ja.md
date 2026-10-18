---
title: コンピュータが実際に誰と通信しているか丸見えにする — Snitch、完全ローカルのOSSネットワークモニター
tags: Python, Security, 個人開発, opensource, privacy
platform: qiita
url: https://qiita.com/aixis/items/f7686017adaa0b8be861
---

あなたのコンピュータは毎日何百ものサーバーと通信しています。ほとんどは正常ですが、「自分のマシンが実際に誰と話しているのか」を見るのは意外と難しいものです。

私は **Snitch** というオープンソース(AGPL)のリアルタイム・ネットワークモニターを作りました — macOS / Windows / Linux 対応で、完全ローカル動作(アカウント不要・テレメトリなし)。

## Snitch とは

一言でいうと:**コンピュータが行うすべての接続を世界地図上にリアルタイムで可視化**します。

- どのアプリが → どのサーバーに → どの国に接続しているか
- オフラインIPジオロケーション(MaxMind/DB-IPローカルDB — IPは外部に送信されません)
- プロセスごとの帯域表示・接続履歴(ローカルSQLite、24時間保持)
- 異常検知:ポートスキャン、ビーコニング(一定間隔のコールバック=典型的なC2パターン)、大量送信
- プライバシースコア + 編集可能なトラッカーリスト
- LAN内デバイスの受動スキャン(システムARPテーブル使用 — パケット注入なし)
- 英語/フランス語UI + 中国語README

## プライバシー設計

- APIは `127.0.0.1` のみバインド + トークン認証
- 外部への送信はゼロ(GeoIP DBダウンロードのみ明示的な同意が必要)
- AGPL — すべてのネットワークコードは監査可能

## 技術構成

- パケットキャプチャ:`ctypes → libpcap`(macOS/Linux)/ Npcap(Windows)— Scapy不使用
- IPv4/IPv6/TCP/UDP/DNS/TLS-SNIパーサーを独自実装(パイプライン全体で約2000行)
- バックエンド:FastAPI + WebSockets
- フロントエンド:React + D3(フォースグラフ + TopoJSON地図)

## インストール

```bash
# Linux (Docker)
docker run --network host ghcr.io/aixisstudio/Snitch

# Windows: Npcapをインストール → snitch-backend.exe を管理者として実行
# macOS: リリースのアプリまたは brew
# 管理者権限なしで試すデモモード:
SNITCH_DEMO=1 snitch-backend
```

## 面白い話:Windowsポートは他人が作った

私は一人でメンテナンスしていますが、Windowsポートはコミュニティが作りました — ユーザーが根本原因分析つきのバグレポートを出し、見知らぬ人が3つのPRで修正しました。オープンソースの良いところです。

**リポジトリ:** https://github.com/aixisstudio/Snitch

注意:Snitchは「見せる」ツールで、ブロック(ファイアウォール)機能はありません。ブロックが必要ならOpenSnitch(Linux)やPortmasterと併用してください。

フィードバック・バグレポート歓迎です ⭐
