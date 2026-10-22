# ローンチ用下書き — 全てコピペ可能

[English](drafts-launch.md) | [Français](drafts-launch.md) | [Español](drafts-launch.es.md) | [Deutsch](drafts-launch.de.md) | [Русский](drafts-launch.ru.md) | **日本語** | [Português](drafts-launch.pt-BR.md) | [中文](drafts-launch.zh-CN.md)

> **注:** 貼り付ける本文は英語のまま — HN と Reddit は英語プラットフォームのため。完全な正典 EN/FR 版は `drafts-launch.md` に。ここでは運用サマリ。

## Show HN —「バズ」パッケージ

**タイミング: 火曜 14:30-15:00 パリ時間**（= ニューヨーク 8:30-9:00、平日火曜は週最高のスロット）。それ以前は NG: US のフロントページが活発でなければ。

**URL:** `https://github.com/aixisstudio/Snitch`

### タイトル — 案 A（データフック、推奨）

`Show HN: Snitch – my Mac talked to 347 servers in one idle hour, so I built this`

### タイトル — 案 B（ストーリーフック、A 使用済みの場合）

`Show HN: I open-sourced a network monitor — strangers shipped the Windows port`

### 著者のファーストコメント — 投稿後 60 秒以内に

`drafts-launch.md` の完全な著者コメントを使用 — スタック詳細: ctypes→libpcap、psutil 帰属、.mmdb オフライン、FastAPI 127.0.0.1＋トークン、`SNITCH_DEMO=1`、コミュニティ製 Windows 移植の物語。

## Reddit — 同日に r/privacy + r/selfhosted

**タイトル:** `Snitch — open-source app that shows every connection your PC makes (world map + process names, 100% local)`

**本文:** `drafts-launch.md` 参照 — 正直さ優先（「 I'm the author 」）、機能箇条書き、管理者無しデモ、リポリンク。sub が許せばマップのスクショも。

## r/netsec — 週次 Show スレッド

技術アングル: Scapy 無しの ctypes→libpcap パイプライン、手書き ~2K 行パーサ、psutil 帰属、ビーコニング/DNS トンネル検知、OS ファイアウォール連携。SOC/アナリスト調で、マーケ調は避ける。

## 準備済み回答（防御的 FAQ）

完全な回答は `drafts-launch.md` に: 「GlassWire/Portmaster/OpenSnitch は?」「なぜ Rust ではなく Python?」「キャプチャに root 必要?」「外部呼び出しは?」（全てオプトイン: GeoIP、更新、TI、Webhook）、「コード署名は?」（SignPath 申請中＋ハッシュ公開）。
