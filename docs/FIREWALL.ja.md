# セキュリティ機能

[English](FIREWALL.md) | [Français](FIREWALL.md) | [Español](FIREWALL.es.md) | [Deutsch](FIREWALL.de.md) | [Русский](FIREWALL.ru.md) | **日本語** | [Português](FIREWALL.pt-BR.md) | [中文](FIREWALL.zh-CN.md)

Snitch は受動的観察の上にスレットハンティング層を載せています。
**何をするか — そして同じくらい重要な、何をしないか:**

## 送信ファイアウォール連携

Snitch はユーザースペースでパケットをフィルタ**しません**。ルールは
OS ネイティブファイアウォールへ best-effort で適用されます:

| OS | 仕組み |
|---|---|
| Windows | `netsh advfirewall` の送信ブロックルール |
| Linux | `iptables -A OUTPUT -j DROP`（lockdown 用に専用 `SNITCH_LOCK` チェーン） |
| macOS | 生成した `pf` アンカーを `pfctl` でロード |

ルール種別: `ip`、`cidr`、`domain`（適用時に一度だけ解決）、`process`、
`port`。ルールは `snitch.db` に永続化され起動時に再適用。

**正直な制限:**

- 適用にはキャプチャと同等の権限が必要。権限が無い場合、ルールに
  `applied=False` が記録され UI は「可視化のみ」と表示。マッチングは
  継続： ルール違反パケットはルール別カウンタ付きの
  `BLOCKED_ATTEMPT` アラートを発生。
- macOS の `pf` は*プロセス*をマッチできない — プロセスルールは
  設計上「可視化のみ」。
- `domain` ルールは名前を一度だけ解決；IP を変える CDN は再作成まで
  ルールを逃れる。
- **Lockdown** は*公開* IP への送信だけを切断 — loopback と LAN は
  維持され UI はアクセス可能。

## インシデント対応

- `POST /processes/kill` / `POST /processes/suspend` — PID 指定。PID ≤ 3
  と Snitch 自身は拒否。通常の OS 権限が適用。
- `POST /firewall/rules`、`DELETE /firewall/rules/{id}`、
  `POST /firewall/rules/{id}/toggle`、`POST /firewall/lockdown` —
  すべて認証必須。
- `GET /forensics/export?process=<名>&ip=<ip>` — 調査バンドル:
  プロセスツリー（最大 8 祖先）、実行ファイル SHA-256、cmdline、
  関連アラート、分単位履歴。`format=json|csv|stix` で出力選択
  （STIX = SIEM 取込み用の最小 2.1 bundle）。ローカルデータのみ；
  エクスポートはダウンロードでありアップロードではない。

## Threat intelligence — オプトイン、デフォルト OFF

*設定 → Threat intelligence* はプロバイダ（`abuseipdb`、`otx`、
`virustotal`）＋**自分の API キー**を受け付ける。有効時、新規公開 IP
は 24 時間 TTL ごとに 1 回照会；判定はキャッシュされ、
`suspicious`/`malicious` で `THREAT_HIT` が発火。プロバイダ・キー
なしなら**外向き呼び出しゼロ**。`GET /security/ti` はマスク済み設定を
返し、`POST /security/threat_check` は手動照会（こちらもキャッシュ
考慮）。

## Webhook — オプトイン、デフォルト OFF

*設定 → 外部 Webhook* に URL とスイッチ。warning と critical アラートを
ライブ POST: Discord/Slack `{content}`、Telegram `{chat_id, text}`
（telegram URL 使用時は chat ID 欄を表示）、その他は
`{alert, source, text}`。失敗はログのみ、致命ではない。

## 検知の追加

- `DNS_TUNNEL` — 異常に長い DNS 名/ラベル（>60 文字 / ラベル >40）、
  古典的な流出パターン；ホストごと 10 分に 1 回。
- `CLEARTEXT` — 本質的に非暗号のポートへの送信 TCP
  （80, 21, 23, 25, 110, 143…）、INFO レベル、監査の入力。
- `BASELINE_DEVIATION` — 各プロセスは最初のパケット群で通常の行き先国を
  学習し、その後新しい国へ一度だけ警告。ベースラインは永続化
  （`app_baselines`）。
- `BEACON` — 既存機能： 微小トラフィックでも働く定期間隔検知
  （到着間隔の変動係数）。
- `BLOCKED_ATTEMPT`、`LOCKDOWN`、`THREAT_HIT` — 上記モジュールが追加した
  アラート種別。

## セキュリティ監査

`GET /security/audit` は直近 500 件のアラートとライブグラフから
0–100 のスコアを算出: 種別カウント、高リスク国との接触、未解決
ホスト、ファイアウォール姿勢 — 平易な言葉の推奨付き。*検出レポート*
であり、認定ではありません。
