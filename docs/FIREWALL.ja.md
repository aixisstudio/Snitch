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

### v1.2 の新機能 / Nouveautés v1.2

- **`sinkhole` アクション** — `domain`/`ip` ルールはブロックの代わりに loopback へリダイレクト可能：ドメインは hosts ファイル内の `# snitch-sinkhole` マーカー付きブロックで（全 OS）、IP/CIDR は iptables `DNAT` で（Linux のみ）。`process`/`port` への `sinkhole` は拒否、非対応 OS では正直に `applied=False`。
- **ドメイン再解決** — `domain` ルールは約10分ごとに再解決され、IP 差分が OS ごとに適用されるため、CDN ローテーションで名前のブロックが外れません。
- **整合性監視**（デフォルト有効・読み取り専用・ローカル） — ネットワーク使用実行ファイルの SHA-256 ベースライン（`BINARY_CHANGED`）、名前/exe 不一致（`NAME_MISMATCH`）、Linux のみ `rwxp` スキャン（`MEM_RWX`、既知 JIT アプリは info レベル）。`GET /security/integrity`、`POST /security/integrity/check`。
- **アラート説明** — `GET /security/explain?type=X` が手書きの二言語（EN/FR）説明を返します；決定的でオフライン動作 — モデルではありません。UI の「なぜ？」ボタンから表示。

### オプションのプローブ (v1.3)

すべて **デフォルトで無効または自己制限** で、正直に劣化し、マシン外へデータを送りません：

- **eBPF connect プローブ**（Linux、`ebpf_probe`）— `tcpconnect` 型の BCC kprobe が、ソケットテーブルが取り逃がす短命プロセスの `connect()` を帰属。`python3-bcc` + root が必要。曖昧な宛先は推測しません。`GET /security/ebpf`。
- **Frida インスペクション** — `POST /security/deep_inspect {pid,seconds}` は1つの pid に ≤60 秒アタッチし、各 `connect()` を発行したロード済みモジュールを報告。staging パス → `INJECT_SUSPECT`。
- **シンクホールレスポンダ** — `sinkhole` ルール有効中、:80/:443 の loopback リスナーが各試行を `SINKHOLE_HIT`（Host/URI または SNI + プロセス）に変換。
- **モジュール整合性** — 実行可能マッピングの Merkle ルート → `MODULE_CHANGED`；`/tmp`/memfd のパス → `MODULE_SUSPECT`。
- **マイニング検知** — payload ヘッド内の stratum JSON → `MINING_STRATUM`；プールポート + 持続的高 CPU → `MINING_SUSPECT`。
- **ハードウェアカウンタ** — `POST /security/perf` が `perf_event_open` でサイクル/命令数をサンプル (Linux)。
- **ローカル LLM** — opt-in（`slm_enabled`）：`/security/explain` は Ollama 互換エンドポイントを **loopback のみ** 呼び出し — リモートは拒否。
- **IOC パック** — `GET /security/iocpack` が Bloom + randomized response でエクスポート（平文なし）；`POST /security/iocpack/import` が宛先を確率的に照合。

### ポリシー＆レスポンスの追加 (v1.4)

- **名前付きプロファイル** — `POST /firewall/profile`: `permissive`（初期化）、`balanced`（控えめな送信ベースライン）、`strict`（ベースライン＋ロックダウン）。通常ルールに展開・重複排除。
- **カスタムアラートルール** — `GET/POST/DELETE /alerts/rules`: フィールド＋演算子＋値 → `CUSTOM_RULE` アラート（通知のみ、ブロックなし）。
- **ブロックリストのインポート** — `POST /firewall/blocklist`: ローカルファイル（完全ローカル）またはオプトイン URL（≤4 MiB HTTPS、`remote_fetch` と明記）→ `domain` ルール。重複排除・上限 500–5000。
- **PCAP エクスポート** — `GET /forensics/pcap`（`ip`/`process` フィルタ）: ~4 MiB リングバッファを Wireshark 用 `.pcap` で。
- **リモートペアリング** — `POST /remote/pairing` が `lan_bind` を永続化（次回起動時適用）；トークンは引き続き必須。`GET /remote/pairing` が bind と LAN IP を報告。
- **ネットワーク遮断サンドボックス** — `POST /security/sandbox` がバイナリを送信ゼロで実行（Linux `unshare -n`、macOS `sandbox-exec`；手動版 `contrib/snitch-contain`）。
- **埋め込みモデル** — `slm_mode=embedded` がユーザーの `.gguf` を `llama-cpp-python` で読込 — ネットワーク一切なし。
- **ネイティブスケルトン** — `contrib/wfp-callout/`（C の WFP callout＋署名メモ）と `contrib/macos-filter/`（`NEFilterDataProvider` Swift＋entitlement メモ）：研究用スキャフォールド、出荷なし。
- **ASN** — `GeoLite2-ASN.mmdb`/`dbip-asn-lite.mmdb` がある場合、ノードに `org` に加え `asn` を付与。

## v1.5 — パッシブ検査、カーネル判定、フリート同期

- **パッシブTLS証明書インスペクション** — 制限付きTCP再構成（≤16 KiB/フロー、TTL 30秒）で `Certificate` メッセージを読み取り：発行者/サブジェクト CN+O、自己署名、SAN、有効期限、`san_mismatch` → `TLS_CERT`。**TLS 1.3は不透明のまま** — 推測せず観測不可と正直に報告。
- **高エントロピー監視** — 非TLSチャネルで ≥48 B・≥4.7ビット/バイトのペイロード → `HIGH_ENTROPY`；ホスト毎10分クールダウン。
- **ICMPトンネル検知** — ≥24 Bペイロードのエコーが5分で3回以上 → `ICMP_TUNNEL`。
- **MLフロー異常** — 純Pythonのisolation forest（64本、依存ゼロ）が自フロー要約をスコアリング；384フロー未満では不活性、0.62で `ML_ANOMALY`。ベースライン偏差でありマルウェア分類器では**ありません**。
- **Ask-on-Connect（Linux、オプトイン）** — `ask_enabled` + root + `python-netfilterqueue`：新規送信フローをNFQUEUE 7に `POST /security/ask/verdict` まで保留；タイムアウト15秒、fail-closed（`ask_failopen=1`で反転）。Windows/macOSは `contrib/` の署名済みcallout/NetworkExtensionが必要。
- **eBPF cgroupエンフォースメント（Linux、オプトイン）** — `POST /security/ebpf/isolate {pid}` + `/security/ebpf/block {ip}`：snitch cgroupへattach — カーネルdropは隔離プロセスのみ。
- **ハロウィングチェック（Linux）** — `POST /security/hollow {pid}` が `/proc/<pid>/mem` のfile-backed実行可能ページをディスクと比較。
- **IOCピア同期（オプトイン）** — `gossip_peers` ≤32 + `gossip_enabled`：Merkleプルーフパックを5分毎に認証HTTP(S)で — 探索なし、ZKプロトコルではありません。
- **Syslog（オプトイン）** — `syslog_addr`（`host:port` UDPまたは `tcp://`）→ RFC 3164 `local4`。
- **Firejailコンテインメント** — `firejail --net=none` 優先、`unshare` にフォールバック。
- **nftablesバックエンド** — `nft` があれば専用 `inet snitch` テーブル（iptablesの代わり）。
- **アクション可能アラート** — 構造化 `actions`（IPブロック、終了/一時停止、ask判定）をワンクリックボタンとして表示。
- **カスタムルールの `asn`/`country`** — ローカルgeo DB、`action=block` と組み合わせてgeoフェンスに。
