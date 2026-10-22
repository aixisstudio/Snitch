# Snitch — エンタープライズ統合

*Community translated — PRs welcome for refinement / コミュニティ翻訳 — 改善PR歓迎。*

**日本語:** Snitch を SOC スタックに組み込むためのステップバイステップ
ガイド — Wazuh、Splunk、Graylog/Loki、Ansible、Docker/Kubernetes。
すべて無料・セルフホストで、Snitch のローカルファースト方針と一致します。
Snitch 自身はテレメトリを一切送信しません。外部への接続は、ここで
設定するものだけです。

---

## 1. SIEM 出力

アラート転送用に3つのネイティブ形式を提供：

| 設定 | 値 | 効果 |
|---|---|---|
| `syslog_addr` | `host:514` または `tcp://host:514` | syslog 転送を有効化（UDP がデフォルト、`tcp://` プレフィックスで TCP） |
| `syslog_format` | `rfc3164` *（デフォルト）* | 古典的 BSD syslog — あらゆるコレクターで読める |
| | `cef` | `CEF:0|Snitch|…` — ArcSight/Wazuh/Splunk が `src`、`dst`、`dpt`、`cs1`（プロセス）を自動パース |
| `webhook_url` + `webhook_enabled` | URL | 汎用 JSON `POST`（Discord/Slack/Telegram のペイロードは自動検出） |
| `GET /forensics/export?format=…` | `json`、`csv`、`stix`、`ecs` | ワンショットのフォレンジックバンドル — `ecs` は Elastic Common Schema NDJSON を出力 |

UI（設定 → セキュリティ）または `snitch.toml` で設定：

```toml
syslog_addr = "siem.example.com:514"
syslog_format = "cef"
```

## 2. Wazuh

1. Wazuh マネージャーで syslog リスナーを有効化（`/var/ossec/etc/ossec.conf`）：

   ```xml
   <remote>
     <connection>syslog</connection>
     <port>514</port>
     <protocol>udp</protocol>
     <allowed-ips>your-agent-subnet</allowed-ips>
   </remote>
   ```

2. 各 Snitch エージェントを向ける — Ansible：

   ```yaml
   snitch_syslog_addr: "wazuh.example.com:514"
   snitch_syslog_format: "cef"
   ```

3. Wazuh の CEF デコーダーが `CEF:0|Snitch|…` を拾い、`severity` は
   syslog PRI にマップされます（critical→2、warning→4、info→6）。

## 3. Splunk

1. 設定 → データ入力 → UDP → 514 の新規入力、sourcetype `syslog`
   （`tcp://…` 送信側には TCP 入力）。
2. `syslog_format = "cef"` で `src`、`dst`、`dpt`、`cs1Label` が無料で
   使えます。ダッシュボードには scripted input で
   `GET /forensics/export?format=ecs` をポーリング — JSON は自動抽出。

## 4. Graylog / Loki

- **Graylog**: System → Inputs → Syslog UDP、514 にバインド。CEF 拡張
  フィールドはメッセージフィールドとして届きます。
- **Loki/Grafana**: `syslog_addr` を `promtail` の syslog ターゲットに
  向けるか、cron → Loki push ジョブで
  `/forensics/export?format=ecs` をスクレイプ。

## 5. 宣言的設定（Security-as-Code）

バックエンドは起動時に**1つのファイル**を適用します — `$SNITCH_CONFIG`、
なければデータディレクトリの `snitch.toml`/`snitch.json`。宣言された
キーは UI/DB の値を上書き — このファイルがフリートの真実の源です：

```toml
syslog_addr = "siem.example.com:514"
syslog_format = "cef"
kill_switch_enabled = true
ask_enabled = false          # headless サーバー
gossip_peers = ["sec-01:8000"]
ports = [80, 443]
```

完全な語彙は `packaging/snitch.toml.example` を参照。

## 6. Ansible / Puppet / Salt / GPO

- **Ansible** — `deploy/ansible/` に完成済みロール：

  ```bash
  ansible-playbook -i inventory deploy/ansible/site.yml
  ```

  `/opt/snitch`、venv、`/etc/snitch/snitch.toml`、強化 systemd ユニットを
  インストールし、`snitch.service` を有効化します。

- **Puppet / SaltStack** — `deploy/puppet/` と `deploy/salt/` に
  コミュニティ製スケルトン（`help wanted` ラベル）：同じ3つの
  プリミティブ — バックエンドツリー配置、`snitch.toml` レンダリング、
  `snitch.service` 管理。

- **Windows GPO** — `deploy/gpo/Install-Snitch.ps1` がサイレント
  インストールを実行（ProgramData 設定、venv、127.0.0.1 の SYSTEM
  タスク）。Windows の ask-on-connect には署名済み WFP コールアウトが
  さらに必要 — `docs/SIGNING.md` 参照。

## 7. Docker & Kubernetes

- **単一ホスト**: `docker compose up` — `network_mode: host` +
  `cap_add: NET_RAW/NET_ADMIN` は `docker-compose.yml` 設定済み。
- **フリートコンソール**: `deploy/helm/snitch` — `mode: collector` は
  設定済みエージェントの監査を `GET /remote/fleet` に集約する
  ClusterIP Deployment を起動；`mode: agent` は `NET_RAW`/`NET_ADMIN`
  付きのホストネットワーク DaemonSet をレンダリング。

  ```bash
  helm install snitch ./deploy/helm/snitch \
      --set token=$(openssl rand -hex 32) \
      --set config.gossip_peers='["agent-1:8000","agent-2:8000"]'
  ```

## 8. Sigma ルール

`POST /alerts/rules/sigma` は Sigma 検出 YAML を受け取り、サポート済み
サブセット（フィールド→値セレクション、`|contains`/`|startswith`/
`|endswith`/`|re`/`|cidr`/`|gt`/`|lt`/`|all`、`1 of`/`all of` 条件）を
Snitch カスタムルールにコンパイル — アラートのみ、非対応部分は
`skipped` に理由を返します。フィールドは*パケット*センサーが見えるものに
マッピング（`DestinationIp→remote_ip`、`Image→process_name`、
`Domain→host` など）。

Google SecOps/Chronicle 向け YARA-L：`GET /alerts/rules/yaral` が全
ルール（Sigma 由来を含む）を `.yar` ファイルとしてエクスポート —
Sigma→YARA-L パスはこれでカバー済み。

## 9. リモートエージェント（snitch-agent/1）

`agent/` には軽量 Rust デーモン（依存ゼロ、単一 ~1MB バイナリ）があり、
ホストのソケットテーブル（`/proc/net/*`）を監視し、新しいアウトバウンド
フローを `POST /ingest/events` にプッシュします。ソケットを観測する
だけ — ペイロード/SNI なし（それはローカルキャプチャの仕事）；
プロセス帰属は TODO マーク済み。トランスポートは HTTP + Bearer
（`gossip_peers` と同じトラストドメイン）。

## 10. 無料脅威インテリジェンスフィード

`POST /firewall/blocklist` は両方の形式をインポート：

- `kind: "domain"` — hosts/ドメインリスト（StevenBlack、EasyList…）→
  `domain` ファイアウォールルール；
- `kind: "ip"` — IP フィード（Blocklist.de、URLhaus/Feodo エクスポート）
  → `ip` ルール；プライベート/予約/ループバックは絶対にインポートしない。

`path:` はローカルファイルを読む（完全オフライン）；`url:` は明示的で
監査可能なオプトインフェッチ（レスポンスに `remote_fetch: true`）。
上限 `max_entries ≤ 5000` — 巨大フィードはリゾルバーの仕事。

オプトイン API プロバイダー（AbuseIPDB / OTX / VirusTotal）は
`ti_provider` + `ti_api_key` で利用可能 — キーを設定しない限り
何も送信しません。

## 11. ヘッドレス/デーモンモード

GUI はオプション：バックエンドが製品のすべて。直接起動
（`uvicorn api.main:app`）、同梱 systemd ユニット、またはコンテナ —
上記すべての機能がフロントエンドなしで動作します。
`SNITCH_DEMO=1` は研修や CTF 向けに root 不要の合成フィードを
提供し続けます。
