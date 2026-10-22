# Snitch — 企业集成

*Community translated — PRs welcome for refinement / 社区翻译 — 欢迎提交改进 PR。*

**中文：** 将 Snitch 接入 SOC 技术栈的分步指南 — Wazuh、Splunk、
Graylog/Loki、Ansible、Docker/Kubernetes — 全部免费且自托管，
符合 Snitch 的本地优先原则。Snitch 自身不发送任何遥测数据；
唯一的出站连接就是您在此处配置的连接。

---

## 1. SIEM 输出

Snitch 为告警转发提供三种原生格式：

| 设置 | 取值 | 效果 |
|---|---|---|
| `syslog_addr` | `host:514` 或 `tcp://host:514` | 启用 syslog 转发（默认 UDP，`tcp://` 前缀使用 TCP） |
| `syslog_format` | `rfc3164` *（默认）* | 经典 BSD syslog — 任何采集器均可读取 |
| | `cef` | `CEF:0|Snitch|…` — ArcSight/Wazuh/Splunk 自动解析 `src`、`dst`、`dpt`、`cs1`（进程） |
| `webhook_url` + `webhook_enabled` | URL | 通用 JSON `POST`（自动识别 Discord/Slack/Telegram 负载） |
| `GET /forensics/export?format=…` | `json`、`csv`、`stix`、`ecs` | 一次性取证包 — `ecs` 输出 Elastic Common Schema NDJSON |

在 UI（设置 → 安全）或 `snitch.toml` 中配置：

```toml
syslog_addr = "siem.example.com:514"
syslog_format = "cef"
```

## 2. Wazuh

1. 在 Wazuh 管理器上启用 syslog 监听器（`/var/ossec/etc/ossec.conf`）：

   ```xml
   <remote>
     <connection>syslog</connection>
     <port>514</port>
     <protocol>udp</protocol>
     <allowed-ips>your-agent-subnet</allowed-ips>
   </remote>
   ```

2. 将每个 Snitch 代理指向它 — Ansible：

   ```yaml
   snitch_syslog_addr: "wazuh.example.com:514"
   snitch_syslog_format: "cef"
   ```

3. Wazuh 的 CEF 解码器会接收 `CEF:0|Snitch|…` 消息；`severity`
   映射到 syslog PRI（critical→2、warning→4、info→6）。

## 3. Splunk

1. 设置 → 数据输入 → UDP → 在 514 上新建输入，sourcetype 为
   `syslog`（`tcp://…` 发送方用 TCP 输入）。
2. `syslog_format = "cef"` 免费提供 `src`、`dst`、`dpt`、`cs1Label`
   字段；仪表盘可通过 scripted input 定时拉取
   `GET /forensics/export?format=ecs` — JSON 自动提取。

## 4. Graylog / Loki

- **Graylog**：System → Inputs → Syslog UDP，绑定 514。CEF 扩展字段
  会作为消息字段到达。
- **Loki/Grafana**：将 `syslog_addr` 指向 `promtail` 的 syslog target，
  或用 cron → Loki push 任务抓取 `/forensics/export?format=ecs`。

## 5. 声明式配置（Security-as-Code）

后端启动时应用**一个文件** — `$SNITCH_CONFIG`，否则为数据目录中的
`snitch.toml`/`snitch.json`。声明的每个键都会覆盖 UI/DB 值 ——
该文件是整个集群的单一事实来源：

```toml
syslog_addr = "siem.example.com:514"
syslog_format = "cef"
kill_switch_enabled = true
ask_enabled = false          # 无头服务器
gossip_peers = ["sec-01:8000"]
ports = [80, 443]
```

完整词汇见 `packaging/snitch.toml.example`。

## 6. Ansible / Puppet / Salt / GPO

- **Ansible** — `deploy/ansible/` 中现成的 role：

  ```bash
  ansible-playbook -i inventory deploy/ansible/site.yml
  ```

  安装 `/opt/snitch`、venv、`/etc/snitch/snitch.toml` 和加固的
  systemd 单元，然后启用 `snitch.service`。

- **Puppet / SaltStack** — `deploy/puppet/` 与 `deploy/salt/` 中的
  社区骨架（`help wanted` 标签）：同样三个原语 —— 部署 backend
  目录树、渲染 `snitch.toml`、管理 `snitch.service`。

- **Windows GPO** — `deploy/gpo/Install-Snitch.ps1` 执行静默安装
  （ProgramData 配置、venv、127.0.0.1 上的 SYSTEM 计划任务）。
  Windows 上的 ask-on-connect 还需要已签名的 WFP callout —
  见 `docs/SIGNING.md`。

## 7. Docker 与 Kubernetes

- **单主机**：`docker compose up` — `network_mode: host` +
  `cap_add: NET_RAW/NET_ADMIN` 已在 `docker-compose.yml` 中配置。
- **集群控制台**：`deploy/helm/snitch` — `mode: collector` 运行
  ClusterIP Deployment，将所有已配置代理的审计合并到
  `GET /remote/fleet`；`mode: agent` 渲染带 `NET_RAW`/`NET_ADMIN`
  的 host-network DaemonSet。

  ```bash
  helm install snitch ./deploy/helm/snitch \
      --set token=$(openssl rand -hex 32) \
      --set config.gossip_peers='["agent-1:8000","agent-2:8000"]'
  ```

## 8. Sigma 规则

`POST /alerts/rules/sigma` 接受 Sigma 检测 YAML，将支持的子集
（字段→值选择、`|contains`/`|startswith`/`|endswith`/`|re`/`|cidr`/
`|gt`/`|lt`/`|all`、`1 of`/`all of` 条件）编译为 Snitch 自定义规则 ——
仅告警，超出子集的内容会在 `skipped` 中返回原因。字段映射到
*数据包*传感器实际可见的内容（`DestinationIp→remote_ip`、
`Image→process_name`、`Domain→host` 等）。

面向 Google SecOps/Chronicle 的 YARA-L：`GET /alerts/rules/yaral`
将所有规则（包括导入的 Sigma 规则）导出为 `.yar` 文件 ——
Sigma→YARA-L 路径就此打通。

## 9. 远程代理（snitch-agent/1）

`agent/` 包含一个轻量 Rust 守护进程（零依赖，单个 ~1MB 二进制），
监视主机 socket 表（`/proc/net/*`）并将新的出站流推送到
`POST /ingest/events`。它只观测 socket —— 无 payload/SNI
（那是本地抓包的职责）；进程归属标记为 TODO。传输：HTTP + Bearer
（与 `gossip_peers` 相同的信任域）。

## 10. 免费威胁情报源

`POST /firewall/blocklist` 支持两种导入形式：

- `kind: "domain"` — hosts/域名列表（StevenBlack、EasyList…）→
  `domain` 防火墙规则；
- `kind: "ip"` — IP 源（Blocklist.de、URLhaus/Feodo 导出）→ `ip`
  规则；私有/保留/回环地址永远不会被导入。

`path:` 读取本地文件（完全离线）；`url:` 是显式、可审计的 opt-in
抓取（响应中带 `remote_fetch: true`）。上限 `max_entries ≤ 5000` ——
巨型源应交给解析器。

Opt-in API 提供商（AbuseIPDB / OTX / VirusTotal）仍可通过
`ti_provider` + `ti_api_key` 使用 —— 不设密钥就不会有任何外呼。

## 11. 无头/守护进程模式

GUI 是可选的：后端即全部产品。直接运行（`uvicorn api.main:app`）、
用附带的 systemd 单元或在容器中 —— 以上所有功能无需前端即可工作。
`SNITCH_DEMO=1` 继续为培训和 CTF 提供免 root 的合成流量。
