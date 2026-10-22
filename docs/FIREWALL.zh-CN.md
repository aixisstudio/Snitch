# 安全功能

[English](FIREWALL.md) | [Français](FIREWALL.md) | [Español](FIREWALL.es.md) | [Deutsch](FIREWALL.de.md) | [Русский](FIREWALL.ru.md) | [日本語](FIREWALL.ja.md) | [Português](FIREWALL.pt-BR.md) | **中文**

Snitch 在被动观察之上叠加了威胁狩猎层。**它做什么——以及同样重要的，
它不做什么：**

## 出站防火墙编排

Snitch **不**在用户态过滤数据包。规则会被尽力下发到操作系统原生
防火墙：

| 系统 | 机制 |
|---|---|
| Windows | `netsh advfirewall` 出站阻断规则 |
| Linux | `iptables -A OUTPUT -j DROP`（lockdown 使用专用 `SNITCH_LOCK` 链） |
| macOS | 生成的 `pf` 锚点，经 `pfctl` 加载 |

规则类型：`ip`、`cidr`、`domain`（应用时解析一次）、`process`、
`port`。规则持久化到 `snitch.db` 并在启动时重新下发。

**如实的限制：**

- 下发规则需要与抓包相同的权限。没有提权时，规则上记录
  `applied=False`——UI 显示「仅可见」。匹配仍然工作：违反规则的
  数据包会产生带规则计数的 `BLOCKED_ATTEMPT` 告警。
- macOS 的 `pf` 无法匹配*进程*——进程规则在设计上仅是可见性的。
- `domain` 规则只解析一次；IP 变动的 CDN 在重建规则前会绕过它。
- **Lockdown** 只切断到*公网* IP 的出站流量——回环和 LAN 保持，
  UI 依然可达。

## 事件响应

- `POST /processes/kill` / `POST /processes/suspend` —— 按 PID，
  拒绝 PID ≤ 3 以及 Snitch 自身。适用常规 OS 权限。
- `POST /firewall/rules`、`DELETE /firewall/rules/{id}`、
  `POST /firewall/rules/{id}/toggle`、`POST /firewall/lockdown` ——
  与所有端点一样需要认证。
- `GET /forensics/export?process=<名>&ip=<ip>` —— 调查包：进程树
  （最多 8 层祖先）、可执行文件 SHA-256、命令行、关联告警、按分钟
  历史。`format=json|csv|stix` 选择输出（STIX = 供 SIEM 导入的
  最小 2.1 bundle）。仅限本地数据；导出是下载，绝不上传。

## 威胁情报——opt-in，默认关闭

*设置 → Threat intelligence* 接受提供商（`abuseipdb`、`otx`、
`virustotal`）加上**你自己的 API 密钥**。启用后，每个新公网 IP 按
24 小时 TTL 查询一次；判定被缓存，`suspicious`/`malicious` 判定会
触发 `THREAT_HIT`。没有提供商或密钥时，**零出站调用**。
`GET /security/ti` 返回脱敏配置；`POST /security/threat_check`
执行手动查询（同样感知缓存）。

## Webhook——opt-in，默认关闭

*设置 → 外部 Webhook* 接受 URL 和开关。warning 与 critical 告警
实时 POST：Discord/Slack `{content}`、Telegram `{chat_id, text}`
（telegram URL 时显示 chat ID 字段）、其他端点收到
`{alert, source, text}`。失败仅记录日志，绝不致命。

## 检测新增

- `DNS_TUNNEL` —— 超长 DNS 名称/标签（>60 字符 / 标签 >40），典型
  外泄模式；每主机每 10 分钟一次。
- `CLEARTEXT` —— 出站 TCP 到本质不加密的端口（80、21、23、25、
  110、143…），INFO 级，喂给审计。
- `BASELINE_DEVIATION` —— 每个进程在最初的数据包中学习常去的
  国家，之后到达新国家时只提醒一次。基线持久化（`app_baselines`）。
- `BEACON` —— 已有功能：规则间隔检测（到达间隔的变异系数），即使
  微小流量也有效。
- `BLOCKED_ATTEMPT`、`LOCKDOWN`、`THREAT_HIT` —— 上述模块新增的
  告警类型。

## 安全审计

`GET /security/audit` 基于最近 500 条告警和实时图计算 0–100 分：
按类型计数、与高风险国家的接触、未解析主机、防火墙姿态——并
返回通俗语言的建议。这是一份*发现报告*，而非认证。

### v1.2 新功能 / Nouveautés v1.2

- **`sinkhole` 动作** — `domain`/`ip` 规则可重定向到 loopback 而非阻断：域名通过 hosts 文件中带 `# snitch-sinkhole` 标记的块（所有 OS），IP/CIDR 通过 iptables `DNAT`（仅 Linux）。`process`/`port` 的 `sinkhole` 被拒绝；不支持的平台如实返回 `applied=False`。
- **域名重解析** — `domain` 规则每约 10 分钟重新解析，按 OS 应用 IP 差值，CDN 轮换不会静默放行域名。
- **完整性监视**（默认开启，只读，本地） — 联网可执行文件的 SHA-256 基线（`BINARY_CHANGED`）、名称/exe 不匹配（`NAME_MISMATCH`）、仅 Linux `rwxp` 扫描（`MEM_RWX`，已知 JIT 应用为 info 级）。`GET /security/integrity`、`POST /security/integrity/check`。
- **告警解释** — `GET /security/explain?type=X` 返回手写的双语（EN/FR）解释；确定性、完全离线 — 非模型。UI 中每条告警的「为什么？」按钮显示。

### 可选探针 (v1.3)

所有探针**默认关闭或自我限制**，降级时如实报告，绝不向机器外发送数据：

- **eBPF connect 探针**（Linux，`ebpf_probe`）— `tcpconnect` 型 BCC kprobe 归属套接字表漏掉的短命进程的 `connect()`。需要 `python3-bcc` + root；模糊目标绝不猜测。`GET /security/ebpf`。
- **Frida 深度检查** — `POST /security/deep_inspect {pid,seconds}` 附加到单个 pid ≤60 秒，报告每个 `connect()` 由哪个已加载模块发起。staging 路径 → `INJECT_SUSPECT`。
- **沉洞响应器** — `sinkhole` 规则启用期间，:80/:443 上的 loopback 监听器把每次尝试转为 `SINKHOLE_HIT` 告警（Host/URI 或 SNI + 进程）。
- **模块完整性** — 可执行映射的 Merkle 根 → `MODULE_CHANGED`；`/tmp`/memfd 路径 → `MODULE_SUSPECT`。
- **挖矿检测** — payload 头部中的 stratum JSON → `MINING_STRATUM`；矿池端口 + 持续高 CPU → `MINING_SUSPECT`。
- **硬件计数器** — `POST /security/perf` 通过 `perf_event_open` 采样周期/指令数 (Linux)。
- **本地 LLM** — 可选（`slm_enabled`）：`/security/explain` 调用 Ollama 兼容端点，**仅限 loopback** — 远程端点被拒绝。
- **IOC 包** — `GET /security/iocpack` 以 Bloom + randomized response 导出（绝不明文）；`POST /security/iocpack/import` 概率性地检查目标。

### 策略与响应新增 (v1.4)

- **命名配置文件** — `POST /firewall/profile`：`permissive`（清空）、`balanced`（保守出站基线）或 `strict`（基线＋锁定）；展开为普通规则并去重。
- **自定义告警规则** — `GET/POST/DELETE /alerts/rules`：字段＋运算符＋值 → `CUSTOM_RULE` 告警（仅告警，绝不阻断）。
- **导入屏蔽列表** — `POST /firewall/blocklist`：本地文件（纯本地）或可选 URL（≤4 MiB HTTPS 抓取，响应标记 `remote_fetch`）→ `domain` 规则，去重，上限 500–5000。
- **PCAP 导出** — `GET /forensics/pcap`（`ip`/`process` 过滤）：~4 MiB 环形缓冲区输出为 Wireshark 可用的 `.pcap`。
- **远程配对** — `POST /remote/pairing` 持久化 `lan_bind`（下次启动生效）；令牌仍然必需。`GET /remote/pairing` 报告绑定地址与 LAN IP。
- **无网络沙箱** — `POST /security/sandbox` 以零出站运行二进制（Linux `unshare -n`、macOS `sandbox-exec`；手动版 `contrib/snitch-contain`）。
- **内置模型** — `slm_mode=embedded` 通过 `llama-cpp-python` 加载用户 `.gguf` — 完全零网络。
- **原生骨架** — `contrib/wfp-callout/`（C 版 WFP callout＋签名说明）与 `contrib/macos-filter/`（Swift `NEFilterDataProvider`＋entitlement 说明）：研究用脚手架，不随产品分发。
- **ASN** — 存在 `GeoLite2-ASN.mmdb`/`dbip-asn-lite.mmdb` 时，节点除 `org` 外还带 `asn`。

## v1.5 — 被动检查、内核判定与集群同步

- **被动 TLS 证书检查** — 有界 TCP 重组（≤16 KiB/流，TTL 30 秒）读取 `Certificate` 消息：签发者/主体 CN+O、自签名、SAN、有效期、`san_mismatch` → `TLS_CERT`。**TLS 1.3 保持不透明** — 诚实报告不可观测而非猜测。
- **高熵监视** — 非 TLS 通道上 ≥48 B、≥4.7 比特/字节的载荷 → `HIGH_ENTROPY`；每主机 10 分钟冷却。
- **ICMP 隧道启发式** — 载荷 ≥24 B 的 echo 类型，5 分钟内 ≥3 次 → `ICMP_TUNNEL`。
- **ML 流异常** — 纯 Python isolation forest（64 棵树、零依赖）对您自己的流摘要打分；<384 流时惰性，0.62 触发 `ML_ANOMALY`。基线偏差，**不是**恶意软件分类器。
- **Ask-on-connect（Linux，可选）** — `ask_enabled` + root + iptables：新出站流在 NFQUEUE 7 挂起至 `POST /security/ask/verdict` — NFQUEUE 客户端为**纯 Python**（`detection/nfqueue.py`，AF_NETLINK），无需 `python-netfilterqueue`；超时 15 秒，默认拒绝（`ask_failopen=1` 反转）。Windows/macOS 需要 `contrib/` 中的签名 callout/NetworkExtension。
- **eBPF cgroup 执行（Linux，可选）** — `POST /security/ebpf/isolate {pid}` + `/security/ebpf/block {ip}`：程序挂载到 snitch cgroup — 内核丢弃仅作用于被隔离进程。
- **空心化检查（Linux）** — `POST /security/hollow {pid}` 对比 `/proc/<pid>/mem` 中文件映射的可执行页与磁盘。
- **IOC 节点同步（可选）** — `gossip_peers` ≤32 + `gossip_enabled`：每 5 分钟经认证 HTTP(S) 推送 Merkle 证明包 — 无发现机制，非 ZK。
- **Syslog（可选）** — `syslog_addr`（`主机:端口` UDP 或 `tcp://`）→ RFC 3164 `local4`。
- **Firejail 隔离** — 优先 `firejail --net=none`，回退 `unshare`。
- **nftables 后端** — 有 `nft` 时使用专用 `inet snitch` 表替代 iptables。
- **可操作告警** — 结构化 `actions`（封锁 IP、终止/挂起、ask 判定）以一键按钮呈现。
- **自定义规则的 `asn`/`country`** — 本地 geo 数据库，可与 `action=block` 组成地理围栏。
- **DGA 启发式** — 已解析的 DNS 名与 TLS SNI 按词汇特征评分（熵、
  元音比、辅音连缀、数字）→ `DGA_SUSPECT`。纯本地启发式；无 WHOIS
  或域名年龄数据。
- **伪装协议** — ≤64 字节负载头部必须与端口声明的协议相符
  （HTTP/80、DNS/53、SSH/22、TLS/443+853、邮件 ASCII 命令）→
  `PROTO_MISMATCH`，按流冷却。
- **流量终止开关（可选）** — `kill_switch_enabled` 将 `UPLOAD_SPIKE`
  变为对远程 IP 的真实防火墙封锁（去重、尽力而为）。默认关闭。
