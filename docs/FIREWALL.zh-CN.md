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
