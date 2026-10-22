---
title: "Windows 上的免费开源 Little Snitch 替代品（是的，它存在）"
description: "Little Snitch 仅限 macOS。如果你在 Windows 或 Linux 上想看看电脑在和哪些服务器通信，这里有一份对真实替代方案的诚实对比。"
tags: [opensource, privacy, windows, networking]
canonical_url: https://aixisstudio.github.io/Snitch/
---

你的电脑每天和数百台服务器通信。大部分没问题——更新、同步、你同意的遥测。有些则不是。「我的机器到底在和谁通信？」这个问题正是 Little Snitch 能在 macOS 上长盛 15 年的原因。

问题在于：**Little Snitch 在 Windows 和 Linux 上不存在。** 而 Windows 上大多数「替代品」要么收费、要么要账号、要么是 firewall-first——可你只想要可见性。

我是 [Snitch](https://github.com/aixisstudio/Snitch) 的作者——一个有 Windows 移植的开源（AGPL）实时网络可视化工具——先声明利益相关。以下是各选项的真实现状。

## 先分清：可视化 vs 阻断器

值得说清楚，因为大家经常混淆：

- **可见性** =「让我看看机器在和谁通信」（地图、按应用归属、历史）
- **阻断** =「让我决定允许什么」（防火墙规则、弹窗）

Little Snitch 两者都做。有些替代品只做其一。Snitch 现在两者都做——可见性是强项，阻断则编排 OS 防火墙。

## 诚实对比

| 工具 | OS | 能阻断？ | 免费？ | 要账号？ | 说明 |
|---|---|---|---|---|---|
| **Little Snitch** | macOS | ✅ | 付费（~$59） | 否 | 标杆。macOS 之外无对手。 |
| **Snitch** | macOS、Windows、Linux | ✅ OS 防火墙规则 + lockdown（best-effort） | ✅ AGPL | 否 | 实时世界地图、异常检测、隐私评分、opt-in 威胁情报、取证导出。100% 本地。 |
| **Portmaster** | Win、Linux、macOS | ✅ | ✅ 核心免费 | 否 | DNS 级阻断 + 应用规则。较重——以系统服务运行。 |
| **OpenSnitch** | Linux | ✅ | ✅ GPL | 否 | 最接近的 Linux 等价物——带弹窗的应用防火墙。 |
| **GlassWire** | Windows、Android | ✅ | freemium | 推账号/云 | UI 精致，但关键功能 + 历史在付费墙后，且老推云档。 |
| **Wireshark** | 全平台 | ❌ | ✅ | 否 | *深度*包分析的金标准——但用于解剖数据包，而非「现在谁在 phone-home」。 |
| **LuLu** | macOS | ✅ | ✅ | 否 | 优秀的 macOS 免费防火墙——但仅 macOS，block-first 可视化极少。 |

## Snitch 实际做什么

一句话：**电脑建立的每条连接的实时地图——哪个应用、哪台服务器、哪个国家。**

- 实时力导向图 + 世界地图，离线定位（MaxMind/DB-IP——IP 不离开本机）
- 进程归属：是哪个*应用*打开的连接，不只是哪个 IP
- 异常检测：端口扫描、信标模式、外泄流量、DNS 隧道
- 隐私评分 + 可编辑列表的跟踪器检测
- 按应用流量、时间线（15/30/60 分钟）、24 小时 SQLite 历史
- 被动 LAN 扫描器（读 ARP 表——展示网络上每台设备）
- **出站规则 + lockdown**：在 OS 防火墙中阻断 IP/CIDR/域名/进程/端口（Windows 用 `netsh advfirewall`），结束/挂起进程，JSON/CSV/STIX 取证导出
- **opt-in 威胁情报**：用自己的 API key 查 AbuseIPDB / OTX / VirusTotal

隐私人士关心的部分：**一切本地。** 无账号、无遥测，每次外发调用——GeoIP、更新、威胁情报、webhook——都是 opt-in。API 默认绑定 loopback 且 token 认证。

## Snitch 不做什么

诚实环节，反正 HN/Reddit 会追问：

- **它的阻断是编排，不是驱动。** v1.2 起 Snitch 把 `ip`/`cidr`/`domain`/`process`/`port` 规则推入 OS 原生防火墙（Windows 用 `netsh advfirewall`、Linux 用 `iptables`、macOS 用 `pf`）并有 lockdown 开关——best-effort：真正应用规则需要与抓包相同的权限，且 `pf` 无法匹配进程。规则应用失败时 UI 会如实告知。要成熟的交互式应用防火墙，Portmaster（或 macOS 上的 Little Snitch）仍是标杆。
- **需要 admin/root** 抓包（不可避免——和 Wireshark 一样）。
- **深度包解剖**——这方面 Wireshark 依然胜出。Snitch 是万尺高空视角。

## 在 Windows 上安装

1. 安装 [Npcap](https://npcap.com)（Windows 抓包驱动——必需，和 Wireshark 同样的依赖）
2. 从[最新 release](https://github.com/aixisstudio/Snitch/releases) 下载 `Snitch Setup <version>.exe`——带托盘的原生 Electron 应用——或 Lite 纯后端安装包
3. 以管理员身份运行（安装包在后端启动时处理 UAC 提示）
4. UI 自动打开——在 Electron 窗口中，或 Lite 模式下在浏览器中

Linux：`docker run --network host ghcr.io/aixisstudio/snitch`——或 release tarball。macOS：打包应用或 `brew`。

## Windows 移植是怎么来的

项目由我一人维护。Windows 移植不是我做的——用户提交的 bug 报告附带根因分析，随后一位陌生人发来三个 PR 修好了抓包 + 正确的网卡 + 启动崩溃。开源如其宣传。v1.0.5 上周发布。

如果你试用后抓到了有趣的东西，仓库里有 [「你抓到了什么？」讨论](https://github.com/aixisstudio/Snitch/discussions/39)。如果觉得有用，[GitHub](https://github.com/aixisstudio/Snitch) 上的 ⭐ 对项目被发现真的有帮助。

**仓库：** https://github.com/aixisstudio/Snitch —— AGPL，UI 和文档共 8 种语言（EN/FR/ES/DE/RU/JA/PT-BR/中文）。
