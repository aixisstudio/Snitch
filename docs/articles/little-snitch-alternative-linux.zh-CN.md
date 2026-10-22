你的电脑每天要和数百台服务器通信。Linux 上的经典答案是 `tcpdump`、`ss`、`netstat` 或 Wireshark——很强大，但它们回答的是「给我看数据包」，而不是「我的机器在和谁通信，该不该担心？」。

我为后一个问题写了 [Snitch](https://github.com/aixisstudio/Snitch)——一个开源（AGPL）实时网络可视化工具，在 Linux 上通过 Docker 或 release 二进制完整支持。先声明：我是作者，所以下面是对现有方案与 Snitch 定位的诚实盘点。

## Linux 现状

| 工具 | 能做什么 | 不能做什么 |
|---|---|---|
| **tcpdump / ss / netstat** | 原始连接数据 | 无 UI、无历史、无地理定位、无应用映射 |
| **Wireshark** | 深度数据包解剖 | 回答「谁在 phone-home」属于杀鸡用牛刀——是显微镜不是仪表盘 |
| **OpenSnitch** | 应用防火墙（block/allow 弹窗） | 可视化极少——block-first，仅 Linux |
| **iftop / nethogs / nload** | 按接口或按进程的带宽 | 无世界地图、无异常检测、无持久化 |
| **Snitch** | 每条连接的实时地图：app → server → 国家、异常检测、24 小时历史、经 OS 防火墙的 opt-in 阻断 | OS 规则应用为 best-effort（需权限）；不是完整的交互式防火墙 |

OpenSnitch 与 Snitch 是互补而非竞争：OpenSnitch 是成熟的交互式应用防火墙，Snitch 展示你的机器在*做什么*——v1.2 起还能把规则（`ip`/`cidr`/`domain`/`process`/`port`）推入 `iptables` 并提供 lockdown 开关，以 best-effort 方式。

## Snitch 在 Linux 上能给你什么

- **实时世界地图**——每条出站连接带进程归属：是哪个应用打开的，而不只是哪个 IP
- **离线地理定位**——经本地 MaxMind/DB-IP 数据库，IP 从不离开本机
- **异常检测**：LAN 端口扫描、信标回连（定间隔回调，典型 C2 特征）、异常出站流量、DNS 隧道、按进程基线偏离
- **隐私评分** + 可编辑后缀列表的跟踪器检测
- **按应用带宽**、时间线、24 小时 SQLite 保留、告警抑制规则
- **被动 LAN 扫描**——读系统 ARP 表，零注入展示网络上每台设备
- **出站防火墙规则 + lockdown**——经 OS 原生防火墙（Linux 用 `iptables`）阻断 IP、CIDR、域名、进程或端口，结束/挂起进程，导出取证包（JSON/CSV/STIX）
- **opt-in 威胁情报**——用你自己的 API key 查 AbuseIPDB / AlienVault OTX / VirusTotal 信誉
- UI 和文档共 8 种语言（EN/FR/ES/DE/RU/JA/PT-BR/中文）

## 隐私部分

这是 Linux 用户往往最先验证的，所以：API 绑定 **127.0.0.1** 且需要 token。**无遥测、无账号**，每一次外发调用——GeoIP 下载、更新检查、威胁情报、webhook——都独立 opt-in。流量数据存在你拥有的本地 SQLite 文件中。

## 安装

```bash
# Docker（抓包需要 host networking）
docker run --network host ghcr.io/aixisstudio/snitch

# 或 release tarball——和 tcpdump 一样需要 root/cap_net_raw
sudo ./snitch-backend
```

然后打开打印出的 URL。还有演示模式（`SNITCH_DEMO=1`），用合成流量跑真实管线，方便你在授予抓包权限前先看看。

## 引擎盖下（给好奇的人）

纯 Python + ctypes → libpcap 抓包——不依赖 Scapy。IPv4/IPv6/TCP/UDP/DNS/TLS-SNI 解析全部手写，整条管线约 2K 行。FastAPI + WebSocket 后端，React + D3 前端，桌面端 Electron 外壳。

如果你想在 Linux 上得到「我的机器凌晨 3 点在和奇怪的地方通信吗」的答案——不用买防火墙、也不用整日挂着抓包——这正是它的用途。觉得值得就去 [GitHub](https://github.com/aixisstudio/Snitch) 点个 ⭐，Discussions 里有「你抓到了什么？」讨论串，欢迎贴截图。
