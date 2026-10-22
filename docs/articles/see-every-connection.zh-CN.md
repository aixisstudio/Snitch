你的电脑此刻正在和互联网通信。大概率有几十条连接——同步、遥测、更新检查、你打开的标签页、应用的后台碎语。「我的机器究竟在做什么？」听起来是个基础问题，但真去回答时你会发现工具要么过于显微（Wireshark），要么藏在付费墙后。

这里有一份真正看清它的实用指南——包括我为此构建的工具 [Snitch](https://github.com/aixisstudio/Snitch)（开源，AGPL——声明：是我写的）。

## 60 秒版本

```bash
# macOS / Linux —— 经典但原始
sudo tcpdump -i any -n | head -50        # 每个包，无上下文
netstat -anp tcp | grep ESTABLISHED      # 仅当前连接
lsof -i -nP | head                       # 进程 → socket 映射

# Windows
netstat -ano | findstr ESTABLISHED
Get-NetTCPConnection -State Established  # PowerShell
```

这些命令回答「现在存在哪些连接」。它们不会告诉你是哪个应用、服务器在哪、是否可疑。可视化工具填的正是这个空白。

## 可视化方法

Snitch 把每条连接渲染为实时图 + 世界地图：

- **节点 = 你的机器**位于中心，连线指向每个远程端点
- **每个端点有标签**：主机名（经反向 DNS + TLS SNI）、地理定位的国家/城市——全部离线，来自本地 MaxMind/DB-IP 数据库
- **按应用归属**：连接画到打开它的*进程*
- **时间线**：15/30/60 分钟流量，本地 SQLite 保存 24 小时历史

与 tcpdump 的区别：数据*已经被加工*。不是「发往 142.250.74.78 的包」——而是「Chrome → google.com → 法兰克福」。

## 读图：正常 vs 可疑

正常的地图：指向 Apple/Google/Microsoft/你标签页的 CDN、你的路由器、其他 LAN 设备的辐条。

值得注意的：

- **信标回连**——按固定间隔触发的连接（Snitch 会标记；典型 C2 模式）
- **向陌生端点的长期上传**——数据持续流向你不认识的地方
- **端口扫描**——触碰你机器大量端口的 LAN 主机会被标记
- **应用与不合常理的国家**通信
- **跟踪器**——Snitch 将主机名与可编辑的跟踪器后缀列表比对，计入隐私评分
- **DNS 隧道**——域名异常冗长或频率反常的 DNS 查询

内置**异常检测**自动监视这一切，验证过的模式可按规则抑制告警。

## 安装（2 分钟）

```bash
# macOS：从 releases 下载应用，或 brew
# Windows：安装 Npcap → 以管理员运行 snitch-backend.exe
# Linux / Docker:
docker run --network host ghcr.io/aixisstudio/snitch

# 没有管理员权限？演示模式用合成流量展示完整 UI：
SNITCH_DEMO=1 snitch-backend
```

一切留在本地——loopback 上 token 认证的 API、零遥测、无账号，每次外发调用（GeoIP、更新、威胁情报、webhook）都是 opt-in。这不是营销话术；它是 AGPL 代码库，你可以亲自验证网络路径。

而当某样东西看起来不对时，你可以行动——v1.2 起 Snitch 能把阻断规则推入 OS 原生防火墙（netsh / iptables / pf），有一键 lockdown、kill/suspend 按钮，以及为你抓到的东西准备的取证导出（JSON/CSV/STIX）。

## 然后呢？

一旦你能*看见*流量，有趣的部分才开始——社区最爱的节目是 [「你抓到了什么？」讨论串](https://github.com/aixisstudio/Snitch/discussions/39)：凌晨 3 点和云服务器聊天的打印机、电视遥测，应有尽有。

仓库：https://github.com/aixisstudio/Snitch —— 如果它回答了它想回答的问题，请给 ⭐。
