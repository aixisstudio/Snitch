如果你在 Windows 上找过网络监控工具，一定遇见过 GlassWire。它精致漂亮——然后付费墙接踵而至：历史记录要订阅、防火墙功能分档、不断推荐的账号、云端「精英」同步。

为软件付费没有错。但「让我看看电脑在和谁通信」属于基础卫生——本就不该上锁。我是 [Snitch](https://github.com/aixisstudio/Snitch) 的作者——一款免费的开源（AGPL）替代品——所以这里给出诚实的对比而非销售话术。

## Snitch 对比 GlassWire，逐项功能

| | **Snitch** | **GlassWire** |
|---|---|---|
| 价格 | 永久免费 | Freemium——关键功能付费 |
| 许可证 | AGPL 开源 | 专有 |
| 账号 | **永远不需要** | 推荐账号/云档 |
| 遥测 | **无 opt-in 即无任何外发调用**（GeoIP、更新、威胁情报、webhook 默认全关） | 为同步/功能 phone-home |
| 数据位置 | 本地 SQLite，归你 | 存在云关联功能 |
| 连接实时世界地图 | ✅ 离线定位 | ✅（付费档） |
| 按应用流量与带宽 | ✅ | ✅（部分免费） |
| 历史 | 免费 24 小时（SQLite 环形缓冲） | 免费档受限 |
| 异常告警（端口扫描、信标回连、外泄、DNS 隧道） | ✅ | ✅（多为付费） |
| LAN 设备扫描 | ✅ 被动，经 ARP | ✅（付费） |
| 防火墙/阻断 | ✅ OS 防火墙编排 + lockdown（best-effort，需权限） | ✅（GlassWire 防火墙更成熟） |
| 威胁情报信誉 | ✅ opt-in（AbuseIPDB / OTX / VirusTotal，自备密钥） | ❌ |
| 结束/挂起进程 | ✅ 内置 | ✅ |
| 取证导出 | ✅ JSON / CSV / STIX | ❌ |
| 平台 | macOS、Windows、Linux | Windows、Android |
| 隐私评分/跟踪器检测 | ✅ 可编辑列表 | ❌ |

## GlassWire 仍然胜出的地方

公平地说：

- **阻断成熟度。** GlassWire 的应用防火墙打磨了十年——Snitch 的出站阻断（v1.2 新增）以 best-effort 方式编排 OS 原生防火墙，真正应用规则需要抓包级权限。如果交互式「拒绝此应用」是你的核心需求，GlassWire（或免费的 Portmaster）仍是更成熟的选择。
- **完成度。** GlassWire 有十年的 UI 积累。Snitch 年轻得多——图很棒，设置够用，边角粗糙请见谅。
- **长历史保留** —— Snitch 设计上只保留 24 小时（隐私优先也意味着*不*囤积你的流量）。

## 真正重要的架构差异

GlassWire 的模式是行业惯例：免费档 → 烦扰 → 订阅 → 云功能。Snitch 相反：你运行的二进制就是产品全部。没有要解锁的，因为没有上锁的。你的历史存在本地 SQLite 文件里——代码是 AGPL，想偷偷 phone-home，diff 立刻公之于众。

具体来说：API 绑定 loopback 且 token 认证，零遥测端点，代码里没有任何分析 SDK（你可以 grep——它是开源的）。

## 试一试

```bash
# Windows：安装 Npcap，然后以管理员运行 release 的 exe
# Linux/Docker:
docker run --network host ghcr.io/aixisstudio/snitch
# macOS：打包应用或 brew
# 无管理员的演示模式：SNITCH_DEMO=1
```

仓库：https://github.com/aixisstudio/Snitch —— 欢迎 issue 和功能请求，Windows 移植本身就是社区贡献。如果它替换了你不想要的订阅，那就是意义所在。若如此请给个 ⭐。
