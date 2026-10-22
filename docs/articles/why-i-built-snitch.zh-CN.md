三周前，我想回答一个简单到可笑的问题：**我的电脑到底在和谁通信？**

不是「能不能抓包」（Wireshark 可以——但那是显微镜，而我要的是挡风玻璃）。也不是「拦截连接」（macOS 上 Little Snitch 能做到，$59，而 Windows 上没有等价物）。只是：一个实时的、可视化的答案。哪个应用、哪台服务器、哪个国家——就在此刻。

于是我做了 [Snitch](https://github.com/aixisstudio/Snitch)。开源、AGPL、8 种语言的 UI、三周约 400 颗星。以下是我的收获——以及陌生人替我完成 Windows 移植的那一段。

## 构建

我给自己定的约束：**不要重依赖，不要遥测，永远不。**

- 捕获：macOS/Linux 用 `ctypes → libpcap`，Windows 用 Npcap。不用 Scapy——直接绑定更轻，字段控制更精确。
- 解析：手写 IPv4/IPv6/TCP/UDP/DNS/TLS-SNI 解码器，整条管线约 2K 行。
- 后端：FastAPI + WebSockets + SQLite 环形缓冲（保留 24 小时后自我删除——隐私也意味着*不*囤积）。
- 前端：React + D3 力导向图 + TopoJSON 世界地图。
- 地理定位：本地 MaxMind/DB-IP 文件，IP 从不离开本机。

把安全姿态做成特性：API 只绑定 loopback、token 认证，所有外发调用均为 opt-in——GeoIP 下载、更新检查、威胁情报和 webhook 默认全部关闭。对隐私工具而言，代码*就是*承诺——AGPL 让它可审计。

## 计划之外的事

我先发布了 macOS 版，并给仓库打上 Windows 方向的「help wanted」标签。几天之内：

- 用户提交的 bug 报告**附带根因分析**——不是「不能用」，而是真实的栈跟踪和已定位的故障捕获路径
- 一位从未交谈过的陌生人发来三个 PR：Npcap 捕获、网卡选择、启动崩溃
- 另有人提交了 [winget 包 PR](https://github.com/microsoft/winget-pkgs/pull/455520)

v1.0.5 上周发布，Windows 移植完整可用。这个项目找到的最强分发渠道不是营销技巧——而是「把真实问题公之于众，有同样问题的人自然会出现」。

## 流量数据说了什么

有趣的元时刻：Snitch 自己的引荐流量讲出了故事。一家中国科技通讯（ruanyifeng.com）推荐了项目——突然约 20% 的流量成了盯着英文 README 的中文读者。于是有了完整的 [README 中文](https://github.com/aixisstudio/Snitch/blob/main/README.zh-CN.md)——以及总共 8 种语言的翻译。数据做决定；我只负责倾听。

## 想对做开发者工具的人说的话

1. **解决切身的问题。**「我的机器在和谁通信」是本能之问——人人好奇，无人可见。
2. **local-first 已是差异化卖点。**「无账号、无遥测」不是限制，而是卖点本身。
3. **多语言文档不是慈善**——是通往零竞争受众的分发渠道。
4. **Issues 和 Discussions 会转化。**快速回复把 bug 报告者变成了贡献者。我的 Windows 移植就是这么来的。

## 试一试

```bash
docker run --network host ghcr.io/aixisstudio/snitch   # Linux
# macOS/Windows：releases 页面——SNITCH_DEMO=1 无需管理员即可运行
```

仓库：https://github.com/aixisstudio/Snitch —— AGPL，UI 和文档覆盖 EN/FR/ES/DE/RU/JA/PT-BR/中文；v1.2 加入了呼声最高的功能：经 OS 防火墙的出站阻断、opt-in 威胁情报、一键取证导出。[「你抓到了什么？」讨论串](https://github.com/aixisstudio/Snitch/discussions/39)开放中，如果它值得，⭐ 真的有帮助。
