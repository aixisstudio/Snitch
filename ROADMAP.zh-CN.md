# 路线图

[English](ROADMAP.md) | [Français](ROADMAP.md) | [Español](ROADMAP.es.md) | [Deutsch](ROADMAP.de.md) | [Русский](ROADMAP.ru.md) | [日本語](ROADMAP.ja.md) | [Português](ROADMAP.pt-BR.md) | **中文**

> 在 [GitHub Discussions](https://github.com/aixisstudio/Snitch/discussions) 的 *Ideas* 分类中提议或投票功能。具体 bug 请用 [Issues](https://github.com/aixisstudio/Snitch/issues)。

## ✅ 已发布

| 版本 | 内容 |
|---|---|
| **v1.0.4** | 首个公开版本——实时图＋世界地图、按进程归属、离线地理定位（.mmdb）、异常告警、隐私评分、被动 LAN 发现（ARP/OUI）、麦克风/摄像头监控（Windows/Linux）、演示模式、EN/FR UI |
| **v1.0.5** | **Windows 支持**（Npcap、打包后端）、进程图标、+24 个跟踪器域名、修复 |
| **v1.2（main，未打 tag）** | **安全与威胁狩猎套件**——OS 防火墙编排（IP/CIDR/域名/进程/端口规则经 `netsh`/`iptables`/`pf` 下发，尽力而为）、lockdown 应急开关、kill/suspend 操作、可选威胁情报（AbuseIPDB/OTX/VirusTotal）、可选 webhook（Discord/Slack/Telegram/通用）、DNS 隧道/明文流量/国家基线偏离检测、安全审计、取证导出（进程树＋SHA-256、JSON/CSV/STIX）、8 语言 UI |
| **v1.5.x** | **企业/SOC 层**——声明式 `snitch.toml`、CEF + RFC 3164 syslog + `format=ecs` NDJSON、Sigma 导入 + YARA-L 导出、`/remote/fleet` 视图 + Helm chart、Ansible/Puppet/Salt/GPO 部署、加固 systemd 单元 + nfpm `.deb`/`.rpm`、免费 TI 源、MkDocs + `INTEGRATIONS.md` ×7 语言 |
| **v1.6.x** | **代理与集群身份**——零依赖 Rust 代理（`agent/`、Linux `/proc` 套接字→PID 归因）、按代理注册（`sagt_…` 哈希令牌、`/ingest/revoke`）、`ti_feeds` 自动刷新 worker、3 平台代理 CI、无头 `snitchd` 配方、CodeQL 告警全部关闭、235 个后端测试 |

已上线：GHCR 的 Docker 镜像、Homebrew tap（`brew install --cask aixisstudio/tap/snitch` + 无头 `snitchd` 配方）、winget 包[已提交](https://github.com/microsoft/winget-pkgs/pull/455520)、8 语言 README、GitHub Discussions。

## 🚧 v1.x — 进行中

- [x] **签名的 Windows 安装器** —— CI 已接入 [SignPath](https://signpath.org) OSS（获批项目可免费使用 Authenticode）；申请通过后自动生效——见 `docs/SIGNING.md`
- [ ] **签名＋公证的 macOS 构建** —— 需要 Apple Developer 账号（99 美元/年），无免费途径。在此之前 [tap](https://github.com/aixisstudio/homebrew-tap) 会代为移除隔离标记
- [ ] **Homebrew 官方**（`brew install --cask snitch`）——受阻：`snitch` 名称已被无关项目占用；有了 Developer ID 签名后再议
- [ ] **winget 发布** —— [PR #455520](https://github.com/microsoft/winget-pkgs/pull/455520)（v1.0.8）已开启；流水线将在每个 tag 自动提交最新 NSIS 构建
- [ ] **Chocolatey** —— 包已就绪；等待 `CHOCO_API_KEY` 密钥
- [ ] **Windows/macOS 代理归因** —— `GetExtendedTcpTable`/`libproc` 后端
- [ ] **集群扩展** —— 队列式采集器 + PostgreSQL/TimescaleDB（>1 000 代理）
- [x] **Windows 一键安装器** —— Electron NSIS＋Inno Lite，随 tag 在 CI 构建；自 v1.0.6 起
- [x] **Linux 包** —— Docker 之外的 .deb / AppImage / **snap**（无 Flatpak：沙箱无法暴露抓包能力）
- [x] **自动更新** —— electron-updater 走 `latest-*.yml` 源，可在设置中关闭
- [x] **导出格式** —— UI 中图＋告警导出 JSON/CSV
- [ ] **更广的跟踪器覆盖** —— `backend/classifier/lists/` 中社区可编辑的列表
- [ ] **PCAP 导出** —— 按主机或会话

## 💭 考虑中

- UI 内自定义告警规则
- 无屏主机的可选远程配对——需同意＋令牌保护
- 地图图层：ASN / 组织视图
- 导入拦截列表（StevenBlack hosts、EasyList）——需先过隐私/许可审查
- 防火墙配置档（严格/出行 vs 开发/宽松）

## 🔬 研究 —— 仅记录在案，未实现

把 Snitch 推向桌面 EDR/XDR 的想法。如实列出——**均未实现**；每项都需要
独立设计、原生组件，通常还需要第二个二进制产物：

- **eBPF 探针（Linux）** —— 内核态捕获 `sys_enter_connect`/`accept`，难以被绕过；需要编译好的 BPF 程序＋root
- **WFP callout（Windows）** —— 真正的内核包过滤，取代 `netsh` 编排；需要签名的内核驱动
- **NetworkExtension（macOS）** —— 按 bundle 过滤的 `NEFilterProvider`；需要 Apple Developer ID＋entitlements
- **内存/流量关联** —— 未签名 DLL、`PAGE_EXECUTE_READWRITE` 区域检查与可疑连接交叉比对
- **动态污点分析（DTA）** —— 逐字节证明数据外泄；重量级研究
- **本地 SecOps SLM** —— 用 1–3B 参数模型以自然语言解释告警
- **ZKP 机群情报** —— 节点间共享检测结果而不暴露端点
- **PMU/硬件计数器** —— OS 之下的勒索软件信号（投机执行、加密突发）
- **已加载模块的 Merkle 完整性** —— 在首个数据包前发现热补丁 DLL
- **Sinkholing / 微隔离** —— 把可疑流量引入本地蜜罐而非直接终结
- **PCAP 导出** 保留在上文范围内

## 🚫 范围之外

有意为之，设计使然：

- **遥测、分析、账号、云同步** —— 永远不会。
- **全网被动 IDS** —— Snitch 只看*这台*机器，不看整个网络。
- **用户态包过滤** —— 阻断委托给 OS 原生防火墙（或未来的内核组件），绝不重造轮子。

## 🤝 参与贡献

好的切入点：`good first issue` 标签、跟踪器列表 PR（`backend/classifier/lists/`）、翻译（i18n 已就绪，一种语言一个文件）、打包（Linux .deb/.rpm）。见 [CONTRIBUTING.md](CONTRIBUTING.md)。
