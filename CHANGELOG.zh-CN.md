# 更新日志

[English](CHANGELOG.md) | [Français](CHANGELOG.md) | [Español](CHANGELOG.es.md) | [Deutsch](CHANGELOG.de.md) | [Русский](CHANGELOG.ru.md) | [日本語](CHANGELOG.ja.md) | [Português](CHANGELOG.pt-BR.md) | **中文**

Snitch 的所有重要变更。

格式遵循 [Keep a Changelog](https://keepachangelog.com/)。

## [Unreleased]

### 新增

- **出站防火墙编排** — 用户规则（`ip`、`cidr`、`domain`、`process`、`port`）以 best-effort 方式应用到 OS 原生防火墙：Windows 用 `netsh advfirewall`，Linux 用 `iptables`，macOS 生成 `pf` 锚点。规则持久化、启动时重新应用，无权限时如实返回 `applied=False`（匹配与 `BLOCKED_ATTEMPT` 计数仍然工作）。
- **Lockdown** —— 一键切断指向公网 IP 的出站流量，同时保留 loopback/LAN（Linux 的 `SNITCH_LOCK` 链、`netsh` 规则、`pf` 锚点）。
- **进程操作** —— `POST /processes/kill` 与 `POST /processes/suspend`（按 PID，拒绝 PID ≤ 3 及 Snitch 自身）；进程列表内提供 kill/suspend 按钮。
- **威胁情报（opt-in）** —— 使用你自己的 API key 对 AbuseIPDB、AlienVault OTX 或 VirusTotal 做信誉核查；默认关闭，每个新出现的公网 IP 仅调用一次，有界 LRU 缓存 + 去重，可疑/恶意判定触发 `THREAT_HIT` 告警。
- **外部 Webhook（opt-in）** —— warning/critical 告警实时 POST 到 Discord、Slack、Telegram（带 chat ID）或任意端点；默认关闭。
- **新增检测** —— `DNS_TUNNEL`（超长 DNS 名/标签）、`CLEARTEXT`（FTP/Telnet/HTTP/明文邮件出站）、`BASELINE_DEVIATION`（按进程学习的国家画像，持久化）。
- **安全审计** —— `GET /security/audit` 根据近期告警与实时图计算 0–100 分并给出通俗建议；显示在防火墙面板。
- **取证导出** —— `GET /forensics/export?format=json|csv|stix` 打包进程树、可执行文件 SHA-256、相关告警与流量历史；STIX 为最小 2.1 bundle（indicators + observed-data），供 SIEM 导入。
- **防火墙与安全 UI** —— 专属面板：lockdown 开关、规则创建/切换/删除、按规则拦截计数、平台能力如实显示、审计报告、取证下载按钮；侧栏可按连接执行阻断。
- **新增五个 UI 语言** —— de、ru、ja、pt-BR、zh-CN（共 8 个，280 键奇偶校验通过）；词典移至 `frontend/src/locales/*.js` —— 新增语言只需单文件 PR。

## [1.1.0] — 2026-10-22

### 新增

- **自动更新** —— 桌面应用启动时及每 6 小时通过 electron-updater 检查 GitHub Releases（`latest-*.yml` feed 早已发布）。下载在重启时安装；托盘与设置实时显示状态。可在设置中或通过 `SNITCH_NO_UPDATE=1` 关闭。
- **QUIC / HTTP/3 可见性** —— UDP/443 流量标记为 `QUIC/HTTP3`，不再归入 HTTPS 或未知。QUIC Initial 的 SNI 已加密且从不读取——标签如实反映可观测内容。
- **Watchlist** —— 可固定 IP 或域名后缀（`example.com` 同样匹配 `api.example.com`）；专用 `WATCHLIST_HIT` 告警在首次接触时触发，按（条目，主机）限流。持久化，在设置中管理。
- **按进程上传告警** —— 当进程超过可配置的 MB/分钟上限（默认 50，0 = 关闭）时 `UPLOAD_SPIKE` 告警——覆盖基线相对 `VOLUME_SPIKE` 在新进程上漏掉的外传行为。
- **抓包接口选择器** —— `GET/POST /capture/interfaces` + 设置页列出 libpcap 设备的下拉框；切换即时重启抓包。替代桌面用户的 `SNITCH_IFACE` 环境变量。
- **Wi-Fi 上下文** —— 工具栏显示当前 SSID（非 Wi-Fi 时显示抓包接口）。按 OS best-effort，缓存 60 秒。
- **西班牙语 UI** —— 完整 `es` 词典（194 键，奇偶校验通过）；语言切换变为 EN/FR/ES。
- **Snap 包** —— electron-builder 现输出 strict confinement 的 `.snap`（带 `network-observe` 插口用于 AF_PACKET 抓包）。Flatpak 有意不提供——沙箱无法暴露原始抓包（见 `docs/PACKAGING.md`）。
- **免费代码签名途径** —— CI 中可选集成 SignPath Foundation OSS（`vars.SIGNPATH_*` + `secrets.SIGNPATH_API_TOKEN`）：项目获批后 Windows 安装包自动获得 Authenticode 签名。`docs/SIGNING.md` 完整记录，包括 macOS 的实情（不存在免费公证）。

## [1.0.8] — 2026-10-22

### 变更

- **真正的原生浅色主题** —— 以完整的设计令牌系统取代 v1.0.7 的反色滤镜：应用内每个表面、文字、边框与强调色都通过 CSS 自定义属性用精心挑选的浅色调色板绘制。地图、力导向图、时间线与 WebGL 极光全部跟随主题，切换仍持久化你的选择。

## [1.0.7] — 2026-10-22

### 新增

- **浅色主题** —— 默认遵循 `prefers-color-scheme`，可用工具栏的太阳/月亮开关覆盖；选择存于 `localStorage`。实现方式为保留色相的暗色调色板反转，因此图形、地图与极光保持协调。

### 修复

- **AppImage 目录合规** —— Linux 资产更名为 `Snitch-x86_64.AppImage`（正确的架构命名），electron-builder 发布 GitHub 更新元数据（`latest-linux.yml` + `.zsync`），使兼容 AppImageUpdate 的工具可以自动更新。

## [1.0.6] — 2026-10-21

### 新增

- **每个 OS 一个下载** —— 每个 tag 发布 CI 构建的即用应用：
  - **Windows** —— `Snitch Setup <version>.exe`（Electron + NSIS：原生窗口、托盘、内置 Npcap 检测、后端启动时 UAC 提示）与 `Snitch-Lite-Setup-<version>-windows-x64.exe`（Inno Setup：仅后端，UI 在浏览器打开）。
  - **macOS (Apple Silicon)** —— CI 构建 `Snitch-<version>-macos-arm64.zip` + `.dmg`（此前为手工）。
  - **Linux** —— `Snitch-<version>.AppImage` + `.deb` —— 桌面应用不再需要 Docker。
- **`--launcher` 后端模式** —— 选取空闲 loopback 端口、计算 API token 并打开浏览器；供 Lite 安装包快捷方式使用。

### 修复

- **独立后端包现在内置 UI** —— 所有 OS 的 PyInstaller bundle 均打包 `frontend_dist`；此前裸 tarball 只提供 API。

### 变更

- CI `package` 任务在三个 OS 构建 Electron 安装包，`release` 任务将所有构件自动发布到 GitHub release。

## [1.0.5] — 2026-10-17

### 新增

- **Windows 支持** —— 打包应用现可在 Windows 上启动并抓包（Npcap）。
- **进程图标** —— 应用表格中按进程显示 Lucide 图标（外部贡献）。
- **新增 24 个跟踪器域名** 加入分类器黑名单（外部贡献）。

### 修复

- `console=False` PyInstaller 构建的后端崩溃（`sys.stdout`/`sys.stderr` = None）——issue #25。
- Windows 抓包接口选择——Snitch 现在选择默认路由所在接口，而非 `vEthernet (WSL)`。
- 带时区偏移的告警时间显示 `NaNh ago`。
- Electron 启动画面不再遮挡错误对话框；超时信息列出原因 + 日志目录。
- 法语词典中残留的四条英文字符串已翻译（外部贡献）。
- 版本号现统一来源于 `backend/version.py`。

### 变更

- React 18 → 19、uvicorn 0.30 → 0.54、fastapi → 0.143、psutil → 7.2、websockets → 17.2、maxminddb → 3.2、aiofiles → 25.1、lucide-react → 1.55、vite → 8.3.4、electron → 44.7（+ dev deps）。

## [1.0.4] — 2026-10-05

- 首个公开版本。
