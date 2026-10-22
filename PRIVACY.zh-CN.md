# 隐私

[English](PRIVACY.md) | [Français](PRIVACY.md) | [Español](PRIVACY.es.md) | [Deutsch](PRIVACY.de.md) | [Русский](PRIVACY.ru.md) | [日本語](PRIVACY.ja.md) | [Português](PRIVACY.pt-BR.md) | **中文**

Snitch 是一款隐私工具——它绝不能泄露它所帮助你监控的那些数据。

**遥测：没有。** 无分析统计、无崩溃报告、无任何形式的「回连」。

**Snitch 发出的出站网络调用：全部可选，全部默认关闭。** 其余均为
被动观察或由你触发——没有静默流量：

- 在本地网卡上抓包（被动观察），
- 读取系统 ARP/邻居表（无主动扫描），
- 通过系统解析器做反向 DNS——任何网络活动本来就会隐式发生的标准
  PTR 查询（`SNITCH_DISABLE_PTR=1` 可完全禁用），
- 在 `127.0.0.1` 上为你自己的浏览器提供 Web UI。

**桌面应用会在 github.com 检查新版本** —— 启动时以及每 6 小时
（electron-updater，读取公开的 `latest-*.yml` 文件）。这是唯一的
周期性出站调用。可在*设置 → 更新 → 自动检查*中关闭（持久化）或用
`SNITCH_NO_UPDATE=1`。Docker 构建和后端本身从不检查更新。

**GeoIP 数据库下载**（*设置 → 地理定位*）从 db-ip.com 拉取约 50 MB
——仅在你点击时进行，需要明确同意。

**威胁情报（选择性开启，默认关闭）。** 当你配置了提供商
（AbuseIPDB、AlienVault OTX 或 VirusTotal）*并且*在设置中粘贴了你自己的
API 密钥后，Snitch 才会就新出现的公网主机向该提供商查询信誉——只发送
被查询的 IP。判定结果本地缓存；密钥存于 `snitch.db`（绝不写入日志，
UI 中掩码显示）。没有提供商或密钥则零查询——`ti.check()` 是空操作。

**外部 Webhook（选择性开启，默认关闭）。** 当你粘贴 webhook URL
（Discord、Slack、Telegram 机器人端点或任意 URL）并打开开关后，
warning/critical 告警文本会实时 POST 到该端点。开关关闭时不发送
任何内容。

**本地 LLM 增强（选择性开启，默认关闭）。** 启用 `slm_enabled` 后，
告警*元数据*（类型、进程、目标）可能发送到 Ollama 兼容模型 ——
**仅限 loopback 地址**：后端会拒绝任何不解析到 127.0.0.1 / ::1 的
端点。确定性模板仍为默认。

**IOC 包绝不会由 Snitch 传输。** `GET /security/iocpack` 将本地指标
编码为 Bloom 过滤器 + randomized response（ε≈4.6）并把文件交给你
—— 是否分享由你决定。导入仅返回概率性提示，绝不自动封禁。

**检查探针保持只读且本地。** eBPF 探针、Frida 深度检查、
`perf_event_open` 计数器、模块完整性扫描和沉洞响应器只*读取*本地
状态并监听 127.0.0.1 —— 没有任何数据被发送。

**地理定位 100% 离线。** 只要 `<data_dir>/geo/` 中存在 DB-IP Lite 或
MaxMind GeoLite2 的 `.mmdb` 文件，查询全部在本地完成。没有数据库时，
IP 只是不显示位置。不存在任何 HTTP 地理定位服务——ip-api.com 被移除
正是因为它会把访问过的 IP 以明文发给第三方。

**本地存储的内容：**

| 数据 | 位置 | 保留期 |
|---|---|---|
| 按分钟流量聚合 | `snitch.db` | 24 小时（可用 `retention_hours` 调整） |
| 告警历史 | `snitch.db` | 同一保留窗口 |
| 设置（过滤器、白名单、语言…） | `snitch.db` | 直到你修改 |
| API 令牌 | `api_token.txt`（0600） | Electron 每次启动重新生成 |
| 日志 | `logs/snitch.log`（轮转） | 最大约 5 MB |

数据目录：开发/Docker 为 `data/`；Windows 为 `%LOCALAPPDATA%\Snitch`；
macOS 为 `~/Library/Application Support/Snitch`；Linux 安装后运行时为
`~/.local/share/snitch`。
