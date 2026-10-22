# 威胁模型

[English](threat-model.md) | [Français](threat-model.md) | [Español](threat-model.es.md) | [Deutsch](threat-model.de.md) | [Русский](threat-model.ru.md) | [日本語](threat-model.ja.md) | [Português](threat-model.pt-BR.md) | **中文**

## Snitch 是什么

本地优先的网络流量可视化工具。它在主机上抓包、归属到进程、**离线**
富化（本地 `.mmdb` 地理定位、本地 DNS/SNI 映射），并由同一进程提供
Web UI 展示。**无云组件、无遥测。**

## 资产

- 你的流量元数据（目标 IP、端口、流量、进程名）。
- API 令牌（Electron 每次启动生成；CLI/Docker 按安装生成）。
- 本地 SQLite 数据库（`traffic`、`alerts_log`、历史、设置）。
- 机器本身的完整性（被攻陷的 Snitch 可能对你撒谎）。

## 信任边界

| 边界 | 威胁 | 缓解 |
|---|---|---|
| 浏览器/远程客户端 → REST | LAN 攻击者或恶意网页读取/控制你的流量视图 | **每个**端点都要求令牌（`Authorization: Bearer`）。默认绑定 `127.0.0.1`。Docker 中 `0.0.0.0` 需要显式 `SNITCH_TOKEN`。 |
| 网页 → `/ws` | 跨站 WebSocket 劫持（CSWSH） | 令牌**＋**`Origin` 白名单（仅回环＋Electron 的 `null` 来源）。 |
| 主机 → 第三方 | 隐私泄露 | 默认零出站调用。GeoIP 下载、威胁情报、webhook、更新检查全部为 **opt-in**，见 PRIVACY.md。 |
| 捕获驱动 → 解析器 | 畸形帧使进程崩溃 | 解析器对每个偏移做边界检查；畸形包返回 `None`，绝不向捕获循环抛异常。 |
| Renderer ↔ main（Electron） | 页面窃取令牌 | `contextIsolation`＋`sandbox`；令牌只经 `ipcRenderer.invoke` 传递，不进入 DOM 或 URL。 |
| 具有文件系统访问的本地攻击者 | 窃取令牌/历史 | 令牌文件权限 `0600`；数据目录位于用户目录；数据库未加密——磁盘加密属 OS 职责。 |

## 已知限制

- **抓包需要 admin/root**，但仅限后端：Electron UI 非特权运行，后端
  通过平台提示提权（Windows `Start-Process -Verb RunAs`、macOS
  `osascript`、Linux `pkexec`），并经认证的 `/shutdown` 端点停止。
- 令牌保护 HTTP/WS，但**无法**防御同账户下能读取
  `data/api_token.txt` 或 Electron IPC 的其他本地进程。
- SQLite 静态数据未加密。
- 告警抑制是本地且静默的——能写库的攻击者可屏蔽告警（防线：文件
  系统权限）。

## 范围之外

恶意载荷（仅解析头部）、内核/驱动被攻陷、恶意管理员。
