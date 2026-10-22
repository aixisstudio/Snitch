# 安全策略

[English](SECURITY.md) | [Français](SECURITY.md) | [Español](SECURITY.es.md) | [Deutsch](SECURITY.de.md) | [Русский](SECURITY.ru.md) | [日本語](SECURITY.ja.md) | [Português](SECURITY.pt-BR.md) | **中文**

## 漏洞报告

请通过 GitHub 的「Report a vulnerability」功能（Security 标签页）或
仓库资料页中列出的维护者邮箱私下报告漏洞。请勿为安全问题开设公开
issue。

## 本地攻击面

API 会暴露你的完整流量图——它从设计上就受到保护：

- **令牌认证**：每个 REST 端点和 WebSocket 都要求令牌
  （`X-Snitch-Token` 或 `?token=`）。Electron 每次启动生成；其他模式
  下以 0600 权限持久化。
- **默认仅回环绑定**（`127.0.0.1`），适用于所有模式。
- **Origin 白名单**：WebSocket 握手中仅允许回环主机 + `null`，阻止
  跨站 WebSocket 劫持。
- **受限 CORS** —— 仅回环来源，不带凭据。
- **按代理令牌** —— `POST /ingest/enroll` 为集群代理签发专用 `sagt_…` 令牌；仅存哈希、可经 `/ingest/revoke` 撤销。代理令牌只能以自己名义提交事件 —— 无读取、无冒名。

## 权限

抓包需要提升权限——但只有后端持有这些权限。打包后的 Electron 应用
在所有 OS 上以非特权运行 UI，仅通过平台原生提示提升后端：

- **Windows：**`Start-Process -Verb RunAs`（每次启动一次 UAC 提示）＋ Npcap（由你从 npcap.com 安装）
- **macOS：**`osascript … with administrator privileges`（原生密码对话框）
- **Linux：**`pkexec`（polkit 对话框）；无 polkit 时回退为非特权运行

被提权的子进程通过已认证的 `/shutdown` 端点停止，因为非特权进程
无法向其发信号。拒绝提示时会提供重试 / 无抓包继续，而不是直接退出。

## 依赖

Scapy 已移除（GPL-2.0-only 加上较大的攻击面）。抓包是对 libpcap 的
极简 ctypes 绑定加上我们自研的带边界检查的解析器。依赖已锁定并由
Dependabot 监控。
