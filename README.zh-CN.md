<div align="center">

# Snitch

**追踪每一个隐藏的网络连接。**

[English](README.md#english) | [Français](README.md#français) | **中文**

⭐ **如果 Snitch 对你有帮助，一颗 Star 意义重大！** ⭐

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Platform: macOS](https://img.shields.io/badge/Platform-macOS-blue.svg)]()
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue.svg)]()
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux%20(Docker)-blue.svg)]()
[![Version](https://img.shields.io/badge/Version-1.0.5-green.svg)]()
[![GitHub release](https://img.shields.io/github/v/release/aixisstudio/Snitch?include_prereleases&label=release)](https://github.com/aixisstudio/Snitch/releases/latest)
[![Downloads](https://img.shields.io/github/downloads/aixisstudio/Snitch/total?color=brightgreen&style=flat)](https://github.com/aixisstudio/Snitch/releases/latest)
[![GitHub stars](https://img.shields.io/github/stars/aixisstudio/Snitch?style=flat-square&logo=github)](https://github.com/aixisstudio/Snitch/stargazers)

<!-- EN: Live capture of the demo mode (SNITCH_DEMO=1) — synthetic traffic only.
     ZH: 演示模式 (SNITCH_DEMO=1) 的实时截图 — 仅为合成流量。 -->
![Snitch live graph — LAN perimeter, geolocated hosts, alerts](docs/assets/demo.gif)

</div>

---

## 简介

**Snitch** 是一款实时网络流量可视化工具。
它能让你看到电脑的每一个连接——连接了谁、对方在哪里、以及是哪个应用程序发起的。

整个界面提供 **英语和法语** 两种语言：使用右上角工具栏的 `EN / FR` 切换。

### 为什么选择 Snitch？

- **对比 Little Snitch / Lulu** —— 它们是 macOS 防火墙，用于*阻止*连接；Snitch 则*可视化并解释*流量，且跨平台、免费、开源。
- **对比 GlassWire** —— Snitch 免费、开源（AGPL），无需注册账号，**零对外网络请求**——连地理位置查询都是离线完成。
- **对比 Wireshark** —— Snitch 提供任何人都能读懂的实时高层概览，而不是原始数据包剖析。
- **对比云端监控方案** —— 一切运行在 `127.0.0.1` 并受令牌保护；你的流量数据永远不会离开本机。

### 功能特性

| 功能 | 说明 |
|---|---|
| 力导向图 | 实时节点图——你的机器居中，每个连接为一个节点 |
| 世界地图 | 交互式地球仪上的地理位置 IP 与动画弧线 |
| 15/30/60 分钟时间线 | 本地 SQLite 滑动历史（保留 24 小时） |
| 异常检测 | 标记端口扫描、信标回连（beaconing）、潜在数据外泄 |
| 进程归属 | 知道哪个应用产生了哪条流量（每条连接前 5 名） |
| 局域网扫描 | 通过系统 ARP 表被动发现设备（无广播扫描） |
| 隐私评分 | 实时评估你的出站流量暴露程度 |
| 应用视图 | 每个进程的目的地、流量与 60 分钟历史 |
| 告警抑制 | 可持久化的「忽略此主机/类型」规则，界面内可管理 |
| 设置面板 | 语言、保留时长、过滤器、需授权的 GeoIP 下载、诊断 |
| 追踪器识别 | 后缀匹配的域名列表，以可编辑数据文件形式提供（`backend/classifier/lists/`） |
| 带宽监控 | 实时 MB/s 迷你曲线 |
| EN / FR 界面 | 完整双语界面，一键切换 |

### 下载

| 平台 | 安装方式 |
|---|---|
| **macOS（Apple Silicon）** | `brew install --cask aixisstudio/tap/snitch` —— 或 [Snitch-1.0.5-macos-arm64.zip](https://github.com/aixisstudio/Snitch/releases/download/v1.0.5/Snitch-1.0.5-macos-arm64.zip) |
| **Linux** | `sudo docker compose up --build` —— 见 [Docker (Linux)](#docker-linux) |
| **Windows** | [snitch-backend-windows-latest.tar.gz](https://github.com/aixisstudio/Snitch/releases/latest)（后端，需要 [Npcap](https://npcap.com/)）—— 或从源码构建，见 [构建安装包](#构建安装包) |

或直接获取最新版本：**[github.com/aixisstudio/Snitch/releases](https://github.com/aixisstudio/Snitch/releases)**

> **macOS 首次运行** — Snitch 为 ad-hoc 签名、未经过公证（没有付费 Apple 开发者证书）。上面的 `brew install --cask` 会帮你移除隔离标记。若使用手动下载的 zip：右键点击 → **打开**，或运行 `xattr -dr com.apple.quarantine /Applications/Snitch.app`。首次启动时 Snitch 会请求管理员密码**一次**——抓包需要该权限，与 tcpdump/Wireshark 相同；界面本身不需要特权。

### 技术栈

| 层 | 技术 |
|---|---|
| 数据包捕获 | ctypes → libpcap —— Npcap（Windows）/ libpcap（Linux/macOS）—— 自研解析器（IPv4/IPv6/TCP/UDP/DNS/TLS-SNI） |
| 后端 API | FastAPI —— WebSockets —— SQLite |
| 前端 | React 19 —— Vite —— D3.js v7 —— TopoJSON |
| 桌面封装 | Electron 44 |
| 地理位置 | **仅离线** —— 内置 gzip 压缩的 DB-IP Lite（CC BY 4.0），首次运行自动解压；也支持 MaxMind GeoLite2 `.mmdb` |

### 安全与隐私

- **API 令牌** —— 每个 REST 端点和 WebSocket 都需要令牌。Electron 每次启动自动生成；在 Docker/浏览器模式中，令牌会在后端日志中打印一次，并存入 `data/api_token.txt`。通过 `http://localhost:8000/?token=<TOKEN>` 打开界面（或按提示输入）。
- **默认仅监听回环** —— API 在任何模式下都只绑定 `127.0.0.1`。仅当你明确需要局域网访问时才设置 `SNITCH_BIND=0.0.0.0`（令牌认证依然生效）。
- **CORS/WebSocket 来源白名单** —— 仅允许 `localhost:5173`、后端自身来源以及 Electron `file://` 页面连接。
- **地理位置完全离线** —— *没有*在线查询。DB-IP Lite（[CC BY 4.0](https://db-ip.com/db/lite.php)）以 gzip 形式内置在 `backend/data/geo/`，首次启动自动解压到 `<data_dir>/geo/`——开箱即用，零网络请求。你也可以把更新的 `GeoLite2-City.mmdb`/`GeoLite2-ASN.mmdb`（MaxMind）放入 `<data_dir>/geo/`，或在设置面板下载最新版 DB-IP Lite（需明确授权，是唯一可能的外联请求）。
- **所有数据留在本地** —— `snitch.db`（24 小时滑动窗口，可通过 `retention_hours` 配置）和 `data/logs/snitch.log` 永远不会离开本机。零遥测。唯一可能的外联请求是选择加入的 DB-IP Lite 下载（设置 → “下载 DB-IP Lite”），需要明确点击。
- **设置持久化** —— 端口过滤器、排除进程、IP 白名单、语言和保留时长存储于 SQLite，重启后恢复。
- **告警抑制** —— 每条告警提供「忽略此类型/主机」操作；抑制规则被持久化（`alert_suppressions` 表），在告警发出或记录前生效，重启后依然有效，通过 `POST /alerts/ignore` / `DELETE /alerts/ignore` / `GET /alerts/ignore` 管理。
- **历史记录** —— 按主机与按进程的每分钟字节/包聚合并存储于 SQLite（`host_history`、`process_history`），在保留窗口内驱动应用视图与 `GET /history/host/{ip}` / `GET /history/process/{name}`。
- **诊断** —— `GET /diagnostics` 返回运行时 JSON 快照（捕获状态、GeoIP 数据库状态、接口、版本、路径），不含任何机密；设置面板可导出或打开日志目录（Electron）。
- **局域网设备** 通过系统 ARP 表被动发现——不做主动广播扫描。设备名称来自设备自身广播：mDNS `*.local`（Apple/Linux）、LLMNR 与 NetBIOS 名称（Windows）、DHCP 主机名选项，外加完整的离线 IEEE OUI 厂商表；网关自动识别为路由器。
- 完整威胁模型见 [docs/threat-model.md](docs/threat-model.md)。

### Docker（Linux）

Docker 部署面向不想安装任何额外依赖的 Linux 用户。
抓包通过 `network_mode: host` 工作——容器可以看到真实的主机流量。

> **注意：** Mac/Windows 上的 Docker Desktop 运行在虚拟机内，**无法**捕获主机流量。请在这些平台上使用 Electron 应用。

```bash
# 克隆并进入仓库
git clone https://github.com/aixisstudio/Snitch.git snitch
cd snitch

# 可选：把你的 MaxMind GeoLite2-City.mmdb 放入 data/ 以启用离线地理定位
mkdir -p data

# 构建并运行（需要 Docker + root/sudo 权限进行原始套接字抓包）
sudo docker compose up --build
```

获取 API 令牌（启动时打印一次，或 `cat data/api_token.txt`），然后在浏览器打开 **http://localhost:8000/?token=TOKEN**。

后台运行：`sudo docker compose up -d --build`

Docker 限制：
- 进程归属仅限于容器内进程（默认不共享主机 PID）
- 部分网络配置下局域网扫描可能不可用

### 开发

环境要求：
- Python 3.11+
- Node.js 18+
- 已安装 [Npcap](https://npcap.com/)（仅 Windows）
- 后端需要管理员/root 终端（原始数据包捕获）

> **演示模式** —— 用 `SNITCH_DEMO=1` 启动后端，将合成流量注入真实管道：无需 root、无需 libpcap、不触碰真实数据包。适合截图、测试和预览。

```bash
# 后端（管理员终端）— API 位于 http://127.0.0.1:8000
cd backend
pip install -r requirements.txt
python run_backend.py   # 打印一次 API 令牌

# 前端（另一个终端）— 界面位于 http://localhost:5173/?token=TOKEN
cd frontend
npm install
npm run dev

# Electron（可选，管理员终端）— 令牌自动注入
cd electron
npm install
set VITE_DEV=1   # Windows
# VITE_DEV=1     # macOS/Linux
npx electron .
```

测试：

```bash
cd backend && pip install -r requirements-dev.txt && python -m pytest tests/ -v
cd frontend && npm test
```

### 构建安装包

```bash
# 1 — 编译后端（PyInstaller）
cd backend
pip install -r requirements.txt pyinstaller
pyinstaller backend.spec --distpath ../dist/backend

# 2 — 构建前端
cd ../frontend
npm ci
npm run build

# 3 — 构建 Electron 安装包（图标自动生成）
cd ../electron
npm ci
npm run build       # NSIS 安装包 -> dist/installer/Snitch Setup <version>.exe
# npm run build:dir # 免安装目录 -> dist/installer/win-unpacked/
```

### 项目结构

```
snitch/
├── backend/       Python FastAPI + libpcap 捕获引擎（ctypes，自研解析器）
├── frontend/      React + D3.js 界面（EN/FR）
├── electron/      Electron 封装（main、splash、preload）
├── data/          运行时数据（SQLite 数据库、geo/ 中的 .mmdb 地理库）
└── dist/          编译产物（后端可执行文件、安装包）
```

---

## 许可证

[AGPL-3.0](LICENSE) —— 免费使用、修改自由。第三方声明见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 作者

由 **aiXis** 构建 — [aixis.fr](https://aixis.fr/) · [github.com/aixisstudio](https://github.com/aixisstudio)

⭐ **如果 Snitch 对你有帮助，一颗 Star 意义重大！** ⭐
