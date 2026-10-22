# 第三方声明

[English](THIRD_PARTY_NOTICES.md) | [Français](THIRD_PARTY_NOTICES.md) | [Español](THIRD_PARTY_NOTICES.es.md) | [Deutsch](THIRD_PARTY_NOTICES.de.md) | [Русский](THIRD_PARTY_NOTICES.ru.md) | [日本語](THIRD_PARTY_NOTICES.ja.md) | [Português](THIRD_PARTY_NOTICES.pt-BR.md) | **中文**

Snitch 采用 AGPL-3.0-or-later 许可。以下列出其所用的第三方组件与数据来源及各自许可证。为保持依赖集合的 AGPL 兼容性，我们特意移除了 GPL-2.0-only 代码（Scapy）。

## 运行时依赖

| Component | License |
|---|---|
| FastAPI | MIT |
| Uvicorn | BSD-3-Clause |
| Starlette | BSD-3-Clause |
| Pydantic / pydantic-core | MIT |
| websockets | BSD-3-Clause |
| maxminddb | Apache-2.0 |
| psutil | BSD-3-Clause |
| python-dotenv | BSD-3-Clause |
| aiofiles | Apache-2.0 |
| React | MIT |
| Vite | MIT |
| D3.js | ISC |
| TopoJSON | ISC |
| lucide-react | ISC |
| Electron | MIT |
| electron-builder | MIT |

## 界面组件

| Component | License | Attribution |
|---|---|---|
| Aurora Curtain (`frontend/src/components/AuroraCurtain.jsx`) | MIT | Ported from [SmoothUI](https://smoothui.dev) by Eduardo Lopez ([educlopez/smoothui](https://github.com/educlopez/smoothui)) — adapted to plain JSX (no Tailwind/Motion dependency) |

## 系统库

| Component | License | Notes |
|---|---|---|
| libpcap | BSD-3-Clause | Linux/macOS packet capture — loaded via ctypes, not bundled |
| Npcap | Npcap License | Windows capture driver — **NOT bundled**; user installs from [npcap.com](https://npcap.com). The free version is not redistributable; Snitch only links to the official site. |

## 数据来源

| Data | License | Attribution |
|---|---|---|
| DB-IP Lite (City + ASN) | CC BY 4.0 | "IP Geolocation by [DB-IP](https://db-ip.com)" — recommended default |
| MaxMind GeoLite2 | GeoLite2 EULA | Optional alternative — requires a free MaxMind account; review the EULA before use |
| `classifier/lists/*.txt` (bundled tracker + CDN domain lists) | CC0-1.0 | Curated in this repository — public domain, contributions welcome |

两个 `.mmdb` 数据库均由用户手动放入 `<data_dir>/geo/`。
任何数据库都不会被自动下载或联系。
