# Уведомления о сторонних компонентах

[English](THIRD_PARTY_NOTICES.md) | [Français](THIRD_PARTY_NOTICES.md) | [Español](THIRD_PARTY_NOTICES.es.md) | [Deutsch](THIRD_PARTY_NOTICES.de.md) | **Русский** | [日本語](THIRD_PARTY_NOTICES.ja.md) | [Português](THIRD_PARTY_NOTICES.pt-BR.md) | [中文](THIRD_PARTY_NOTICES.zh-CN.md)

Snitch лицензирован под AGPL-3.0-or-later. Ниже — используемые сторонние компоненты и источники данных с их лицензиями. Код GPL-2.0-only (Scapy) был сознательно удалён ради AGPL-совместимости зависимостей.

## Зависимости времени выполнения

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

## Компоненты интерфейса

| Component | License | Attribution |
|---|---|---|
| Aurora Curtain (`frontend/src/components/AuroraCurtain.jsx`) | MIT | Ported from [SmoothUI](https://smoothui.dev) by Eduardo Lopez ([educlopez/smoothui](https://github.com/educlopez/smoothui)) — adapted to plain JSX (no Tailwind/Motion dependency) |

## Системные библиотеки

| Component | License | Notes |
|---|---|---|
| libpcap | BSD-3-Clause | Linux/macOS packet capture — loaded via ctypes, not bundled |
| Npcap | Npcap License | Windows capture driver — **NOT bundled**; user installs from [npcap.com](https://npcap.com). The free version is not redistributable; Snitch only links to the official site. |

## Источники данных

| Data | License | Attribution |
|---|---|---|
| DB-IP Lite (City + ASN) | CC BY 4.0 | "IP Geolocation by [DB-IP](https://db-ip.com)" — recommended default |
| MaxMind GeoLite2 | GeoLite2 EULA | Optional alternative — requires a free MaxMind account; review the EULA before use |
| `classifier/lists/*.txt` (bundled tracker + CDN domain lists) | CC0-1.0 | Curated in this repository — public domain, contributions welcome |

Обе базы `.mmdb` пользователь размещает вручную в `<data_dir>/geo/`.
Ни одна база не скачивается и не опрашивается автоматически.
