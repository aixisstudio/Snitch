# Заготовки к запуску — всё копируется

[English](drafts-launch.md) | [Français](drafts-launch.md) | [Español](drafts-launch.es.md) | [Deutsch](drafts-launch.de.md) | **Русский** | [日本語](drafts-launch.ja.md) | [Português](drafts-launch.pt-BR.md) | [中文](drafts-launch.zh-CN.md)

> **Примечание:** вставляемые тексты оставлены на английском — HN и Reddit англоязычные площадки. Полная каноническая версия EN/FR в `drafts-launch.md`; здесь — оперативная выжимка.

## Show HN — « buzz »-пакет

**Тайминг: вторник 14:30-15:00 по Парижу** (= 8:30-9:00 Нью-Йорк, рабочий вторник = лучший слот недели). НЕ раньше: американская фронт-пейджа должна быть активна.

**URL:** `https://github.com/aixisstudio/Snitch`

### Заголовок — вариант A (дата-хук, рекомендуется)

`Show HN: Snitch – my Mac talked to 347 servers in one idle hour, so I built this`

### Заголовок — вариант B (стори-хук, если A уже занят)

`Show HN: I open-sourced a network monitor — strangers shipped the Windows port`

### Первый комментарий автора — постить В ТЕЧЕНИЕ 60 секунд

Использовать полный авторский комментарий из `drafts-launch.md` — детали стека: ctypes→libpcap, psutil-атрибуция, .mmdb офлайн, FastAPI 127.0.0.1 + токен, `SNITCH_DEMO=1`, история комьюнити Windows-порта.

## Reddit — r/privacy + r/selfhosted в тот же день

**Заголовок:** `Snitch — open-source app that shows every connection your PC makes (world map + process names, 100% local)`

**Тело:** см. `drafts-launch.md` — честность сначала (« I'm the author »), буллеты фич, демо без админа, ссылка на репо. Приложить скриншот карты, если саб позволяет.

## r/netsec — еженедельный Show-тред

Технический угол: конвейер ctypes→libpcap без Scapy, свой парсер ~2K строк, psutil-атрибуция, детект beaconing/DNS-туннелей, оркестрация OS-фаервола. Тон SOC/аналитика, не маркетинг.

## Заготовленные ответы (FAQ-дефенс)

Полные ответы в `drafts-launch.md` на: « а GlassWire/Portmaster/OpenSnitch? », « почему Python, а не Rust? », « захвату нужен root? », « исходящие вызовы? » (все opt-in: GeoIP, обновления, TI, вебхуки), « подпись кода? » (SignPath pending + опубликованные хэши).
