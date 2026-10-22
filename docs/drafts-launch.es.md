# Brouillons de lanzamiento — todo copiable

[English](drafts-launch.md) | [Français](drafts-launch.md) | **Español** | [Deutsch](drafts-launch.de.md) | [Русский](drafts-launch.ru.md) | [日本語](drafts-launch.ja.md) | [Português](drafts-launch.pt-BR.md) | [中文](drafts-launch.zh-CN.md)

> **Nota:** los textos a pegar se dejan en inglés — HN y Reddit son plataformas anglófonas. La versión canónica completa EN/FR está en `drafts-launch.md`; aquí el resumen operativo.

## Show HN — el paquete « buzz »

**Timing: martes 14h30-15h00 París** (= 8h30-9h Nueva York, martes laborable = el mejor hueco de la semana). NO antes: la front page US debe estar activa.

**URL:** `https://github.com/aixisstudio/Snitch`

### Título — opción A (data hook, recomendado)

`Show HN: Snitch – my Mac talked to 347 servers in one idle hour, so I built this`

### Título — opción B (story hook, si A ya fue usado)

`Show HN: I open-sourced a network monitor — strangers shipped the Windows port`

### Primer comentario de autor — postear EN LOS 60 SEGUNDOS tras enviar

Usar el comentario autor completo de `drafts-launch.md` (sección « Premier commentaire auteur ») — stack details: ctypes→libpcap, psutil attribution, .mmdb offline, FastAPI 127.0.0.1 + token, `SNITCH_DEMO=1`, la historia del port de Windows comunitario.

## Reddit — r/privacy + r/selfhosted el mismo día

**Título:** `Snitch — open-source app that shows every connection your PC makes (world map + process names, 100% local)`

**Cuerpo:** ver `drafts-launch.md` — honestidad primero (« I'm the author »), bullets de features, demo sin admin, link repo. Añade captura del mapa si el sub lo permite.

## r/netsec — Show thread semanal

Angulo técnico: pipeline ctypes→libpcap sin Scapy, parser propio ~2K líneas, atribución psutil, detección beaconing/DNS-tunnel, orquestación firewall OS. Tono SOC/analista, no marketing.

## Respuestas preparadas (FAQ defensiva)

Ver `drafts-launch.md` para las respuestas completas a: « ¿y GlassWire/Portmaster/OpenSnitch? », « ¿por qué Python y no Rust? », « ¿la captura requiere root? », « ¿llamadas salientes? » (todas opt-in: GeoIP, updates, TI, webhooks), « ¿firma de código? » (SignPath en curso + hashes publicados).
