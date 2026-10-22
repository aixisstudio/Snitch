---
title: "Una alternativa gratuita y open source a Little Snitch para Windows (sí, existe)"
description: "Little Snitch es solo macOS. Si estás en Windows o Linux y quieres ver con qué servidores habla tu ordenador, aquí va una comparación honesta de las alternativas reales."
tags: [opensource, privacy, windows, networking]
canonical_url: https://aixisstudio.github.io/Snitch/
---

Tu ordenador habla con cientos de servidores cada día. La mayoría está bien — updates, sync, telemetría que aceptaste. Parte no lo está. La pregunta "¿con quién habla realmente mi máquina?" es la razón por la que Little Snitch lleva 15 años siendo un básico de macOS.

El problema: **Little Snitch no existe en Windows ni Linux.** Y la mayoría de "alternativas" en Windows son de pago, exigen cuenta, o son firewall-first cuando solo querías visibilidad.

Soy el autor de [Snitch](https://github.com/aixisstudio/Snitch), un visualizador de red en tiempo real open source (AGPL) con port de Windows — así que transparencia desde el principio. Este es el estado honesto de las opciones.

## Primero: visualizador vs bloqueador

Vale ser preciso, porque la gente los confunde:

- **Visibilidad** = "muéstrame con quién habla mi máquina" (un mapa, atribución por app, historial)
- **Bloqueo** = "déjame decidir qué está permitido" (reglas de firewall, prompts)

Little Snitch hace ambas. Algunas alternativas hacen una u otra. Snitch hoy hace ambas — la visibilidad es su fuerte, el bloqueo orquesta el firewall del SO.

## La comparación honesta

| Herramienta | OS | ¿Bloquea? | ¿Gratis? | ¿Cuenta? | Notas |
|---|---|---|---|---|---|
| **Little Snitch** | macOS | ✅ | de pago (~59 $) | no | La referencia. Nada igual fuera de macOS. |
| **Snitch** | macOS, Windows, Linux | ✅ reglas OS-firewall + lockdown (best-effort) | ✅ AGPL | no | Mapa mundial en vivo, detección de anomalías, privacy score, threat intel opt-in, export forense. 100% local. |
| **Portmaster** | Win, Linux, macOS | ✅ | ✅ núcleo gratis | no | Bloqueo a nivel DNS + reglas por app. Más pesado — corre como servicio. |
| **OpenSnitch** | Linux | ✅ | ✅ GPL | no | El equivalente Linux más cercano — firewall de aplicación con prompts. |
| **GlassWire** | Windows, Android | ✅ | freemium | empuja cuenta/cloud | UI pulida, pero funciones clave + historial tras paywall e insiste con el nivel cloud. |
| **Wireshark** | todos | ❌ | ✅ | no | El estándar de oro para análisis *profundo* — pero es para disecar paquetes, no para "¿quién llama a casa ahora?". |
| **LuLu** | macOS | ✅ | ✅ | no | Gran firewall gratis para macOS — pero solo macOS, block-first con visualización mínima. |

## Lo que Snitch hace de verdad

En una frase: **un mapa en vivo de cada conexión que hace tu ordenador — qué app, qué servidor, qué país.**

- Force-graph + mapa mundial en tiempo real, geolocalizado offline (MaxMind/DB-IP — ninguna IP sale de tu máquina)
- Atribución por proceso: qué *app* abrió la conexión, no solo la IP
- Detección de anomalías: port scans, patrones beaconing, volúmenes de exfiltración, DNS tunneling
- Privacy score + detección de trackers por listas editables
- Vista de tráfico por app, timeline (15/30/60 min), historial SQLite 24 h
- Escáner LAN pasivo (lee la tabla ARP — muestra cada dispositivo de tu red)
- **Reglas de salida + lockdown**: bloquea IP/CIDR/dominio/proceso/puerto en el firewall del SO (`netsh advfirewall` en Windows), kill/suspend de procesos, exportación forense JSON/CSV/STIX
- **Threat intel opt-in**: AbuseIPDB / OTX / VirusTotal con tu clave API

La parte que importa a la gente de privacidad: **todo es local.** Sin cuenta, sin telemetría, y cada llamada saliente — GeoIP, updates, threat intel, webhooks — es opt-in. La API está autenticada por token y atada a loopback por defecto.

## Lo que Snitch NO hace

Sección de honestidad, porque HN/Reddit preguntará igual:

- **Su bloqueo es orquestación, no un driver.** Desde la v1.2 Snitch empuja reglas `ip`/`cidr`/`domain`/`process`/`port` al firewall nativo del SO (`netsh advfirewall` en Windows, `iptables` en Linux, `pf` en macOS) más un interruptor lockdown — best-effort: las reglas necesitan los mismos privilegios que la captura para aplicarse de verdad, y `pf` no puede matchear procesos. La UI es honesta cuando una regla no pudo aplicarse. Para un firewall de aplicación interactivo maduro, Portmaster (o Little Snitch en macOS) sigue siendo la referencia.
- **Necesita admin/root** para capturar paquetes (inevitable — igual que Wireshark).
- **Disección profunda de paquetes** — para eso, Wireshark sigue ganando. Snitch es la vista a 10.000 pies.

## Instalación en Windows

1. Instala [Npcap](https://npcap.com) (el driver de captura para Windows — requerido, misma dependencia que Wireshark)
2. Baja `Snitch Setup <versión>.exe` de la [última release](https://github.com/aixisstudio/Snitch/releases) — app Electron nativa con tray — o el instalador Lite solo-backend
3. Ejecútalo como Administrador (el instalador maneja el prompt UAC al lanzar el backend)
4. La UI se abre sola — en la ventana Electron, o en tu navegador con Lite

Linux: `docker run --network host ghcr.io/aixisstudio/snitch` — o el tarball de release. macOS: la app empaquetada o `brew`.

## Una nota sobre cómo nació el port de Windows

Mantengo el proyecto en solitario. El port de Windows no fui yo — usuarios reportaron bugs con análisis de causa raíz incluido, y un desconocido envió tres PRs que arreglaron captura + la interfaz correcta + el crash de arranque. Open source funcionando como promete. v1.0.5 salió la semana pasada.

Si lo pruebas y caza algo interesante, hay una [discusión "¿Qué atrapaste?"](https://github.com/aixisstudio/Snitch/discussions/39) en el repo. Y si te sirve, una ⭐ en [GitHub](https://github.com/aixisstudio/Snitch) ayuda de verdad a que el proyecto se encuentre.

**Repo:** https://github.com/aixisstudio/Snitch — AGPL, UI y docs en 8 idiomas (EN/FR/ES/DE/RU/JA/PT-BR/中文).
