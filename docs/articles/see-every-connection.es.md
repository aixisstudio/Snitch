Tu ordenador está hablando con internet ahora mismo. Probablemente docenas de conexiones — sync, telemetría, chequeos de update, tus pestañas abiertas, el ruido de fondo de tus apps. La pregunta "¿qué hace realmente mi máquina?" suena básica, pero intenta responderla y verás que las herramientas son microscópicas (Wireshark) o de pago.

Aquí va una guía práctica para verlo de verdad — incluida la herramienta que construí para ello, [Snitch](https://github.com/aixisstudio/Snitch) (open source, AGPL — declaración: es mía).

## La versión de 60 segundos

```bash
# macOS / Linux — clásico pero crudo
sudo tcpdump -i any -n | head -50        # cada paquete, sin contexto
netstat -anp tcp | grep ESTABLISHED      # solo conexiones actuales
lsof -i -nP | head                       # mapeo proceso → socket

# Windows
netstat -ano | findstr ESTABLISHED
Get-NetTCPConnection -State Established  # PowerShell
```

Estas responden "qué conexiones existen ahora". No te dicen qué app, dónde está el servidor, ni si es sospechoso. Ese hueco es exactamente lo que llena un visualizador.

## El enfoque de visualización

Snitch dibuja cada conexión como un grafo en vivo + mapa mundial:

- **Nodo = tu máquina** en el centro, líneas hacia cada endpoint remoto
- **Cada endpoint etiquetado**: hostname (vía DNS inverso + TLS SNI), país/ciudad geolocalizado — todo offline, desde una base local MaxMind/DB-IP
- **Atribución por app**: la conexión se dibuja hacia el *proceso* que la abrió
- **Timeline**: volumen de tráfico de 15/30/60 min, 24 h de historial en un SQLite local

Lo que lo diferencia de tcpdump: el dato *ya está procesado*. No "paquete a 142.250.74.78" — "Chrome → google.com → Fráncfort".

## Leyendo el mapa: normal vs sospechoso

Un mapa normal: radios hacia Apple/Google/Microsoft/CDNs de tus pestañas, tu router, otros dispositivos LAN.

Lo que destaca:

- **Beaconing** — una conexión que dispara a intervalos regulares (Snitch las marca; es un patrón C2 clásico)
- **Subidas largas a endpoints desconocidos** — datos saliendo constantemente hacia algún sitio que no reconoces
- **Port scans** — un host LAN tocando muchos puertos de tu máquina queda marcado
- **Apps hablando con países sin sentido** para lo que hace la app
- **Trackers** — Snitch cruza hostnames con listas de sufijos de trackers editables y los integra en un privacy score
- **DNS tunneling** — consultas DNS con nombres anormalmente largos o frecuencia inusual

La **detección de anomalías** integrada vigila todo esto automáticamente, y puedes suprimir alertas por regla una vez validado un patrón.

## Instálalo (2 minutos)

```bash
# macOS: descarga la app de releases, o brew
# Windows: instala Npcap → ejecuta snitch-backend.exe como Admin
# Linux / Docker:
docker run --network host ghcr.io/aixisstudio/snitch

# ¿Sin derechos de admin? El modo demo muestra la UI completa con tráfico sintético:
SNITCH_DEMO=1 snitch-backend
```

Todo queda local — API autenticada por token en loopback, cero telemetría, sin cuenta, y cada llamada saliente (GeoIP, updates, threat intel, webhooks) es opt-in. No es frase de marketing; es una codebase AGPL, puedes verificar la ruta de red tú mismo.

Y cuando algo parece mal, puedes actuar — desde la v1.2, Snitch empuja reglas de bloqueo al firewall nativo del SO (netsh / iptables / pf), tiene un interruptor lockdown de un clic, botones kill/suspend, y exportación forense (JSON/CSV/STIX) para lo que cazaste.

## ¿Y luego?

Cuando puedes *ver* el tráfico empieza lo interesante — el pasatiempo favorito de la comunidad es el [hilo "¿Qué atrapaste?"](https://github.com/aixisstudio/Snitch/discussions/39): impresoras hablando con servidores cloud a las 3am, telemetría de TVs, de todo.

Repo: https://github.com/aixisstudio/Snitch — ⭐ si responde la pregunta que se propuso responder.
