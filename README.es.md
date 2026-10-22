<div align="center">

# Snitch

**Rastrea cada conexión oculta.**

[English](README.md#english) | [Français](README.md#français) | **Español** | [Deutsch](README.de.md) | [Русский](README.ru.md) | [日本語](README.ja.md) | [Português](README.pt-BR.md) | [中文](README.zh-CN.md)

⭐ **Si Snitch te ayuda, ¡una estrella significa mucho!** ⭐

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Platform: macOS](https://img.shields.io/badge/Platform-macOS-blue.svg)]()
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue.svg)]()
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux%20(Docker)-blue.svg)]()
[![GitHub release](https://img.shields.io/github/v/release/aixisstudio/Snitch?include_prereleases&label=release)](https://github.com/aixisstudio/Snitch/releases/latest)
[![GitHub stars](https://img.shields.io/github/stars/aixisstudio/Snitch?style=flat-square&logo=github)](https://github.com/aixisstudio/Snitch/stargazers)

<!-- ES: Captura en vivo del modo demo (SNITCH_DEMO=1) — solo tráfico sintético. -->
![Snitch live graph — LAN perimeter, geolocated hosts, alerts](docs/assets/demo.gif)

</div>

---

**Snitch** es un visualizador de tráfico de red en tiempo real.
Mira cada conexión que hace tu ordenador: con quién habla, dónde está y qué aplicación es la responsable.

Toda la interfaz está disponible en **English, Français, Español, Deutsch, Русский, 日本語, Português (BR) y 简体中文**: usa el selector de idioma en la barra de herramientas.

### ¿Por qué Snitch?

- **vs Little Snitch / Lulu** — misma idea (visibilidad por app + reglas de bloqueo saliente), pero Snitch es multiplataforma, gratuito y de código abierto. El bloqueo se orquesta a través del firewall nativo del SO (`netsh` / `iptables` / `pf`) — Snitch nunca filtra en espacio de usuario.
- **vs GlassWire** — Snitch es gratuito, open-source (AGPL), sin cuenta y con **cero llamadas salientes** por defecto; incluso la geolocalización es offline.
- **vs Wireshark** — Snitch ofrece una vista de alto nivel en vivo que cualquiera puede leer, en lugar de disección cruda de paquetes.
- **vs monitores en la nube** — todo corre en `127.0.0.1` tras un token; tus datos de tráfico nunca salen de la máquina.

### Funciones

| Función | Descripción |
|---|---|
| Grafo de fuerza | Grafo de nodos en vivo — tu máquina al centro, cada conexión un nodo |
| Mapa mundial | IPs geolocalizadas con arcos animados en un globo interactivo |
| Timeline 15/30/60 min | Historial deslizante en SQLite local (retención 24 h) |
| Detección de anomalías | Escaneos de puertos, beaconing (C2 a intervalo regular), exfiltración potencial |
| Detección avanzada | Heurística de túnel DNS, puertos en claro, desviación de baseline de país por app |
| Orquestación de firewall | Reglas de bloqueo (IP/CIDR/dominio/proceso/puerto) aplicadas al firewall del SO — `netsh`/`iptables`/`pf`, persistidas, contadores por regla |
| Modo lockdown | Interruptor de pánico — marca y bloquea todo el tráfico saliente público, la LAN sigue activa |
| Respuesta a incidentes | Matar / suspender un proceso, bloquear una IP — un clic desde el detalle |
| Threat intelligence | Verificaciones de reputación **opt-in** (AbuseIPDB / AlienVault OTX / VirusTotal) con tu propia clave API — desactivado por defecto, resultados en caché |
| Auditoría de seguridad | Informe de hardening integrado — puntuación, hallazgos, recomendaciones en lenguaje claro |
| Export forense | Paquete de investigación en un clic — árbol de procesos + SHA-256 del binario, historial y alertas asociadas (JSON/CSV/STIX) |
| Webhooks de alertas | Reenvío **opt-in** de alertas warning/críticas a Discord, Slack, Telegram o cualquier endpoint |
| Atribución de procesos | Sabe qué app genera qué tráfico (top 5 por conexión) |
| Escáner LAN | Descubrimiento pasivo vía tabla ARP del sistema (sin escaneos broadcast) |
| Privacy Score | Puntuación en vivo de la exposición de tu tráfico saliente |
| Vista por aplicación | Destinos, volúmenes e historial de 60 min por proceso |
| Supresión de alertas | Reglas «ignorar host/tipo» persistidas, gestionables en la UI |
| Panel de ajustes | Idioma, retención, filtros, descarga GeoIP con consentimiento, diagnósticos |
| Detección de trackers | Listas de dominios por sufijo en archivos editables (`backend/classifier/lists/`) |
| Monitor de ancho de banda | Sparkline de MB/s en vivo |
| UI en 8 idiomas | EN · FR · ES · DE · RU · JA · PT-BR · ZH-CN — cambio con un clic, locales en `frontend/src/locales/` |
| Tema claro / oscuro | Sigue la preferencia del SO, conmutación manual persistida |
| Actualización automática | La app de escritorio consulta GitHub Releases (desactivable en Ajustes; `SNITCH_NO_UPDATE=1`) |
| QUIC / HTTP/3 | Flujos UDP/443 etiquetados honestamente — el SNI QUIC está cifrado y nunca se lee |
| Watchlist | Fija IPs/dominios — alerta dedicada en cuanto el tráfico los toca |
| Alerta de pico de subida | Techo de MB/min por proceso con umbral ajustable |
| Selector de interfaz | Elige qué adaptador se escucha — sin variable de entorno |
| Contexto Wi-Fi | SSID actual en la barra de herramientas |
| Export | Grafo + alertas a JSON/CSV, un clic |

### Descarga

| Plataforma | Paquete |
|---|---|
| **macOS (Apple Silicon)** | `brew install --cask aixisstudio/tap/snitch` — o **Snitch.app** zip/dmg desde la [última release](https://github.com/aixisstudio/Snitch/releases/latest) |
| **Linux** | **Snitch AppImage / .deb / .rpm / .snap** desde la [última release](https://github.com/aixisstudio/Snitch/releases/latest) — o `sudo docker compose up --build`, ver [Docker (Linux)](#docker-linux) |
| **Headless (cualquier SO)** | `brew install aixisstudio/tap/snitch` → daemon `snitchd` (servidores/VM, sin GUI) |
| **Windows** | **Snitch Setup** `.exe` — instalador NSIS de un clic (app nativa, prompt UAC al lanzar, detección de Npcap integrada) desde la [última release](https://github.com/aixisstudio/Snitch/releases/latest). Alternativa lite: `Snitch-Lite-Setup` (backend + UI en navegador). Requiere [Npcap](https://npcap.com/) |
| **Todas (1 clic)** | [Pinokio](https://pinokio.co/apps/github-com-aixisstudio-snitch) — instala dependencias, lanza el backend, abre la UI |

O descarga la última release: **[github.com/aixisstudio/Snitch/releases](https://github.com/aixisstudio/Snitch/releases)**

> **Primer arranque en macOS** — Snitch está firmado ad-hoc, no notarizado (sin Developer ID de pago). El `brew install --cask` elimina la cuarentena por ti. Para el zip manual: clic derecho → **Abrir**, o `xattr -dr com.apple.quarantine /Applications/Snitch.app`. En el primer arranque pide tu contraseña de admin **una vez** — la captura de paquetes la exige, como tcpdump/Wireshark; la UI sigue sin privilegios.
>
> **Firma de código en Windows** — los builds de Windows serán firmados con Authenticode gracias a un certificado open source gratuito ofrecido por la [SignPath Foundation](https://signpath.org) vía [SignPath.io](https://signpath.io) (solicitud enviada, pendiente de aprobación). Hasta el primer build firmado, SmartScreen puede advertir — clic en **Más información → Ejecutar de todas formas**.

### Stack

| Capa | Tecnología |
|---|---|
| Captura de paquetes | ctypes → libpcap — Npcap (Windows) / libpcap (Linux/macOS) — parser propio (IPv4/IPv6/TCP/UDP/DNS/TLS-SNI) |
| API backend | FastAPI — WebSockets — SQLite |
| Frontend | React 19 — Vite — D3.js v7 — TopoJSON |
| Envoltorio de escritorio | Electron 44 |
| Geolocalización | **Solo offline** — DB-IP Lite (CC BY 4.0) empaquetada gzip en `backend/data/geo/`, extraída en el primer arranque; también admite `.mmdb` de MaxMind GeoLite2 |

### Seguridad y privacidad

- **Token de API** — cada endpoint REST y el WebSocket exigen un token. Electron lo genera por lanzamiento; en Docker/navegador se imprime una vez en los logs del backend y se guarda en `data/api_token.txt`. Abre la UI con `http://localhost:8000/?token=<TOKEN>`.
- **Solo loopback por defecto** — la API escucha en `127.0.0.1` en todos los modos. Usa `SNITCH_BIND=0.0.0.0` solo si quieres explícitamente acceso LAN (el token sigue siendo obligatorio).
- **Allowlist CORS/Origin de WebSocket** — solo `localhost:5173`, el propio origen del backend y las páginas `file://` de Electron pueden conectar.
- **Geolocalización 100 % offline** — *ninguna* consulta en línea. DB-IP Lite ([CC BY 4.0](https://db-ip.com/db/lite.php)) se autoextrae a `<data_dir>/geo/`; puedes soltar `.mmdb` de MaxMind más recientes o descargar DB-IP Lite desde Ajustes (consentimiento explícito; las demás llamadas salientes opt-in — threat intel, webhooks, actualizaciones — están en [PRIVACY.md](PRIVACY.md)).
- **Todos los datos se quedan en local** — `snitch.db` (ventana deslizante de 24 h, `retention_hours`) y `data/logs/snitch.log` nunca salen de la máquina. Sin telemetría. Cada llamada saliente es opt-in.
- **Los ajustes persisten** — filtros de puertos, procesos excluidos, whitelist IP, reglas de firewall, idioma y retención se guardan en SQLite y se restauran al reiniciar.
- **Reglas de firewall best-effort** — el backend pilota el firewall del SO (`netsh advfirewall`, `iptables`, anchors `pf`); sin privilegios la regla se conserva y se evalúa para *visibilidad* (alertas BLOCKED_ATTEMPT) marcada «no aplicada», sin fingir aplicación real. El lockdown mantiene loopback + LAN para que la UI siga accesible.
- **Threat intel y webhooks opt-in** — desactivados por defecto; activar un proveedor o un webhook añade llamadas salientes, documentadas en [PRIVACY.md](PRIVACY.md).
- **Supresión de alertas** — cada alerta ofrece «Ignorar este tipo/host»; reglas persistidas (`alert_suppressions`), gestionables vía `POST|DELETE|GET /alerts/ignore`.
- **Historial** — agregados por minuto, por host y por proceso en SQLite (`host_history`, `process_history`), alimentando la vista por aplicación y `GET /history/*`.
- **Diagnósticos** — `GET /diagnostics` devuelve una instantánea JSON del runtime sin secretos; exportable desde Ajustes.
- **Dispositivos LAN** descubiertos pasivamente vía tabla ARP — sin escaneo broadcast activo. Los nombres se aprenden de lo que los propios dispositivos emiten: mDNS `*.local`, LLMNR/NetBIOS, hostname DHCP, tabla IEEE OUI offline; la puerta de enlace se detecta como router.
- Ver [docs/threat-model.md](docs/threat-model.md) para el modelo de amenaza completo y [docs/FIREWALL.md](docs/FIREWALL.md) para la suite de seguridad.

### Docker (Linux)

El despliegue Docker es para usuarios Linux que quieren ejecutar Snitch sin instalar nada más.
La captura funciona vía `network_mode: host` — el contenedor ve el tráfico real del host.

**Imagen precompilada** — sin clonar ni compilar:

```bash
sudo docker run --network host --cap-add NET_ADMIN --cap-add NET_RAW \
  -v snitch-data:/app/data ghcr.io/aixisstudio/snitch
```

> **Nota:** Docker Desktop en Mac/Windows corre dentro de una VM y no puede capturar el tráfico del host. Usa la app Electron en esas plataformas.

Obtén el token de API (impreso una vez al inicio, o `cat data/api_token.txt`) y abre **http://localhost:8000/?token=TOKEN** en tu navegador.
En segundo plano: `sudo docker compose up -d --build`

Limitaciones de Docker: la atribución de procesos se limita a los del contenedor; el escáner LAN puede no estar disponible según la red.

### Desarrollo

Requisitos: Python 3.11+, Node.js 18+, [Npcap](https://npcap.com/) (solo Windows), terminal con privilegios para el backend.

> **Modo demo** — `SNITCH_DEMO=1` alimenta tráfico sintético por el pipeline real: sin root, sin libpcap, sin paquetes reales. Ideal para capturas y pruebas.

```bash
cd backend && pip install -r requirements.txt && python run_backend.py
cd frontend && npm install && npm run dev   # http://localhost:5173/?token=TOKEN
cd electron && npm install && VITE_DEV=1 npx electron .
```

Tests:

```bash
cd backend && pip install -r requirements-dev.txt && python -m pytest tests/ -v
cd frontend && npm test
```

### Estructura del proyecto

```
snitch/
├── backend/       FastAPI + captura libpcap (ctypes, parser propio)
├── frontend/      UI React + D3.js (8 idiomas)
├── electron/      Envoltorio Electron (main, splash, preload)
├── data/          Datos en ejecución (SQLite, .mmdb en geo/)
└── dist/          Salida compilada (exe backend, instalador)
```

---

### Enterprise y flota

Snitch también funciona headless para despliegues SOC — todo por archivos y gratis:

- **Security-as-Code** — un `snitch.toml` (o `$SNITCH_CONFIG`) sobreescribe todos los ajustes; provisiona flotas con Ansible (`deploy/ansible/`), Puppet, Salt o GPO.
- **Agente Rust** — un daemon sin dependencias (`agent/`) envía sockets a `POST /ingest/events` con atribución `/proc`→PID en Linux; `POST /ingest/enroll` emite tokens `sagt_…` de un solo uso (hasheados, revocables).
- **Nativo SIEM** — syslog CEF o RFC 3164, webhooks genéricos y `GET /forensics/export?format=ecs` (NDJSON Elastic Common Schema) alimentan Wazuh, Splunk, Graylog, Loki y Elastic. Importación Sigma (`POST /alerts/rules/sigma`), exportación YARA-L (`GET /alerts/rules/yaral`).
- **Vista de flota** — `GET /remote/fleet` fusiona las auditorías de todos los pares; un chart Helm (`deploy/helm/snitch`) ejecuta el colector en el clúster.
- **Feeds TI gratuitos** — `POST /firewall/blocklist` importa listas de dominios (StevenBlack) e IPs (Blocklist.de, URLhaus/Feodo); `ti_feeds` programa actualizaciones automáticas.

Recetas paso a paso en [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

## Licencia

AGPL v3 — ver [LICENSE](LICENSE). Libre de usar, estudiar y modificar; las obras derivadas deben permanecer open source bajo AGPL v3.

## Historial de estrellas

[![Star History Chart](https://api.star-history.com/svg?repos=aixisstudio/Snitch&type=Date)](https://star-history.com/#aixisstudio/Snitch&Date)
