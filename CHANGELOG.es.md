# Registro de cambios

[English](CHANGELOG.md) | [Français](CHANGELOG.md) | **Español** | [Deutsch](CHANGELOG.de.md) | [Русский](CHANGELOG.ru.md) | [日本語](CHANGELOG.ja.md) | [Português](CHANGELOG.pt-BR.md) | [中文](CHANGELOG.zh-CN.md)

Todos los cambios notables de Snitch.

El formato sigue [Keep a Changelog](https://keepachangelog.com/).

## [1.5.0] — 2026-10-22

### Añadido

- **Inspección pasiva del certificado TLS** — `capture/tlscert.py` reensambla el mensaje `Certificate` del servidor a través de segmentos TCP (limitado a 16 KiB/flujo) y lee el DER hoja: emisor/sujeto, flag autofirmado, SANs, validez → `TLS_CERT` si autofirmado o mismatch SAN/SNI. TLS 1.3 se reporta honestamente como inobservable — sin MITM, sin descifrado.
- **Heurística de túnel ICMP** — ecos repetidos con payloads grandes (≥24 B, 3+ en 5 min) → `ICMP_TUNNEL` (firma ptunnel/icmpsh).
- **Detección de alta entropía** — cabeceras de payload casi aleatorias (≥4,7 bits/byte) en sockets en claro → `HIGH_ENTROPY` (indicio de cifrado encubierto/estego).
- **Isolation Forest (Python puro)** — `detection/iforest.py` + `mlflow.py` puntúan flujos salientes con 6 features; `ML_ANOMALY` a partir de score 0,62, inerte bajo 384 flujos aprendidos.
- **Ask-on-connect (Linux NFQUEUE, opt-in)** — `ask_enabled` retiene nuevos flujos salientes en la cola 7 hasta `POST /security/ask/verdict` — veredicto real, el timeout droppea por defecto.
- **Enforcement eBPF de egress** — `detection/ebpf_enforce.py` + `POST /security/ebpf/isolate|block` — drops en kernel solo para procesos del cgroup snitch.
- **Prueba de hollowing** — `POST /security/hollow` compara páginas ejecutables en RAM con el fichero en disco (Linux, `/proc`).
- **Sincronización IOC entre pares** — `gossip_peers` + `gossip_enabled`: paquetes Merkle salados cada 5 min a pares explícitamente listados — solo compromisos hash, sin discovery.
- **Syslog** — `syslog_addr` (UDP o `tcp://`) reenvía alertas warning/críticas como RFC 3164 — camino SIEM/Wazuh.
- **Reglas geo + auto-bloqueo** — reglas custom con `asn`/`country` (mmdb local) y `action:"block"` instalan reglas de firewall reales por IP coincidente.
- **Alertas accionables + UI de ajustes** — Bloquear IP / Matar / Suspender / Permitir-Denegar por alerta; nuevos controles en ajustes (syslog, ask, pares).
- **Backend nftables + firejail** — `nft` cuando falta iptables (tabla `inet snitch` dedicada); `firejail --net=none` como fallback de sandbox.

## [Unreleased]

### Añadido

- **Orquestación del firewall de salida** — reglas de usuario (`ip`, `cidr`, `domain`, `process`, `port`) aplicadas al firewall nativo del SO al mejor esfuerzo: `netsh advfirewall` en Windows, `iptables` en Linux, ancla `pf` generada en macOS. Persistidas, reaplicadas al inicio, `applied=False` honesto sin privilegios (el matching y los contadores `BLOCKED_ATTEMPT` siguen activos).
- **Lockdown** — interruptor de pánico que corta el tráfico saliente hacia IPs públicas preservando loopback/LAN (cadena `SNITCH_LOCK` en Linux, reglas `netsh`, ancla `pf`).
- **Acciones de proceso** — `POST /processes/kill` y `POST /processes/suspend` (por PID, rechaza PID ≤ 3 y al propio Snitch); botones kill/suspend en la lista de procesos.
- **Threat intelligence (opt-in)** — verificación de reputación contra AbuseIPDB, AlienVault OTX o VirusTotal con tu propia clave API; desactivado por defecto, una llamada por IP pública nueva, caché LRU acotada + dedup, alertas `THREAT_HIT` en veredictos sospechosos/maliciosos.
- **Webhooks externos (opt-in)** — alertas warning/critical enviadas por POST en vivo a Discord, Slack, Telegram (con chat ID) o cualquier endpoint; desactivado por defecto.
- **Nuevas detecciones** — `DNS_TUNNEL` (nombres/labels DNS sobredimensionados), `CLEARTEXT` (egreso FTP/Telnet/HTTP/mail en claro), `BASELINE_DEVIATION` (perfil de países aprendido por proceso, persistido).
- **Auditoría de seguridad** — `GET /security/audit` calcula un score 0–100 más recomendaciones en lenguaje claro desde alertas recientes y el grafo; visible en el panel Firewall.
- **Exportación forense** — `GET /forensics/export?format=json|csv|stix` empaqueta árbol de procesos, SHA-256 del ejecutable, alertas e historial de tráfico; STIX es un bundle 2.1 mínimo (indicators + observed-data) para importar en SIEM.
- **UI de firewall y seguridad** — panel dedicado: interruptor lockdown, crear/activar/borrar reglas, contadores de bloqueo por regla, honestidad de soporte por plataforma, informe de auditoría, botones de descarga forense; acción Bloquear por conexión en la barra lateral.
- **Cinco nuevas locales de UI** — de, ru, ja, pt-BR, zh-CN (8 en total, paridad de 280 clés verificada); los diccionarios se movieron a `frontend/src/locales/*.js` — un idioma nuevo = PR de un archivo.

## [1.1.0] — 2026-10-22

### Añadido

- **Auto-actualización** — la app de escritorio comprueba GitHub Releases al arrancar y cada 6 h via electron-updater (los feeds `latest-*.yml` ya se publicaban). Las descargas se instalan al reiniciar; el tray y Ajustes muestran el estado en vivo. Opt-out en Ajustes o con `SNITCH_NO_UPDATE=1`.
- **Visibilidad QUIC / HTTP/3** — los flujos UDP/443 se etiquetan `QUIC/HTTP3` en lugar de agruparse en HTTPS o desconocido. El SNI del Initial QUIC está cifrado y nunca se lee — la etiqueta es honesta sobre lo observable.
- **Watchlist** — fija IPs o sufijos de dominio (`example.com` también casa `api.example.com`); una alerta dedicada `WATCHLIST_HIT` salta en el primer contacto, limitada por (entrada, host). Persistida, gestionada en Ajustes.
- **Alerta de subida por proceso** — `UPLOAD_SPIKE` avisa cuando un proceso supera un techo MB/min configurable (50 por defecto, 0 = off) — cubre exfiltración que el `VOLUME_SPIKE` relativo pierde en procesos recién arrancados.
- **Selector de interfaz de captura** — `GET/POST /capture/interfaces` + desplegable en Ajustes con dispositivos libpcap; el cambio reinicia la captura al instante. Sustituye la variable `SNITCH_IFACE` para usuarios de escritorio.
- **Contexto Wi-Fi** — la barra muestra el SSID actual (o la interfaz cuando no hay Wi-Fi). Al mejor esfuerzo por OS, caché 60 s.
- **UI en español** — diccionario `es` completo (194 claves, paridad verificada); el selector pasa a EN/FR/ES.
- **Paquete snap** — electron-builder emite ahora un `.snap` en confinamiento estricto (con el plug `network-observe` para captura AF_PACKET). Flatpak deliberadamente no publicado — la sandbox no puede exponer captura cruda (documentado en `docs/PACKAGING.md`).
- **Vía de firma de código gratuita** — integración opcional de SignPath Foundation OSS en CI (`vars.SIGNPATH_*` + `secrets.SIGNPATH_API_TOKEN`): el instalador Windows se firma con Authenticode automáticamente cuando el proyecto es aceptado. Documentado en `docs/SIGNING.md`, incluida la situación honesta de macOS (no existe notarización gratuita).

## [1.0.8] — 2026-10-22

### Cambiado

- **Tema claro nativo real** — sustituye el filtro de inversión de la v1.0.7 por un sistema completo de design tokens: cada superficie, texto, borde y acento se pinta con propiedades CSS y una paleta clara elegida a mano. Mapa, grafo, línea temporal y aurora WebGL siguen el tema, y el interruptor persiste tu elección.

## [1.0.7] — 2026-10-22

### Añadido

- **Tema claro** — respeta `prefers-color-scheme` de serie y se puede forzar con el botón sol/luna de la barra; la elección persiste en `localStorage`. Implementado como inversión que preserva el tono de la paleta oscura, así grafos, mapa y aurora siguen coherentes.

### Corregido

- **Cumplimiento del catálogo AppImage** — el asset Linux se nombra ahora `Snitch-x86_64.AppImage` (nomenclatura de arquitectura correcta) y electron-builder publica metadatos de actualización (`latest-linux.yml` + `.zsync`), habilitando auto-actualización con herramientas compatibles con AppImageUpdate.

## [1.0.6] — 2026-10-21

### Añadido

- **Una descarga por OS** — cada tag publica apps listas para usar construidas por CI:
  - **Windows** — `Snitch Setup <versión>.exe` (Electron + NSIS: ventana nativa, tray, detección Npcap integrada, prompt UAC) y `Snitch-Lite-Setup-<versión>-windows-x64.exe` (Inno Setup: solo backend, la UI abre en el navegador).
  - **macOS (Apple Silicon)** — `Snitch-<versión>-macos-arm64.zip` + `.dmg` construidos en CI (antes manual).
  - **Linux** — `Snitch-<versión>.AppImage` + `.deb` — Docker ya no es obligatorio para la app de escritorio.
- **Modo backend `--launcher`** — elige un puerto loopback libre, computa el token de API y abre el navegador; usado por el acceso directo del instalador Lite.

### Corregido

- **Los bundles backend standalone ahora incluyen la UI** — `frontend_dist` se empaqueta dentro del bundle PyInstaller en todos los OS; el tarball antes solo servía la API.

### Cambiado

- El job CI `package` construye los instaladores Electron en los tres OS y un job `release` publica todos los artefactos en la release de GitHub automáticamente.

## [1.0.5] — 2026-10-17

### Añadido

- **Soporte Windows** — la app empaquetada arranca y captura en Windows (Npcap).
- **Iconos de proceso** — iconos Lucide por proceso en la tabla de Apps (contribución externa).
- **24 nuevos dominios tracker** en la lista del clasificador (contribución externa).

### Corregido

- Crash del backend en builds PyInstaller `console=False` (`sys.stdout`/`sys.stderr` = None) — issue #25.
- Selección de interfaz de captura en Windows — Snitch elige ahora la interfaz de la ruta por defecto en vez de `vEthernet (WSL)`.
- `NaNh ago` en los timestamps de alertas con offsets de zona horaria.
- El splash de Electron ya no oculta diálogos de error; el mensaje de timeout lista causas + carpeta de logs.
- Cuatro cadenas inglesas restantes traducidas en el diccionario francés (contribución externa).
- Versión ahora en fuente única desde `backend/version.py`.

### Cambiado

- React 18 → 19, uvicorn 0.30 → 0.54, fastapi → 0.143, psutil → 7.2, websockets → 17.2, maxminddb → 3.2, aiofiles → 25.1, lucide-react → 1.55, vite → 8.3.4, electron → 44.7 (+ dev deps).

## [1.0.4] — 2026-10-05

- Primera release pública.
