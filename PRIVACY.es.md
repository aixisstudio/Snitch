# Privacidad

[English](PRIVACY.md) | [Français](PRIVACY.md) | **Español** | [Deutsch](PRIVACY.de.md) | [Русский](PRIVACY.ru.md) | [日本語](PRIVACY.ja.md) | [Português](PRIVACY.pt-BR.md) | [中文](PRIVACY.zh-CN.md)

Snitch es una herramienta de privacidad — nunca debe filtrar los datos que
te ayuda a monitorizar.

**Telemetría: ninguna.** Sin analíticas, sin reportes de crash, ninguna
llamada «a casa» de ningún tipo.

**Llamadas de red emitidas por Snitch: todas opcionales, todas apagadas
por defecto.** Todo lo demás es observación pasiva o desencadenado por ti —
no hay tráfico silencioso:

- captura paquetes en tus interfaces locales (observación pasiva),
- lee la tabla ARP/vecinos del sistema (sin escaneo activo),
- resuelve DNS inverso vía el resolvedor de tu SO — consultas PTR estándar
  que ya ocurren implícitamente con cualquier actividad de red
  (`SNITCH_DISABLE_PTR=1` para desactivarlas por completo),
- sirve una UI web en `127.0.0.1` para tu propio navegador.

**La app de escritorio comprueba nuevas versiones en github.com** al
arrancar y cada 6 h (electron-updater, lee los `latest-*.yml` públicos).
Es la única llamada saliente periódica. Se desactiva en *Ajustes →
Actualizaciones → Comprobar automáticamente* (persistido) o con
`SNITCH_NO_UPDATE=1`. El build Docker y el backend nunca comprueban.

**La descarga de la base GeoIP** (*Ajustes → Geolocalización*) trae ~50 MB
desde db-ip.com — solo cuando haces clic, con consentimiento explícito.

**Threat intelligence (opt-in, desactivado por defecto).** Cuando
configuras un proveedor (AbuseIPDB, AlienVault OTX o VirusTotal) *y*
pegas tu propia clave API en Ajustes, Snitch consulta a ese proveedor la
reputación de los nuevos hosts públicos — enviándole solo la IP consultada.
Los veredictos se cachean localmente; la clave se guarda en `snitch.db`
(nunca en logs, enmascarada en la UI). Sin proveedor ni clave, cero
consultas — `ti.check()` es un no-op.

**Webhooks externos (opt-in, desactivados por defecto).** Cuando pegas una
URL de webhook (Discord, Slack, endpoint de bot de Telegram o cualquier
URL) y activas el interruptor, los textos de alertas warning/críticas se
POSTean a ese endpoint en tiempo real. Nada se envía con el interruptor
apagado.

**Enriquecimiento LLM local (opt-in, desactivado por defecto).** Con
`slm_enabled`, los *metadatos* de alertas (tipo, proceso, destino) pueden
enviarse a un modelo compatible con Ollama — **solo loopback**: el backend
rechaza cualquier endpoint que no resuelva a 127.0.0.1 / ::1. Los
gabarits deterministas siguen siendo el valor por defecto.

**Los paquetes IOC nunca los transmite Snitch.** `GET /security/iocpack`
codifica tus indicadores en un filtro Bloom + randomized response (ε≈4,6)
y te entrega el archivo — tú decides si compartirlo. Importar un paquete
solo devuelve pistas probabilísticas; nunca bloquea automáticamente.

**Las sondas de inspección son de solo lectura y locales.** La sonda
eBPF, la inspección Frida, los contadores `perf_event_open`, los escaneos
de integridad de módulos y el respondedor sinkhole solo *leen* estado
local y escuchan en 127.0.0.1 — ninguno envía datos.

**La geolocalización es 100 % offline.** Una vez un `.mmdb` de DB-IP Lite
o MaxMind GeoLite2 en `<data_dir>/geo/`, las consultas son locales. Sin
base, las IP simplemente no muestran ubicación. No hay servicio HTTP de
geolocalización — ip-api.com se eliminó precisamente porque enviaba las IP
visitadas a un tercero en claro.

**Qué se almacena localmente:**

| Dato | Ubicación | Retención |
|---|---|---|
| Agregados de tráfico por minuto | `snitch.db` | 24 h (configurable: `retention_hours`) |
| Historial de alertas | `snitch.db` | misma ventana |
| Ajustes (filtros, whitelist, idioma…) | `snitch.db` | hasta que los cambies |
| Token de API | `api_token.txt` (0600) | regenerado por lanzamiento en Electron |
| Logs | `logs/snitch.log` (rotativo) | ~5 MB máx. |

Directorio de datos: `data/` en dev/Docker, `%LOCALAPPDATA%\Snitch` en
Windows, `~/Library/Application Support/Snitch` en macOS,
`~/.local/share/snitch` en Linux cuando está instalado.

## Novedades v1.4 (privacidad)

- **Importar blocklist por URL (opt-in)** — un *archivo local* es una lectura puramente local; una *URL* realiza un único fetch HTTPS acotado (≤4 MiB, ≤10 s), confirmado en la UI y marcado `remote_fetch`.
- **Emparejamiento remoto (opt-in, desactivado)** — la API solo escucha en 127.0.0.1; activar el pairing persiste `lan_bind` para el próximo arranque — el token sigue obligatorio en cada petición.
- **Sandbox sin red** — `POST /security/sandbox` ejecuta un binario en un namespace sin red (`unshare -n` Linux) o seatbelt (`sandbox-exec` macOS): egress cero, la salida queda en la máquina.
- **Pruebas IOC `format=proof`** — hojas SHA-256 saladas + raíz Merkle: pertenencia exacta sin enumerar indicadores no sospechados; nada se transmite automáticamente.
- **Modelo embebido** — `slm_mode=embedded` carga tu `.gguf` en proceso vía `llama-cpp-python` — cero red; Snitch nunca descarga pesos.
