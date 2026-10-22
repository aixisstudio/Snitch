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
