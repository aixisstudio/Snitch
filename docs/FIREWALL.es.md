# Funciones de seguridad

[English](FIREWALL.md) | [Français](FIREWALL.md) | **Español** | [Deutsch](FIREWALL.de.md) | [Русский](FIREWALL.ru.md) | [日本語](FIREWALL.ja.md) | [Português](FIREWALL.pt-BR.md) | [中文](FIREWALL.zh-CN.md)

Snitch añade una capa de caza de amenazas sobre la observación pasiva.
**Qué hace — e igual de importante, qué no hace:**

## Orquestación del firewall de salida

Snitch **no** filtra paquetes en user-space. Las reglas se aplican al
firewall nativo del SO, best-effort:

| SO | Mecanismo |
|---|---|
| Windows | reglas de bloqueo de salida `netsh advfirewall` |
| Linux | `iptables -A OUTPUT -j DROP` (cadena `SNITCH_LOCK` para el lockdown) |
| macOS | anchor `pf` generada cargada con `pfctl` |

Tipos de regla: `ip`, `cidr`, `domain` (resuelto una vez al aplicar),
`process`, `port`. Las reglas persisten en `snitch.db` y se reaplican al
arrancar.

**Límites honestos:**

- Aplicar reglas exige los mismos privilegios que la captura. Sin
  elevación, `applied=False` queda en la regla — la UI muestra «solo
  visibilidad». El matching sigue activo: los paquetes que violan una
  regla levantan alertas `BLOCKED_ATTEMPT` con contadores por regla.
- `pf` en macOS no puede casar un *proceso* — las reglas de proceso ahí
  son solo visibilidad, por diseño.
- Las reglas `domain` resuelven el nombre una vez; una CDN que cambia de
  IP se salta la regla hasta recrearla.
- **Lockdown** solo corta el tráfico de salida hacia IP *públicas* —
  loopback y LAN quedan vivos para que la UI siga accesible.

## Respuesta a incidentes

- `POST /processes/kill` / `POST /processes/suspend` — por PID, rechaza
  PID ≤ 3 y al propio Snitch. Privilegios normales del SO.
- `POST /firewall/rules`, `DELETE /firewall/rules/{id}`,
  `POST /firewall/rules/{id}/toggle`, `POST /firewall/lockdown` —
  autenticados como todo endpoint.
- `GET /forensics/export?process=<nombre>&ip=<ip>` — paquete de
  investigación: árbol de procesos (hasta 8 ancestros), SHA-256 del
  ejecutable, cmdline, alertas asociadas, historial por minuto.
  `format=json|csv|stix` elige la salida (STIX = bundle 2.1 minimal para
  SIEM). Datos locales solo; la exportación es una descarga, nunca una
  subida.

## Threat intelligence — opt-in, desactivado por defecto

*Ajustes → Threat intelligence* acepta un proveedor (`abuseipdb`, `otx`,
`virustotal`) más **tu propia clave API**. Activado, cada nueva IP pública
se verifica una vez por TTL de 24 h; los veredictos se cachean y un
veredicto `suspicious`/`malicious` emite una alerta `THREAT_HIT`. Sin
proveedor ni clave, **cero llamadas salientes**. `GET /security/ti`
muestra la config enmascarada; `POST /security/threat_check` lanza una
verificación manual (también consciente del caché).

## Webhooks — opt-in, desactivados por defecto

*Ajustes → Webhook externo* acepta una URL y un interruptor. Las alertas
warning y críticas se POSTean en vivo: Discord/Slack `{content}`,
Telegram `{chat_id, text}` (campo chat ID si es URL de telegram),
cualquier otro endpoint recibe `{alert, source, text}`. Los fallos se
loguean, nunca son fatales.

## Nuevas detecciones

- `DNS_TUNNEL` — nombres/labels DNS sobredimensionados (>60 car. / label
  >40), patrón clásico de exfiltración; una vez por host por 10 min.
- `CLEARTEXT` — TCP saliente a puertos no cifrados por naturaleza
  (80, 21, 23, 25, 110, 143…), nivel INFO, alimenta la auditoría.
- `BASELINE_DEVIATION` — cada proceso aprende sus países de destino
  habituales en sus primeros paquetes y luego avisa una vez al alcanzar
  uno nuevo. Los baselines persisten (`app_baselines`).
- `BEACON` — ya existente: intervalos regulares (CV de tiempos de
  inter-llegada) incluso con tráfico mínimo.
- `BLOCKED_ATTEMPT`, `LOCKDOWN`, `THREAT_HIT` — tipos añadidos por los
  módulos anteriores.

## Auditoría de seguridad

`GET /security/audit` calcula un score 0–100 desde las últimas 500
alertas y el grafo: conteos por tipo, contactos con países de riesgo,
hosts sin resolver, postura del firewall — y devuelve recomendaciones en
lenguaje claro. Es un *informe de hallazgos*, no una certificación.
