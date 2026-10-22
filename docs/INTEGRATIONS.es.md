# Snitch — Integraciones empresariales

*Community translated — PRs welcome for refinement / Traducido por la comunidad — se aceptan PRs de mejora.*

**ES:** Recetas paso a paso para integrar Snitch en un stack SOC —
Wazuh, Splunk, Graylog/Loki, Ansible, Docker/Kubernetes — todo gratis y
auto-alojado, coherente con la postura local-first de Snitch. Snitch no
emite telemetría propia; las únicas conexiones salientes son las que
configuras aquí.

---

## 1. Salida SIEM

Snitch ofrece tres formatos nativos para reenviar alertas:

| Ajuste | Valores | Efecto |
|---|---|---|
| `syslog_addr` | `host:514` o `tcp://host:514` | Activa el reenvío syslog (UDP por defecto, TCP con prefijo `tcp://`) |
| `syslog_format` | `rfc3164` *(por defecto)* | Syslog BSD clásico — legible por cualquier colector |
| | `cef` | `CEF:0|Snitch|…` — ArcSight/Wazuh/Splunk parsean `src`, `dst`, `dpt`, `cs1` (proceso) automáticamente |
| `webhook_url` + `webhook_enabled` | URL | `POST` JSON genérico (o payloads Discord/Slack/Telegram autodetectados) |
| `GET /forensics/export?format=…` | `json`, `csv`, `stix`, `ecs` | Bundles forenses de una vez — `ecs` emite Elastic Common Schema en NDJSON |

Configúralos en la UI (Ajustes → Seguridad) o en `snitch.toml`:

```toml
syslog_addr = "siem.example.com:514"
syslog_format = "cef"
```

## 2. Wazuh

1. Activa un listener syslog en el manager Wazuh (`/var/ossec/etc/ossec.conf`):

   ```xml
   <remote>
     <connection>syslog</connection>
     <port>514</port>
     <protocol>udp</protocol>
     <allowed-ips>your-agent-subnet</allowed-ips>
   </remote>
   ```

2. Apunta cada agente Snitch — Ansible:

   ```yaml
   snitch_syslog_addr: "wazuh.example.com:514"
   snitch_syslog_format: "cef"
   ```

3. El decodificador CEF de Wazuh recoge los `CEF:0|Snitch|…`; la
   `severity` se mapea a PRI syslog (critical→2, warning→4, info→6).

## 3. Splunk

1. Configuración → Entradas de datos → UDP → nueva entrada en 514,
   sourcetype `syslog` (o entrada TCP para emisores `tcp://…`).
2. `syslog_format = "cef"` te da `src`, `dst`, `dpt`, `cs1Label` gratis;
   para dashboards consulta `GET /forensics/export?format=ecs` con un
   scripted input — el JSON se extrae automáticamente.

## 4. Graylog / Loki

- **Graylog**: System → Inputs → Syslog UDP, puerto 514. Los campos de
  extensión CEF llegan como campos del mensaje.
- **Loki/Grafana**: apunta `syslog_addr` a un target syslog de `promtail`
  o scrapea `/forensics/export?format=ecs` con cron → job push a Loki.

## 5. Configuración declarativa (Security-as-Code)

El backend aplica **un archivo** al arrancar — `$SNITCH_CONFIG`, o
`snitch.toml`/`snitch.json` en el directorio de datos. Cada clave
declarada sobrescribe el valor UI/DB: el archivo es la fuente de verdad
de la flota:

```toml
syslog_addr = "siem.example.com:514"
syslog_format = "cef"
kill_switch_enabled = true
ask_enabled = false          # servidores headless
gossip_peers = ["sec-01:8000"]
ports = [80, 443]
```

Vocabulario completo: `packaging/snitch.toml.example`.

## 6. Ansible / Puppet / Salt / GPO

- **Ansible** — rol listo en `deploy/ansible/`:

  ```bash
  ansible-playbook -i inventory deploy/ansible/site.yml
  ```

  Instala `/opt/snitch`, el venv, `/etc/snitch/snitch.toml` y la unidad
  systemd endurecida, y habilita `snitch.service`.

- **Puppet / SaltStack** — esqueletos comunitarios en `deploy/puppet/` y
  `deploy/salt/` (label `help wanted`): las mismas tres primitivas —
  copiar el árbol backend, renderizar `snitch.toml`, gestionar
  `snitch.service`.

- **Windows GPO** — `deploy/gpo/Install-Snitch.ps1` hace la instalación
  silenciosa (config en ProgramData, venv, tarea SYSTEM en 127.0.0.1).
  Ask-on-connect en Windows requiere además el callout WFP firmado —
  ver `docs/SIGNING.md`.

## 7. Docker & Kubernetes

- **Host único**: `docker compose up` — `network_mode: host` +
  `cap_add: NET_RAW/NET_ADMIN` ya en `docker-compose.yml`.
- **Consola de flota**: `deploy/helm/snitch` — `mode: collector` lanza
  un Deployment ClusterIP que fusiona las auditorías de todos los
  agentes configurados en `GET /remote/fleet`; `mode: agent` renderiza
  un DaemonSet host-network con `NET_RAW`/`NET_ADMIN`.

  ```bash
  helm install snitch ./deploy/helm/snitch \
      --set token=$(openssl rand -hex 32) \
      --set config.gossip_peers='["agent-1:8000","agent-2:8000"]'
  ```

## 8. Reglas Sigma

`POST /alerts/rules/sigma` acepta un YAML Sigma y compila el subconjunto
soportado (selecciones campo→valor, `|contains`/`|startswith`/`|endswith`/
`|re`/`|cidr`/`|gt`/`|lt`/`|all`, condiciones `1 of`/`all of`) en reglas
custom de Snitch — solo alertas, con motivos `skipped` para lo no
soportado. Los campos se mapean a lo que un sensor de *paquetes* ve
(`DestinationIp→remote_ip`, `Image→process_name`, `Domain→host`, …).

YARA-L para Google SecOps/Chronicle: `GET /alerts/rules/yaral` exporta
todas las reglas (incluidas las Sigma importadas) como archivo `.yar` —
el camino Sigma→YARA-L queda cubierto.

## 9. Agentes remotos (snitch-agent/1)

`agent/` contiene un daemon Rust ligero (cero dependencias, un solo
binario ~1 MB) que observa la tabla de sockets del host (`/proc/net/*`)
y envía los nuevos flujos salientes a `POST /ingest/events`. Observa
sockets — sin payloads/SNI (eso queda en el capture local); la
atribución de proceso está marcada como TODO. Transporte: HTTP + bearer
(dominio de confianza como `gossip_peers`).

## 10. Feeds de threat-intel gratuitos

`POST /firewall/blocklist` importa ambas formas:

- `kind: "domain"` — listas hosts/dominios (StevenBlack, EasyList…) →
  reglas `domain`;
- `kind: "ip"` — feeds IP (Blocklist.de, exports URLhaus/Feodo) → reglas
  `ip`; nunca se importan direcciones privadas/reservadas/loopback.

`path:` lee un archivo local (totalmente offline); `url:` es un fetch
opt-in explícito y auditado (`remote_fetch: true` en la respuesta).
Límite `max_entries ≤ 5000` — los feeds gigantes pertenecen a un resolver.

Los proveedores opt-in (AbuseIPDB / OTX / VirusTotal) siguen disponibles
vía `ti_provider` + `ti_api_key` — nada sale sin tu clave.

## 11. Modo headless / daemon

La GUI es opcional: el backend es todo el producto. Ejecútalo directo
(`uvicorn api.main:app`), bajo la unidad systemd incluida o en el
contenedor — todas las funciones anteriores funcionan sin frontend.
`SNITCH_DEMO=1` sigue ofreciendo un feed sintético sin root para
formaciones y CTFs.
