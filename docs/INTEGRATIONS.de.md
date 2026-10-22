# Snitch — Enterprise-Integrationen

*Community translated — PRs welcome for refinement / Von der Community übersetzt — PRs zur Verbesserung willkommen.*

**DE:** Schritt-für-Schritt-Anleitungen, um Snitch in einen SOC-Stack
einzubinden — Wazuh, Splunk, Graylog/Loki, Ansible, Docker/Kubernetes —
alles kostenlos und selbst gehostet, passend zu Snitches Local-first-Ansatz.
Snitch sendet keine eigene Telemetrie; die einzigen ausgehenden
Verbindungen sind die hier konfigurierten.

---

## 1. SIEM-Ausgabe

Snitch bietet drei native Formate für die Alarm-Weiterleitung:

| Einstellung | Werte | Wirkung |
|---|---|---|
| `syslog_addr` | `host:514` oder `tcp://host:514` | Aktiviert Syslog-Weiterleitung (UDP Standard, TCP mit `tcp://`-Präfix) |
| `syslog_format` | `rfc3164` *(Standard)* | Klassisches BSD-Syslog — von jedem Kollektor lesbar |
| | `cef` | `CEF:0|Snitch|…` — ArcSight/Wazuh/Splunk parsen `src`, `dst`, `dpt`, `cs1` (Prozess) automatisch |
| `webhook_url` + `webhook_enabled` | URL | Generischer JSON-`POST` (oder automatisch erkannte Discord/Slack/Telegram-Payloads) |
| `GET /forensics/export?format=…` | `json`, `csv`, `stix`, `ecs` | Einmalige Forensik-Bundles — `ecs` erzeugt zeilenweise Elastic Common Schema |

In der UI setzen (Einstellungen → Sicherheit) oder in `snitch.toml`:

```toml
syslog_addr = "siem.example.com:514"
syslog_format = "cef"
```

## 2. Wazuh

1. Syslog-Listener auf dem Wazuh-Manager aktivieren (`/var/ossec/etc/ossec.conf`):

   ```xml
   <remote>
     <connection>syslog</connection>
     <port>514</port>
     <protocol>udp</protocol>
     <allowed-ips>your-agent-subnet</allowed-ips>
   </remote>
   ```

2. Jeden Snitch-Agenten darauf zeigen lassen — Ansible:

   ```yaml
   snitch_syslog_addr: "wazuh.example.com:514"
   snitch_syslog_format: "cef"
   ```

3. Der CEF-Decoder von Wazuh übernimmt die `CEF:0|Snitch|…`-Meldungen;
   `severity` wird auf syslog-PRI abgebildet (critical→2, warning→4, info→6).

## 3. Splunk

1. Einstellungen → Daten-Inputs → UDP → neuer Input auf 514, Sourcetype
   `syslog` (oder TCP-Input für `tcp://…`-Sender).
2. `syslog_format = "cef"` liefert `src`, `dst`, `dpt`, `cs1Label` gratis;
   für Dashboards `GET /forensics/export?format=ecs` per Scripted Input
   abfragen — JSON wird automatisch extrahiert.

## 4. Graylog / Loki

- **Graylog**: System → Inputs → Syslog UDP, Port 514. CEF-Erweiterungsfelder
  landen als Nachrichtenfelder.
- **Loki/Grafana**: `syslog_addr` auf ein `promtail`-Syslog-Target richten
  oder `/forensics/export?format=ecs` per Cronjob → Loki-Push-Job scrapen.

## 5. Deklarative Konfiguration (Security-as-Code)

Das Backend wendet **eine Datei** beim Start an — `$SNITCH_CONFIG`, sonst
`snitch.toml`/`snitch.json` im Datenverzeichnis. Jede deklarierte
Einstellung überschreibt den UI/DB-Wert — die Datei ist die
Wahrheitsquelle der Flotte:

```toml
syslog_addr = "siem.example.com:514"
syslog_format = "cef"
kill_switch_enabled = true
ask_enabled = false          # headless Server
gossip_peers = ["sec-01:8000"]
ports = [80, 443]
```

Vollständiges Vokabular: `packaging/snitch.toml.example`.

## 6. Ansible / Puppet / Salt / GPO

- **Ansible** — fertige Rolle in `deploy/ansible/`:

  ```bash
  ansible-playbook -i inventory deploy/ansible/site.yml
  ```

  Installiert `/opt/snitch`, das venv, `/etc/snitch/snitch.toml` und die
  gehärtete systemd-Unit, aktiviert dann `snitch.service`.

- **Puppet / SaltStack** — Community-Skelette in `deploy/puppet/` und
  `deploy/salt/` (Label `help wanted`): dieselben drei Primitive —
  Backend-Baum kopieren, `snitch.toml` rendern, `snitch.service` verwalten.

- **Windows GPO** — `deploy/gpo/Install-Snitch.ps1` führt die
  Silent-Installation aus (ProgramData-Config, venv, SYSTEM-Aufgabe auf
  127.0.0.1). Ask-on-connect unter Windows braucht zusätzlich den
  signierten WFP-Callout — siehe `docs/SIGNING.md`.

## 7. Docker & Kubernetes

- **Einzelhost**: `docker compose up` — `network_mode: host` +
  `cap_add: NET_RAW/NET_ADMIN` bereits in `docker-compose.yml`.
- **Flotten-Konsole**: `deploy/helm/snitch` — `mode: collector` startet
  ein ClusterIP-Deployment, das die Audits aller konfigurierten Agenten
  in `GET /remote/fleet` zusammenführt; `mode: agent` rendert ein
  Host-Network-DaemonSet mit `NET_RAW`/`NET_ADMIN`.

  ```bash
  helm install snitch ./deploy/helm/snitch \
      --set token=$(openssl rand -hex 32) \
      --set config.gossip_peers='["agent-1:8000","agent-2:8000"]'
  ```

## 8. Sigma-Regeln

`POST /alerts/rules/sigma` akzeptiert ein Sigma-YAML und kompiliert die
unterstützte Teilmenge (Feld→Wert-Selektionen, `|contains`/`|startswith`/
`|endswith`/`|re`/`|cidr`/`|gt`/`|lt`/`|all`, `1 of`/`all of`-Bedingungen)
in Snitch-Custom-Rules — nur Alarme, `skipped`-Gründe für alles
außerhalb der Teilmenge. Felder werden auf das gemappt, was ein
*Paket*-Sensor sieht (`DestinationIp→remote_ip`, `Image→process_name`,
`Domain→host`, …).

YARA-L für Google SecOps/Chronicle: `GET /alerts/rules/yaral` exportiert
alle Regeln (inkl. importierter Sigma-Regeln) als `.yar`-Datei — der
Weg Sigma→YARA-L ist damit abgedeckt.

## 9. Remote-Agenten (snitch-agent/1)

`agent/` enthält einen leichten Rust-Daemon (null Abhängigkeiten, ein
~1-MB-Binary), der die Socket-Tabelle des Hosts (`/proc/net/*`)
beobachtet und neue ausgehende Flows an `POST /ingest/events` pusht.
Er beobachtet Sockets — keine Payloads/SNI (das bleibt beim lokalen
Capture); Prozess-Attribution ist als TODO markiert. Transport: HTTP +
Bearer-Token (Trust-Domain wie `gossip_peers`).

## 10. Kostenlose Threat-Intel-Feeds

`POST /firewall/blocklist` importiert beide Formen:

- `kind: "domain"` — Hosts-/Domain-Listen (StevenBlack, EasyList…) →
  `domain`-Firewall-Regeln;
- `kind: "ip"` — IP-Feeds (Blocklist.de, URLhaus/Feodo-Exports) →
  `ip`-Regeln; private/reservierte/Loopback-Adressen werden nie importiert.

`path:` liest eine lokale Datei (vollständig offline); `url:` ist ein
expliziter, auditierter Opt-in-Fetch (`remote_fetch: true` in der
Antwort). Limit `max_entries ≤ 5000` — riesige Feeds gehören in einen
Resolver.

Opt-in-API-Anbieter (AbuseIPDB / OTX / VirusTotal) bleiben über
`ti_provider` + `ti_api_key` verfügbar — ohne Schlüssel geht nichts raus.

## 11. Headless- / Daemon-Modus

Die GUI ist optional: das Backend ist das gesamte Produkt. Direkt
(`uvicorn api.main:app`), unter der mitgelieferten systemd-Unit oder im
Container — alle Funktionen oben laufen ohne Frontend.
`SNITCH_DEMO=1` liefert weiterhin einen root-freien synthetischen Feed
für Schulungen und CTFs.
