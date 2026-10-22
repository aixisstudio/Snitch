# Snitch — Enterprise integrations / Intégrations entreprise

**EN:** Step-by-step recipes for wiring Snitch into a SOC stack —
Wazuh, Splunk, Graylog/Loki, Ansible, Docker/Kubernetes — all free and
self-hosted, matching Snitch's local-first posture. Snitch emits no
telemetry of its own; the only outbound connections are the ones you
configure below.

**FR :** Recettes pas-à-pas pour brancher Snitch dans une stack SOC —
Wazuh, Splunk, Graylog/Loki, Ansible, Docker/Kubernetes — gratuites et
auto-hébergées, dans l'esprit local-first de Snitch. Snitch n'émet
aucune télémétrie propre ; les seules connexions sortantes sont celles
configurées ci-dessous.

---

## 1. SIEM output / Sortie SIEM

Snitch ships three native formats for alert forwarding:

| Setting / Réglage | Values / Valeurs | Effect / Effet |
|---|---|---|
| `syslog_addr` | `host:514` or `tcp://host:514` | Enables syslog forwarding (UDP default, TCP with the `tcp://` prefix) |
| `syslog_format` | `rfc3164` *(default)* | Classic BSD syslog — readable by every collector |
| | `cef` | `CEF:0|Snitch|…` — ArcSight/Wazuh/Splunk auto-parse `src`, `dst`, `dpt`, `cs1` (process)… |
| `webhook_url` + `webhook_enabled` | URL | Generic JSON `POST` (or Discord/Slack/Telegram auto-detected payloads) |
| `GET /forensics/export?format=…` | `json`, `csv`, `stix`, `ecs` | One-shot forensic bundles — `ecs` emits newline-delimited Elastic Common Schema |

Set them in the UI (Settings → Security) or in `snitch.toml`:

```toml
syslog_addr = "siem.example.com:514"
syslog_format = "cef"
```

## 2. Wazuh

1. Enable a syslog listener on the Wazuh manager (`/var/ossec/etc/ossec.conf`):

   ```xml
   <remote>
     <connection>syslog</connection>
     <port>514</port>
     <protocol>udp</protocol>
     <allowed-ips>your-agent-subnet</allowed-ips>
   </remote>
   ```

2. Point each Snitch agent at it — Ansible:

   ```yaml
   snitch_syslog_addr: "wazuh.example.com:514"
   snitch_syslog_format: "cef"
   ```

3. Wazuh's CEF decoder picks the `CEF:0|Snitch|…` messages up; alert
   `severity` maps to syslog PRI (critical→2, warning→4, info→6).

## 3. Splunk

1. Settings → Data Inputs → UDP → new input on 514, sourcetype `syslog`
   (or a TCP input for `tcp://…` senders).
2. `syslog_format = "cef"` gives you `src`, `dst`, `dpt`, `cs1Label`
   fields for free; for dashboards, poll `GET /forensics/export?format=ecs`
   on a schedule through a scripted input and let the JSON auto-extract.

## 4. Graylog / Loki

- **Graylog**: System → Inputs → Syslog UDP, bind 514. CEF extension
  fields land as message fields.
- **Loki/Grafana**: point `syslog_addr` at a `promtail` syslog target or
  scrape `/forensics/export?format=ecs` with a cron → `loki` push job.

## 5. Declarative configuration (Security-as-Code)

The backend applies **one file** at startup — `$SNITCH_CONFIG`, else
`snitch.toml`/`snitch.json` in the data dir. Every key it declares
overrides the UI/DB value, so the file is the fleet source of truth:

```toml
syslog_addr = "siem.example.com:514"
syslog_format = "cef"
kill_switch_enabled = true
ask_enabled = false          # headless servers
gossip_peers = ["sec-01:8000"]
ports = [80, 443]
```

See `packaging/snitch.toml.example` for the full vocabulary.

## 6. Ansible / Puppet / Salt / GPO

- **Ansible** — ready-made role in `deploy/ansible/`:

  ```bash
  ansible-playbook -i inventory deploy/ansible/site.yml
  ```

  It installs `/opt/snitch`, the venv, `/etc/snitch/snitch.toml` and the
  hardened systemd unit, then enables `snitch.service`.

- **Puppet / SaltStack** — community skeletons in `deploy/puppet/` and
  `deploy/salt/` (label `help wanted`): the same three primitives —
  copy the backend tree, render `snitch.toml`, manage `snitch.service`.

- **Windows GPO** — `deploy/gpo/Install-Snitch.ps1` performs the silent
  install (ProgramData config, venv, SYSTEM scheduled task on 127.0.0.1)
  for GPO startup scripts or Intune win32 packaging. Ask-on-connect on
  Windows additionally needs the signed WFP callout — see
  `docs/SIGNING.md`.

## 7. Docker & Kubernetes

- **Single host**: `docker compose up` — `network_mode: host` +
  `cap_add: NET_RAW/NET_ADMIN` already configured in `docker-compose.yml`.
- **Fleet console**: `deploy/helm/snitch` — `mode: collector` runs a
  ClusterIP Deployment that merges every configured agent's audit into
  `GET /remote/fleet`; `mode: agent` renders a host-network DaemonSet
  with `NET_RAW`/`NET_ADMIN`.

  ```bash
  helm install snitch ./deploy/helm/snitch \
      --set token=$(openssl rand -hex 32) \
      --set config.gossip_peers='["agent-1:8000","agent-2:8000"]'
  ```

## 8. Sigma rules & YARA-L

`POST /alerts/rules/sigma` accepts a Sigma detection YAML and compiles the
supported subset (field→value selections, `|contains`/`|startswith`/
`|endswith`/`|re`/`|cidr`/`|gt`/`|lt`/`|all`, `1 of`/`all of` conditions)
into Snitch custom rules — alert-only, `skipped` reasons returned for
anything outside the subset. Fields map to what a *packet* sensor sees
(`DestinationIp→remote_ip`, `Image→process_name`, `Domain→host`, …).

YARA-L for Google SecOps/Chronicle: `GET /alerts/rules/yaral` exports all
custom rules (including Sigma-imported ones) as a `.yar` file — the
Sigma→YARA-L path is covered transitively.

## 9. Remote agents (snitch-agent/1)

`agent/` ships a zero-dependency Rust daemon (~1 MB single binary) that
watches the host socket table (`/proc/net/*`, Linux) and pushes newly
observed outbound flows to `POST /ingest/events`. It observes sockets —
no payloads/SNI (that's the local capture's job); process attribution is
a marked TODO. Transport: HTTP + bearer token, same trust-domain model
as `gossip_peers`. A `snitch-agent.service` unit lives in
`deploy/systemd/`.

## 10. Threat-intel feeds (free)

`POST /firewall/blocklist` imports both shapes:

- `kind: "domain"` — hosts/domain lists (StevenBlack, EasyList…) →
  `domain` firewall rules;
- `kind: "ip"` — IP feeds (Blocklist.de, URLhaus/Feodo exports) → `ip`
  rules; private/reserved/loopback addresses are never imported.

`path:` reads a local file (fully offline); `url:` is an explicit,
audited opt-in fetch (`remote_fetch: true` in the response). Cap at
`max_entries ≤ 5000` — giant feeds belong in a resolver.

Opt-in API providers (AbuseIPDB / OTX / VirusTotal) stay available via
`ti_provider` + `ti_api_key` — nothing calls out until you set a key.

## 11. Headless / daemon mode

The GUI is optional: the backend is the whole product. Run it bare
(`uvicorn api.main:app`), under the shipped systemd unit, or in the
container — every feature above works without the frontend.
`SNITCH_DEMO=1` still gives a no-root synthetic feed for training rooms
and CTFs.
