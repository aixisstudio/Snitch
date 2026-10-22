# Snitch — Integrações empresariais

*Community translated — PRs welcome for refinement / Traduzido pela comunidade — PRs de melhoria são bem-vindos.*

**PT-BR:** Receitas passo a passo para ligar o Snitch a um stack SOC —
Wazuh, Splunk, Graylog/Loki, Ansible, Docker/Kubernetes — tudo grátis e
auto-hospedado, coerente com a postura local-first do Snitch. O Snitch
não emite telemetria própria; as únicas conexões de saída são as que
você configura aqui.

---

## 1. Saída SIEM

O Snitch oferece três formatos nativos para encaminhar alertas:

| Ajuste | Valores | Efeito |
|---|---|---|
| `syslog_addr` | `host:514` ou `tcp://host:514` | Ativa o encaminhamento syslog (UDP por padrão, TCP com prefixo `tcp://`) |
| `syslog_format` | `rfc3164` *(padrão)* | Syslog BSD clássico — legível por qualquer coletor |
| | `cef` | `CEF:0|Snitch|…` — ArcSight/Wazuh/Splunk fazem parse de `src`, `dst`, `dpt`, `cs1` (processo) automaticamente |
| `webhook_url` + `webhook_enabled` | URL | `POST` JSON genérico (ou payloads Discord/Slack/Telegram autodetectados) |
| `GET /forensics/export?format=…` | `json`, `csv`, `stix`, `ecs` | Bundles forenses únicos — `ecs` emite Elastic Common Schema em NDJSON |

Configure na UI (Configurações → Segurança) ou no `snitch.toml`:

```toml
syslog_addr = "siem.example.com:514"
syslog_format = "cef"
```

## 2. Wazuh

1. Ative um listener syslog no manager Wazuh (`/var/ossec/etc/ossec.conf`):

   ```xml
   <remote>
     <connection>syslog</connection>
     <port>514</port>
     <protocol>udp</protocol>
     <allowed-ips>your-agent-subnet</allowed-ips>
   </remote>
   ```

2. Aponte cada agente Snitch — Ansible:

   ```yaml
   snitch_syslog_addr: "wazuh.example.com:514"
   snitch_syslog_format: "cef"
   ```

3. O decodificador CEF do Wazuh captura os `CEF:0|Snitch|…`; a
   `severity` mapeia para PRI syslog (critical→2, warning→4, info→6).

## 3. Splunk

1. Configurações → Entradas de dados → UDP → nova entrada na 514,
   sourcetype `syslog` (ou entrada TCP para remetentes `tcp://…`).
2. `syslog_format = "cef"` dá `src`, `dst`, `dpt`, `cs1Label` de graça;
   para dashboards, consulte `GET /forensics/export?format=ecs` via
   scripted input — o JSON é extraído automaticamente.

## 4. Graylog / Loki

- **Graylog**: System → Inputs → Syslog UDP, porta 514. Os campos de
  extensão CEF chegam como campos da mensagem.
- **Loki/Grafana**: aponte `syslog_addr` para um target syslog do
  `promtail` ou faça scrape de `/forensics/export?format=ecs` via cron
  → job push para o Loki.

## 5. Configuração declarativa (Security-as-Code)

O backend aplica **um arquivo** na inicialização — `$SNITCH_CONFIG`, ou
`snitch.toml`/`snitch.json` no diretório de dados. Cada chave declarada
sobrescreve o valor UI/DB: o arquivo é a fonte de verdade da frota:

```toml
syslog_addr = "siem.example.com:514"
syslog_format = "cef"
kill_switch_enabled = true
ask_enabled = false          # servidores headless
gossip_peers = ["sec-01:8000"]
ports = [80, 443]
```

Vocabulário completo: `packaging/snitch.toml.example`.

## 6. Ansible / Puppet / Salt / GPO

- **Ansible** — role pronta em `deploy/ansible/`:

  ```bash
  ansible-playbook -i inventory deploy/ansible/site.yml
  ```

  Instala `/opt/snitch`, o venv, `/etc/snitch/snitch.toml` e a unit
  systemd endurecida, e habilita `snitch.service`.

- **Puppet / SaltStack** — esqueletos comunitários em `deploy/puppet/` e
  `deploy/salt/` (label `help wanted`): as mesmas três primitivas —
  copiar a árvore backend, renderizar `snitch.toml`, gerenciar
  `snitch.service`.

- **Windows GPO** — `deploy/gpo/Install-Snitch.ps1` faz a instalação
  silenciosa (config no ProgramData, venv, tarefa SYSTEM em 127.0.0.1).
  Ask-on-connect no Windows requer adicionalmente o callout WFP
  assinado — ver `docs/SIGNING.md`.

## 7. Docker & Kubernetes

- **Host único**: `docker compose up` — `network_mode: host` +
  `cap_add: NET_RAW/NET_ADMIN` já no `docker-compose.yml`.
- **Console de frota**: `deploy/helm/snitch` — `mode: collector` sobe um
  Deployment ClusterIP que funde as auditorias de todos os agentes
  configurados em `GET /remote/fleet`; `mode: agent` renderiza um
  DaemonSet host-network com `NET_RAW`/`NET_ADMIN`.

  ```bash
  helm install snitch ./deploy/helm/snitch \
      --set token=$(openssl rand -hex 32) \
      --set config.gossip_peers='["agent-1:8000","agent-2:8000"]'
  ```

## 8. Regras Sigma

`POST /alerts/rules/sigma` aceita um YAML Sigma e compila o subconjunto
suportado (seleções campo→valor, `|contains`/`|startswith`/`|endswith`/
`|re`/`|cidr`/`|gt`/`|lt`/`|all`, condições `1 of`/`all of`) em regras
custom do Snitch — apenas alertas, com motivos `skipped` para o que não
é suportado. Os campos mapeiam para o que um sensor de *pacotes* vê
(`DestinationIp→remote_ip`, `Image→process_name`, `Domain→host`, …).

YARA-L para Google SecOps/Chronicle: `GET /alerts/rules/yaral` exporta
todas as regras (incluindo as importadas de Sigma) como arquivo `.yar` —
o caminho Sigma→YARA-L fica coberto.

## 9. Agentes remotos (snitch-agent/1)

`agent/` contém um daemon Rust leve (zero dependências, um binário ~1 MB)
que observa a tabela de sockets do host (`/proc/net/*`) e envia novos
fluxos de saída para `POST /ingest/events`. Observa sockets — sem
payloads/SNI (isso fica com o capture local); atribuição de processo é
TODO marcado. Transporte: HTTP + bearer (mesmo domínio de confiança de
`gossip_peers`).

## 10. Feeds de threat-intel gratuitos

`POST /firewall/blocklist` importa ambas as formas:

- `kind: "domain"` — listas hosts/domínios (StevenBlack, EasyList…) →
  regras `domain`;
- `kind: "ip"` — feeds IP (Blocklist.de, exports URLhaus/Feodo) → regras
  `ip`; endereços privados/reservados/loopback nunca são importados.

`path:` lê arquivo local (totalmente offline); `url:` é um fetch opt-in
explícito e auditado (`remote_fetch: true` na resposta). Limite
`max_entries ≤ 5000` — feeds gigantes pertencem a um resolver.

Provedores opt-in (AbuseIPDB / OTX / VirusTotal) seguem disponíveis via
`ti_provider` + `ti_api_key` — nada sai sem a sua chave.

## 11. Modo headless / daemon

A GUI é opcional: o backend é o produto inteiro. Rode direto
(`uvicorn api.main:app`), sob a unit systemd incluída ou no container —
todas as funções acima funcionam sem frontend. `SNITCH_DEMO=1` segue
oferecendo um feed sintético sem root para treinamentos e CTFs.
