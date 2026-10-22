# Snitch — корпоративные интеграции

*Community translated — PRs welcome for refinement / Перевод сообщества — PR с правками приветствуются.*

**RU:** Пошаговые рецепты подключения Snitch к SOC-стеку —
Wazuh, Splunk, Graylog/Loki, Ansible, Docker/Kubernetes — всё бесплатно
и self-hosted, в духе local-first Snitch. Snitch сам не отправляет
телеметрию; единственные исходящие соединения — те, что настроены здесь.

---

## 1. Вывод в SIEM

Три нативных формата пересылки алертов:

| Настройка | Значения | Эффект |
|---|---|---|
| `syslog_addr` | `host:514` или `tcp://host:514` | Включает syslog-пересылку (UDP по умолчанию, TCP через префикс `tcp://`) |
| `syslog_format` | `rfc3164` *(по умолчанию)* | Классический BSD syslog — читается любым коллектором |
| | `cef` | `CEF:0|Snitch|…` — ArcSight/Wazuh/Splunk автоматически парсят `src`, `dst`, `dpt`, `cs1` (процесс) |
| `webhook_url` + `webhook_enabled` | URL | Универсальный JSON `POST` (или автоопределяемые payload-ы Discord/Slack/Telegram) |
| `GET /forensics/export?format=…` | `json`, `csv`, `stix`, `ecs` | Разовые форензик-бандлы — `ecs` выдаёт Elastic Common Schema в NDJSON |

Настраивается в UI (Настройки → Безопасность) или в `snitch.toml`:

```toml
syslog_addr = "siem.example.com:514"
syslog_format = "cef"
```

## 2. Wazuh

1. Включите syslog-слушатель на менеджере Wazuh (`/var/ossec/etc/ossec.conf`):

   ```xml
   <remote>
     <connection>syslog</connection>
     <port>514</port>
     <protocol>udp</protocol>
     <allowed-ips>your-agent-subnet</allowed-ips>
   </remote>
   ```

2. Направьте каждого агента Snitch — Ansible:

   ```yaml
   snitch_syslog_addr: "wazuh.example.com:514"
   snitch_syslog_format: "cef"
   ```

3. CEF-декодер Wazuh подхватит `CEF:0|Snitch|…`; `severity` маппируется
   в syslog PRI (critical→2, warning→4, info→6).

## 3. Splunk

1. Settings → Data Inputs → UDP → новый ввод на 514, sourcetype
   `syslog` (или TCP-ввод для отправителей `tcp://…`).
2. `syslog_format = "cef"` даёт поля `src`, `dst`, `dpt`, `cs1Label`;
   для дашбордов опрашивайте `GET /forensics/export?format=ecs` через
   scripted input — JSON извлекается автоматически.

## 4. Graylog / Loki

- **Graylog**: System → Inputs → Syslog UDP, порт 514. Расширенные
  поля CEF прилетают полями сообщения.
- **Loki/Grafana**: направьте `syslog_addr` на syslog-target `promtail`
  или забирайте `/forensics/export?format=ecs` через cron → push-джоб
  в Loki.

## 5. Декларативная конфигурация (Security-as-Code)

Бэкенд применяет **один файл** при старте — `$SNITCH_CONFIG`, либо
`snitch.toml`/`snitch.json` в каталоге данных. Каждый объявленный ключ
переопределяет значение UI/DB — файл является источником истины флота:

```toml
syslog_addr = "siem.example.com:514"
syslog_format = "cef"
kill_switch_enabled = true
ask_enabled = false          # headless-серверы
gossip_peers = ["sec-01:8000"]
ports = [80, 443]
```

Полный словарь: `packaging/snitch.toml.example`.

## 6. Ansible / Puppet / Salt / GPO

- **Ansible** — готовая роль в `deploy/ansible/`:

  ```bash
  ansible-playbook -i inventory deploy/ansible/site.yml
  ```

  Ставит `/opt/snitch`, venv, `/etc/snitch/snitch.toml` и усиленный
  systemd-юнит, затем включает `snitch.service`.

- **Puppet / SaltStack** — комьюнити-скелеты в `deploy/puppet/` и
  `deploy/salt/` (label `help wanted`): те же три примитива —
  развернуть дерево backend, отрендерить `snitch.toml`, управлять
  `snitch.service`.

- **Windows GPO** — `deploy/gpo/Install-Snitch.ps1` выполняет тихую
  установку (конфиг в ProgramData, venv, SYSTEM-задача на 127.0.0.1).
  Ask-on-connect в Windows дополнительно требует подписанный
  WFP-коллаут — см. `docs/SIGNING.md`.

## 7. Docker & Kubernetes

- **Один хост**: `docker compose up` — `network_mode: host` +
  `cap_add: NET_RAW/NET_ADMIN` уже в `docker-compose.yml`.
- **Флит-консоль**: `deploy/helm/snitch` — `mode: collector` запускает
  ClusterIP-Deployment, сливающий аудиты всех настроенных агентов в
  `GET /remote/fleet`; `mode: agent` рендерит host-network DaemonSet
  с `NET_RAW`/`NET_ADMIN`.

  ```bash
  helm install snitch ./deploy/helm/snitch \
      --set token=$(openssl rand -hex 32) \
      --set config.gossip_peers='["agent-1:8000","agent-2:8000"]'
  ```

## 8. Правила Sigma

`POST /alerts/rules/sigma` принимает Sigma YAML и компилирует
поддерживаемое подмножество (селекции поле→значение, `|contains`/
`|startswith`/`|endswith`/`|re`/`|cidr`/`|gt`/`|lt`/`|all`, условия
`1 of`/`all of`) в кастомные правила Snitch — только алерты, причины
`skipped` возвращаются для всего вне подмножества. Поля маппируются на
то, что видит *пакетный* сенсор (`DestinationIp→remote_ip`,
`Image→process_name`, `Domain→host`, …).

YARA-L для Google SecOps/Chronicle: `GET /alerts/rules/yaral`
экспортирует все правила (включая импортированные из Sigma) в файл
`.yar` — путь Sigma→YARA-L закрыт.

## 9. Удалённые агенты (snitch-agent/1)

`agent/` содержит лёгкий Rust-демон (ноль зависимостей, один бинарник
~1 МБ), наблюдающий таблицу сокетов хоста (`/proc/net/*`) и пушащий
новые исходящие потоки в `POST /ingest/events`. Он наблюдает сокеты —
без payload/SNI (это дело локальной capture-ветки); атрибуция процессов
помечена TODO. Транспорт: HTTP + bearer (та же trust-domain-модель,
что `gossip_peers`).

## 10. Бесплатные threat-intel фиды

`POST /firewall/blocklist` импортирует обе формы:

- `kind: "domain"` — hosts/доменные списки (StevenBlack, EasyList…) →
  правила `domain`;
- `kind: "ip"` — IP-фиды (Blocklist.de, экспорты URLhaus/Feodo) →
  правила `ip`; приватные/зарезервированные/loopback-адреса никогда
  не импортируются.

`path:` читает локальный файл (полностью офлайн); `url:` — явный
аудируемый opt-in fetch (`remote_fetch: true` в ответе). Лимит
`max_entries ≤ 5000` — гигантские фиды относятся к резолверу.

Opt-in провайдеры (AbuseIPDB / OTX / VirusTotal) доступны через
`ti_provider` + `ti_api_key` — без ключа ничего наружу не уходит.

## 11. Headless-режим / демон

GUI опционален: бэкенд — это весь продукт. Запускайте напрямую
(`uvicorn api.main:app`), под прилагаемым systemd-юнитом или в
контейнере — все функции выше работают без фронтенда. `SNITCH_DEMO=1`
по-прежнему даёт синтетический фид без root для обучения и CTF.
