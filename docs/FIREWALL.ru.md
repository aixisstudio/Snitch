# Функции безопасности

[English](FIREWALL.md) | [Français](FIREWALL.md) | [Español](FIREWALL.es.md) | [Deutsch](FIREWALL.de.md) | **Русский** | [日本語](FIREWALL.ja.md) | [Português](FIREWALL.pt-BR.md) | [中文](FIREWALL.zh-CN.md)

Snitch добавляет слой threat-hunting поверх пассивного наблюдения.
**Что он делает — и, не менее важно, чего не делает:**

## Оркестрация исходящего фаервола

Snitch **не** фильтрует пакеты в user-space. Правила применяются к
нативному фаерволу ОС, best-effort:

| ОС | Механизм |
|---|---|
| Windows | исходящие правила блокировки `netsh advfirewall` |
| Linux | `iptables -A OUTPUT -j DROP` (отдельная цепь `SNITCH_LOCK` для lockdown) |
| macOS | сгенерированный якорь `pf`, загружаемый через `pfctl` |

Виды правил: `ip`, `cidr`, `domain` (резолвится один раз при применении),
`process`, `port`. Правила хранятся в `snitch.db` и применяются заново
при старте.

**Честные ограничения:**

- Применение требует тех же привилегий, что и захват. Без повышения на
  правиле ставится `applied=False` — UI показывает «только видимость».
  Матчинг продолжает работать: пакеты, нарушающие правило, вызывают
  тревоги `BLOCKED_ATTEMPT` со счётчиками по правилам.
- `pf` на macOS не умеет матчить *процесс* — процессные правила там
  по дизайну только для видимости.
- Правила `domain` резолвят имя один раз; CDN со сменными IP уйдёт от
  правила до его пересоздания.
- **Lockdown** рвёт исходящий трафик только к *публичным* IP — loopback
  и LAN остаются, чтобы UI был доступен.

## Реагирование на инциденты

- `POST /processes/kill` / `POST /processes/suspend` — по PID, отказывает
  PID ≤ 3 и самому Snitch. Обычные привилегии ОС.
- `POST /firewall/rules`, `DELETE /firewall/rules/{id}`,
  `POST /firewall/rules/{id}/toggle`, `POST /firewall/lockdown` —
  аутентифицированы, как все endpoint'ы.
- `GET /forensics/export?process=<имя>&ip=<ip>` — пакет расследования:
  дерево процессов (до 8 предков), SHA-256 исполняемого файла, cmdline,
  связанные тревоги, поминутная история. `format=json|csv|stix` выбирает
  вывод (STIX — минимальный bundle 2.1 для SIEM). Только локальные
  данные; экспорт — загрузка, а не отправка.

## Threat intelligence — opt-in, выключено по умолчанию

*Настройки → Threat intelligence* принимает провайдера (`abuseipdb`,
`otx`, `virustotal`) плюс **ваш API-ключ**. Включённая проверка идёт раз
за TTL 24 ч на новый публичный IP; вердикты кэшируются, а `suspicious`/
`malicious` вызывает `THREAT_HIT`. Без провайдера или ключа — **ноль
исходящих вызовов**. `GET /security/ti` показывает замаскированный
конфиг; `POST /security/threat_check` запускает ручную проверку (тоже с
учётом кэша).

## Webhook'и — opt-in, выключены по умолчанию

*Настройки → Внешний webhook* принимает URL и переключатель. Тревоги
warning и critical отправляются вживую: Discord/Slack `{content}`,
Telegram `{chat_id, text}` (поле chat ID при telegram-URL), прочие
endpoint'ы получают `{alert, source, text}`. Сбои пишутся в лог, никогда
не фатальны.

## Новые детекции

- `DNS_TUNNEL` — аномально длинные DNS-имена/метки (>60 симв. / метка >40),
  классический паттерн эксфильтрации; раз на хост за 10 мин.
- `CLEARTEXT` — исходящий TCP на заведомо незашифрованные порты
  (80, 21, 23, 25, 110, 143…), уровень INFO, питает аудит.
- `BASELINE_DEVIATION` — каждый процесс учит обычные страны назначения
  на первых пакетах, затем однократно предупреждает при новой. Базовые
  профили сохраняются (`app_baselines`).
- `BEACON` — уже было: регулярные интервалы (CV межпакетных задержек)
  даже при крошечном трафике.
- `BLOCKED_ATTEMPT`, `LOCKDOWN`, `THREAT_HIT` — новые типы от модулей выше.

## Аудит безопасности

`GET /security/audit` считает оценку 0–100 по последним 500 тревогам и
живому графу: счётчики по типам, контакты с рискованными странами,
неразрешённые хосты, постура фаервола — и выдаёт рекомендации простым
языком. Это *отчёт находок*, а не сертификация.

### Новое в v1.2 / Nouveautés v1.2

- **Действие `sinkhole`** — правила `domain`/`ip` могут перенаправлять на loopback вместо блокировки: домены через помеченный блок `# snitch-sinkhole` в файле hosts (все ОС), IP/CIDR через `DNAT` iptables (только Linux). `sinkhole` для `process`/`port` отклоняется; неподдерживаемые платформы → честный `applied=False`.
- **Перерезолв доменов** — правила `domain` перерезолвятся каждые ~10 мин, дельта IP применяется по ОС — ротация CDN не снимет блок silently.
- **Контроль целостности** (включён по умолчанию, read-only, локально) — SHA-256 baselines исполняемых файлов (`BINARY_CHANGED`), несовпадение имени/exe (`NAME_MISMATCH`), скан `rwxp` только Linux (`MEM_RWX`, уровень info для известных JIT-приложений). `GET /security/integrity`, `POST /security/integrity/check`.
- **Объяснения алертов** — `GET /security/explain?type=X` возвращает двуязычные (EN/FR) объяснения, написанные вручную; детерминированно и офлайн — не модель. UI показывает их за кнопкой «Почему?».

### Опциональные зонды (v1.3)

Все **выключены по умолчанию или самоограничены**, деградируют честно и никогда не отправляют данные с машины:

- **Зонд eBPF connect** (Linux, `ebpf_probe`) — kprobe BCC типа `tcpconnect` атрибутирует `connect()` короткоживущих процессов. Нужны `python3-bcc` + root; неоднозначные цели не угадываются. `GET /security/ebpf`.
- **Инспекция Frida** — `POST /security/deep_inspect {pid,seconds}` присоединяется к ОДНОМУ pid ≤60 с и сообщает, какой модуль инициировал каждый `connect()`. Staging-пути → `INJECT_SUSPECT`.
- **Респондер sinkhole** — при активной `sinkhole`-правиле loopback-листенеры на :80/:443 превращают каждую попытку в алерт `SINKHOLE_HIT` с Host/URI или SNI + процессом.
- **Целостность модулей** — корень Меркла над исполняемыми маппингами → `MODULE_CHANGED`; пути в `/tmp`/memfd → `MODULE_SUSPECT`.
- **Детект майнинга** — stratum JSON в голове payload → `MINING_STRATUM`; порты пулов + устойчивая CPU → `MINING_SUSPECT`.
- **Аппаратные счётчики** — `POST /security/perf` сэмплирует циклы/инструкции через `perf_event_open` (Linux).
- **Локальный LLM** — opt-in (`slm_enabled`): `/security/explain` вызывает Ollama-эндпоинт **только loopback** — удалённые отклоняются.
- **Пакеты IOC** — `GET /security/iocpack` экспортирует Bloom + randomized response (не в открытом виде); `POST /security/iocpack/import` проверяет цели вероятностно.

### Новинки политики и реагирования (v1.4)

- **Именные профили** — `POST /firewall/profile`: `permissive` (чистый лист), `balanced` (осторожная база исходящих) или `strict` (база + lockdown); разворачиваются в обычные правила с дедупликацией.
- **Свои правила алертов** — `GET/POST/DELETE /alerts/rules`: поле + оператор + значение → алерты `CUSTOM_RULE` (только алерт, никогда не блокируют).
- **Импорт блоклистов** — `POST /firewall/blocklist`: локальный файл (чисто локально) или opt-in URL (HTTPS-запрос ≤4 МиБ, помечен `remote_fetch`) → правила `domain`, дедупликация, лимит 500–5000.
- **Экспорт PCAP** — `GET /forensics/pcap` (фильтры `ip`/`process`): кольцевой буфер ~4 МиБ в `.pcap` для Wireshark.
- **Удалённое сопряжение** — `POST /remote/pairing` сохраняет `lan_bind` до следующего запуска; токен обязателен. `GET /remote/pairing` сообщает bind + LAN-адреса.
- **Песочница без сети** — `POST /security/sandbox` запускает бинарник с нулевым egress (`unshare -n` Linux, `sandbox-exec` macOS; `contrib/snitch-contain` вручную).
- **Встроенная модель** — `slm_mode=embedded` загружает `.gguf` пользователя через `llama-cpp-python` — ноль сети.
- **Нативные скелеты** — `contrib/wfp-callout/` (WFP callout на C + подпись) и `contrib/macos-filter/` (`NEFilterDataProvider` Swift + entitlements): исследовательский каркас, не поставляется.
- **ASN** — с `GeoLite2-ASN.mmdb`/`dbip-asn-lite.mmdb` узлы несут `asn` в дополнение к `org`.

## v1.5 — Пассивная инспекция, вердикты ядра и синхронизация флота

- **Пассивная инспекция TLS-сертификата** — ограниченная TCP-сборка (≤16 КиБ/поток, TTL 30 с) читает сообщение `Certificate`: CN+O издателя/субъекта, самоподпись, SAN, срок, `san_mismatch` → `TLS_CERT`. **TLS 1.3 остаётся непрозрачным** — честно ненаблюдаем, а не угадываем.
- **Сторож высокой энтропии** — payloads ≥48 Б на не-TLS каналах с ≥4,7 бит/байт → `HIGH_ENTROPY`; кулдаун 10 мин на хост.
- **Эвристика ICMP-туннеля** — echo с ≥24 Б payload, ≥3× за 5 мин → `ICMP_TUNNEL`.
- **ML-аномалия потока** — isolation forest на чистом Python (64 дерева, ноль зависимостей) по вашим же сводкам; неактивно <384 потоков, `ML_ANOMALY` при 0,62. Отклонение от baseline, **не** классификатор.
- **Ask-on-connect (Linux, opt-in)** — `ask_enabled` + root + `python-netfilterqueue`: новые исходящие потоки удерживаются в NFQUEUE 7 до `POST /security/ask/verdict`; таймаут 15 с, fail-closed (`ask_failopen=1` наоборот). Windows/macOS требуют подписанные callout/NetworkExtension из `contrib/`.
- **eBPF cgroup-эндфорсмент (Linux, opt-in)** — `POST /security/ebpf/isolate {pid}` + `/security/ebpf/block {ip}`: программа attach к cgroup snitch — дропы в ядре ТОЛЬКО для изолированных процессов.
- **Проверка hollowing (Linux)** — `POST /security/hollow {pid}` сравнивает file-backed исполняемые страницы `/proc/<pid>/mem` с диском.
- **Синхронизация IOC с пирами (opt-in)** — `gossip_peers` ≤32 + `gossip_enabled`: Merkle-пакеты каждые 5 мин по аутентифицированному HTTP(S) — без discovery, не ZK.
- **Syslog (opt-in)** — `syslog_addr` (`хост:порт` UDP или `tcp://`) → RFC 3164 `local4`.
- **Сдерживание Firejail** — `firejail --net=none` предпочтительно, `unshare` как фолбэк.
- **Backend nftables** — отдельная таблица `inet snitch` вместо iptables, где есть `nft`.
- **Действующие алерты** — структурные `actions` (блок IP, убить/приостановить, вердикт ask) кнопками в один клик.
- **`asn`/`country` в своих правилах** — локальная geo-БД, комбинируется с `action=block` как geo-fence.
