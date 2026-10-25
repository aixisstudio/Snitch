# Changelog

[English](CHANGELOG.md) | [Français](CHANGELOG.md) | [Español](CHANGELOG.es.md) | [Deutsch](CHANGELOG.de.md) | [Русский](CHANGELOG.ru.md) | [日本語](CHANGELOG.ja.md) | [Português](CHANGELOG.pt-BR.md) | [中文](CHANGELOG.zh-CN.md)

All notable changes to Snitch. / Toutes les modifications notables de Snitch.

The format follows [Keep a Changelog](https://keepachangelog.com/) — EN/FR.

## [Unreleased]

### Added / Ajouté

- EN: **Recent-traffic search** — the live packet feed gains a query
  field that narrows rows by process name, remote host or protocol,
  answering the most requested triage shortcut. Localized in all 8 UI
  languages.
  FR: **Recherche dans le trafic récent** — le flux de paquets gagne un
  champ de requête qui réduit les lignes par nom de processus, hôte
  distant ou protocole. Localisé dans les 8 langues de l'UI.

### Fixed / Corrigé

- EN: **Windows console-window flash fixed** — backend console tools
  (`netsh` SSID poll every 60 s, firewall rules, `route`/`arp` lookups)
  now spawn with `CREATE_NO_WINDOW`/`SW_HIDE`; no more transient popup
  storm on Windows (issue #62, reported by @minghao999, confirmed by
  @iactor).
  FR: **Clignotement de console Windows corrigé** — les outils console
  du backend (`netsh` pour le SSID toutes les 60 s, règles pare-feu,
  `route`/`arp`) se lancent désormais avec `CREATE_NO_WINDOW`/`SW_HIDE` ;
  plus de rafale de popups sous Windows (issue #62, signalée par
  @minghao999, confirmée par @iactor).

- EN: **Dark-mode legibility** — `--text-muted`/`--text-faint` (and the
  light-theme equivalents) were ~2.5–4:1 contrast at the 9–10px sizes
  used in lists; bumped to ≈4.5–5.5:1, and the packet feed microtext
  goes from 9px to 10px. Reported by a user on TabNews.
  FR: **Lisibilité du thème sombre** — `--text-muted`/`--text-faint`
  (et les équivalents clairs) tombaient à ~2,5–4:1 aux tailles 9–10px
  des listes ; remontés à ≈4,5–5,5:1, et le microtexte du flux de
  paquets passe de 9px à 10px. Signalé par un utilisateur TabNews.

## [1.6.4] — 2026-10-23 — security & efficiency hardening / durcissement sécurité & efficacité

### Security / Sécurité

- EN: **Agent↔collector TLS** — `snitch-agent` gains opt-in rustls
  transport (`SNITCH_TLS=1`, WebPKI roots, `SNITCH_CA` for private CAs);
  the collector terminates TLS when `SNITCH_TLS_CERT`/`SNITCH_TLS_KEY`
  are set. The `sagt_…` token and flow metadata no longer travel in
  cleartext on hostile links.
  FR: **TLS agent↔collecteur** — `snitch-agent` gagne un transport rustls
  opt-in (`SNITCH_TLS=1`, racines WebPKI, `SNITCH_CA` pour CA privée) ;
  le collecteur termine TLS avec `SNITCH_TLS_CERT`/`SNITCH_TLS_KEY`. Le
  jeton `sagt_…` et les métadonnées ne transitent plus en clair.
- EN: **hosts-file injection closed** — `domain` firewall rules are now
  validated against a strict RFC-1034 hostname regex before any
  sinkhole write, and `port` rules must be an integer 1–65535 (both
  reached argv/hosts verbatim before).
  FR: **Injection hosts colmatée** — les règles `domain` sont validées
  par regex RFC-1034 stricte avant toute écriture sinkhole, et les
  règles `port` exigent un entier 1–65535.
- EN: **`?token=` restricted to the WebSocket** — REST endpoints only
  accept the `X-Snitch-Token` header, so the credential can no longer
  leak into browser history or access logs via API URLs.
  FR: **`?token=` réservé au WebSocket** — les endpoints REST
  n'acceptent que l'en-tête `X-Snitch-Token`.
- EN: **Per-IP brute-force ban** — 20 failed auth attempts in 5 min →
  HTTP 429 / WS close for 60 s (loopback included).
  FR: **Bannissement anti-force brute par IP** — 20 échecs en 5 min →
  HTTP 429 / fermeture WS pendant 60 s (loopback inclus).
- EN: `SNITCH_PRINT_TOKEN=0` suppresses the one-time stdout token
  print for hardened deployments (api_token.txt stays readable, 0600).
  FR: `SNITCH_PRINT_TOKEN=0` supprime l'affichage stdout du jeton.
- EN: IP whitelist entries are validated (real addresses only, ≤512);
  port/process filter lists bounded to 512 entries.
  FR: Les entrées whitelist sont validées (vraies adresses, ≤512) ;
  filtres de ports/processus bornés à 512.
- EN: **Custom-rule regexes reject nested quantifiers** — `(a+)+`,
  `(.*)*`, `(a?)+`, `(a{1,3})+` and friends are refused at validation.
  Python's `re` has no match timeout, so the catastrophic-backtracking
  shape is rejected instead of hoped away; bounded-only patterns stay
  legal. Residual (ambiguous alternation `(a|a)+`) is documented.
  FR: **Les regex des règles refusent les quantifieurs imbriqués** —
  `(a+)+`, `(.*)*`, `(a?)+`, `(a{1,3})+` sont refusés à la validation ;
  les motifs bornés restent légaux.

### Changed / Modifié

- EN: **Non-blocking WebSocket broadcast** — each client send has a 5 s
  timeout and runs concurrently, so one stalled UI can no longer delay
  the packet feed for every other client.
  FR: **Diffusion WebSocket non bloquante** — chaque envoi client a un
  timeout de 5 s et tourne en parallèle.
- EN: `lan_devices` is now bounded (1024 entries, quietest-eviction) —
  private-prefix enumeration can't grow the map forever.
  FR: `lan_devices` est désormais bornée (1024 entrées, éviction de la
  plus discrète).

### Fixed / Corrigé

- EN: **ask-mode rollback is now complete** — a mid-start iptables
  failure mirror-deletes every rule already planted (previously the
  NFQUEUE jump or RETURN exemptions could strand the host's outbound
  traffic until reboot), and `stop()` removes the full rule set instead
  of only the queue jump (repeated start/stop used to stack stale
  RETURN rules on OUTPUT).
  FR: **Rollback du mode ask désormais complet** — un échec iptables en
  cours de start supprime en miroir toutes les règles posées (le saut
  NFQUEUE ou les exemptions pouvaient étrangler le trafic sortant
  jusqu'au reboot), et `stop()` retire l'ensemble complet.
- EN: **NFQUEUE verdicts are race-safe** — `decide()`/timeout-waiter
  verdicts survive a concurrent `stop()` closing the socket instead of
  surfacing as API 500s; remembered verdicts are bounded at 65 536
  entries (ephemeral ports grow them forever otherwise).
  FR: **Verdicts NFQUEUE insensibles aux courses** — les verdicts
  survivent à un `stop()` concurrent ; les verdicts mémorisés sont
  bornés à 65 536 entrées.
- EN: libpcap `_sockaddr_ip` reads the 2-byte family before sizing the
  struct (no more 24-byte over-read on short sockaddrs), and a failed
  BPF compile/setfilter closes the live handle instead of leaking it.
  FR: `_sockaddr_ip` lit la famille avant de dimensionner la lecture ;
  un échec BPF ferme le handle live au lieu de le fuiter.
- EN: the buffered-alert queue is capped at 10 000 between 10 s flushes
  (oldest-quarter eviction, `alerts_dropped()` counter) and the miner
  suspect map at 4 096 — alert storms can no longer balloon RAM.
  FR: la file d'alertes tampon est bornée à 10 000 entre flushes
  (éviction du quart le plus ancien, compteur `alerts_dropped()`) et la
  map de suspects mineur à 4 096.
- EN: media monitor polls every 10 s by default (was 3 s — each Linux
  tick walks every process's open files); `SNITCH_MEDIA_INTERVAL`
  (3–300 s) overrides.
  FR: le moniteur média sonde toutes les 10 s par défaut (3 s avant —
  chaque tick Linux parcourt les fichiers ouverts de tous les
  processus) ; `SNITCH_MEDIA_INTERVAL` (3–300 s) ajuste.
- EN: **GPO installer no longer writes the master token in cleartext**
  — `-Token` now lands in `%ProgramData%\Snitch\api_token.txt` ACL'd to
  SYSTEM+Administrators instead of a world-readable `SNITCH_TOKEN=…`
  line inside `%ProgramFiles%\Snitch\run.cmd`. The launcher also quotes
  `set "VAR=value"` so `&`/spaces in paths cannot inject.
  FR: **L'installeur GPO n'écrit plus le jeton maître en clair** —
  `-Token` atterrit dans `api_token.txt` restreint à
  SYSTEM+Administrateurs au lieu d'une ligne lisible par tous dans
  `run.cmd`. Le lanceur quote aussi `set "VAR=valeur"`.
- EN: **Electron elevated launches hardened** — the macOS osascript
  command now shell-quotes paths BEFORE AppleScript-quoting (a `"`/`$`
  in the data dir or binary path could no longer survive into
  `/bin/sh`), and the Windows UAC command uses PowerShell single-quoted
  strings (`'` → `''`).
  FR: **Lancements élevés Electron durcis** — quoting shell puis
  AppleScript sous macOS, et chaînes PowerShell en apostrophes sous
  Windows.
- EN: `/security/ask/verdict` normalizes `remote_ip` through
  `ipaddress` at the boundary (it feeds the whitelist, a firewall rule
  and the flow-key match); `/settings` rejects >256 keys per batch;
  kill/suspend report fixed labels instead of exception text; WFP
  keep-alive pins and the gossip fleet-audit body read are bounded.
  FR: `/security/ask/verdict` normalise `remote_ip` via `ipaddress` ;
  `/settings` refuse >256 clés ; kill/suspend renvoient des libellés
  fixes ; les pins WFP et la lecture fleet-audit sont bornés.

- EN: **All project surfaces synced to v1.6.3** — README (Rust agent,
  enrollment, `ti_feeds`, `.rpm`, `snitchd` formula), ROADMAP (v1.5.x/
  v1.6.x shipped rows, fleet scale-out items), wiki (API catalog → 76
  endpoints, new *Fleet & Agent* page, Installation/Roadmap/FAQ/Usage
  refreshed), GitHub Pages (monitor+firewall positioning, fleet/SIEM
  cards, brew/deb/rpm install lines), topics (+rust/ebpf/edr/siem/
  fleet-management), milestone `v1.7.0` + tracking issues #53–#57.
  FR: **Toutes les surfaces du projet synchronisées en v1.6.3** —
  README, ROADMAP, wiki (catalogue API complet, nouvelle page *Flotte
  & agent*), GitHub Pages, topics, milestone `v1.7.0` + tickets #53–#57.
- EN: release workflow — `workflow_dispatch` enabled for manual
  re-publish; winget asset gate no longer fails red when the count is
  non-zero (`if` instead of `&&`, bash forced on Windows runner).
  FR: workflow release — `workflow_dispatch` pour republication
  manuelle ; le garde winget n'échoue plus quand le compte est non nul.

- EN: **Packaged app icon restored** — `generate-icon.js` used to
  redraw the deprecated wireframe "radar eye" and overwrite `icon.png`
  on every build; the committed monogram is now the single icon source
  for Windows/macOS/Linux artifacts.
  FR: **Icône de l'app packagée restaurée** — `generate-icon.js`
  redessinait l'ancien « œil radar » et écrasait `icon.png` à chaque
  build ; le monogramme commité est désormais la source unique.
- EN: **Elevated backend no longer bricks the data dir** — files it
  creates (logs, `snitch.db`, `api_token.txt`) are chowned back to the
  real user via `SNITCH_OWNER_UID/GID` (on every write and again
  recursively at shutdown), instead of leaving root-owned files that
  killed the next unprivileged launch with EACCES.
  FR: **Le backend élevé ne brique plus le dossier de données** — les
  fichiers qu'il crée sont rendus à l'utilisateur réel via
  `SNITCH_OWNER_UID/GID` (à chaque écriture et récursivement à l'arrêt),
  au lieu de laisser des fichiers root qui tuaient le lancement suivant.
- EN: Electron now shows a bilingual error with the repair command when
  `userData` is unwritable (e.g. root-owned leftovers) instead of dying
  silently.
  FR: Electron affiche désormais une erreur bilingue avec la commande de
  réparation quand `userData` est inscriptible, au lieu de mourir en
  silence.

## [1.6.3] — 2026-10-22 — hygiene & hardening / hygiène & durcissement

### Fixed / Corrigé

- EN: **All 9 CodeQL alerts fixed at the source** — askmode exempt IPs
  are validated and normalized through `ipaddress.ip_network` before
  reaching iptables argv (command-line injection ×2); webhook provider
  detection matches parsed hostnames instead of raw URL substrings
  (×3); API responses no longer leak exception text (×2);
  `ci-agent.yml` declares `contents: read` permissions; one test-only
  substring assertion made exact.
  FR: **Les 9 alertes CodeQL corrigées à la source** — IP exemptées
  validées et normalisées via `ipaddress.ip_network` avant argv
  iptables (injection ×2) ; détection webhook par hostname parsé au
  lieu de sous-chaîne d'URL (×3) ; les réponses API ne fuient plus le
  texte d'exception (×2) ; `contents: read` sur `ci-agent.yml`.
- EN: Homebrew launcher renamed `snitch` → `snitchd` — the bare CLI
  name belongs to `karol-broda/snitch` (an ss/netstat replacement).
  Refs #51.
  FR: Lanceur Homebrew renommé `snitch` → `snitchd` — le nom CLI nu
  appartient à `karol-broda/snitch`. Refs #51.
- EN: **All 11 dependabot updates merged** — electron 44.9, fastapi,
  react/react-dom 19.3.1, lucide-react, vitest, ruff, and the docker /
  download-artifact / setup-buildx / login GitHub Actions.
  FR: **Les 11 mises à jour dependabot mergées** — electron 44.9,
  fastapi, react/react-dom, lucide-react, vitest, ruff et les actions
  docker/download-artifact/setup-buildx/login.
- EN: release pipeline end-to-end green — nfpm `.deb`/`.rpm` built,
  formula pushed to `aixisstudio/homebrew-tap`, winget/choco jobs
  skip cleanly until their installer assets/keys exist.
  FR: pipeline release vert de bout en bout — `.deb`/`.rpm` construits,
  formule poussée vers le tap, winget/choco sautent proprement tant
  que leurs assets/clés n'existent pas.

## [1.6.2] — 2026-10-22 — fleet maturity / maturité de flotte

### Added / Ajouté

- EN: **Per-agent enrollment** — `POST /ingest/enroll` mints one-shot
  `sagt_…` credentials (only the hash is stored), `GET /ingest/agents`
  lists them, `POST /ingest/revoke` kills one by name. `/ingest/events`
  accepts `X-Snitch-Agent: sagt_…` where the enrolled name is
  authoritative (a stolen token can't spoof another agent) or the master
  `X-Snitch-Token` for local deployments.
  FR: **Enrôlement par agent** — `POST /ingest/enroll` mint des crédences
  `sagt_…` one-shot (seul le hash est stocké), `GET /ingest/agents` les
  liste, `POST /ingest/revoke` les révoque par nom. `/ingest/events`
  accepte `X-Snitch-Agent: sagt_…` (le nom enrôlé fait foi — un jeton
  volé ne peut pas usurper un autre agent) ou le jeton maître.
- EN: **Agent process attribution (Linux)** — the Rust agent now maps
  socket inodes to `pid`/`process` via a `/proc/*/fd` walk, lazily
  (only when new sockets appear). Still zero-dependency; Windows/macOS
  builds compile and report `pid: 0` until their OS paths land.
  FR: **Attribution de processus (Linux)** — l'agent Rust mappe les
  inodes de socket vers `pid`/`process` via `/proc/*/fd`, à la demande.
  Toujours zéro-dépendance ; les builds Windows/macOS compilent et
  reportent `pid: 0` tant que leurs chemins OS ne sont pas livrés.
- EN: **Scheduled threat feeds** — the `ti_feeds` setting (declarative
  via `snitch.toml` or `POST /settings`) refreshes each feed on its own
  `hours` clock through a background asyncio worker; imports run
  through the same dedupe/caps path as `/firewall/blocklist` and the
  firewall reloads hot. `ti_feeds_state` persists last-fetch times.
  FR: **Flux TI planifiés** — le réglage `ti_feeds` (déclaratif via
  `snitch.toml` ou `POST /settings`) rafraîchit chaque flux selon son
  horloge `hours` via un worker asyncio ; imports par le même chemin
  dédupe/caps que `/firewall/blocklist`, pare-feu rechargé à chaud.
- EN: **Agent CI** — `.github/workflows/ci-agent.yml` compiles and
  unit-tests `snitch-agent` on Linux, macOS and Windows targets on every
  `agent/**` push; 6 unit tests cover hex decoding, table parsing,
  attribution and JSON escaping.
  FR: **CI agent** — `.github/workflows/ci-agent.yml` compile et teste
  `snitch-agent` sur cibles Linux/macOS/Windows à chaque push
  `agent/**` ; 6 tests unitaires.

### Fixed / Corrigé

- EN: the agent previously sent `Authorization: Bearer`, which the
  ingest endpoint never read — it now sends `X-Snitch-Agent` (enrolled
  `sagt_…`) or `X-Snitch-Token` (master) matching the actual auth path.
  FR: l'agent envoyait `Authorization: Bearer`, jamais lu par l'endpoint
  — il envoie désormais `X-Snitch-Agent` (`sagt_…` enrôlé) ou
  `X-Snitch-Token` (maître) selon le vrai chemin d'auth.

## [1.6.1] — 2026-10-22 — enterprise follow-through / suite entreprise

### Added / Ajouté

- **Rust agent + ingest API / Agent Rust + API d'ingestion** — `agent/` ships a zero-dependency Rust daemon (~1 MB single binary) that diffs the host socket table (`/proc/net/*`, Linux) and pushes new outbound flows to the new authenticated `POST /ingest/events` (contract `snitch-agent/1`, ≤1000 events/request, per-item validation). Events feed the SAME custom-rule detection surface as local packets and accumulate under `agent-host:…` history keys. Honest scope: sockets only — no payloads/SNI, process attribution is a marked TODO, HTTP transport for LAN trust domains. `deploy/systemd/snitch-agent.service` included. / Daemon Rust zéro-dépendance qui diff la table de sockets et pousse les nouveaux flux vers `POST /ingest/events` (contrat `snitch-agent/1`, borné et validé). Mêmes règles custom que les paquets locaux. Périmètre honnête : sockets seulement.
- **YARA-L export / Export YARA-L** — `GET /alerts/rules/yaral` + `detection/yaral.py`: all custom rules (including Sigma-imported `conds` rules) exported as a YARA-L 2.0 file for Google SecOps/Chronicle, with packet-sensor→UDM field mapping documented inline; untranslatable clauses become `// SKIPPED` comments. Gives a Sigma→YARA-L path for free. / Export unidirectionnel des règles custom en YARA-L 2.0 (mapping UDM documenté, clauses intraduisibles en `// SKIPPED`) — chemin Sigma→YARA-L inclus.
- **Puppet / Salt / GPO skeletons / Squelettes Puppet / Salt / GPO** — `deploy/puppet/` module + ERB template, `deploy/salt/` state, `deploy/gpo/Install-Snitch.ps1` silent installer (ProgramData config, venv, SYSTEM scheduled task on 127.0.0.1) — all `help wanted` community-maintained. / Module Puppet + template ERB, state Salt, installeur silencieux PowerShell pour GPO/Intune — tous marqués `help wanted`.
- **Release automation / Automatisation de release** — `.github/workflows/release.yml`: on `v*` tags, builds nfpm `.deb`/`.rpm`, renders + pushes the Homebrew formula to `aixisstudio/homebrew-tap`, submits the winget manifest (winget-releaser) and packs/pushes Chocolatey — all gated on documented secrets (`HOMEBREW_TAP_TOKEN`, `WINGET_TOKEN`, `CHOCO_API_KEY`). Formula/nuspec templates in `packaging/homebrew/` + `packaging/choco/`. / Sur tags `v*` : paquets nfpm, formule Homebrew vers le tap, manifeste winget, push Chocolatey — tout conditionné aux secrets documentés.
- **Translated INTEGRATIONS docs / Doc INTEGRATIONS traduite** — `docs/INTEGRATIONS.{de,es,ja,pt-BR,ru,zh-CN}.md` generated with a "community translated — PRs welcome" banner. / Variantes traduites avec bandeau « traduction communautaire — PR bienvenues ».
- **Community on GitHub / Communauté sur GitHub** — no Discord/Matrix to moderate: issues for bugs, Discussions for ideas/questions/feedback, searchable next to the code. `.github/ISSUE_TEMPLATE/config.yml` routes users to Discussions, private security advisories and the integration docs from the issue picker; README carries a Discussions badge. / Pas de Discord/Matrix à modérer : issues pour les bugs, Discussions pour idées/questions/retours — recherchable près du code. `config.yml` oriente vers Discussions, advisories privés et la doc depuis le sélecteur d'issues ; badge Discussions dans le README.

## [1.6.0] — 2026-10-22 — enterprise layer / couche entreprise

### Added / Ajouté

- **Security-as-Code config file / Fichier de config Security-as-Code** — `backend/configfile.py` applies `$SNITCH_CONFIG`, else `snitch.toml`/`snitch.json` in the data dir at startup; every declared key overrides the DB so Ansible/Puppet/GPO provision Snitch with one file (`packaging/snitch.toml.example`). / `configfile.py` applique `$SNITCH_CONFIG` ou `snitch.toml`/`.json` du data dir ; chaque clé déclarée écrase la DB — un fichier suffit pour provisionner.
- **Sigma rule import / Import de règles Sigma** — `POST /alerts/rules/sigma` + `detection/sigma.py`: a bounded, documented subset (field selections, `|contains`/`|startswith`/`|endswith`/`|re`/`|cidr`/`|gt`/`|lt`/`|all`, `1 of`/`all of` conditions) compiled into multi-clause AND custom rules (`conds:`); unmappable selections are reported in `skipped`, never mistranslated. / Sous-ensemble borné et documenté compilé en règles AND multi-clauses ; les sélections non mappables sont rapportées dans `skipped`.
- **IP threat feeds / Flux TI IP** — `POST /firewall/blocklist` accepts `kind: "ip"` (Blocklist.de, URLhaus/Feodo exports, plain IP-per-line or CSV) imported as `ip` rules; private/reserved/loopback never imported, CIDRs over 4096 addresses rejected. `kind: "domain"` unchanged. / `kind: "ip"` importe les flux IP en règles `ip` ; privées/réservées jamais importées.
- **Fleet console view / Vue console de flotte** — `GET /remote/fleet` merges every `gossip_peers` node's `/security/audit` (agent count, worst/mean hardening score, per-peer findings) — any Snitch instance can act as the collector; per-peer failures degrade gracefully. / `GET /remote/fleet` fusionne les `/security/audit` des pairs — n'importe quelle instance fait collecteur.
- **CEF syslog output / Sortie syslog CEF** — `syslog_format: "cef"` wraps forwarded alerts in `CEF:0|Cognition|Snitch|…` (ArcSight/Wazuh/Splunk-ready) over the same UDP/TCP syslog path; `rfc3164` remains the default. / `syslog_format: "cef"` enveloppe les alertes en CEF; `rfc3164` reste le défaut.
- **ECS export / Export ECS** — `GET /forensics/export?format=ecs` emits NDJSON Elastic Common Schema 8.11 (alerts → `event.kind=alert`, process entries carry `file.hash.sha256`), ingestible by Elastic Agent/Logstash/OpenSearch. / NDJSON ECS 8.11 ingérable par Elastic/Logstash/OpenSearch.
- **Deployment assets / Assets de déploiement** — hardened systemd unit (`deploy/systemd/`), Ansible role + playbook (`deploy/ansible/`), Helm chart for collector/agent modes (`deploy/helm/snitch/`), nfpm config for .deb/.rpm (`packaging/nfpm.yaml`), MkDocs site (`mkdocs.yml`), integration guide `docs/INTEGRATIONS.md` (Wazuh, Splunk, Graylog/Loki, Ansible, Docker/K8s), canonical GitHub labels (`.github/labels.yml`). / Unité systemd durcie, rôle Ansible, chart Helm (collecteur/agent), nfpm .deb/.rpm, site MkDocs, guide d'intégrations, labels GitHub.
- **Multi-clause custom rules / Règles multi-clauses** — `customrules` rules may now carry `conds:` (Sigma-style AND over any field set); the single `field/op/value` form is unchanged. / Les règles acceptent `conds:` (AND multi-champs façon Sigma) ; la forme simple est inchangée.

## [1.5.3] — 2026-10-22

### Added / Ajouté

- **Permanent ask verdicts / Verdicts ask permanents** — `POST /security/ask/verdict` accepts `permanent`: allow-always writes the IP to `whitelisted_ips` (and gets an iptables RETURN exemption at next start, so the flow is never re-asked), deny-always creates a persisted firewall block rule. The UI now offers all four classic choices. / `permanent` sur le verdict ask : autoriser-toujours whitelist l'IP (+ exemption iptables au prochain start), refuser-toujours crée une règle de blocage persistée. Les quatre choix classiques sont dans l'UI.
- **Translation contribution docs / Doc contribution traductions** — README explains how to add a language (one file under `frontend/src/locales/` + registration in `i18n.jsx`). / Le README explique comment ajouter une langue (un fichier dans `frontend/src/locales/` + enregistrement dans `i18n.jsx`).

## [1.5.2] — 2026-10-22

### Added / Ajouté

- **Pure-Python NFQUEUE client / Client NFQUEUE pur Python** — `detection/nfqueue.py` speaks `nfnetlink_queue` over AF_NETLINK directly: config commands (PF_UNBIND/PF_BIND/BIND/COPY_PACKET) verified by netlink ACKs, packet receive + ACCEPT/DROP verdicts. Ask-on-connect no longer needs `python-netfilterqueue` or `libnetfilter_queue` — Linux + root + iptables only. Each held packet now waits on its own waiter thread so a stalled flow can't starve other verdicts. / `detection/nfqueue.py` parle nfnetlink_queue en AF_NETLINK directement : bind vérifié par ACK, réception + verdicts ACCEPT/DROP. Plus besoin de `python-netfilterqueue` — Linux + root + iptables seulement. Chaque paquet retenu a son thread d'attente dédié.
- **DGA heuristic / Heuristique DGA** — `detection/dga.py` scores resolved DNS names and TLS SNIs on lexical features (Shannon entropy, vowel ratio, consonant runs, digit noise, nesting) → `DGA_SUSPECT` (info), one alert per name per hour. Pure local heuristic — no WHOIS, no domain-age data. / `detection/dga.py` note les noms DNS/SNI sur traits lexicaux → `DGA_SUSPECT` (info), cooldown 1 h par nom. Heuristique locale pure.
- **Protocol/port mismatch / Protocole déguisé** — `detection/protomatch.py` verifies the ≤64 B payload head against the well-known port (HTTP/80, DNS/53 both transports, SSH/22, TLS/443+853, mail ASCII commands) → `PROTO_MISMATCH` (info), cooled down per flow. / `detection/protomatch.py` vérifie la tête du payload contre le port bien connu → `PROTO_MISMATCH` (info).
- **Volume kill-switch (opt-in) / Kill-switch de volume (opt-in)** — setting `kill_switch_enabled` upgrades an `UPLOAD_SPIKE` alert into a real firewall block on the remote IP (deduped per IP, best-effort — needs privileges). Off by default; toggle in Settings. / Le réglage `kill_switch_enabled` transforme `UPLOAD_SPIKE` en vrai blocage pare-feu sur l'IP distante (dédupliqué, privilèges requis). Off par défaut.

### Changed / Modifié

- **Ask-on-connect dependency / Dépendance ask-on-connect** — dropped `NetfilterQueue`/`libnetfilter_queue`; `askmode` uses the bundled pure-Python client. / `NetfilterQueue`/`libnetfilter_queue` abandonnés ; `askmode` utilise le client pur Python embarqué.

## [1.5.1] — 2026-10-22

### Added / Ajouté

- **Settings UI for the new opt-ins / Réglages UI des nouveaux opt-ins** — syslog address, ask-on-connect (timeout + fail-open + live availability), IOC peer list + periodic toggle are all editable in Settings; `ask_timeout`/`ask_failopen`/`gossip_enabled` apply live. / Adresse syslog, ask-on-connect, liste de pairs IOC + bascule périodique — tous éditables dans les Réglages, appliqués à chaud.
- **Periodic IOC push / Push IOC périodique** — `gossip_enabled` re-pushes your salted-Merkle proof pack to configured peers every 5 min automatically. / `gossip_enabled` repousse le paquet Merkle salé toutes les 5 min.
- **eBPF enforcer endpoints / Endpoints enforceur eBPF** — `GET /security/ebpf_enforce`, `POST /security/ebpf/isolate {pid}`, `POST /security/ebpf/block {ip}` wire the cgroup-skb enforcer into the API. / Le enforcer cgroup-skb exposé : statut + isolation de pid + blocage d'IP.
- **Translated v1.5 docs / Docs v1.5 traduites** — CHANGELOG, PRIVACY and FIREWALL sections now exist in de/es/ja/pt-BR/ru/zh-CN. / Sections CHANGELOG, PRIVACY et FIREWALL v1.5 en de/es/ja/pt-BR/ru/zh-CN.

### Fixed / Corrigé

- **eBPF attach scope / Portée de l'attach eBPF** — the cgroup-skb program attached at the cgroup2 *root*, which would have made every blocked-IP drop host-wide; it now attaches to the dedicated `snitch` cgroup so drops apply only to `isolate_pid()`-moved processes, as documented. / Le programme cgroup-skb s'attachait à la racine cgroup2 — chaque blocage aurait été global ; attach au cgroup `snitch` dédié désormais.
- **iForest split quality / Qualité des splits iForest** — trees now only split on features with variance in the subset (constant columns compressed every score toward 0.5) and draw a fresh subsample per tree — measurably better baseline/outlier contrast. / Les arbres ne splittent que sur les features à variance réelle + sous-échantillon frais par arbre — contraste réel restauré.
- **Flaky ML test / Test ML flaky** — seeded forest + realistic baseline (stable destination set) make the score assertion deterministic. / Forêt seedée + baseline réaliste rendent l'assertion déterministe.

## [1.5.0] — 2026-10-22

### Added / Ajouté

- **Passive TLS certificate inspection / Inspection passive des certificats TLS** — `capture/tlscert.py` reassembles the server's TLS `Certificate` handshake message across TCP segments (bounded 16 KiB/flow, 256 flows, 30 s TTL) and parses the leaf DER with a minimal reader: issuer/subject CN·O, self-signed flag (strict DER equality), dNSName SANs, validity. Self-signed leaves and SAN/SNI mismatches raise `TLS_CERT`. TLS 1.3 encrypts that message — reported as unobservable, never faked. Zero MITM, zero decryption. / `capture/tlscert.py` réassemble le message Certificate du serveur à travers les segments TCP (borné) et parse le DER feuille : issuer/subject, auto-signé, SANs, validité → alerte `TLS_CERT`. TLS 1.3 chiffre ce message — rapporté inobservable, jamais simulé.
- **ICMP payload capture + tunnel heuristic / Capture payload ICMP + heuristique tunnel** — ICMP/ICMPv6 packets now keep type/code in `flags` (type<<8|code) and their payload head in `app_head`; repeated fat echo payloads (≥24 B, 3+ in 5 min) raise `ICMP_TUNNEL` — the ptunnel/icmpsh exfiltration signature. / Les paquets ICMP/ICMPv6 gardent type/code dans `flags` et la tête du payload dans `app_head` ; des échos gros répétés → `ICMP_TUNNEL`.
- **High-entropy cleartext detection / Détection haute entropie en clair** — near-random payload heads (≥4.7 bits/byte over ≥48 B) on non-TLS sockets raise `HIGH_ENTROPY` (info) — covert encryption/stego hint; cooled down per host. / Têtes de payload quasi aléatoires sur sockets non TLS → `HIGH_ENTROPY` (info), cooldown par hôte.
- **Pure-Python isolation forest / Forêt d'isolation pur Python** — `detection/iforest.py` (Liu et al. 2008, ~150 lines, zero deps) + `detection/mlflow.py` score outbound flows on 6 privacy-safe features (port, size, interval, fan-out, hour); inert until 384 flows learned, `ML_ANOMALY` at score ≥0.62 with per-(process,remote) cooldown. Honest scope: unsupervised outlier vs YOUR baseline, complements heuristics. / `detection/iforest.py` (~150 lignes, zéro dépendance) + `detection/mlflow.py` scorant les flux sortants sur 6 features sûres ; inerte avant 384 flux, `ML_ANOMALY` à score ≥0,62 avec cooldown. Non supervisé vs VOTRE baseline.
- **Ask-on-first-connect (Linux NFQUEUE) / Verdict à la première connexion** — opt-in `ask_enabled` diverts each NEW outbound flow into NFQUEUE 7 (iptables, private ranges + established exempt) and holds it up to `ask_timeout` for `POST /security/ask/verdict` allow/deny — real verdict power, decisions persist per session; timeout drops by default. Requires root + `NetfilterQueue`; `GET /security/ask` reports availability honestly (Windows/macOS need the contrib kernel tracks). / `ask_enabled` détourne chaque NOUVEAU flux vers NFQUEUE 7 et le gèle jusqu'au verdict allow/deny — vrai pouvoir de verdict ; timeout = drop. Root + `NetfilterQueue` requis ; statut honnête via `GET /security/ask`.
- **eBPF egress enforcement / Enforcement eBPF en sortie** — `detection/ebpf_enforce.py` attaches a `BPF_PROG_TYPE_CGROUP_SKB` program at cgroup2 egress dropping destinations in a kernel map, with `isolate_pid()` reparenting a process into our dedicated cgroup for per-process filtering. Root + bcc + cgroup2; degrades to applied=False. / Programme `cgroup_skb` attaché en egress cgroup2 + `isolate_pid()` — filtrage par processus dans le noyau. Root + bcc requis.
- **Process-hollowing evidence / Preuve de hollowing** — `POST /security/hollow` diffs a process's file-backed executable pages in `/proc/<pid>/mem` against the same ranges on disk (SHA-256, ≤64 MiB, read-only regions only) — memory≠disk means post-load patching. Linux, on-demand, never raises. / `POST /security/hollow` diff les pages exécutables mémoire vs disque — écart = patch post-chargement. Linux, à la demande.
- **IOC peer sync (decentralized-lite) / Sync IOC entre pairs** — opt-in `gossip_peers` + `POST /remote/ioc_sync` pushes your salted-Merkle proof pack to explicitly-listed peers' authenticated `/security/iocpack/import`; per-peer results surface in `GET /remote/ioc_sync`. Hash commitments only, no discovery, no central server. / `gossip_peers` + `POST /remote/ioc_sync` pousse le paquet Merkle salé vers les pairs explicitement listés — engagements de hash seulement.
- **Syslog alerting / Alerting syslog** — `syslog_addr` (`host:port` UDP or `tcp://`) forwards warning/critical alerts as RFC 3164 datagrams (local4 facility, severity-mapped PRI) — the SIEM/Wazuh path, independent of the webhook switch; never breaks detection on failure. / `syslog_addr` relaie les alertes en datagrammes RFC 3164 — chemin SIEM/Wazuh, indépendant du webhook, jamais bloquant.
- **Geo-aware + actionable custom rules / Règles géo + actionnables** — new `asn`/`country` fields (local .mmdb only), `eq`/`ne`/`contains` ops; `action:"block"` additionally installs a REAL firewall rule on each newly-matched remote IP (deduped per rule+target — the flow-level kill-switch). / Champs `asn`/`country` (mmdb local) ; `action:"block"` installe une vraie règle pare-feu par IP matchée (dédupliquée — kill-switch de flux).
- **Actionable alerts / Alertes actionnables** — alert details now carry `pid`/`process`; the UI offers one-click **Block IP** (real firewall rule), **Kill**, **Suspend**, and ASK_VERDICT **Allow/Deny** buttons; explanation templates gained remediation actions for all new types. / Les alertes portent `pid`/`process` ; l'UI propose Bloquer IP, Tuer, Suspendre et Autoriser/Refuser ; gabarits d'explication avec actions de remédiation.
- **nftables backend / Backend nftables** — Linux firewall rules, lockdown, IP-sinkhole DNAT and domain refresh now drive `nft` directly when iptables is absent (dedicated `inet snitch` table, comment-tagged handle cleanup); per-process rules refuse honestly (no PID owner match in nft). / Règles, lockdown, DNAT sinkhole et refresh domaine pilotent `nft` quand iptables est absent ; les règles par processus refusent honnêtement.
- **firejail sandbox fallback / Repli firejail** — Linux containment falls back to `firejail --net=none --quiet` when `unshare` is unavailable; `available()` reports which backend it will use. / Repli `firejail --net=none` quand `unshare` est absent ; `available()` rapporte le backend choisi.
- **Real-OS integration tests / Tests d'intégration OS réels** — new `integration` CI job (per-OS) running `tests/test_integration_os.py` with `SNITCH_OS_INTEGRATION=1`: Linux proves `unshare -n` egress denial, real `iptables` DROP + live connect failure, `tc` clsact/flower, `perf_event_open`; Windows opens the real `fwpuclnt` engine and proves a WFP BLOCK filter with a TCP connect that fails then recovers after key-delete; macOS proves `sandbox-exec` deny-network end-to-end and hosts-file sinkhole apply/remove. Every test cleans up in `finally` and skips honestly when the primitive is unavailable. / Nouveau job CI `integration` par OS exécutant `tests/test_integration_os.py` : `unshare`, `iptables` réels + connexion probée, `tc`, `perf` sous Linux ; moteur WFP + blocage prouvé par connexion TCP sous Windows ; `sandbox-exec` + hosts sous macOS. Nettoyage en `finally`, skip honnête si la primitive manque.
- **WFP filter enums + byte order / Enums WFP + ordre des octets** — real Windows CI caught `FWP_DATA_TYPE` constants off-by-N (`BYTE_ARRAY16`=11, `BYTE_BLOB`=12, composite addr-mask types at 0x100/0x101) and host-order IPv4 encoding in `FWP_V4_ADDR_AND_MASK` (must be network order); filters now actually match traffic on real Windows. / La CI Windows réelle a attrapé des constantes `FWP_DATA_TYPE` décalées et un encodage IPv4 host-order — les filtres matchent maintenant réellement.
- **perfprobe Windows import / Import perfprobe Windows** — `fcntl` is now imported lazily inside the Linux path instead of top-level (collection crash on Windows). / `fcntl` importé paresseusement dans le chemin Linux (crash de collecte sous Windows).## [1.4.0] — 2026-10-23

### Added / Ajouté

- **Forensic PCAP export / Export PCAP forensique** — `GET /forensics/pcap` serializes the bounded raw-frame ring buffer (~4 MiB) into a Wireshark-ready `.pcap` written by a pure-Python `capture/pcapwriter.py`; real libpcap timestamps preserved, optional `ip`/`process` filters. / `GET /forensics/pcap` sérialise l'anneau de trames brutes (~4 Mio) en `.pcap` lisible par Wireshark via `capture/pcapwriter.py` pur Python ; timestamps réels, filtres `ip`/`process` optionnels.
- **Outbound byte observation / Observation des octets sortants** — Frida deep inspection now also hooks `send`/`WSASend`/`sendto`/`sendmsg` where exports exist, returning bounded head bytes + SHA-256 per flow — an honest byte-observation slice, not full taint analysis. / L'inspection Frida hooke aussi `send`/`WSASend`/`sendto`/`sendmsg` quand présents — tête bornée + SHA-256 par flux : tranche d'observation honnête, pas une analyse de taint complète.
- **Exact-membership IOC proofs / Preuves d'appartenance exactes IOC** — `format=proof` on `GET /security/iocpack` builds `snitch-ioc-proof/1`: salted SHA-256 leaves + a Merkle commitment root; `POST /security/iocpack/import` verifies membership cryptographically (zero false positives) and detects tampering. Not an interactive ZK protocol — documented as such. / `format=proof` produit `snitch-ioc-proof/1` : feuilles SHA-256 salées + racine d'engagement Merkle ; l'import vérifie l'appartenance cryptographiquement (zéro faux positif) et détecte la falsification. Pas un protocole ZK — documenté ainsi.
- **Network-denial sandbox / Sandbox sans réseau** — `POST /security/sandbox` detonates a user-chosen executable with **zero egress**: Linux unprivileged `unshare --user --net` or macOS `sandbox-exec` deny-network; bounded runtime + output, honest unsupported-error elsewhere. `contrib/snitch-contain` is the manual twin. / `POST /security/sandbox` exécute un binaire choisi avec zéro égress : `unshare --user --net` non privilégié (Linux) ou `sandbox-exec` deny-network (macOS) ; durée + sortie bornées, erreur honnête ailleurs. `contrib/snitch-contain` est le pendant manuel.
- **Embedded local model / Modèle local embarqué** — `slm_mode=embedded` loads a user-provided `.gguf` via the optional `llama-cpp-python` package — alert explanations fully in-process, **zero network at all**. Snitch never downloads weights. / `slm_mode=embedded` charge un `.gguf` fourni par l'utilisateur via `llama-cpp-python` optionnel — explications entièrement en processus, zéro réseau. Snitch ne télécharge jamais de poids.
- **Named firewall profiles / Profils pare-feu nommés** — `POST /firewall/profile` applies `permissive` (clean slate), `balanced` (conservative egress baseline: spam-SMTP + common stratum pool ports) or `strict` (baseline + lockdown) through the ordinary rule machinery, with dedup. / `POST /firewall/profile` applique `permissive` (table rase), `balanced` (base sortante prudente) ou `strict` (base + lockdown) via la machinerie de règles ordinaire, avec dédup.
- **Custom alert rules / Règles d'alerte personnalisées** — user-defined matchers (`remote_ip`, `host`, `process_name`, `remote_port`, `protocol`, `direction`, `size` × `eq`/`ne`/`contains`/`regex`/`gt`/`lt`/`cidr`) raising `CUSTOM_RULE` alerts; persisted, bounded regex cache, validated at creation, alert-only (never blocks). / Filtres définis par l'utilisateur levant des alertes `CUSTOM_RULE` ; persistés, cache regex borné, validés à la création, alerte seule (jamais de blocage).
- **Blocklist import / Import de blocklist** — `POST /firewall/blocklist` turns a local hosts/domain file (purely local) or an **opt-in** remote URL (bounded HTTPS fetch, `remote_fetch` flagged in the response) into `domain` rules, deduplicated and capped at 500–5000 entries. / `POST /firewall/blocklist` convertit un fichier local ou une URL opt-in (fetch HTTPS borné, `remote_fetch` signalé) en règles `domain` dédupliquées, plafonnées à 500–5000.
- **Remote pairing / Pairing distant** — opt-in `lan_bind` persisted setting (`POST /remote/pairing`) exposing the API on `0.0.0.0` or a chosen LAN address at next backend start; `GET /remote/pairing` reports effective bind, source and LAN addresses honestly. Token auth always enforced. / Réglage `lan_bind` opt-in exposant l'API sur `0.0.0.0` ou une adresse LAN au prochain démarrage ; `GET /remote/pairing` rapporte honnêtement bind effectif, source et adresses LAN. Jeton toujours exigé.
- **ASN attribution / Attribution ASN** — `GeoLite2-ASN.mmdb`/`dbip-asn-lite.mmdb` lookups now surface `node.asn` (AS number) alongside the org string when the database is present. / Les lookups ASN exposent `node.asn` (numéro d'AS) en plus de l'org quand la base est présente.
- **Native-filter skeletons / Squelettes de filtres natifs** — `contrib/wfp-callout/` (C: WFP kernel callout register/classify/unregister skeleton + signing/build README, references Microsoft `network/trans/inspect` and `WFPStarterKit`) and `contrib/macos-filter/` (Swift `NEFilterDataProvider` skeleton + entitlements README). Research scaffolding, not shipped components — documented honestly. / `contrib/wfp-callout/` (squelette callout WFP noyau + README signature/build) et `contrib/macos-filter/` (squelette `NEFilterDataProvider` Swift + README entitlements). Échafaudage de recherche, pas des composants livrés — documenté honnêtement.
- **UI for the new surface / UI des nouvelles fonctionnalités** — profile buttons, blocklist import form (file/URL with opt-in confirm), custom alert rule CRUD, PCAP export button, remote-pairing toggle with LAN addresses + restart notice, sandbox detonation form, SLM backend selector (Ollama/embedded + GGUF path); 43 new i18n keys × 8 locales (365 total, parity-checked). / Boutons de profils, formulaire d'import blocklist, CRUD de règles d'alerte, bouton export PCAP, bascule pairing distant avec adresses LAN + avis de redémarrage, formulaire de détonation sandbox, sélecteur de backend SLM ; 43 nouvelles clés × 8 locales (365 au total, parité vérifiée).

## [1.3.0] — 2026-10-22

### Added / Ajouté

- **Windows Filtering Platform / Filtrage WFP (Windows)** — `detection/wfp.py` drives `fwpuclnt.dll` directly via ctypes: outbound ALE filters matched per app path, remote IP/CIDR and port, created with deterministic keys (deleted cleanly on rule removal) and orphan-purged by enumeration. Replaces `netsh` as the Windows backend when elevated; honest `applied=False` otherwise. User-mode filter management only — no kernel callout. / `detection/wfp.py` pilote `fwpuclnt.dll` en ctypes : filtres ALE sortants par chemin d'appli, IP/CIDR et port, clés déterministes (suppression propre) + purge des filtres orphelins par énumération. Remplace `netsh` sous Windows avec élévation ; `applied=False` honnête sinon. Gestion user-mode seule — pas de callout noyau.
- **eBPF connect probe / Sonde eBPF connect** — optional BCC `tcpconnect`-style kprobe (`backend/capture/ebpf_probe.py`, setting `ebpf_probe`, Linux + root + python3-bcc) that attributes `connect()` calls of short-lived processes the socket table misses; ambiguous destinations are never guessed. Status at `GET /security/ebpf`. / Kprobe BCC optionnel qui attribue les `connect()` des processus éphémères ratés par la table des sockets ; jamais de supposition en cas d'ambiguïté. État via `GET /security/ebpf`.
- **Frida deep inspection / Inspection profonde Frida** — `POST /security/deep_inspect` attaches to one PID for ≤60 s (opt-in `frida` package) and reports which loaded module issued each `connect()`/`WSAConnect()`; module paths under staging dirs yield `INJECT_SUSPECT`. / `POST /security/deep_inspect` attache à un PID ≤60 s et rapporte quel module chargé a émis chaque `connect()`/`WSAConnect()` ; chemins de staging → `INJECT_SUSPECT`.
- **Sinkhole responder / Répondeur sinkhole** — loopback HTTP listener (:80) and TLS/SNI probe (:443) activated while a `sinkhole` rule is enabled; every redirected attempt becomes a `SINKHOLE_HIT` alert with Host/URI or SNI plus process attribution. / Écoute HTTP (:80) et sonde SNI (:443) en loopback tant qu'une règle `sinkhole` est active ; chaque tentative devient une alerte `SINKHOLE_HIT` avec Host/URI ou SNI + processus.
- **Loaded-module integrity / Intégrité des modules chargés** — Merkle root over a process's file-backed executable mappings → `MODULE_CHANGED`; mapped paths under temp/memfd/staging locations → `MODULE_SUSPECT`. Bounded, read-only. / Racine Merkle sur les mappings exécutables fichier-basés → `MODULE_CHANGED` ; chemins temp/memfd/staging → `MODULE_SUSPECT`. Borné, lecture seule.
- **Cryptomining detection / Détection de cryptominage** — bounded cleartext `app_head` parser field: stratum JSON (`mining.subscribe`) → `MINING_STRATUM` (critical); known pool ports mark suspects that sustained process CPU corroborates into `MINING_SUSPECT` — port alone never alerts. / Champ `app_head` borné : JSON stratum → `MINING_STRATUM` (critique) ; ports de pools + CPU soutenue → `MINING_SUSPECT` — un port seul n'alerte jamais.
- **Hardware counters / Compteurs matériels** — `POST /security/perf` samples cycles/instructions/cache-misses for a PID via `perf_event_open` (ctypes, Linux, gated by `perf_event_paranoid`) to corroborate mining suspicion. / `POST /security/perf` échantillonne cycles/instructions/cache-misses d'un PID via `perf_event_open` (ctypes, Linux) pour corroborer la suspicion de minage.
- **Local LLM enrichment / Enrichissement LLM local** — opt-in (`slm_enabled`): `/security/explain` can enrich its bilingual explanation through an Ollama-compatible endpoint **restricted to loopback** — remote endpoints are rejected. Deterministic templates remain the default and the fallback. / Opt-in : `/security/explain` enrichit ses explications via un endpoint Ollama **loopback uniquement** — les endpoints distants sont rejetés. Les gabarits restent le défaut.
- **Privacy-preserving IOC packs / Paquets IOC préservant la vie privée** — `GET /security/iocpack` exports this machine's indicators as a Bloom filter + randomized response (ε≈4.6, plausible deniability — never raw IOCs); `POST /security/iocpack/import` checks observed destinations against a received pack, probabilistically, never auto-blocks. / `GET /security/iocpack` exporte les indicateurs en filtre de Bloom + randomized response (jamais en clair) ; `/security/iocpack/import` confronte les destinations à un paquet reçu, en probabiliste, sans blocage automatique.
- **Egress throttling / Bridage sortant** — rule `action: "throttle"` with `rate` kbit/s polices a destination via Linux `tc` clsact/flower filters (applied/removed per rule, delta-applied on domain re-resolution). Rejected on port/process rules; `applied=False` off Linux. / Action `throttle` + `rate` kbit/s bride une destination via `tc` clsact/flower sous Linux. Rejetée sur port/processus ; `applied=False` hors Linux.
- **UI for the new surface / UI des nouvelles fonctionnalités** — deep-inspect button per process, throttle action + rate in the rule form, IOC pack export/import in the Firewall panel, eBPF and local-LLM settings; 29 new i18n keys × 8 locales (322 total, parity-checked). / Bouton d'inspection profonde par processus, action throttle + débit, export/import de paquet IOC, réglages eBPF et LLM local ; 29 nouvelles clés × 8 locales (322 au total, parité vérifiée).

## [1.2.0] — 2026-10-22

### Added / Ajouté

- **Outbound firewall orchestration / Orchestration du pare-feu sortant** — user rules (`ip`, `cidr`, `domain`, `process`, `port`) applied to the OS-native firewall best-effort: `netsh advfirewall` on Windows, `iptables` on Linux, a generated `pf` anchor on macOS. Persisted, re-applied at startup, honest `applied=False` when privileges are missing (matching + `BLOCKED_ATTEMPT` counters still work). / Règles utilisateur (`ip`, `cidr`, `domain`, `process`, `port`) appliquées au pare-feu natif OS au mieux : `netsh` sous Windows, `iptables` sous Linux, ancre `pf` sous macOS. Persistées, réappliquées au démarrage, `applied=False` honnête sans privilèges (matching + compteurs `BLOCKED_ATTEMPT` actifs).
- **Lockdown / Confinement** — panic switch dropping outbound traffic to public IPs while keeping loopback/LAN alive (Linux `SNITCH_LOCK` chain, `netsh` rules, `pf` anchor). / Interrupteur panique coupant le trafic sortant vers les IP publiques tout en préservant loopback/LAN.
- **Process actions / Actions processus** — `POST /processes/kill` and `POST /processes/suspend` (by PID, refuses PIDs ≤ 3 and Snitch itself); kill/suspend buttons in the process list. / `POST /processes/kill` et `POST /processes/suspend` (par PID, refuse les PID ≤ 3 et Snitch) ; boutons kill/suspend dans la liste des processus.
- **Threat intelligence (opt-in) / Threat intel (opt-in)** — reputation checks against AbuseIPDB, AlienVault OTX or VirusTotal with your own API key; off by default, one call per newly-seen public IP, bounded LRU cache + dedup, `THREAT_HIT` alerts on suspicious/malicious verdicts. / Vérifs de réputation via AbuseIPDB, AlienVault OTX ou VirusTotal avec votre clé ; désactivé par défaut, un appel par IP publique nouvelle, cache LRU borné + dédup, alertes `THREAT_HIT`.
- **External webhooks (opt-in) / Webhooks externes (opt-in)** — warning/critical alerts POSTed live to Discord, Slack, Telegram (with chat ID) or any endpoint; off by default. / Alertes warning/critiques POSTées en direct vers Discord, Slack, Telegram ou tout endpoint ; désactivé par défaut.
- **Detection additions / Ajouts de détection** — `DNS_TUNNEL` (oversized DNS names/labels), `CLEARTEXT` (FTP/Telnet/HTTP/plain-mail egress), `BASELINE_DEVIATION` (per-process learned country profile, persisted). / `DNS_TUNNEL` (noms/labels DNS surdimensionnés), `CLEARTEXT` (sorties FTP/Telnet/HTTP/mail en clair), `BASELINE_DEVIATION` (profil pays appris par processus, persisté).
- **Security audit / Audit de sécurité** — `GET /security/audit` computes a 0–100 score plus plain-language recommendations from recent alerts and the live graph; surfaced in the Firewall panel. / `GET /security/audit` calcule un score 0–100 + recommandations en langage clair depuis les alertes récentes et le graphe ; affiché dans le panneau Pare-feu.
- **Forensics export / Export forensique** — `GET /forensics/export?format=json|csv|stix` bundles process tree, executable SHA-256, matching alerts and traffic history; STIX is a minimal 2.1 bundle (indicators + observed-data) for SIEM import. / `GET /forensics/export?format=json|csv|stix` — arbre de processus, SHA-256 de l'exécutable, alertes et historique ; STIX = bundle 2.1 minimal pour SIEM.
- **Firewall & security UI / UI pare-feu & sécurité** — dedicated panel: lockdown switch, rule create/toggle/delete, per-rule blocked counters, platform-support honesty, audit report, forensics download buttons; per-connection Block action in the sidebar. / Panneau dédié : lockdown, création/bascule/suppression de règles, compteurs bloqués par règle, honnêteté plateforme, rapport d'audit, boutons d'export forensique ; action Bloquer par connexion dans la sidebar.
- **Five new UI locales / Cinq nouvelles locales** — de, ru, ja, pt-BR, zh-CN (8 total, 280-key parity-checked); dictionaries moved to `frontend/src/locales/*.js` so a new language is a single-file PR. / de, ru, ja, pt-BR, zh-CN (8 au total, parité 280 clés) ; dictionnaires déplacés vers `frontend/src/locales/*.js` — une nouvelle langue = PR d'un fichier.
- **Sinkhole rule action / Action sinkhole** — `POST /firewall/rules` accepts `action: "sinkhole"`: domains are redirected to loopback via a marked `# snitch-sinkhole` block in the hosts file (all OSes), IPs/CIDRs via iptables `DNAT` in the nat OUTPUT chain (Linux only). `sinkhole` on `process`/`port` is rejected; unsupported platforms report `applied=False` honestly. / `action: "sinkhole"` : les domaines sont redirigés vers loopback via un bloc marqué dans le fichier hosts (tous OS), les IP/CIDR via `DNAT` iptables (Linux). Rejeté pour `process`/`port` ; plateformes non gérées → `applied=False` honnête.
- **Domain rules re-resolution / Re-résolution des règles domaine** — enabled `domain` rules re-resolve every ~10 min; the resolved-IP delta is applied per-OS so CDN rotation can't silently unblock a name. / Les règles `domain` actives sont re-résolues toutes les ~10 min ; le delta d'IP est appliqué par OS pour que la rotation CDN ne débloque pas un nom en silence.
- **Process integrity watch / Veille d'intégrité des processus** — on by default (read-only, local): SHA-256 baselines of networked executables (`BINARY_CHANGED`, persisted `integrity_baselines`), name/exe mismatch (`NAME_MISMATCH`), Linux-only `rwxp` maps scan (`MEM_RWX`, info-level for known JIT apps). `GET /security/integrity` reports capabilities; `POST /security/integrity/check` forces a PID re-check; Settings toggle. / Activée par défaut (lecture seule, local) : baselines SHA-256 des exécutables en réseau (`BINARY_CHANGED`, `integrity_baselines` persisté), mismatch nom/exe (`NAME_MISMATCH`), scan `rwxp` Linux (`MEM_RWX`, niveau info pour les apps JIT connues). `GET /security/integrity`, `POST /security/integrity/check`, interrupteur dans Réglages.
- **Alert explanations / Explications d'alertes** — `GET /security/explain?type=X` returns hand-written bilingual (EN/FR) explanations (meaning, why it matters, next steps) for every alert type; deterministic and offline — not a model. The UI shows them behind a "Why?" button on each alert. / `GET /security/explain?type=X` renvoie des explications bilingues (EN/FR) écrites à la main pour chaque type d'alerte ; déterministes et hors-ligne — pas un modèle. Bouton « Pourquoi ? » sur chaque alerte.

## [1.1.0] — 2026-10-22

### Added / Ajouté

- **Auto-update / Mise à jour automatique** — the desktop app checks GitHub Releases at launch and every 6 h via electron-updater (the `latest-*.yml` feeds were already published). Downloads install on restart; tray menu and Settings show live status. Opt-out in Settings or via `SNITCH_NO_UPDATE=1`. / L'app bureau vérifie les releases GitHub au lancement puis toutes les 6 h via electron-updater. Installation au redémarrage ; statut en direct dans le tray et les Réglages. Désactivation dans Réglages ou via `SNITCH_NO_UPDATE=1`.
- **QUIC / HTTP/3 visibility / visibilité QUIC/HTTP3** — UDP/443 flows are labelled `QUIC/HTTP3` instead of being lumped into HTTPS or unknown. The QUIC Initial's SNI is encrypted and is never read — the label is honest about what is observable. / Les flux UDP/443 sont étiquetés `QUIC/HTTP3` au lieu d'être rangés en HTTPS ou inconnu. Le SNI du paquet Initial QUIC est chiffré et jamais lu — l'étiquette reste honnête.
- **Watchlist** — pin IPs or domain suffixes (`example.com` also matches `api.example.com`); a dedicated `WATCHLIST_HIT` alert fires on first contact, rate-limited per (entry, host). Persisted, managed in Settings. / Épinglez des IP ou suffixes de domaine ; l'alerte dédiée `WATCHLIST_HIT` tire au premier contact, limitée par (entrée, hôte). Persistée, gérée dans Réglages.
- **Per-process upload alert / Alerte d'envoi par processus** — `UPLOAD_SPIKE` warns when one process exceeds a configurable MB/min ceiling (default 50, 0 = off) — covers exfiltration that the baseline-relative `VOLUME_SPIKE` misses on cold-start processes. / `UPLOAD_SPIKE` alerte quand un processus dépasse un plafond Mo/min réglable (50 par défaut, 0 = off) — couvre l'exfiltration que le `VOLUME_SPIKE` relatif rate sur les processus frais.
- **Capture interface selector / Sélecteur d'interface de capture** — `GET/POST /capture/interfaces` + a Settings dropdown listing libpcap devices; switching restarts capture instantly. Replaces the `SNITCH_IFACE` env var for desktop users. / `GET/POST /capture/interfaces` + liste déroulante dans Réglages ; le changement redémarre la capture aussitôt. Remplace la variable `SNITCH_IFACE`.
- **Wi-Fi context / Contexte Wi-Fi** — the toolbar shows the current SSID (or the capture interface when not on Wi-Fi). Best-effort per OS, 60 s cache. / La barre d'outils affiche le SSID courant (ou l'interface hors Wi-Fi). Au mieux par OS, cache 60 s.
- **Spanish UI / UI espagnole** — full `es` dictionary (194 keys, parity-checked); the language toggle is now EN/FR/ES. / Dictionnaire `es` complet (194 clés, parité vérifiée) ; le sélecteur devient EN/FR/ES.
- **Snap package / Paquet snap** — electron-builder now emits a strict-confinement `.snap` (with the `network-observe` plug for AF_PACKET capture). Flatpak is deliberately not shipped — the sandbox cannot expose raw packet capture (documented in `docs/PACKAGING.md`). / electron-builder émet un `.snap` en confinement strict (plug `network-observe` pour la capture AF_PACKET). Pas de Flatpak — la sandbox ne peut pas exposer la capture brute (documenté dans `docs/PACKAGING.md`).
- **Free code signing path / Signature de code gratuite** — optional SignPath Foundation OSS integration in CI (`vars.SIGNPATH_*` + `secrets.SIGNPATH_API_TOKEN`): the Windows installer is Authenticode-signed automatically once the project is accepted. Fully documented in `docs/SIGNING.md` including the honest macOS story (no free notarization exists). / Intégration optionnelle de SignPath Foundation OSS dans la CI : l'installeur Windows est signé Authenticode automatiquement une fois le projet accepté. Documenté dans `docs/SIGNING.md`, y compris la situation macOS (pas de notarisation gratuite).

## [1.0.8] — 2026-10-22

### Changed / Modifié

- **True native light theme / Vrai thème clair natif** — replaces the v1.0.7 invert filter with a full design-token system: every surface, text, border and accent colour in the app paints through CSS custom properties with a hand-picked light palette. Map, force graph, timeline and the WebGL aurora all follow the theme, and the toggle still persists your choice. / Remplace le filtre d'inversion de la v1.0.7 par un système de tokens : chaque surface, texte, bordure et accent passe par des variables CSS avec une palette claire choisie à la main. Carte, graphe, timeline et aurore WebGL suivent le thème, et le choix reste persisté.

## [1.0.7] — 2026-10-22

### Added / Ajouté

- **Light theme / Thème clair** — honours `prefers-color-scheme` out of the box and can be overridden with the sun/moon toggle in the toolbar; the choice is persisted in `localStorage`. Implemented as a hue-preserving invert of the authored dark palette, so graphs, map and aurora stay coherent. / Respecte `prefers-color-scheme` par défaut et se remplace via le bouton soleil/lune de la barre d'outils ; le choix est persisté. Réalisé par inversion préservant la teinte de la palette sombre, donc graphe, carte et aurore restent cohérents.

### Fixed / Corrigé

- **AppImage catalog compliance / conformité au catalogue AppImage** — the Linux asset is now named `Snitch-x86_64.AppImage` (proper architecture naming) and electron-builder publishes GitHub update metadata (`latest-linux.yml` + `.zsync`), enabling auto-update through AppImageUpdate-compatible tools. / L'asset Linux est désormais nommé `Snitch-x86_64.AppImage` (nommage d'architecture correct) et electron-builder publie les métadonnées de mise à jour GitHub (`latest-linux.yml` + `.zsync`), permettant l'auto-mise à jour via les outils compatibles AppImageUpdate.

## [1.0.6] — 2026-10-21

### Added / Ajouté

- **One download per OS / Un téléchargement par OS** — every tag now ships ready-to-run apps built by CI: / chaque tag publie des apps prêtes à lancer, construites par la CI :
  - **Windows** — `Snitch Setup <version>.exe` (Electron + NSIS: native window, tray, built-in Npcap check, UAC prompt at backend spawn) and `Snitch-Lite-Setup-<version>-windows-x64.exe` (Inno Setup: backend only, UI opens in the browser). / installeur NSIS Electron (fenêtre native, tray, détection Npcap intégrée, prompt UAC) et variante Inno Lite (backend seul, UI dans le navigateur).
  - **macOS (Apple Silicon)** — `Snitch-<version>-macos-arm64.zip` + `.dmg` built in CI (previously manual). / zip + dmg construits en CI (auparavant manuels).
  - **Linux** — `Snitch-<version>.AppImage` + `.deb` — no more Docker requirement for the desktop app. / AppImage + deb — Docker n'est plus obligatoire pour l'app de bureau.
- **`--launcher` backend mode / mode backend `--launcher`** — picks a free loopback port, computes the API token and opens the browser; used by the Lite installer shortcut. / port loopback libre + jeton API + ouverture du navigateur ; utilisé par le raccourci de l'installeur Lite.

### Fixed / Corrigé

- **Standalone backend bundles now ship the UI** — `frontend_dist` is staged inside the PyInstaller bundle on all OSes; the bare tarball previously served only the API. / Les bundles backend autonomes embarquent désormais l'UI — `frontend_dist` est inclus dans le bundle PyInstaller ; le tarball ne servait auparavant que l'API.

### Changed / Modifié

- CI `package` job builds Electron installers on all three OSes and a `release` job publishes every artifact to the GitHub release automatically. / Le job CI `package` construit les installeurs Electron sur les trois OS et un job `release` publie tous les artefacts sur la release GitHub automatiquement.

## [1.0.5] — 2026-10-17

### Added / Ajouté

- **Windows support / Support Windows** — the packaged app now boots and captures on Windows (Npcap). / L'app packagée démarre et capture sous Windows (Npcap).
- **Process icons / Icônes de processus** — per-process Lucide icons in the Apps table (external contribution). / Icônes Lucide par processus dans le tableau Applications (contribution externe).
- **24 new tracker domains / 24 domaines trackers** in the classifier blocklist (external contribution). / dans la liste de classification (contribution externe).

### Fixed / Corrigé

- Backend crash on `console=False` PyInstaller builds (`sys.stdout`/`sys.stderr` = None) — issue #25. / Crash backend sur les builds PyInstaller `console=False`.
- Capture interface selection on Windows — Snitch now picks the interface carrying the default route instead of `vEthernet (WSL)`. / Sélection de l'interface de capture sous Windows — Snitch choisit celle qui porte la route par défaut.
- `NaNh ago` on alert timestamps with timezone offsets. / Horodatages d'alertes affichant « NaNh ago ».
- Electron splash no longer hides error dialogs; timeout message lists causes + log folder. / Le splash Electron ne masque plus les dialogues d'erreur.
- Four leftover English strings translated in the French dictionary (external contribution). / Quatre chaînes anglaises restantes traduites (contribution externe).
- Version now single-sourced from `backend/version.py` (diagnostics showed 1.1.0). / Version unifiée depuis `backend/version.py`.

### Changed / Modifié

- React 18 → 19, uvicorn 0.30 → 0.54, fastapi → 0.143, psutil → 7.2, websockets → 17.2, maxminddb → 3.2, aiofiles → 25.1, lucide-react → 1.55, vite → 8.3.4, electron → 44.7 (+ dev deps). / Montées de versions majeures validées par la CI complète.

## [1.0.4] — 2026-10-05

- First public release. / Première release publique.
