# Kit de lancement mondial — tout copiable-collable

[English](drafts-launch.md) | [Français](drafts-launch.md) | [Español](drafts-launch.es.md) | [Deutsch](drafts-launch.de.md) | [Русский](drafts-launch.ru.md) | [日本語](drafts-launch.ja.md) | [Português](drafts-launch.pt-BR.md) | [中文](drafts-launch.zh-CN.md)

> **Objectif : GitHub Trending.** L'algorithme mesure la *vélocité* des stars
> (pics sur 24-48 h), pas le total. Tout doit donc sortir dans la même
> fenêtre de ~6 h le jour J : mardi ou mercredi.

## Timing jour J

- **Jour :** mardi ou mercredi (jamais lundi, vendredi ni week-end)
- **Heure pivot : 14 h Paris** = 8 h New York = 21 h Tokyo = 22 h Sydney
- **Ordre :** Show HN en premier → Reddit (1 sub/heure) → posts régionaux
  (V2EX, Habr, TabNews, OKKY…) dans la foulée → réponses aux commentaires
  pendant 3-4 h
- Les articles longs (Qiita ✅, Zenn ✅, Habr, LinuxFr, dev.to ✅) peuvent
  sortir *avant* — ils créent les liens que le jour J citera.

## Fiche d'identité (pour harmoniser toutes les plateformes)

- **Nom :** Snitch
- **Tagline EN :** Open-source application firewall — see and block every connection, 100% local
- **Repo :** https://github.com/aixisstudio/Snitch
- **Site :** https://aixisstudio.github.io/Snitch/
- **Licence :** AGPL-3.0-or-later
- **Plateformes :** Windows, macOS, Linux (+ Docker, agent Rust headless)
- **Langues UI :** EN, FR, ES, DE, RU, JA, PT-BR, ZH-CN
- **Arguments clés :** blocage par processus (eBPF / NFQUEUE / nftables /
  Windows WFP), règles Sigma, threat intel offline, détection DGA / tunnel
  ICMP / beaconing, zéro télémétrie, API loopback+token, `SNITCH_DEMO=1`,
  exports SIEM (ECS/CEF/JSON/Syslog), déploiement Ansible/Helm/GPO.

---

## 1. Show HN — news.ycombinator.com/submit

**URL :** `https://github.com/aixisstudio/Snitch`

### Titre — option A (recommandé)

`Show HN: Snitch – open-source app firewall, Sigma rules and one-click blocking`

(80/80 caractères)

### Titre — option B

`Show HN: Open-source Little Snitch alternative that actually blocks (eBPF/WFP)`

### Premier commentaire auteur — dans les 60 s après soumission

```
Author here. Snitch started as a passive network map and grew into a
full application firewall: it attributes every outbound connection to
its process and can now *block* it in one click.

Stack details for the curious:

- Capture: ctypes → libpcap (Npcap on Windows), own bounded parsers
  for IPv4/IPv6/TCP/UDP/DNS/TLS-SNI — no Scapy (GPL-2.0-only).
- Enforcement: eBPF on modern Linux, NFQUEUE + nftables elsewhere,
  Windows Filtering Platform on Windows. Ask-on-first-connect mode
  (NFQUEUE) prompts allow/deny per process.
- Detection: Sigma-compatible rule engine, offline threat intel,
  DGA domain detection, ICMP-tunnel and beaconing heuristics.
- Local-first: offline GeoIP (.mmdb), API on 127.0.0.1 only behind
  a per-launch token, zero telemetry, no account, AGPL-3.0.
- Server side: lightweight Rust agent, REST/WebSocket API, ECS/CEF/
  JSON/Syslog export for SIEM, Docker/Helm/Ansible/GPO deployment,
  declarative snitch.toml.
- SNITCH_DEMO=1 feeds synthetic traffic through the real pipeline —
  try it without root.

UI is in 8 languages (EN FR ES DE RU JA PT-BR ZH-CN). Happy to
answer anything — especially the blocking pipeline and why I skipped
Scapy for license reasons.
```

### Règles HN

- Repost OK si l'ancien est mort (guidelines officielles)
- **Jamais** demander d'upvotes ni organiser de vote — shadowban
- Répondre à CHAQUE commentaire dans les minutes qui suivent
- Rester en ligne 2-3 h si ça décolle ; honnêteté > marketing

---

## 2. Reddit — 1 post/heure, angles différents

### r/netsec (le plus technique — en premier)

**Title:** `Snitch — open-source app firewall: per-process outbound monitoring + one-click blocking (Sigma, eBPF/WFP)`

```
Passive pcap → per-process attribution → one-click blocking.

- Capture: ctypes → libpcap / Npcap, own bounded parsers
  (IPv4/IPv6/TCP/UDP/DNS/TLS-SNI), no Scapy
- Enforcement: eBPF / NFQUEUE / nftables / Windows WFP;
  ask-on-first-connect mode prompts per process
- Detection: Sigma-compatible rules, offline threat intel,
  DGA domains, ICMP tunnels, beaconing
- Offline GeoIP, loopback-only API + token, zero telemetry
- Server mode: Rust agent, ECS/CEF/JSON/Syslog export,
  Docker/Helm/Ansible/GPO, declarative snitch.toml
- Windows/macOS/Linux, AGPL-3.0, UI in 8 languages

github.com/aixisstudio/Snitch — SNITCH_DEMO=1 runs synthetic
traffic through the real pipeline, no root needed.
```

### r/opensource

**Title:** `Snitch — open-source Little Snitch alternative that also blocks (AGPL, Windows/macOS/Linux)`

```
Little Snitch is macOS-only and paid. Snitch is the same idea,
open-source (AGPL-3.0) and cross-platform — and it blocks too.

- See every outbound connection per process in real time
- Block apps in one click (eBPF/NFQUEUE/nftables/WFP)
- Sigma-compatible detection rules + offline threat intel
- DGA domain, ICMP-tunnel and beaconing detection
- 100% local: offline GeoIP, loopback API + token, zero telemetry
- Lightweight Rust agent for servers, SIEM export
  (ECS/CEF/JSON/Syslog), headless/CLI mode
- UI in 8 languages

github.com/aixisstudio/Snitch
```

### r/selfhosted — **vendredi uniquement** (règle « New Project Friday »)

**Title:** `Snitch — self-hosted application firewall & network observer (Docker, Rust agent, SIEM export, AGPL)`

```
Runs headless on servers too: a lightweight Rust agent streams
per-process outbound connection data to a central console.
ECS/CEF/JSON/Syslog output for your SIEM, Docker image, Helm
chart, Ansible role, declarative snitch.toml config.

On desktop it's a one-click app firewall: block any process's
outbound connections via eBPF/NFQUEUE/nftables/WFP. Sigma rules,
offline threat intel, DGA/ICMP-tunnel/beaconing detection.
Zero telemetry, loopback-only API, no account.

github.com/aixisstudio/Snitch
```

### r/sysadmin

**Title:** `Open-source per-process outbound firewall with Sigma rules + fleet agent — Snitch`

```
Per-process outbound visibility and blocking for fleets:
Rust agent → central console, Sigma-compatible rules, offline
threat intel, ECS/CEF/JSON/Syslog export, deploy via
Ansible/Puppet/Salt/GPO or Helm. Kill-switch and IOC gossip
supported. Desktop app for Windows/macOS/Linux too.
AGPL-3.0, zero telemetry, loopback-only API.

github.com/aixisstudio/Snitch
```

### r/privacytoolsIO

**Title:** `Snitch — 100% local application firewall, no account, no telemetry (open source)`

### r/SideProject / r/macapps — adapter le texte r/opensource

> ⚠️ **Jamais sur r/privacy** (R3 + R13 bannissent les posts d'apps).
> Toujours la mention « I built this » ; répondre aux questions
> pendant les premières heures.

---

## 3. Lobste.rs (invitation requise — demander à un membre ou sur le canal #lobsters IRC)

**Titre :** `Snitch: open-source application firewall with Sigma rules and eBPF/WFP blocking`

**Tags :** `security` `networking` `rust` `python`

**Texte :** idem r/netsec — ajouter une ligne sur le refus de Scapy
pour raison de licence (GPL-2.0-only) : Lobsters adore ce détail.

---

## 4. Fediverse — Mastodon / Bluesky / Lemmy

### Mastodon (infosec.exchange, fosstodon.org, hachyderm.io)

```
Snitch — open-source application firewall 🛡️

See every outbound connection per process. Block in one click
(eBPF / NFQUEUE / nftables / WFP). Sigma rules, offline threat
intel, DGA + ICMP-tunnel detection. 100% local, zero telemetry,
no account. 8 languages.

github.com/aixisstudio/Snitch
#opensource #infosec #privacy #cybersecurity #foss
```

### Bluesky — même texte, hashtags sans espaces

### Lemmy — communités cibles

- `selfhosted@lemmy.world` — angle agent Rust/headless
- `privacy@lemmy.ml` — angle 100% local / zéro télémétrie
- `opensource@lemmy.ml` — angle AGPL
- `netsec` / `cybersecurity` instances `infosec.pub` — angle Sigma/eBPF
- 1 post par communauté, texte r/opensource adapté.

---

## 5. FR — LinuxFr.org (dépêche) + Journal du hacker + developpez.net

### LinuxFr — dépêche (syntaxe wiki Markdown, longue)

````
# Snitch : pare-feu applicatif libre — voir et bloquer chaque connexion

Snitch est un pare-feu applicatif libre (AGPL-3.0) pour Windows,
macOS et Linux. Il attribue chaque connexion sortante à son processus
en temps réel et permet de la bloquer en un clic — via eBPF, NFQUEUE,
nftables ou WFP sous Windows.

## Fonctionnement

- Capture `ctypes → libpcap` (Npcap sous Windows) ; parseurs maison
  bornés pour IPv4/IPv6/TCP/UDP/DNS/TLS-SNI — pas de Scapy
  (licence GPL-2.0-only incompatible)
- Détection : moteur de règles compatible Sigma, threat intel
  hors-ligne, détection DGA, tunnels ICMP et beaconing
- Local d'abord : GeoIP hors-ligne (.mmdb), API en écoute sur
  127.0.0.1 avec jeton, zéro télémétrie, aucun compte
- Mode serveur : agent Rust léger, API REST/WebSocket,
  exports ECS/CEF/JSON/Syslog, Docker/Helm/Ansible/GPO,
  configuration déclarative `snitch.toml`
- `SNITCH_DEMO=1` injecte du trafic synthétique dans le vrai
  pipeline — testable sans root

## Pour aller plus loin

Dépôt : https://github.com/aixisstudio/Snitch
Site : https://aixisstudio.github.io/Snitch/
````

### Journal du hacker (journalduhacker.net — Lobsters francophone)

**Titre :** `Snitch : pare-feu applicatif libre — visualiser et bloquer chaque connexion sortante (AGPL)`
**Tags :** sécurité, réseau, open-source
**Texte :** résumé de la dépêche ci-dessus (2 paragraphes).

### developpez.net — forum « présentez vos projets »

Adapter la dépêche, ajouter : « projet solo, retours bienvenus ».

---

## 6. RU — Habr.com (article) + Pikabu

### Habr — article complet (markdown)

**Заголовок:** `Snitch: опенсорсный межсетевой экран уровня приложений — видим и блокируем каждое исходящее соединение`

**Теги:** информационная безопасность, open source, сетевые технологии, python, ebpf

```markdown
Snitch — межсетевой экран уровня приложений с открытым исходным
кодом (AGPL-3.0) для Windows, macOS и Linux. Он показывает каждое
исходящее соединение в разрезе процессов и позволяет заблокировать
его одним кликом.

## Что умеет

- Перехват через ctypes → libpcap (Npcap на Windows); собственные
  парсеры IPv4/IPv6/TCP/UDP/DNS/TLS-SNI — без Scapy
- Блокировка по процессам: eBPF, NFQUEUE, nftables, Windows WFP;
  режим «спросить при первом соединении»
- Детектирование: Sigma-совместимые правила, офлайн
  threat-intelligence, DGA-домены, ICMP-туннели, beaconing
- Полностью локально: офлайн GeoIP, API только на 127.0.0.1 с
  токеном, ноль телеметрии, без аккаунта
- Серверный режим: лёгкий Rust-агент, REST/WebSocket API,
  экспорт в SIEM (ECS/CEF/JSON/Syslog), Docker/Helm/Ansible/GPO
- SNITCH_DEMO=1 — синтетический трафик через реальный pipeline,
  root не нужен

Интерфейс на 8 языках, включая русский.

Репозиторий: https://github.com/aixisstudio/Snitch
Сайт: https://aixisstudio.github.io/Snitch/
```

### Pikabu — пост (тег «IT», «Open Source»)

**Заголовок:** `Сделал опенсорсный брандмауэр — видно и блокируется каждое соединение любой программы`

**Текст:** неформальная версия статьи Habr — что это, зачем сделал,
скриншот карты, ссылка на GitHub.

---

## 7. ZH — V2EX / 掘金 (Juejin) / CSDN / SegmentFault

### V2EX — nœud « 程序员 » ou « 分享创造 »

**标题:** `开源应用防火墙 Snitch：按进程实时查看并一键拦截所有出站连接`

```
大家好，我做了一个开源应用防火墙 Snitch（AGPL-3.0），
Windows / macOS / Linux 全平台支持，界面含简体中文。

- 实时显示每个进程的出站连接（目标主机、国家、ASN、进程名）
- 一键按进程阻断：eBPF / NFQUEUE / nftables / Windows WFP
  也支持「首次连接询问」模式
- Sigma 兼容规则引擎、离线威胁情报、DGA 域名、
  ICMP 隧道与心跳检测
- 完全本地处理：libpcap/Npcap 抓包、离线 GeoIP，
  API 仅监听 127.0.0.1 并带令牌，零遥测，无需注册
- 服务端：轻量 Rust agent、REST/WebSocket API、
  SIEM 输出（ECS/CEF/JSON/Syslog）、Docker/Helm/Ansible/GPO
- SNITCH_DEMO=1 无需 root 即可体验

GitHub：https://github.com/aixisstudio/Snitch
官网：https://aixisstudio.github.io/Snitch/

欢迎试用、提 issue，觉得有用求个 star 🙏
```

### Juejin / CSDN / SegmentFault — article long

**标题：** `我开源了一个应用防火墙：按进程拦截所有出站连接（eBPF/WFP，8 种语言）`

**正文 :** version détaillée du post V2EX + section « 技术实现 »
(libpcap→ctypes, parseur borné, pipeline de blocage, moteur Sigma).

### Gitee — créer un miroir + README zh-CN (lien vers le repo GitHub en description)

---

## 8. JA — ✅ fait

- Qiita : https://qiita.com/aixis/items/95547fdeb91a08756502
- Zenn : https://zenn.dev/aixisstudio/articles/c3f419d80e0114
- Bonus : partager les deux sur Hatena Bookmark (はてブ) et dans le
  texte du jour J.

---

## 9. KO — OKKY.kr / Velog / Tistory

### OKKY — 게시판 « Tech » ou « 자유게시판 »

**제목:** `오픈소스 애플리케이션 방화벽 Snitch — 프로세스별 아웃바운드 연결을 실시간으로 보고 한 클릭에 차단`

```
Windows / macOS / Linux를 지원하는 오픈소스 애플리케이션
방화벽 Snitch(AGPL-3.0)를 만들었습니다. 한국어는 없지만
영어/일본어/중국어 등 8개 언어 UI를 지원합니다.

- 프로세스별 아웃바운드 연결 실시간 표시
- 원클릭 차단: eBPF / NFQUEUE / nftables / Windows WFP
- Sigma 호환 룰, 오프라인 위협 인텔리전스, DGA/ICMP
  터널/비코닝 탐지
- 완전 로컬: 오프라인 GeoIP, loopback 전용 API + 토큰,
  텔레메트리 없음
- 서버용 경량 Rust 에이전트, SIEM 내보내기
  (ECS/CEF/JSON/Syslog), Docker/Helm/Ansible/GPO

GitHub: https://github.com/aixisstudio/Snitch
```

### Velog / Tistory — article technique (architecture libpcap→blocage)

---

## 10. PT-BR — TabNews

**Título:** `Snitch — firewall de aplicação open source: veja e bloqueie cada conexão de saída por processo`

```
Fiz um firewall de aplicação open source (AGPL-3.0) para
Windows, macOS e Linux. Ele mostra em tempo real cada conexão
de saída por processo e permite bloquear com um clique —
via eBPF, NFQUEUE, nftables ou WFP no Windows.

- Regras compatíveis com Sigma + threat intel offline
- Detecção de domínios DGA, túneis ICMP e beaconing
- 100% local: GeoIP offline, API só no 127.0.0.1 com token,
  zero telemetria, sem conta
- Agente Rust leve para servidores, exportação SIEM
  (ECS/CEF/JSON/Syslog), Docker/Helm/Ansible/GPO
- Interface em 8 idiomas, incluindo português (pt-BR)

GitHub: https://github.com/aixisstudio/Snitch
SNITCH_DEMO=1 para testar sem root.
```

---

## 11. DE — Heise / Golem forums + angle Datenschutz

**Titre (Heise Forum / Golem Kommentar):** `Snitch — quelloffene Anwendungs-Firewall: jede ausgehende Verbindung pro Prozess sehen und blockieren`

```
Snitch ist eine Open-Source-Anwendungsfirewall (AGPL-3.0) für
Windows, macOS und Linux: jede ausgehende Verbindung wird dem
Prozess zugeordnet und kann per Klick blockiert werden —
eBPF, NFQUEUE, nftables bzw. Windows WFP.

- Sigma-kompatible Regeln, Offline-Threat-Intel,
  DGA-/ICMP-Tunnel-/Beaconing-Erkennung
- 100% lokal: Offline-GeoIP, API nur auf 127.0.0.1 mit Token,
  keine Telemetrie, kein Konto — echte Datensouveränität
- Leichtgewichtiger Rust-Agent für Server, SIEM-Export
  (ECS/CEF/JSON/Syslog), Docker/Helm/Ansible/GPO
- UI in 8 Sprachen, Deutsch inklusive

GitHub: https://github.com/aixisstudio/Snitch
```

Angle éditorial : **Datenschutz** — un outil de vie privée qui ne
fait lui-même *aucun* appel réseau non consenti.

---

## 12. ES — meneame.net + foros

**Título:** `Snitch — cortafuegos de aplicación open source: ve y bloquea cada conexión saliente por proceso`

```
Firewall de aplicación open source (AGPL-3.0) para Windows,
macOS y Linux. Muestra cada conexión saliente por proceso en
tiempo real y la bloquea con un clic (eBPF / NFQUEUE / nftables
/ WFP). Reglas compatibles con Sigma, inteligencia de amenazas
offline, detección de dominios DGA, túneles ICMP y beaconing.
100% local: GeoIP offline, API solo en 127.0.0.1 con token,
cero telemetría. Interfaz en 8 idiomas, español incluido.

GitHub: https://github.com/aixisstudio/Snitch
```

---

## 13. NL — Tweakers.net (forum « Software Algemeen »)

```
Snitch — open-source applicatie-firewall (AGPL): ziet elke
uitgaande verbinding per proces en blokkeert met één klik
(eBPF / NFQUEUE / nftables / WFP). Sigma-regels, offline
threat-intel, DGA/ICMP-tunnel/beaconing-detectie. Volledig
lokaal, geen telemetrie, geen account. 8 talen.
github.com/aixisstudio/Snitch
```

---

## 14. PL — Wykop.pl (tag `#programowanie` `#opensource`)

```
Snitch — otwartoźródłowa zapora aplikacyjna (AGPL-3.0) na
Windows/macOS/Linux: pokazuje każde wychodzące połączenie
per proces i blokuje je jednym kliknięciem (eBPF / NFQUEUE /
nftables / WFP). Reguły zgodne z Sigma, offline threat-intel,
detekcja DGA/tuneli ICMP/beaconingu. W 100% lokalnie —
zero telemetrii, bez konta. 8 języków.
github.com/aixisstudio/Snitch
```

---

## 15. X / LinkedIn / Bluesky — posts jour J

### X (thread, 2 tweets)

```
1/ Snitch is now a full open-source application firewall.

See every outbound connection per process — and BLOCK it in one
click (eBPF / NFQUEUE / nftables / WFP). Sigma rules, offline
threat intel, DGA/ICMP-tunnel/beaconing detection.

100% local. Zero telemetry. 8 languages. AGPL.
github.com/aixisstudio/Snitch

2/ Try it without root: SNITCH_DEMO=1 feeds synthetic traffic
through the real pipeline. Server mode: lightweight Rust agent,
SIEM export (ECS/CEF/JSON/Syslog), Helm/Ansible/GPO deploy.
Show HN today — link below.
```

### LinkedIn — reprendre le texte r/opensource + « Show HN today »

---

## 16. Réponses evergreen (Quora / Super User / Superuser / Reddit « Little Snitch alternative »)

```
If you're on Windows or Linux, Little Snitch doesn't exist —
closest options:

• Snitch (open source, AGPL): sees every outbound connection
  per process AND blocks it in one click (eBPF/NFQUEUE/
  nftables/WFP). Sigma rules, offline threat intel, 100% local.
  github.com/aixisstudio/Snitch

• For Linux ask-permission blocking: OpenSnitch
• For Windows: Portmaster or GlassWire (freemium)
• For deep packet inspection: Wireshark

Snitch is the closest free cross-platform equivalent —
monitoring and blocking in one.
```

> ⚠️ Toujours citer les alternatives réelles — légitimité et pérennité.

---

## Checklist jour J

- [ ] 09h Paris : poster l'article Habr (RU) — il monte pendant la journée
- [ ] 13h Paris : posts V2EX, Juejin, OKKY, TabNews, Wykop (Asie/AmSud en ligne)
- [ ] 14h Paris : **Show HN** → commentaire auteur dans les 60 s
- [ ] 14h15 : X thread + Bluesky + Mastodon + LinkedIn
- [ ] 14h30 : r/netsec
- [ ] 15h30 : r/opensource
- [ ] 16h30 : r/sysadmin (et r/selfhosted si vendredi)
- [ ] 17h : Lemmy ×4, Journal du hacker, Tweakers, meneame
- [ ] 18h-21h : répondre à TOUS les commentaires (HN surtout)
- [ ] Le lendemain : réponses Quora/Super User evergreen, remercier
      les partages, surveiller GitHub Trending
- [ ] Mi-janvier 2027 : resoumettre à lissy93/awesome-privacy
      (regle des 16 semaines depuis la premiere release stable, PR #858
      fermee pour maturite insuffisante, la mainteneuse demande
      explicitement d'attendre - ne PAS resoumettre avant)
