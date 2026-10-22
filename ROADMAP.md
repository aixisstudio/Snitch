# Roadmap / Feuille de route

[English](ROADMAP.md) | [Français](ROADMAP.md) | [Español](ROADMAP.es.md) | [Deutsch](ROADMAP.de.md) | [Русский](ROADMAP.ru.md) | [日本語](ROADMAP.ja.md) | [Português](ROADMAP.pt-BR.md) | [中文](ROADMAP.zh-CN.md)

> 🇬🇧 Suggest or vote on features in [GitHub Discussions](https://github.com/aixisstudio/Snitch/discussions) — category *Ideas*. For concrete bugs, use [Issues](https://github.com/aixisstudio/Snitch/issues).
>
> 🇫🇷 Proposez ou votez pour des fonctionnalités dans les [Discussions GitHub](https://github.com/aixisstudio/Snitch/discussions) — catégorie *Ideas*. Pour les bugs concrets, utilisez les [Issues](https://github.com/aixisstudio/Snitch/issues).

## ✅ Shipped / Livré

| Version | What landed / Ce qui est arrivé |
|---|---|
| **v1.0.4** | First public release — real-time graph + world map, per-process attribution, offline geolocation (.mmdb), anomaly alerts, privacy score, LAN device discovery (passive ARP/OUI), mic/camera monitoring (Windows/Linux), demo mode, EN/FR UI / Première release publique — graphe temps réel + carte du monde, attribution par processus, géolocalisation hors-ligne, alertes d'anomalies, score de confidentialité, découverte LAN passive, monitoring micro/caméra, mode démo, UI EN/FR |
| **v1.0.5** | **Windows support** (Npcap, packaged backend), process icons, +24 tracker domains, PyInstaller `console=False` crash fix, interface auto-selection, dependency upgrades / **Support Windows** (Npcap, backend packagé), icônes de processus, +24 domaines trackers, correctifs |

Also live / également en place : Docker image on GHCR, Homebrew tap (`brew install --cask aixisstudio/tap/snitch`), winget package [submitted](https://github.com/microsoft/winget-pkgs/pull/455520), zh-CN README, GitHub Discussions.

| **v1.2 (main, untagged)** | **Security & threat-hunting suite** — OS-firewall orchestration (rules IP/CIDR/domain/process/port via `netsh`/`iptables`/`pf`, best-effort privileges), lockdown panic switch, kill/suspend process actions, opt-in threat intel (AbuseIPDB/OTX), opt-in webhooks (Discord/Slack/Telegram/generic), DNS-tunnel & cleartext & country-baseline detection, security audit report, forensics export (process tree + SHA-256), 8-language UI (`locales/` files) / **suite sécurité & chasse aux menaces** — orchestration pare-feu OS, bouton lockdown, actions kill/suspend, threat intel opt-in, webhooks opt-in, détection tunnel DNS / trafic clair / déviation pays, audit de sécurité, export forensique, UI en 8 langues |

## 🚧 v1.x — in progress / en cours

- [x] **Signed Windows installer** — CI wired for [SignPath](https://signpath.org) OSS (free Authenticode for approved projects); activates once the application is accepted — see `docs/SIGNING.md` / CI branchée sur SignPath OSS (signature Authenticode gratuite pour projets acceptés) ; s'active dès l'acceptation — voir `docs/SIGNING.md`
- [ ] **Signed & notarized macOS build** — needs an Apple Developer account ($99/yr), no free path exists. Until then the [tap](https://github.com/aixisstudio/homebrew-tap) strips quarantine for you / build macOS signée et notarisée — nécessite un compte Apple Developer, aucune voie gratuite. En attendant, le tap retire la quarantaine automatiquement
- [ ] **Homebrew upstream** (`brew install --cask snitch`) — blocked: the `snitch` formula name is already taken by an unrelated project; revisit once we have Developer ID signing / bloqué : le nom `snitch` est déjà pris par un autre projet ; à revoir une fois la signature en place
- [ ] **winget publishing** — [PR #455520](https://github.com/microsoft/winget-pkgs/pull/455520) open, awaiting Microsoft review / en attente de validation Microsoft
- [x] **Windows 1-click installers** — Electron NSIS (`Snitch Setup.exe`, native app + tray) and Inno Lite (`Snitch-Lite-Setup.exe`, backend + browser UI) build in CI on tags; shipping since v1.0.6 / installeurs Windows en un clic — NSIS Electron + Inno Lite, construits en CI aux tags ; livré depuis v1.0.6
- [x] **Linux packages** — .deb / AppImage / **snap** alongside Docker (no Flatpak: the sandbox cannot expose packet capture) / paquets Linux en plus de Docker — deb / AppImage / **snap** (pas de Flatpak : la sandbox ne peut pas exposer la capture)
- [x] **Auto-update** — electron-updater on the published `latest-*.yml` feeds, opt-out in Settings / auto-mise à jour — electron-updater sur les flux `latest-*.yml`, désactivable dans Réglages
- [x] **Export formats** — graph + alerts to JSON/CSV in the UI / export graphe + alertes en JSON/CSV dans l'UI
- [ ] **Deeper tracker coverage** — community-editable lists live in `backend/classifier/lists/` / couverture trackers élargie — listes éditables par la communauté
- [ ] **PCAP export** — capture slices per host/session / export PCAP par hôte ou session

## 💭 Under consideration / à l'étude

- ~~Per-process bandwidth alert~~ — shipped as `UPLOAD_SPIKE` / livré via `UPLOAD_SPIKE`
- Custom alert rules in the UI / règles d'alerte personnalisées dans l'UI
- ~~Light theme / thème clair~~ — shipped in v1.0.7 / livré en v1.0.7
- ~~More languages~~ — 8 locales shipped in `frontend/src/locales/`; more welcome via a single-file PR / 8 locales livrées dans `frontend/src/locales/` ; d'autres bienvenues via une PR d'un seul fichier
- Optional remote pairing for headless hosts — consent-gated, token-protected / appairage optionnel d'hôtes sans écran — avec consentement et jeton
- Map layers: ASN / organisation view / couches de carte : vue ASN / organisation
- Blocklist imports (StevenBlack hosts, EasyList) — needs a privacy/licensing review first / import de blocklists — revue vie privée/licence requise
- Firewall profiles (strict/travel vs developer/permissive) / profils pare-feu (strict/voyage vs dev/permissif)

## 🔬 Research — shipped vs remaining / livré vs restant

Ideas that would take Snitch toward a desktop EDR/XDR. v1.3 shipped the
user-mode-accessible parts of most of them — what remains here genuinely
needs a signed kernel component, an Apple entitlement or a research-grade
build / Idées qui mèneraient Snitch vers un EDR/XDR de bureau. La v1.3 a
livré les parties accessibles en user-mode de la plupart d'entre elles —
ce qui reste ici exige réellement un composant noyau signé, un entitlement
Apple ou un développement de recherche :

- **eBPF probes (Linux)** — *shipped, optional*: a BCC `tcpconnect`-style kprobe attributes `connect()` from short-lived processes that `psutil.net_connections` misses (setting `ebpf_probe`, needs python3-bcc + root; ambiguous destinations are never guessed). Full kernel-space packet capture stays here / *livré, optionnel* : kprobe `tcpconnect` BCC pour attribuer les `connect()` des processus éphémères (réglage `ebpf_probe`, exige python3-bcc + root). La capture noyau complète reste ici
- **WFP (Windows)** — *partially shipped*: `detection/wfp.py` drives `fwpuclnt.dll` directly via ctypes — per-app/IP/port ALE filters, delete-by-key, orphan purge. What stays here is a **kernel callout driver** (signed driver, payload inspection) / *partiellement livré* : `wfp.py` pilote `fwpuclnt.dll` en ctypes — filtres ALE par appli/IP/port. Reste ici : un **callout noyau** (driver signé, inspection de payload)
- **NetworkExtension (macOS)** — `NEFilterProvider` for per-bundle filtering; needs Apple Developer ID + entitlements. Verified: `socketfilterfw` only polices *incoming* app connections — no user-mode substitute exists for outbound per-app / `NEFilterProvider` pour filtrer par bundle ; exige Developer ID + entitlements. Vérifié : `socketfilterfw` ne contrôle que l'**entrant** — aucun équivalent user-mode pour le sortant par-appli
- **Memory/flow correlation** — *partially shipped*: RWX scan + name/exe mismatch + exe hash + **Frida deep-inspect** (`/security/deep_inspect`) which reports which loaded module issued each `connect()` — injected code in staging paths → `INJECT_SUSPECT` / *partiellement livré* : scan RWX + mismatch nom/exe + hash + **inspection Frida** qui rapporte quel module a émis chaque `connect()` — code injecté en chemin de staging → `INJECT_SUSPECT`
- **Dynamic Taint Analysis** — Frida's module-origin attribution (above) is the honest user-mode slice; byte-for-byte exfiltration proof stays research / l'attribution de module via Frida (ci-dessus) est la part user-mode honnête ; la preuve d'exfiltration octet par octet reste en recherche
- **Local SecOps SLM** — *shipped, opt-in*: `detection/llm_local.py` enriches `/security/explain` through an Ollama-compatible endpoint **restricted to loopback** (`slm_enabled`, remote endpoints rejected); deterministic bilingual templates remain the default. Bundling a model binary stays here / *livré, opt-in* : enrichissement via endpoint Ollama **loopback uniquement** ; les gabarits déterministes restent le défaut. Embarquer un modèle binaire reste ici
- **ZKP fleet intel** — *honest substitute shipped*: `/security/iocpack` exports a Bloom filter + randomized-response pack (ε≈4.6, plausible deniability) instead of raw IOCs; `/security/iocpack/import` checks observed destinations probabilistically. A real ZK protocol + fleet transport stays research / *substitut honnête livré* : paquets Bloom + randomized response au lieu d'IOC en clair. Un vrai protocole ZK + transport de flotte reste en recherche
- **PMU/hardware counters** — *shipped, Linux*: `detection/perfprobe.py` wraps `perf_event_open` in ctypes for cycles/instructions/cache-misses per pid (`/security/perf`, gated by `perf_event_paranoid`) — corroborates `MINING_SUSPECT` / *livré, Linux* : compteurs `perf_event_open` en ctypes (`/security/perf`) — corrobore `MINING_SUSPECT`
- **Merkle integrity of loaded modules** — *shipped*: a real Merkle root over file-backed executable mappings per process → `MODULE_CHANGED`; staging paths (`/tmp`, memfd, AppData Temp) → `MODULE_SUSPECT`. Kernel-enforced module allowlisting stays here / *livré* : racine Merkle sur les mappings exécutables → `MODULE_CHANGED` ; chemins de staging → `MODULE_SUSPECT`. L'allowlist noyau de modules reste ici
- **Sinkholing / micro-containment** — *mostly shipped*: redirects + a loopback **responder** on :80/:443 that turns each sinkholed attempt into a `SINKHOLE_HIT` alert with Host/SNI/process attribution. Micro-VM containment stays here / *quasi livré* : redirections + **répondeur** loopback :80/:443 → alertes `SINKHOLE_HIT` avec Host/SNI/processus. Le confinement micro-VM reste ici
- **Cryptomining detection** — *shipped*: stratum signatures in bounded payload heads + known pool ports, corroborated by sustained process CPU → `MINING_STRATUM`/`MINING_SUSPECT` / *livré* : signatures stratum + ports de pools, corroborés par CPU soutenue → `MINING_STRATUM`/`MINING_SUSPECT`
- **Egress throttling** — *shipped (Linux)*: `throttle` rule action polices a destination via `tc` clsact/flower at the rule's kbit rate / *livré (Linux)* : action `throttle` bride une destination via `tc` clsact/flower
- **PCAP export** stays in scope above / l'export PCAP reste dans le périmètre ci-dessus

## 🚫 Out of scope / hors périmètre

Deliberately, by design / volontairement, par conception :

- **Telemetry, analytics, accounts, cloud sync** — never. / **Télémétrie, analytics, comptes, synchro cloud** — jamais.
- **Passive network-wide IDS** — Snitch watches *this* machine, not the whole network. / **IDS passif à l'échelle du réseau** — Snitch observe *cette* machine, pas tout le réseau.
- **User-space packet filtering** — blocking is delegated to the OS-native firewall (or future kernel components), never reimplemented. / **Filtrage de paquets en user-space** — le blocage est délégué au pare-feu natif de l'OS (ou à de futurs composants noyau), jamais réimplémenté.

## 🤝 Contributing / contribuer

Good entry points / bons points d'entrée : `good first issue` labels, tracker-list PRs (`backend/classifier/lists/`), translations (i18n ready), packaging (Linux .deb/.rpm). See [CONTRIBUTING.md](CONTRIBUTING.md).
