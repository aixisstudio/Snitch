# Security features / Fonctionnalités de sécurité

[English](FIREWALL.md) | [Français](FIREWALL.md) | [Español](FIREWALL.es.md) | [Deutsch](FIREWALL.de.md) | [Русский](FIREWALL.ru.md) | [日本語](FIREWALL.ja.md) | [Português](FIREWALL.pt-BR.md) | [中文](FIREWALL.zh-CN.md)

## English

Snitch ships a threat-hunting layer on top of passive observation. **What it
does and — just as important — what it does not do:**

### Outbound firewall orchestration

Snitch does **not** filter packets in user-space. Rules you create are
applied to the OS-native firewall, best-effort:

| OS | Mechanism |
|---|---|
| Windows | **WFP user-mode filters** via `fwpuclnt.dll` (ctypes, elevated) — `netsh advfirewall` remains the fallback |
| Linux | `iptables -A OUTPUT -j DROP` (dedicated `SNITCH_LOCK` chain for lockdown); `tc` clsact/flower for throttling |
| macOS | generated `pf` anchor loaded with `pfctl` |

On Windows, `detection/wfp.py` talks to the **Windows Filtering Platform**
directly — no `netsh` subprocess, no kernel driver: outbound ALE filters
matched on app path, remote IP/CIDR and remote port, created with
deterministic keys so a removed rule deletes exactly its own filters, and
an enumeration sweep purges filters Snitch created but forgot. It is
*filter management* — Snitch does not run a WFP callout, does not inspect
payloads in-kernel, and reports `applied=False` when not elevated.

Rule kinds: `ip`, `cidr`, `domain`, `process`, `port`. Rules persist in
`snitch.db` and are re-applied at startup. `domain` rules are re-resolved
every ~10 minutes — the resolved IP delta is applied so CDN rotation can't
silently unblock a name.

Rule actions: `block` (default) drops the traffic; `sinkhole` redirects it
to loopback instead — domains via a marked `# snitch-sinkhole` block in the
hosts file (all OSes), IPs/CIDRs via iptables `DNAT` in the nat OUTPUT chain
(Linux only). A sinkholed destination keeps "answering" from 127.0.0.1 so an
analyst can watch what the process expects instead of severing the call.
`throttle` (Linux only, `rate` kbit/s) polices the destination with a `tc`
clsact egress flower filter instead of blocking — useful for choking a
suspect process without tipping it off.

**Honest limits:**

- Applying rules needs the same privileges as packet capture. If the
  backend is not elevated, `applied=False` is recorded on the rule — the
  UI shows *"visibility only"*. Matching still works: packets violating a
  rule raise `BLOCKED_ATTEMPT` alerts with per-rule counters.
- macOS `pf` can't match a *process* — process rules on macOS are
  visibility-only by design.
- IP/CIDR `sinkhole` is Linux-only (needs the nat table); other platforms
  record `applied=False` with the reason. `sinkhole` on `process`/`port`
  is rejected — redirecting by process/port is not meaningful.
- **Lockdown** drops outbound traffic to *public* IPs only — loopback and
  LAN stay up so the UI remains reachable.

### Incident response

- `POST /processes/kill` / `POST /processes/suspend` — by PID, refuses
  PIDs ≤ 3 and Snitch itself. Normal OS privileges apply (you can't kill a
  root process as a normal user).
- `POST /firewall/rules`, `DELETE /firewall/rules/{id}`,
  `POST /firewall/rules/{id}/toggle`, `POST /firewall/lockdown` —
  authenticated like every endpoint.
- `GET /forensics/export?process=<name>&ip=<ip>` — investigation bundle:
  process tree (up to 8 ancestors), SHA-256 of the executable, cmdline,
  matching alerts, per-minute traffic history. `format=json|csv|stix` picks the
  output (STIX = minimal 2.1 bundle for SIEM import). Local data only;
  export is a download, never an upload.

### Threat intelligence — opt-in, off by default

`Settings → Threat intelligence` accepts a provider (`abuseipdb`, `otx`, `virustotal`)
plus **your own API key**. When enabled, newly-seen public IPs are checked
once per 24 h TTL; verdicts are cached and a `THREAT_HIT` alert fires on
`suspicious`/`malicious` verdicts. With provider `none` or an empty key,
**zero outbound calls** are made. `GET /security/ti` reports the masked
configuration; `POST /security/threat_check` runs a manual check (also
cache-aware).

### Webhooks — opt-in, off by default

`Settings → External webhook` accepts a URL and a switch. Warning and
critical alerts are POSTed live: Discord/Slack `{content}`, Telegram
`{chat_id, text}` (chat ID field shown when a telegram URL is used), any
other endpoint gets `{alert, source, text}`. Failures are logged, never
fatal.

### Detection additions

- `DNS_TUNNEL` — oversized DNS names/labels (>60 chars / label >40),
  classic exfiltration pattern; once per host per 10 min.
- `CLEARTEXT` — outbound TCP to ports that are unencrypted by design
  (80, 21, 23, 25, 110, 143…), INFO level, feeds the audit.
- `BASELINE_DEVIATION` — each process learns its usual destination
  countries over its first packets, then warns once when it reaches a new
  one. Baselines persist across restarts (`app_baselines` setting).
- `BEACON` — already shipped: regular-interval detection (CV of
  inter-arrival times) works even for tiny keep-alive traffic.
- `BLOCKED_ATTEMPT`, `LOCKDOWN`, `THREAT_HIT` — alert types added by the
  modules above.
- `BINARY_CHANGED`, `NAME_MISMATCH`, `MEM_RWX` — emitted by the integrity
  watch below.

### Process integrity watch

`Settings → Integrity watch` (on by default — read-only local inspection)
checks each PID that shows network activity, once per process lifetime:

- **Exe hash watch** — SHA-256 of the executable on disk; the first hash
  per path becomes a persisted baseline (`integrity_baselines`). A changed
  file under a live PID raises `BINARY_CHANGED` (critical).
- **Name/exe mismatch** — process name vs executable basename (tolerates
  `.exe` and version suffixes) → `NAME_MISMATCH` (warning), the classic
  masquerading tell.
- **RWX maps scan** — Linux only: `rwxp` regions in `/proc/<pid>/maps` ≥
  64 KiB → `MEM_RWX`. Known JIT apps (browsers, node, java, electron) are
  reported at *info* — their RWX pages are by design.

Honest limits: the hash compares on-disk file states — detecting true
in-memory tampering (hollowing, reflective injection that never touches
the file) needs kernel/memory tooling and stays on the research roadmap.
`GET /security/integrity` reports capabilities + findings;
`POST /security/integrity/check` forces a re-check on one PID.

### Alert explanations

`GET /security/explain?type=<ALERT_TYPE>` returns a hand-written bilingual
(EN/FR) explanation — what the alert means, why it matters, concrete next
steps. Deterministic templates, fully offline — **not** a language model;
the UI shows it behind the "Why?" button on every alert.

`GET /security/audit` computes a 0–100 score from the last 500 alerts plus
the live graph: alert-type counts, contacts to high-risk countries,
unresolved hosts, firewall posture — and returns plain-language
recommendations. It is a *finding report*, not a certification.

### Optional probes (v1.3)

All of these are **off by default or self-gating**, degrade honestly, and
never ship data off the machine:

- **eBPF connect probe** (Linux, `ebpf_probe` setting) — a BCC
  `tcpconnect`-style kprobe attributes `connect()` calls of processes too
  short-lived for the socket table. Needs `python3-bcc` + root; ambiguous
  destinations (two pids → same `ip:port`) are *never* guessed.
  `GET /security/ebpf` reports availability with the honest reason.
- **Frida deep inspection** — `POST /security/deep_inspect {pid,seconds}`
  attaches to ONE pid for ≤60 s (needs the optional `frida` package +
  debugger rights) and reports *which loaded module* issued each
  `connect()`. Module paths under temp/staging dirs → `INJECT_SUSPECT`.
- **Sinkhole responder** — while a `sinkhole` rule is enabled, loopback
  listeners on :80 (HTTP) and :443 (TLS/SNI) turn every redirected
  attempt into a `SINKHOLE_HIT` alert carrying Host/URI or SNI plus the
  initiating process. `GET /security/sinkhole` shows listeners + hits.
- **Module integrity** — a Merkle root over each process's file-backed
  executable mappings → `MODULE_CHANGED` on tamper; mapped paths under
  `/tmp`, memfd or other staging dirs → `MODULE_SUSPECT`.
- **Mining detection** — stratum JSON (`mining.subscribe`) in a bounded
  cleartext payload head → `MINING_STRATUM`; known pool ports + sustained
  CPU → `MINING_SUSPECT`. A pool port alone never alerts.
- **Hardware counters** — `POST /security/perf {pid,seconds}` samples
  cycles/instructions/cache-misses via `perf_event_open` (Linux, gated by
  `kernel.perf_event_paranoid`) to corroborate mining suspicion.
- **Local LLM enrichment** — opt-in (`slm_enabled`): `/security/explain`
  can call an Ollama-compatible endpoint, **loopback only** — remote
  endpoints are rejected so alert metadata can't leave the machine.
- **IOC packs** — `GET /security/iocpack` exports indicators as a Bloom
  filter + randomized response (ε≈4.6 — deniable, never raw);
  `POST /security/iocpack/import` checks observed destinations against a
  received pack, probabilistically, and never auto-blocks. A second
  `format=proof` pack carries salted SHA-256 leaves + a Merkle
  commitment: membership is cryptographically exact and tampering is
  detected. Not an interactive ZK protocol — a commitment scheme.

### Policy & response additions (v1.4)

- **Named profiles** — `POST /firewall/profile` applies `permissive`
  (clean slate), `balanced` (conservative egress baseline: outbound
  SMTP + common stratum pool ports) or `strict` (baseline + lockdown).
  Profiles expand into ordinary rules via the same machinery the UI
  uses — no hidden code path — and dedup against identical rules.
- **Custom alert rules** — `GET/POST/DELETE /alerts/rules` plus a
  per-rule toggle. One field (`remote_ip`, `host`, `process_name`,
  `remote_port`, `protocol`, `direction`, `size`), one operator
  (`eq`, `ne`, `contains`, `regex`, `gt`, `lt`, `cidr`), one value →
  `CUSTOM_RULE` alerts with hit counters. Validated at creation,
  bounded regex cache, **alert-only** — blocking stays the firewall's.
- **Blocklist import** — `POST /firewall/blocklist` turns a local
  hosts/domain file (a pure local read) or an opt-in URL (bounded
  4 MiB HTTPS fetch — one of the few outbound requests Snitch can ever
  emit, flagged `remote_fetch` in the response) into `domain` rules.
  Deduplicated, capped 500–5000 entries.
- **PCAP export** — `GET /forensics/pcap` (optional `ip=`/`process=`
  filters) serves the bounded ~4 MiB raw-frame ring as a
  Wireshark-ready `.pcap` with real capture timestamps.
- **Remote pairing** — `POST /remote/pairing` persists `lan_bind`
  (`0.0.0.0` or a local LAN address) applied at the *next* backend
  start — uvicorn cannot rebind a live socket, and the API says so.
  Token auth remains mandatory; pairing only widens the listen
  address. `GET /remote/pairing` reports effective bind + LAN IPs.
- **Network-denial sandbox** — `POST /security/sandbox {path,seconds}`
  runs a chosen executable with **zero egress**: unprivileged
  `unshare --user --net` on Linux, `sandbox-exec` deny-network on
  macOS. Bounded runtime + output; honest unsupported-error elsewhere.
  `contrib/snitch-contain` is the manual equivalent.
- **Embedded model** — `slm_mode=embedded` loads a user-provided
  `.gguf` via optional `llama-cpp-python` — explanations fully
  in-process, zero network. Snitch never downloads weights.
- **Native filter skeletons** — `contrib/wfp-callout/` (C WFP kernel
  callout + signing notes) and `contrib/macos-filter/` (Swift
  `NEFilterDataProvider` + entitlements notes). Research scaffolding
  for anyone who wants to build the signed/platform components;
  not shipped, not loaded by Snitch.
- **ASN attribution** — when `GeoLite2-ASN.mmdb`/`dbip-asn-lite.mmdb`
  is present, nodes carry `asn` (AS number) alongside `org`.

---

## Français

Snitch embarque une couche de chasse aux menaces au-dessus de
l'observation passive. **Ce qu'elle fait — et, aussi important, ce qu'elle
ne fait pas :**

### Orchestration du pare-feu sortant

Snitch ne filtre **pas** les paquets en user-space. Les règles créées sont
appliquées au pare-feu natif de l'OS, au mieux :

| OS | Mécanisme |
|---|---|
| Windows | **filtres WFP user-mode** via `fwpuclnt.dll` (ctypes, élevé) — `netsh advfirewall` reste le repli |
| Linux | `iptables -A OUTPUT -j DROP` (chaîne dédiée `SNITCH_LOCK` pour le lockdown) ; `tc` clsact/flower pour le bridage |
| macOS | ancre `pf` générée chargée avec `pfctl` |

Sous Windows, `detection/wfp.py` dialogue avec la **Windows Filtering
Platform** directement — sans subprocess `netsh`, sans driver noyau :
filtres ALE sortants par chemin d'appli, IP/CIDR et port, créés avec des
clés déterministes pour qu'une règle supprimée efface exactement ses
filtres, plus une purge par énumération des filtres orphelins. C'est de la
*gestion de filtres* — Snitch ne fait pas de callout WFP, n'inspecte pas
les payloads en noyau et rapporte `applied=False` sans élévation.

Types de règles : `ip`, `cidr`, `domain`, `process`, `port`. Les règles
persistent dans `snitch.db` et sont réappliquées au démarrage. Les règles
`domain` sont re-résolues toutes les ~10 min — le delta d'IP est appliqué
pour que la rotation CDN ne débloque pas un nom en silence.

Actions : `block` (défaut) droppe le trafic ; `sinkhole` le redirige vers
loopback — domaines via un bloc marqué `# snitch-sinkhole` dans le fichier
hosts (tous OS), IP/CIDR via `DNAT` iptables dans la table nat OUTPUT
(Linux seulement). Une destination sinkholée continue de « répondre »
depuis 127.0.0.1 : l'analyste observe ce que le processus attend au lieu
de couper l'appel. `throttle` (Linux seul, `rate` kbit/s) bride la
destination avec un filtre flower egress `tc` clsact au lieu de bloquer —
utile pour étouffer un processus suspect sans l'alerter.

**Limites honnêtes :**

- Appliquer les règles exige les mêmes privilèges que la capture. Sans
  élévation, `applied=False` est enregistré sur la règle — l'UI affiche
  *« visibilité seule »*. Le matching reste actif : les paquets violant une
  règle lèvent des alertes `BLOCKED_ATTEMPT` avec compteurs par règle.
- `pf` sur macOS ne peut pas matcher un *processus* — les règles processus
  y sont par conception de la visibilité seule.
- Le `sinkhole` IP/CIDR est Linux-only (besoin de la table nat) ; les autres
  plateformes enregistrent `applied=False` avec la raison. `sinkhole` sur
  `process`/`port` est rejeté — rediriger par processus/port n'a pas de sens.
- **Lockdown** ne coupe le trafic sortant que vers les IP *publiques* —
  loopback et LAN restent actifs pour garder l'UI joignable.

### Réponse à incident

- `POST /processes/kill` / `POST /processes/suspend` — par PID, refuse les
  PID ≤ 3 et Snitch lui-même. Privilèges OS usuels (on ne tue pas un
  processus root en simple utilisateur).
- `POST /firewall/rules`, `DELETE /firewall/rules/{id}`,
  `POST /firewall/rules/{id}/toggle`, `POST /firewall/lockdown` —
  authentifiés comme tous les endpoints.
- `GET /forensics/export?process=<nom>&ip=<ip>` — paquet d'investigation :
  arbre de processus (jusqu'à 8 ancêtres), SHA-256 de l'exécutable, ligne
  de commande, alertes associées, historique par minute. `format=json|csv|stix`
  choisit la sortie (STIX = bundle 2.1 minimal pour SIEM). Données locales
  uniquement ; l'export est un téléchargement, jamais un envoi.

### Threat intelligence — opt-in, désactivé par défaut

*Réglages → Threat intelligence* accepte un fournisseur (`abuseipdb`,
`otx`, `virustotal`) plus **votre propre clé API**. Activé, chaque nouvelle IP publique
est vérifiée une fois par TTL de 24 h ; les verdicts sont cachés et une
alerte `THREAT_HIT` est émise sur verdict `suspicious`/`malicious`.
Sans fournisseur ni clé, **zéro appel sortant**. `GET /security/ti`
rapporte la configuration masquée ; `POST /security/threat_check` lance
une vérification manuelle (aussi consciente du cache).

### Webhooks — opt-in, désactivés par défaut

*Réglages → Webhook externe* accepte une URL et un interrupteur. Les
alertes warning et critiques sont POSTées en direct : Discord/Slack
`{content}`, Telegram `{chat_id, text}` (champ chat ID affiché si URL
telegram), tout autre endpoint reçoit `{alert, source, text}`. Les échecs
sont journalisés, jamais fatals.

### Ajouts de détection

- `DNS_TUNNEL` — noms/labels DNS surdimensionnés (>60 car. / label >40),
  motif classique d'exfiltration ; une fois par hôte par 10 min.
- `CLEARTEXT` — TCP sortant vers des ports non chiffrés par nature
  (80, 21, 23, 25, 110, 143…), niveau INFO, alimente l'audit.
- `BASELINE_DEVIATION` — chaque processus apprend ses pays de destination
  usuels sur ses premiers paquets, puis avertit une fois à l'atteinte d'un
  nouveau pays. Les baselines persistent (`app_baselines`).
- `BEACON` — déjà livré : détection d'intervalles réguliers (CV des
  inter-arrivées) même pour un trafic minime.
- `BLOCKED_ATTEMPT`, `LOCKDOWN`, `THREAT_HIT` — types d'alertes ajoutés
  par les modules ci-dessus.
- `BINARY_CHANGED`, `NAME_MISMATCH`, `MEM_RWX` — émis par la veille
  d'intégrité ci-dessous.

### Veille d'intégrité des processus

*Réglages → Veille d'intégrité* (activée par défaut — inspection locale
en lecture seule) contrôle chaque PID avec activité réseau, une fois par
durée de vie du processus :

- **Surveillance du hash exe** — SHA-256 de l'exécutable sur disque ; le
  premier hash par chemin devient une baseline persistée
  (`integrity_baselines`). Un fichier modifié sous un PID actif lève
  `BINARY_CHANGED` (critique).
- **Mismatch nom/exe** — nom du processus vs basename de l'exécutable
  (tolère `.exe` et les suffixes de version) → `NAME_MISMATCH` (warning),
  le signe classique de masquage.
- **Scan maps RWX** — Linux seulement : régions `rwxp` de
  `/proc/<pid>/maps` ≥ 64 Kio → `MEM_RWX`. Les apps à JIT connues
  (navigateurs, node, java, electron) sont signalées en *info* — leurs
  pages RWX sont prévues.

Limites honnêtes : le hash compare les états sur disque — détecter une
altération en mémoire vive (hollowing, injection réflexive sans toucher
au fichier) exige un outillage noyau/mémoire, à la roadmap.
`GET /security/integrity` rapporte capacités + constats ;
`POST /security/integrity/check` force une re-vérification sur un PID.

### Explications d'alertes

`GET /security/explain?type=<TYPE>` renvoie une explication bilingue
(EN/FR) écrite à la main — ce que signifie l'alerte, pourquoi elle compte,
les étapes concrètes. Gabarits déterministes, 100 % hors-ligne — **pas**
un modèle de langage ; l'UI l'affiche derrière le bouton « Pourquoi ? »
de chaque alerte.

`GET /security/audit` calcule un score 0–100 depuis les 500 dernières
alertes et le graphe : comptes par type, contacts vers pays à risque,
hôtes non résolus, posture pare-feu — et renvoie des recommandations en
langage clair. C'est un *rapport de constats*, pas une certification.

### Sondes optionnelles (v1.3)

Toutes sont **désactivées par défaut ou auto-limitées**, dégradent
honnêtement et n'envoient jamais de données hors de la machine :

- **Sonde eBPF connect** (Linux, réglage `ebpf_probe`) — un kprobe BCC de
  type `tcpconnect` attribue les `connect()` des processus trop courts
  pour la table des sockets. Exige `python3-bcc` + root ; les
  destinations ambiguës (deux pids → même `ip:port`) ne sont *jamais*
  devinées. `GET /security/ebpf` rapporte la disponibilité honnêtement.
- **Inspection Frida** — `POST /security/deep_inspect {pid,seconds}`
  attache à UN pid ≤60 s (exige le paquet optionnel `frida` + droits de
  débogage) et rapporte *quel module chargé* a émis chaque `connect()`.
  Chemins de modules sous temp/staging → `INJECT_SUSPECT`.
- **Répondeur sinkhole** — tant qu'une règle `sinkhole` est active, des
  écouteurs loopback sur :80 (HTTP) et :443 (TLS/SNI) transforment chaque
  tentative redirigée en alerte `SINKHOLE_HIT` avec Host/URI ou SNI +
  processus. `GET /security/sinkhole` montre écouteurs + hits.
- **Intégrité des modules** — racine Merkle sur les mappings exécutables
  fichier-basés d'un processus → `MODULE_CHANGED` en cas d'altération ;
  chemins sous `/tmp`, memfd ou staging → `MODULE_SUSPECT`.
- **Détection de minage** — JSON stratum (`mining.subscribe`) dans une
  tête de payload bornée → `MINING_STRATUM` ; ports de pools + CPU
  soutenue → `MINING_SUSPECT`. Un port de pool seul n'alerte jamais.
- **Compteurs matériels** — `POST /security/perf {pid,seconds}`
  échantillonne cycles/instructions/cache-misses via `perf_event_open`
  (Linux, sous réserve de `kernel.perf_event_paranoid`) pour corroborer
  la suspicion de minage.
- **Enrichissement LLM local** — opt-in (`slm_enabled`) :
  `/security/explain` peut appeler un endpoint compatible Ollama,
  **loopback uniquement** — les endpoints distants sont rejetés pour que
  les métadonnées d'alerte ne quittent jamais la machine.
- **Paquets IOC** — `GET /security/iocpack` exporte les indicateurs en
  filtre de Bloom + randomized response (ε≈4,6 — déni plausible, jamais
  en clair) ; `POST /security/iocpack/import` confronte les destinations
  observées à un paquet reçu, en probabiliste, sans blocage automatique.
  Un second format `format=proof` porte des feuilles SHA-256 salées +
  un engagement Merkle : appartenance cryptographiquement exacte et
  falsification détectée. Pas un protocole ZK — un schéma d'engagement.

### Ajouts politique & réponse (v1.4)

- **Profils nommés** — `POST /firewall/profile` applique `permissive`
  (table rase), `balanced` (base sortante prudente : SMTP sortant +
  ports de pools stratum courants) ou `strict` (base + lockdown). Les
  profils se déplient en règles ordinaires par la même machinerie que
  l'UI — aucun chemin caché — avec dédup des règles identiques.
- **Règles d'alerte personnalisées** — `GET/POST/DELETE /alerts/rules`
  + bascule par règle. Un champ (`remote_ip`, `host`, `process_name`,
  `remote_port`, `protocol`, `direction`, `size`), un opérateur
  (`eq`, `ne`, `contains`, `regex`, `gt`, `lt`, `cidr`), une valeur →
  alertes `CUSTOM_RULE` avec compteurs. Validées à la création, cache
  regex borné, **alerte seule** — le blocage reste au pare-feu.
- **Import de blocklist** — `POST /firewall/blocklist` convertit un
  fichier hosts/domaines local (lecture purement locale) ou une URL
  opt-in (fetch HTTPS borné à 4 Mio — l'une des rares requêtes sortantes
  que Snitch puisse émettre, signalée `remote_fetch`) en règles
  `domain`. Dédupliquées, plafonnées à 500–5000 entrées.
- **Export PCAP** — `GET /forensics/pcap` (filtres `ip=`/`process=`
  optionnels) sert l'anneau de trames brutes ~4 Mio en `.pcap` prêt
  pour Wireshark avec les timestamps réels de capture.
- **Pairing distant** — `POST /remote/pairing` persiste `lan_bind`
  (`0.0.0.0` ou une adresse LAN locale) appliqué au *prochain*
  démarrage du backend — uvicorn ne peut re-binder un socket actif, et
  l'API le dit. Le jeton reste obligatoire ; le pairing n'élargit que
  l'adresse d'écoute. `GET /remote/pairing` rapporte bind + IP LAN.
- **Sandbox sans réseau** — `POST /security/sandbox {path,seconds}`
  exécute un binaire choisi avec **zéro égress** : `unshare
  --user --net` non privilégié sous Linux, `sandbox-exec` deny-network
  sous macOS. Durée + sortie bornées ; erreur honnête ailleurs.
  `contrib/snitch-contain` est l'équivalent manuel.
- **Modèle embarqué** — `slm_mode=embedded` charge un `.gguf` fourni
  par l'utilisateur via `llama-cpp-python` optionnel — explications
  entièrement en processus, zéro réseau. Snitch ne télécharge jamais
  de poids.
- **Squelettes de filtres natifs** — `contrib/wfp-callout/` (callout
  WFP noyau en C + notes de signature) et `contrib/macos-filter/`
  (`NEFilterDataProvider` Swift + notes entitlements). Échafaudage de
  recherche pour qui veut construire les composants signés ;
  non livrés, non chargés par Snitch.
- **Attribution ASN** — quand `GeoLite2-ASN.mmdb`/`dbip-asn-lite.mmdb`
  est présente, les nœuds portent `asn` (numéro d'AS) en plus de `org`.
