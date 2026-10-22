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
| Windows | `netsh advfirewall` outbound block rules |
| Linux | `iptables -A OUTPUT -j DROP` (dedicated `SNITCH_LOCK` chain for lockdown) |
| macOS | generated `pf` anchor loaded with `pfctl` |

Rule kinds: `ip`, `cidr`, `domain`, `process`, `port`. Rules persist in
`snitch.db` and are re-applied at startup. `domain` rules are re-resolved
every ~10 minutes — the resolved IP delta is applied so CDN rotation can't
silently unblock a name.

Rule actions: `block` (default) drops the traffic; `sinkhole` redirects it
to loopback instead — domains via a marked `# snitch-sinkhole` block in the
hosts file (all OSes), IPs/CIDRs via iptables `DNAT` in the nat OUTPUT chain
(Linux only). A sinkholed destination keeps "answering" from 127.0.0.1 so an
analyst can watch what the process expects instead of severing the call.

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
| Windows | règles de blocage sortantes `netsh advfirewall` |
| Linux | `iptables -A OUTPUT -j DROP` (chaîne dédiée `SNITCH_LOCK` pour le lockdown) |
| macOS | ancre `pf` générée chargée avec `pfctl` |

Types de règles : `ip`, `cidr`, `domain`, `process`, `port`. Les règles
persistent dans `snitch.db` et sont réappliquées au démarrage. Les règles
`domain` sont re-résolues toutes les ~10 min — le delta d'IP est appliqué
pour que la rotation CDN ne débloque pas un nom en silence.

Actions : `block` (défaut) droppe le trafic ; `sinkhole` le redirige vers
loopback — domaines via un bloc marqué `# snitch-sinkhole` dans le fichier
hosts (tous OS), IP/CIDR via `DNAT` iptables dans la table nat OUTPUT
(Linux seulement). Une destination sinkholée continue de « répondre »
depuis 127.0.0.1 : l'analyste observe ce que le processus attend au lieu
de couper l'appel.

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
