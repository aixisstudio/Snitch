# Privacy / Confidentialité

[English](PRIVACY.md) | [Français](PRIVACY.md) | [Español](PRIVACY.es.md) | [Deutsch](PRIVACY.de.md) | [Русский](PRIVACY.ru.md) | [日本語](PRIVACY.ja.md) | [Português](PRIVACY.pt-BR.md) | [中文](PRIVACY.zh-CN.md)

## English

Snitch is a privacy tool — it must never leak the very data it helps you monitor.

**Telemetry: none.** Snitch contains no analytics, no crash reporting, no
phone-home of any kind.

**Outbound network calls made by Snitch: all optional, all off by
default.** Everything below is passive observation or user-triggered —
there is no silent traffic:

- captures packets on your local interfaces (passive observation),
- reads your system ARP/neighbour table (no active scanning),
- resolves reverse DNS via your OS resolver — standard PTR lookups that
  already happen implicitly with any network activity (set
  `SNITCH_DISABLE_PTR=1` to disable them entirely),
- serves a web UI on `127.0.0.1` for your own browser.

The **desktop app checks github.com for new releases** at launch and every
6 h (electron-updater, reads the public `latest-*.yml` files). This is the
only periodic outbound call. Disable it in *Settings → Updates → Check
automatically* (persisted) or with `SNITCH_NO_UPDATE=1`. The Docker build
and the backend itself never check for updates.

The **GeoIP database download** (`Settings → Geolocation`) fetches ~50 MB
from db-ip.com — only when you click it, with an explicit consent flag.

**Threat intelligence (opt-in, off by default).** When you configure a
provider (AbuseIPDB, AlienVault OTX or VirusTotal) *and* paste your own API key in
Settings, Snitch queries that provider for the reputation of newly-seen
public hosts — sending them the queried IP only. Verdicts are cached
locally; the key is stored in `snitch.db` (never logged, masked in the UI).
With no provider or no key, zero lookups are made — `ti.check()` is a no-op.

**External webhooks (opt-in, off by default).** When you paste a webhook
URL (Discord, Slack, Telegram bot endpoint or any URL) and flip the switch,
warning/critical alert texts are POSTed to that endpoint in real time.
Nothing is sent while the switch is off.

**Local LLM enrichment (opt-in, off by default).** When `slm_enabled` is
set, alert *metadata* (type, process, destination) may be sent to an
Ollama-compatible model endpoint — **restricted to loopback addresses
only**: the backend rejects any endpoint that does not resolve to
127.0.0.1 / ::1, so this can never reach the network. Deterministic
templates remain the default.

**IOC packs are never transmitted by Snitch.** `GET /security/iocpack`
builds a Bloom filter + randomized-response encoding of your local
indicators and gives you the file — you decide whether and where to share
it. The encoding is intentionally lossy (ε≈4.6) so raw IPs/domains can't
be recovered from a pack. Importing a pack only returns probabilistic
hints; it never auto-blocks.

**Inspection probes stay read-only and local.** The eBPF connect probe,
Frida deep-inspection, `perf_event_open` counters, module/Merkle integrity
scans and the loopback sinkhole responder only *read* local state and
listen on 127.0.0.1 — none of them sends data anywhere.

**Geolocation is offline-only.** Once a DB-IP Lite or MaxMind GeoLite2
`.mmdb` file sits in `<data_dir>/geo/`, lookups happen locally against that
file. Without it, IPs simply show no location. There is no HTTP geolocation
service — ip-api.com was removed precisely because it sent visited IPs to a
third party in plaintext.

**What is stored locally:**

| Data | Location | Retention |
|---|---|---|
| Per-minute traffic aggregates | `snitch.db` | 24 h (configurable: `retention_hours` setting) |
| Alert history | `snitch.db` | same retention window |
| Settings (filters, whitelist, language…) | `snitch.db` | until you change them |
| API token | `api_token.txt` (0600) | regenerated per launch under Electron |
| Logs | `logs/snitch.log` (rotating) | ~5 MB max |

Data directory: `data/` in dev/Docker, `%LOCALAPPDATA%\Snitch` on Windows,
`~/Library/Application Support/Snitch` on macOS, `~/.local/share/snitch` on
Linux when running installed.

## Français

Snitch est un outil de confidentialité — il ne doit jamais divulguer les
données qu'il vous aide à surveiller.

**Télémétrie : aucune.** Pas d'analytics, pas de rapports de crash, aucun
appel « maison » d'aucune sorte.

**Appels réseau émis par Snitch : tous optionnels, tous désactivés par
défaut.** Tout le reste est observation passive ou déclenché par vous —
aucun trafic silencieux :

- capturer les paquets sur vos interfaces locales (observation passive),
- lire la table ARP/voisinage système (pas de scan actif),
- résoudre le DNS inverse via le résolveur de votre OS — des requêtes PTR
  standard qui ont déjà lieu implicitement avec toute activité réseau
  (`SNITCH_DISABLE_PTR=1` pour les désactiver complètement),
- servir une UI web sur `127.0.0.1` pour votre propre navigateur.

**L'app bureau vérifie les nouvelles versions sur github.com** au lancement
puis toutes les 6 h (electron-updater, lecture des fichiers publics
`latest-*.yml`). C'est le seul appel sortant *périodique* — les autres
(GeoIP, threat intel, webhooks) restent déclenchés par vous ou opt-in.
Désactivation dans
*Réglages → Mises à jour → Vérifier automatiquement* (persisté) ou via
`SNITCH_NO_UPDATE=1`. Le build Docker et le backend ne vérifient jamais.

**Le téléchargement de la base GeoIP** (*Réglages → Géolocalisation*)
récupère ~50 Mo depuis db-ip.com — uniquement à votre clic, avec un
consentement explicite.

**Threat intelligence (opt-in, désactivé par défaut).** Quand vous
configurez un fournisseur (AbuseIPDB, AlienVault OTX ou VirusTotal) *et* collez votre
propre clé API dans les Réglages, Snitch interroge ce fournisseur sur la
réputation des nouveaux hôtes publics — seule l'IP interrogée lui est
envoyée. Les verdicts sont cachés localement ; la clé est stockée dans
`snitch.db` (jamais journalisée, masquée dans l'UI). Sans fournisseur ni
clé, aucune requête n'est faite — `ti.check()` est inerte.

**Webhooks externes (opt-in, désactivés par défaut).** Quand vous collez
une URL de webhook (Discord, Slack, endpoint de bot Telegram ou toute URL)
et basculez l'interrupteur, les textes des alertes warning/critiques sont
POSTés vers cet endpoint en temps réel. Rien n'est envoyé tant que
l'interrupteur est éteint.

**Enrichissement LLM local (opt-in, désactivé par défaut).** Quand
`slm_enabled` est activé, les *métadonnées* d'alerte (type, processus,
destination) peuvent être envoyées à un modèle compatible Ollama —
**restreint aux adresses loopback uniquement** : le backend rejette tout
endpoint qui ne résout pas vers 127.0.0.1 / ::1, donc cela ne peut jamais
atteindre le réseau. Les gabarits déterministes restent le défaut.

**Les paquets IOC ne sont jamais transmis par Snitch.**
`GET /security/iocpack` construit un encodage filtre de Bloom +
randomized response de vos indicateurs locaux et vous remet le fichier —
vous décidez si et où le partager. L'encodage est volontairement avec
pertes (ε≈4,6) : les IP/domaines en clair ne peuvent pas être retrouvés
depuis un paquet. L'import ne renvoie que des indices probabilistes ;
jamais de blocage automatique.

**Les sondes d'inspection restent en lecture seule et locales.** La sonde
eBPF, l'inspection Frida, les compteurs `perf_event_open`, les scans
d'intégrité module/Merkle et le répondeur sinkhole ne font que *lire*
l'état local et écouter sur 127.0.0.1 — aucun n'envoie de données.

**La géolocalisation est 100 % hors ligne.** Une fois un fichier `.mmdb`
DB-IP Lite ou MaxMind GeoLite2 dans `<data_dir>/geo/`, les recherches se
font localement. Sans base, les IP n'affichent simplement pas de position.
Il n'y a aucun service de géolocalisation HTTP — ip-api.com a été supprimé
précisément parce qu'il envoyait les IP visitées à un tiers en clair.
