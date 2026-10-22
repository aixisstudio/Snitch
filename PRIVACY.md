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

**Syslog output (opt-in, off by default).** Setting `syslog_addr`
(`host:port` for UDP, `tcp://host:port` for TCP) forwards the same
warning/critical alert texts as RFC 3164 datagrams to your SIEM — a
real outbound flow to the configured address, independent of the
webhook switch.

**IOC peer sync (opt-in, off by default).** Setting `gossip_peers` (a list
of explicit Snitch backend URLs you control) lets `POST /remote/ioc_sync`
push your salted-Merkle proof pack to those peers' authenticated import
endpoint — and ONLY that pack (hash commitments, never raw indicators,
never hostnames or paths). Peers must be operator-listed; there is no
discovery and nothing is ever sent to an unlisted address.

**Passive TLS certificate reading stays on the wire.** The handshake
watcher reads the *server's own* Certificate message in cleartext —
no interception, no injection, no decryption. TLS 1.3 encrypts that
message, which we report honestly as unobservable. Metadata (issuer,
subject, SANs) feeds local anomaly checks only and is never persisted
as raw certificate bytes.

**Local LLM enrichment (opt-in, off by default).** When `slm_enabled` is
set, alert *metadata* (type, process, destination) may be sent to an
Ollama-compatible model endpoint — **restricted to loopback addresses
only**: the backend rejects any endpoint that does not resolve to
127.0.0.1 / ::1, so this can never reach the network. With
`slm_mode=embedded`, a `.gguf` you supply is loaded in-process via
`llama-cpp-python` — zero network at all; Snitch never downloads
weights. Deterministic templates remain the default.

**IOC packs are never transmitted by Snitch.** `GET /security/iocpack`
builds a Bloom filter + randomized-response encoding of your local
indicators and gives you the file — you decide whether and where to share
it. The encoding is intentionally lossy (ε≈4.6) so raw IPs/domains can't
be recovered from a pack. A second `format=proof` pack uses salted
SHA-256 leaves + a Merkle commitment — membership is exact, but the salt
still prevents enumerating indicators you don't already suspect.
Importing either pack never auto-blocks.

**Blocklist URL import (opt-in).** Importing a blocklist from a *local
file* is a pure local read. Importing from a *URL* performs one bounded
HTTPS fetch (≤4 MiB, ≤10 s) — one of the few outbound requests Snitch
can ever emit, explicitly confirmed in the UI and flagged `remote_fetch`
in the API response.

**Remote pairing (opt-in, off by default).** Snitch's API listens on
127.0.0.1 only. Enabling remote pairing persists `lan_bind` so the *next*
backend start listens on your LAN — with the API token still mandatory
on every request. It widens the listen address, never the trust model.

**The sandbox cannot leak.** `POST /security/sandbox` runs a binary you
choose inside a network-denying namespace (Linux `unshare -n`) or
seatbelt profile (macOS `sandbox-exec`): the detonated program gets
*zero* egress, whatever it tries. Output stays on the machine.

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

**Sortie syslog (opt-in, désactivée par défaut).** Régler `syslog_addr`
(`hôte:port` en UDP, `tcp://hôte:port` en TCP) relaie les mêmes textes
d'alertes warning/critiques en datagrammes RFC 3164 vers votre SIEM —
un vrai flux sortant vers l'adresse configurée, indépendant de
l'interrupteur webhook.

**Sync IOC entre pairs (opt-in, désactivée par défaut).** Régler
`gossip_peers` (liste explicite d'URL de backends Snitch que vous
contrôlez) permet à `POST /remote/ioc_sync` de pousser votre paquet
Merkle salé vers l'endpoint d'import authentifié de ces pairs — et
UNIQUEMENT ce paquet (engagements de hash, jamais d'indicateurs en
clair, jamais de noms d'hôte ni de chemins). Les pairs doivent être
listés par l'opérateur ; aucune découverte, rien n'est jamais envoyé
à une adresse non listée.

**La lecture passive des certificats TLS reste sur le fil.** L'observateur
de handshake lit le message Certificate *propre au serveur* en clair —
pas d'interception, pas d'injection, pas de déchiffrement. TLS 1.3
chiffre ce message, ce que nous rapportons honnêtement comme
inobservable. Les métadonnées (émetteur, sujet, SANs) n'alimentent que
les contrôles d'anomalies locaux et ne sont jamais persistées en
octets bruts.

**Enrichissement LLM local (opt-in, désactivé par défaut).** Quand
`slm_enabled` est activé, les *métadonnées* d'alerte (type, processus,
destination) peuvent être envoyées à un modèle compatible Ollama —
**restreint aux adresses loopback uniquement** : le backend rejette tout
endpoint qui ne résout pas vers 127.0.0.1 / ::1, donc cela ne peut jamais
atteindre le réseau. Avec `slm_mode=embedded`, un `.gguf` que vous
fournissez est chargé en processus via `llama-cpp-python` — zéro réseau ;
Snitch ne télécharge jamais de poids. Les gabarits déterministes restent
le défaut.

**Les paquets IOC ne sont jamais transmis par Snitch.**
`GET /security/iocpack` construit un encodage filtre de Bloom +
randomized response de vos indicateurs locaux et vous remet le fichier —
vous décidez si et où le partager. L'encodage est volontairement avec
pertes (ε≈4,6) : les IP/domaines en clair ne peuvent pas être retrouvés
depuis un paquet. L'import ne renvoie que des indices probabilistes ;
jamais de blocage automatique. Un second format `format=proof` utilise
des feuilles SHA-256 salées + un engagement Merkle — l'appartenance est
exacte, mais le sel empêche toujours d'énumérer les indicateurs que vous
ne soupçonnez pas déjà.

**Import de blocklist par URL (opt-in).** Importer depuis un *fichier
local* est une lecture purement locale. Importer depuis une *URL*
effectue un seul fetch HTTPS borné (≤4 Mio, ≤10 s) — l'une des rares
requêtes sortantes que Snitch puisse émettre, confirmée explicitement
dans l'UI et signalée `remote_fetch` dans la réponse API.

**Pairing distant (opt-in, désactivé par défaut).** L'API de Snitch
n'écoute que sur 127.0.0.1. Activer le pairing distant persiste
`lan_bind` pour que le *prochain* démarrage écoute sur votre LAN — le
jeton API restant obligatoire sur chaque requête. Cela élargit l'adresse
d'écoute, jamais le modèle de confiance.

**La sandbox ne peut pas fuiter.** `POST /security/sandbox` exécute un
binaire de votre choix dans un namespace sans réseau (`unshare -n`
Linux) ou un profil seatbelt (`sandbox-exec` macOS) : le programme
détoné obtient *zéro* égress, quoi qu'il tente. La sortie reste sur la
machine.

**Les sondes d'inspection restent en lecture seule et locales.** La sonde
eBPF, l'inspection Frida, les compteurs `perf_event_open`, les scans
d'intégrité module/Merkle et le répondeur sinkhole ne font que *lire*
l'état local et écouter sur 127.0.0.1 — aucun n'envoie de données.

**La géolocalisation est 100 % hors ligne.** Une fois un fichier `.mmdb`
DB-IP Lite ou MaxMind GeoLite2 dans `<data_dir>/geo/`, les recherches se
font localement. Sans base, les IP n'affichent simplement pas de position.
Il n'y a aucun service de géolocalisation HTTP — ip-api.com a été supprimé
précisément parce qu'il envoyait les IP visitées à un tiers en clair.
