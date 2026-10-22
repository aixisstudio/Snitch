# Privacy / Confidentialité

## English

Snitch is a privacy tool — it must never leak the very data it helps you monitor.

**Telemetry: none.** Snitch contains no analytics, no crash reporting, no
phone-home of any kind.

**Outbound network calls made by Snitch: two, both optional.** Everything
below is passive observation or user-triggered — there is no silent traffic:

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

**Appels réseau émis par Snitch : deux, tous deux optionnels.** Tout le
reste est observation passive ou déclenché par vous — aucun trafic silencieux :

- capturer les paquets sur vos interfaces locales (observation passive),
- lire la table ARP/voisinage système (pas de scan actif),
- résoudre le DNS inverse via le résolveur de votre OS — des requêtes PTR
  standard qui ont déjà lieu implicitement avec toute activité réseau
  (`SNITCH_DISABLE_PTR=1` pour les désactiver complètement),
- servir une UI web sur `127.0.0.1` pour votre propre navigateur.

**L'app bureau vérifie les nouvelles versions sur github.com** au lancement
puis toutes les 6 h (electron-updater, lecture des fichiers publics
`latest-*.yml`). C'est le seul appel sortant périodique. Désactivation dans
*Réglages → Mises à jour → Vérifier automatiquement* (persisté) ou via
`SNITCH_NO_UPDATE=1`. Le build Docker et le backend ne vérifient jamais.

**Le téléchargement de la base GeoIP** (*Réglages → Géolocalisation*)
récupère ~50 Mo depuis db-ip.com — uniquement à votre clic, avec un
consentement explicite.

**La géolocalisation est 100 % hors ligne.** Une fois un fichier `.mmdb`
DB-IP Lite ou MaxMind GeoLite2 dans `<data_dir>/geo/`, les recherches se
font localement. Sans base, les IP n'affichent simplement pas de position.
Il n'y a aucun service de géolocalisation HTTP — ip-api.com a été supprimé
précisément parce qu'il envoyait les IP visitées à un tiers en clair.
