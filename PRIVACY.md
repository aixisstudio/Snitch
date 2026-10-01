# Privacy / Confidentialité

## English

Snitch is a privacy tool — it must never leak the very data it helps you monitor.

**Telemetry: none.** Snitch contains no analytics, no crash reporting, no
update checks, no phone-home of any kind.

**Outbound network calls made by Snitch itself: none.** The application only:

- captures packets on your local interfaces (passive observation),
- reads your system ARP/neighbour table (no active scanning),
- resolves reverse DNS via your OS resolver — standard PTR lookups that
  already happen implicitly with any network activity,
- serves a web UI on `127.0.0.1` for your own browser.

**Geolocation is offline-only.** If you place a DB-IP Lite or MaxMind
GeoLite2 `.mmdb` file in `<data_dir>/geo/`, lookups happen locally against
that file. Without it, IPs simply show no location. There is no HTTP
geolocation service — ip-api.com was removed precisely because it sent
visited IPs to a third party in plaintext.

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

**Télémétrie : aucune.** Pas d'analytics, pas de rapports de crash, pas de
vérification de mise à jour, aucun appel sortant.

**Appels réseau émis par Snitch : aucun.** L'application se contente de :

- capturer les paquets sur vos interfaces locales (observation passive),
- lire la table ARP/voisinage système (pas de scan actif),
- résoudre le DNS inverse via le résolveur de votre OS — des requêtes PTR
  standard qui ont déjà lieu implicitement avec toute activité réseau,
- servir une UI web sur `127.0.0.1` pour votre propre navigateur.

**La géolocalisation est 100 % hors ligne.** Si vous placez un fichier
`.mmdb` DB-IP Lite ou MaxMind GeoLite2 dans `<data_dir>/geo/`, les recherches
se font localement. Sans base, les IP n'affichent simplement pas de position.
Il n'y a aucun service de géolocalisation HTTP — ip-api.com a été supprimé
précisément parce qu'il envoyait les IP visitées à un tiers en clair.
