# Third-Party Notices / Mentions de tiers

**EN:** Snitch is licensed AGPL-3.0-or-later. Below are the third-party
components and data sources it uses, with their licenses. We deliberately
removed GPL-2.0-only code (Scapy) to keep the dependency set AGPL-compatible.

**FR :** Snitch est sous licence AGPL-3.0-or-later. Voici les composants tiers
et sources de données utilisés, avec leurs licences. Nous avons retiré
volontairement le code GPL-2.0-only (Scapy) pour garder des dépendances
compatibles AGPL.

## Runtime dependencies / Dépendances d'exécution

| Component / Composant | License / Licence |
|---|---|
| FastAPI | MIT |
| Uvicorn | BSD-3-Clause |
| Starlette | BSD-3-Clause |
| Pydantic / pydantic-core | MIT |
| websockets | BSD-3-Clause |
| maxminddb | Apache-2.0 |
| psutil | BSD-3-Clause |
| python-dotenv | BSD-3-Clause |
| aiofiles | Apache-2.0 |
| React | MIT |
| Vite | MIT |
| D3.js | ISC |
| TopoJSON | ISC |
| lucide-react | ISC |
| Electron | MIT |
| electron-builder | MIT |

## UI components / Composants d'interface

| Component / Composant | License / Licence | Attribution |
|---|---|---|
| Aurora Curtain (`frontend/src/components/AuroraCurtain.jsx`) | MIT | Ported from [SmoothUI](https://smoothui.dev) by Eduardo Lopez ([educlopez/smoothui](https://github.com/educlopez/smoothui)) — adapted to plain JSX (no Tailwind/Motion dependency) / porté depuis SmoothUI, adapté en JSX pur |

## System libraries / Bibliothèques système

| Component / Composant | License / Licence | Notes |
|---|---|---|
| libpcap | BSD-3-Clause | Linux/macOS packet capture — loaded via ctypes, not bundled |
| Npcap | Npcap License | Windows capture driver — **NOT bundled**; user installs from [npcap.com](https://npcap.com). The free version is not redistributable; Snitch only links to the official site. |

## Data sources / Sources de données

| Data / Données | License / Licence | Attribution |
|---|---|---|
| DB-IP Lite (City + ASN) | CC BY 4.0 | "IP Geolocation by [DB-IP](https://db-ip.com)" — recommended default |
| MaxMind GeoLite2 | GeoLite2 EULA | Optional alternative — requires a free MaxMind account; review the EULA before use |
| `classifier/lists/*.txt` (bundled tracker + CDN domain lists) | CC0-1.0 | Curated in this repository — public domain, contributions welcome / listes maintenues dans ce dépôt — domaine public, contributions bienvenues |

Both `.mmdb` databases are placed manually by the user in `<data_dir>/geo/`.
No database is downloaded or contacted automatically.

Les deux bases `.mmdb` sont placées manuellement par l'utilisateur dans
`<data_dir>/geo/`. Aucune base n'est téléchargée ni contactée automatiquement.
