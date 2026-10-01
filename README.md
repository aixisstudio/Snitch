<div align="center">

# Snitch

**Know who's talking. / Sache qui parle.**

[English](#english) | [Français](#français)

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue.svg)]()
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux%20(Docker)-blue.svg)]()
[![Version](https://img.shields.io/badge/Version-1.0.0-green.svg)]()

</div>

---

## English

**Snitch** is a real-time network traffic visualizer.
See every connection your computer makes — who it talks to, where they are, and which app is responsible.

The entire interface is available in **English and French**: use the `EN / FR` toggle in the top-right toolbar.

### Features

| Feature | Description |
|---|---|
| Force Graph | Live node graph — your machine at the center, every connection as a node |
| World Map | Geolocated IPs with animated arcs on an interactive globe |
| 60-min Timeline | Sliding history stored locally in SQLite |
| Anomaly Detection | Flags port scans, beaconing, potential exfiltration |
| Process Attribution | Know which app generates which traffic (top 5 per connection) |
| LAN Scanner | ARP discovery of all devices on your local network |
| Privacy Score | Real-time score of your outgoing traffic exposure |
| Bandwidth Monitor | Live MB/s sparkline |
| EN / FR UI | Full bilingual interface, one click to switch |

### Stack

| Layer | Technology |
|---|---|
| Packet capture | Python — Scapy — Npcap (Windows) / libpcap (Linux) |
| Backend API | FastAPI — WebSockets — SQLite |
| Frontend | React 18 — Vite — D3.js v7 — TopoJSON |
| Desktop wrapper | Electron 28 |
| Geolocation | MaxMind GeoLite2 (optional, falls back to ip-api.com) |

### Docker (Linux)

The Docker deployment is for Linux users who want to run Snitch without installing anything beyond Docker.
Packet capture works via `network_mode: host` — the container sees real host traffic.

> **Note:** Docker Desktop on Mac/Windows runs inside a VM and cannot capture traffic from the host. Use the Electron app on those platforms.

```bash
# Clone and enter the repo / Cloner puis entrer dans le dépôt
git clone <your-repo-url> snitch
cd snitch

# Optional: place your MaxMind GeoLite2-City.mmdb in data/ for offline geolocation
# Optionnel : placez votre GeoLite2-City.mmdb dans data/ pour la géolocalisation hors ligne
mkdir -p data

# Build and run (requires Docker + root/sudo for raw socket capture)
# Construire et lancer (Docker + root/sudo requis pour la capture)
sudo docker compose up --build
```

Open **http://localhost:8000** in your browser.

To run in the background: `sudo docker compose up -d --build`

Docker limitations:
- Process attribution is limited to container processes (host PIDs are not shared by default)
- LAN scanner may be unavailable on some network configurations

### Development

Requirements:
- Python 3.11+
- Node.js 18+
- [Npcap](https://npcap.com/) installed (Windows only)
- Administrator/root terminal for the backend (raw packet capture)

```bash
# Backend (admin terminal) — API at http://127.0.0.1:8000
cd backend
pip install -r requirements.txt
python run_backend.py

# Frontend (separate terminal) — UI at http://localhost:5173
cd frontend
npm install
npm run dev

# Electron (optional, admin terminal)
cd electron
npm install
set VITE_DEV=1   # Windows
# VITE_DEV=1     # macOS/Linux shell
npx electron .
```

### Build the installer

```bash
# 1 — Compile backend (PyInstaller)
cd backend
pip install pyinstaller
pyinstaller backend.spec --distpath ../dist/backend

# 2 — Build frontend
cd frontend
npm run build

# 3 — Build Electron installer
cd electron
npm run build:dir
```

### Project structure

```
snitch/
├── backend/       Python FastAPI + Scapy capture engine
├── frontend/      React + D3.js UI (EN/FR)
├── electron/      Electron wrapper (main, splash, preload)
├── data/          Runtime data (SQLite DB, GeoLite2 DB)
└── dist/          Compiled output (backend exe, installer)
```

---

## Français

**Snitch** est un visualiseur de trafic réseau en temps réel.
Voyez chaque connexion que votre ordinateur établit — à qui il parle, où se trouvent les serveurs, et quelle application est responsable.

Toute l'interface est disponible en **français et en anglais** : utilisez le sélecteur `EN / FR` dans la barre d'outils en haut à droite.

### Fonctionnalités

| Fonctionnalité | Description |
|---|---|
| Graphe de force | Graphe de nœuds en direct — votre machine au centre, chaque connexion comme nœud |
| Carte du monde | IPs géolocalisées avec arcs animés sur un globe interactif |
| Timeline 60 min | Historique glissant stocké localement dans SQLite |
| Détection d'anomalies | Signale scans de ports, beaconing, exfiltration potentielle |
| Attribution processus | Sachez quelle app génère quel trafic (top 5 par connexion) |
| Scanner LAN | Découverte ARP de tous les appareils du réseau local |
| Score de confidentialité | Score en temps réel de l'exposition de votre trafic sortant |
| Moniteur de débit | Sparkline MB/s en direct |
| UI FR / EN | Interface entièrement bilingue, bascule en un clic |

### Stack technique

| Couche | Technologie |
|---|---|
| Capture de paquets | Python — Scapy — Npcap (Windows) / libpcap (Linux) |
| API backend | FastAPI — WebSockets — SQLite |
| Frontend | React 18 — Vite — D3.js v7 — TopoJSON |
| Conteneur bureau | Electron 28 |
| Géolocalisation | MaxMind GeoLite2 (optionnel, repli sur ip-api.com) |

### Docker (Linux)

Le déploiement Docker est destiné aux utilisateurs Linux qui veulent lancer Snitch sans rien installer d'autre que Docker.
La capture fonctionne via `network_mode: host` — le conteneur voit le vrai trafic de l'hôte.

> **Remarque :** Docker Desktop sur Mac/Windows tourne dans une VM et ne peut pas capturer le trafic de l'hôte. Utilisez l'application Electron sur ces plateformes.

```bash
git clone <url-de-votre-depot> snitch
cd snitch
mkdir -p data
sudo docker compose up --build
```

Ouvrez **http://localhost:8000** dans votre navigateur.
En arrière-plan : `sudo docker compose up -d --build`

Limites Docker :
- L'attribution de processus est limitée aux processus du conteneur
- Le scanner LAN peut être indisponible selon la configuration réseau

### Développement

Prérequis : Python 3.11+, Node.js 18+, Npcap (Windows), terminal administrateur pour le backend.

```bash
# Backend (terminal admin)
cd backend
pip install -r requirements.txt
python run_backend.py

# Frontend (autre terminal)
cd frontend
npm install
npm run dev

# Electron (optionnel)
cd electron
npm install
VITE_DEV=1 npx electron .
```

### Structure du projet

```
snitch/
├── backend/       Moteur de capture Python FastAPI + Scapy
├── frontend/      Interface React + D3.js (FR/EN)
├── electron/      Conteneur Electron (main, splash, preload)
├── data/          Données d'exécution (SQLite, GeoLite2)
└── dist/          Sortie compilée (exe backend, installateur)
```

---

## License / Licence

AGPL v3 — see / voir [LICENSE](LICENSE).

EN: Free to use, study, and modify. Derivative works must remain open source under AGPL v3.
FR: Libre d'utilisation, d'étude et de modification. Les œuvres dérivées doivent rester open source sous AGPL v3.
