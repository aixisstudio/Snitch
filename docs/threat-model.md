# Threat Model / Modèle de menace

*EN first, FR below — both describe the same system.*

## English

### What Snitch is

A local-first network traffic visualizer. It captures packets on the host,
attributes them to processes, enriches them **offline** (local `.mmdb`
geolocation, local DNS/SNI maps), and renders them in a web UI served by the
same process. There is **no cloud component** and **no telemetry**.

### Assets

- Your traffic metadata (destination IPs, ports, volumes, process names).
- The API token (per-launch in Electron, per-install in CLI/Docker mode).
- The local SQLite history DB (`traffic`, `alerts_log`, histories, settings).
- Integrity of the machine itself (a compromised Snitch could lie to you).

### Trust boundaries

| Boundary | Threat | Mitigation |
|---|---|---|
| Browser/remote client → REST `/`, `/settings`, `/alerts`, `/history/*`, `/geo/*`, `/capture/*` | An attacker on the LAN or a malicious web page reads/controls your traffic view | Token required on **every** endpoint (`Authorization: Bearer`). Bind is `127.0.0.1` by default. In Docker, `0.0.0.0` requires `SNITCH_TOKEN` to be explicitly set. |
| Web page → `/ws` | Cross-site WebSocket hijacking (CSWSH) | Token **and** `Origin` allowlist (loopback + Electron `null` origin only). |
| Host → third parties | Privacy leak | Zero outbound calls by default. The **only** possible outbound call is the DB-IP Lite download, gated behind `/geo/download` with `consent: true` — a deliberate user click. |
| Capture driver → parser | Malformed frames crash the process | The parser bounds-checks every offset; malformed packets return `None`, never raise into the capture loop. |
| Renderer ↔ main process (Electron) | Token exfiltration from the page | `contextIsolation` + `sandbox`; the token only crosses via `ipcRenderer.invoke`, never lands in the DOM or a URL string. |
| Local attacker with FS access | Token/history theft | Token file `0600`; data dir under the platform user dir; DB is not encrypted — full-disk encryption is the OS's job. |

### Known limitations

- **Admin/elevation is still required for capture** — but scoped to the
  backend only: the Electron UI runs unprivileged while the backend is
  spawned elevated through the platform prompt (`Start-Process -Verb RunAs`
  on Windows, `osascript` on macOS, `pkexec` on Linux) and stopped via the
  authenticated `/shutdown` endpoint.
- The API token protects HTTP/WS but **not** against another local process
  running as you that can read `data/api_token.txt` or the Electron IPC.
- SQLite data at rest is unencrypted.
- Alert suppression is local and silent — an attacker who can write to the DB
  can mute alerts (defense: FS permissions).

### Out-of-scope

Malicious packet payloads (we parse headers only), kernel/driver compromise,
a rogue administrator.

---

## Français

### Ce qu'est Snitch

Un visualiseur de trafic réseau local d'abord. Il capture les paquets sur
l'hôte, les attribue aux processus, les enrichit **hors ligne** (base `.mmdb`
locale, tables DNS/SNI locales) et les rend dans une interface web servie par
le même processus. **Aucun composant cloud, aucune télémétrie.**

### Actifs

- Vos métadonnées de trafic (IP de destination, ports, volumes, processus).
- Le jeton API (par lancement sous Electron, par installation en CLI/Docker).
- La base SQLite locale (`traffic`, `alerts_log`, historiques, réglages).
- L'intégrité de la machine (un Snitch compromis pourrait vous mentir).

### Frontières de confiance

| Frontière | Menace | Atténuation |
|---|---|---|
| Navigateur/client distant → REST | Un attaquant LAN ou une page web malveillante lit/contrôle votre vue du trafic | Jeton exigé sur **chaque** endpoint (`Authorization: Bearer`). Bind `127.0.0.1` par défaut. En Docker, `0.0.0.0` exige `SNITCH_TOKEN` explicite. |
| Page web → `/ws` | Détournement de WebSocket cross-site (CSWSH) | Jeton **et** liste blanche d'`Origin` (loopback + origine `null` d'Electron). |
| Hôte → tiers | Fuite de vie privée | Zéro appel sortant par défaut. Le **seul** appel possible est le téléchargement DB-IP Lite, conditionné à `/geo/download` avec `consent: true` — un clic délibéré. |
| Driver de capture → parseur | Des trames malformées plantent le processus | Le parseur borne chaque offset ; les paquets malformés renvoient `None`, jamais d'exception dans la boucle. |
| Renderer ↔ main (Electron) | Exfiltration du jeton depuis la page | `contextIsolation` + `sandbox` ; le jeton ne transite que par `ipcRenderer.invoke`, jamais dans le DOM ni une URL. |
| Attaquant local avec accès FS | Vol du jeton/de l'historique | Fichier jeton `0600` ; dossier de données dans le répertoire utilisateur ; base non chiffrée — le chiffrement disque relève de l'OS. |

### Limites connues

- **Capture = privilèges admin/root**, mais limités au backend : l'UI
  Electron tourne sans privilèges tandis que le backend est lancé élevé via
  l'invite de la plateforme (`Start-Process -Verb RunAs` sous Windows,
  `osascript` sous macOS, `pkexec` sous Linux) et arrêté via l'endpoint
  authentifié `/shutdown`.
- Le jeton protège HTTP/WS mais **pas** contre un autre processus local
  tournant sous votre compte qui lit `data/api_token.txt` ou l'IPC Electron.
- Les données SQLite au repos ne sont pas chiffrées.
- La suppression d'alertes est locale et silencieuse — un attaquant qui écrit
  dans la base peut masquer des alertes (défense : permissions FS).

### Hors périmètre

Charges utiles malveillantes (seuls les en-têtes sont parsés), compromission
noyau/driver, administrateur malveillant.
