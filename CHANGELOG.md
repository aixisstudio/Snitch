# Changelog

All notable changes to Snitch. / Toutes les modifications notables de Snitch.

The format follows [Keep a Changelog](https://keepachangelog.com/) — EN/FR.

## [Unreleased] / [Non publié]

### Added / Ajouté

- **Auto-update / Mise à jour automatique** — the desktop app checks GitHub Releases at launch and every 6 h via electron-updater (the `latest-*.yml` feeds were already published). Downloads install on restart; tray menu and Settings show live status. Opt-out in Settings or via `SNITCH_NO_UPDATE=1`. / L'app bureau vérifie les releases GitHub au lancement puis toutes les 6 h via electron-updater. Installation au redémarrage ; statut en direct dans le tray et les Réglages. Désactivation dans Réglages ou via `SNITCH_NO_UPDATE=1`.
- **QUIC / HTTP/3 visibility / visibilité QUIC/HTTP3** — UDP/443 flows are labelled `QUIC/HTTP3` instead of being lumped into HTTPS or unknown. The QUIC Initial's SNI is encrypted and is never read — the label is honest about what is observable. / Les flux UDP/443 sont étiquetés `QUIC/HTTP3` au lieu d'être rangés en HTTPS ou inconnu. Le SNI du paquet Initial QUIC est chiffré et jamais lu — l'étiquette reste honnête.
- **Watchlist** — pin IPs or domain suffixes (`example.com` also matches `api.example.com`); a dedicated `WATCHLIST_HIT` alert fires on first contact, rate-limited per (entry, host). Persisted, managed in Settings. / Épinglez des IP ou suffixes de domaine ; l'alerte dédiée `WATCHLIST_HIT` tire au premier contact, limitée par (entrée, hôte). Persistée, gérée dans Réglages.
- **Per-process upload alert / Alerte d'envoi par processus** — `UPLOAD_SPIKE` warns when one process exceeds a configurable MB/min ceiling (default 50, 0 = off) — covers exfiltration that the baseline-relative `VOLUME_SPIKE` misses on cold-start processes. / `UPLOAD_SPIKE` alerte quand un processus dépasse un plafond Mo/min réglable (50 par défaut, 0 = off) — couvre l'exfiltration que le `VOLUME_SPIKE` relatif rate sur les processus frais.
- **Capture interface selector / Sélecteur d'interface de capture** — `GET/POST /capture/interfaces` + a Settings dropdown listing libpcap devices; switching restarts capture instantly. Replaces the `SNITCH_IFACE` env var for desktop users. / `GET/POST /capture/interfaces` + liste déroulante dans Réglages ; le changement redémarre la capture aussitôt. Remplace la variable `SNITCH_IFACE`.
- **Wi-Fi context / Contexte Wi-Fi** — the toolbar shows the current SSID (or the capture interface when not on Wi-Fi). Best-effort per OS, 60 s cache. / La barre d'outils affiche le SSID courant (ou l'interface hors Wi-Fi). Au mieux par OS, cache 60 s.
- **Spanish UI / UI espagnole** — full `es` dictionary (194 keys, parity-checked); the language toggle is now EN/FR/ES. / Dictionnaire `es` complet (194 clés, parité vérifiée) ; le sélecteur devient EN/FR/ES.
- **Snap package / Paquet snap** — electron-builder now emits a strict-confinement `.snap` (with the `network-observe` plug for AF_PACKET capture). Flatpak is deliberately not shipped — the sandbox cannot expose raw packet capture (documented in `docs/PACKAGING.md`). / electron-builder émet un `.snap` en confinement strict (plug `network-observe` pour la capture AF_PACKET). Pas de Flatpak — la sandbox ne peut pas exposer la capture brute (documenté dans `docs/PACKAGING.md`).
- **Free code signing path / Signature de code gratuite** — optional SignPath Foundation OSS integration in CI (`vars.SIGNPATH_*` + `secrets.SIGNPATH_API_TOKEN`): the Windows installer is Authenticode-signed automatically once the project is accepted. Fully documented in `docs/SIGNING.md` including the honest macOS story (no free notarization exists). / Intégration optionnelle de SignPath Foundation OSS dans la CI : l'installeur Windows est signé Authenticode automatiquement une fois le projet accepté. Documenté dans `docs/SIGNING.md`, y compris la situation macOS (pas de notarisation gratuite).

## [1.0.8] — 2026-10-22

### Changed / Modifié

- **True native light theme / Vrai thème clair natif** — replaces the v1.0.7 invert filter with a full design-token system: every surface, text, border and accent colour in the app paints through CSS custom properties with a hand-picked light palette. Map, force graph, timeline and the WebGL aurora all follow the theme, and the toggle still persists your choice. / Remplace le filtre d'inversion de la v1.0.7 par un système de tokens : chaque surface, texte, bordure et accent passe par des variables CSS avec une palette claire choisie à la main. Carte, graphe, timeline et aurore WebGL suivent le thème, et le choix reste persisté.

## [1.0.7] — 2026-10-22

### Added / Ajouté

- **Light theme / Thème clair** — honours `prefers-color-scheme` out of the box and can be overridden with the sun/moon toggle in the toolbar; the choice is persisted in `localStorage`. Implemented as a hue-preserving invert of the authored dark palette, so graphs, map and aurora stay coherent. / Respecte `prefers-color-scheme` par défaut et se remplace via le bouton soleil/lune de la barre d'outils ; le choix est persisté. Réalisé par inversion préservant la teinte de la palette sombre, donc graphe, carte et aurore restent cohérents.

### Fixed / Corrigé

- **AppImage catalog compliance / conformité au catalogue AppImage** — the Linux asset is now named `Snitch-x86_64.AppImage` (proper architecture naming) and electron-builder publishes GitHub update metadata (`latest-linux.yml` + `.zsync`), enabling auto-update through AppImageUpdate-compatible tools. / L'asset Linux est désormais nommé `Snitch-x86_64.AppImage` (nommage d'architecture correct) et electron-builder publie les métadonnées de mise à jour GitHub (`latest-linux.yml` + `.zsync`), permettant l'auto-mise à jour via les outils compatibles AppImageUpdate.

## [1.0.6] — 2026-10-21

### Added / Ajouté

- **One download per OS / Un téléchargement par OS** — every tag now ships ready-to-run apps built by CI: / chaque tag publie des apps prêtes à lancer, construites par la CI :
  - **Windows** — `Snitch Setup <version>.exe` (Electron + NSIS: native window, tray, built-in Npcap check, UAC prompt at backend spawn) and `Snitch-Lite-Setup-<version>-windows-x64.exe` (Inno Setup: backend only, UI opens in the browser). / installeur NSIS Electron (fenêtre native, tray, détection Npcap intégrée, prompt UAC) et variante Inno Lite (backend seul, UI dans le navigateur).
  - **macOS (Apple Silicon)** — `Snitch-<version>-macos-arm64.zip` + `.dmg` built in CI (previously manual). / zip + dmg construits en CI (auparavant manuels).
  - **Linux** — `Snitch-<version>.AppImage` + `.deb` — no more Docker requirement for the desktop app. / AppImage + deb — Docker n'est plus obligatoire pour l'app de bureau.
- **`--launcher` backend mode / mode backend `--launcher`** — picks a free loopback port, computes the API token and opens the browser; used by the Lite installer shortcut. / port loopback libre + jeton API + ouverture du navigateur ; utilisé par le raccourci de l'installeur Lite.

### Fixed / Corrigé

- **Standalone backend bundles now ship the UI** — `frontend_dist` is staged inside the PyInstaller bundle on all OSes; the bare tarball previously served only the API. / Les bundles backend autonomes embarquent désormais l'UI — `frontend_dist` est inclus dans le bundle PyInstaller ; le tarball ne servait auparavant que l'API.

### Changed / Modifié

- CI `package` job builds Electron installers on all three OSes and a `release` job publishes every artifact to the GitHub release automatically. / Le job CI `package` construit les installeurs Electron sur les trois OS et un job `release` publie tous les artefacts sur la release GitHub automatiquement.

## [1.0.5] — 2026-10-17

### Added / Ajouté

- **Windows support / Support Windows** — the packaged app now boots and captures on Windows (Npcap). / L'app packagée démarre et capture sous Windows (Npcap).
- **Process icons / Icônes de processus** — per-process Lucide icons in the Apps table (external contribution). / Icônes Lucide par processus dans le tableau Applications (contribution externe).
- **24 new tracker domains / 24 domaines trackers** in the classifier blocklist (external contribution). / dans la liste de classification (contribution externe).

### Fixed / Corrigé

- Backend crash on `console=False` PyInstaller builds (`sys.stdout`/`sys.stderr` = None) — issue #25. / Crash backend sur les builds PyInstaller `console=False`.
- Capture interface selection on Windows — Snitch now picks the interface carrying the default route instead of `vEthernet (WSL)`. / Sélection de l'interface de capture sous Windows — Snitch choisit celle qui porte la route par défaut.
- `NaNh ago` on alert timestamps with timezone offsets. / Horodatages d'alertes affichant « NaNh ago ».
- Electron splash no longer hides error dialogs; timeout message lists causes + log folder. / Le splash Electron ne masque plus les dialogues d'erreur.
- Four leftover English strings translated in the French dictionary (external contribution). / Quatre chaînes anglaises restantes traduites (contribution externe).
- Version now single-sourced from `backend/version.py` (diagnostics showed 1.1.0). / Version unifiée depuis `backend/version.py`.

### Changed / Modifié

- React 18 → 19, uvicorn 0.30 → 0.54, fastapi → 0.143, psutil → 7.2, websockets → 17.2, maxminddb → 3.2, aiofiles → 25.1, lucide-react → 1.55, vite → 8.3.4, electron → 44.7 (+ dev deps). / Montées de versions majeures validées par la CI complète.

## [1.0.4] — 2026-10-05

- First public release. / Première release publique.
