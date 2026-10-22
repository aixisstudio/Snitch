# Changelog

All notable changes to Snitch. / Toutes les modifications notables de Snitch.

The format follows [Keep a Changelog](https://keepachangelog.com/) — EN/FR.

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
