# Changelog

All notable changes to Snitch. / Toutes les modifications notables de Snitch.

The format follows [Keep a Changelog](https://keepachangelog.com/) — EN/FR.

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
