# Roadmap / Feuille de route

> 🇬🇧 Suggest or vote on features in [GitHub Discussions](https://github.com/aixisstudio/Snitch/discussions) — category *Ideas*. For concrete bugs, use [Issues](https://github.com/aixisstudio/Snitch/issues).
>
> 🇫🇷 Proposez ou votez pour des fonctionnalités dans les [Discussions GitHub](https://github.com/aixisstudio/Snitch/discussions) — catégorie *Ideas*. Pour les bugs concrets, utilisez les [Issues](https://github.com/aixisstudio/Snitch/issues).

## ✅ Shipped / Livré

| Version | What landed / Ce qui est arrivé |
|---|---|
| **v1.0.4** | First public release — real-time graph + world map, per-process attribution, offline geolocation (.mmdb), anomaly alerts, privacy score, LAN device discovery (passive ARP/OUI), mic/camera monitoring (Windows/Linux), demo mode, EN/FR UI / Première release publique — graphe temps réel + carte du monde, attribution par processus, géolocalisation hors-ligne, alertes d'anomalies, score de confidentialité, découverte LAN passive, monitoring micro/caméra, mode démo, UI EN/FR |
| **v1.0.5** | **Windows support** (Npcap, packaged backend), process icons, +24 tracker domains, PyInstaller `console=False` crash fix, interface auto-selection, dependency upgrades / **Support Windows** (Npcap, backend packagé), icônes de processus, +24 domaines trackers, correctifs |

Also live / également en place : Docker image on GHCR, Homebrew tap (`brew install --cask aixisstudio/tap/snitch`), winget package [submitted](https://github.com/microsoft/winget-pkgs/pull/455520), zh-CN README, GitHub Discussions.

## 🚧 v1.x — in progress / en cours

- [ ] **Signed & notarized macOS build** — needs an Apple Developer account ($99/yr). Until then the [tap](https://github.com/aixisstudio/homebrew-tap) strips quarantine for you / build macOS signée et notarisée — nécessite un compte Apple Developer. En attendant, le tap retire la quarantaine automatiquement
- [ ] **Homebrew upstream** (`brew install --cask snitch`) — blocked: the `snitch` formula name is already taken by an unrelated project; revisit once we have Developer ID signing / bloqué : le nom `snitch` est déjà pris par un autre projet ; à revoir une fois la signature en place
- [ ] **winget publishing** — [PR #455520](https://github.com/microsoft/winget-pkgs/pull/455520) open, awaiting Microsoft review / en attente de validation Microsoft
- [ ] **Windows 1-click installers** — Electron NSIS (`Snitch Setup.exe`, native app + tray) and Inno Lite (`Snitch-Lite-Setup.exe`, backend + browser UI) now build in CI on tags; first shipping release v1.0.6 / installeurs Windows en un clic — NSIS Electron + Inno Lite, construits en CI aux tags ; première release v1.0.6
- [ ] **Linux packages** — .deb / .rpm / AppImage alongside Docker / paquets Linux en plus de Docker
- [ ] **Export formats** — per-host/session CSV & PCAP slices / exports CSV et PCAP par hôte ou session
- [ ] **Deeper tracker coverage** — community-editable lists live in `backend/classifier/lists/` / couverture trackers élargie — listes éditables par la communauté

## 💭 Under consideration / à l'étude

- Per-process bandwidth history / historique de débit par processus
- Custom alert rules in the UI / règles d'alerte personnalisées dans l'UI
- Light theme / thème clair
- More languages — the i18n layer is ready / autres langues — l'i18n est prête
- Optional remote pairing for headless hosts — consent-gated, token-protected / appairage optionnel d'hôtes sans écran — avec consentement et jeton
- Map layers: ASN / organisation view / couches de carte : vue ASN / organisation

## 🚫 Out of scope / hors périmètre

Deliberately, by design / volontairement, par conception :

- **Blocking / firewall rules** — Snitch *observes and explains*; it does not block. Pair it with [OpenSnitch](https://github.com/evilsocket/opensnitch) or [Portmaster](https://safing.io/) if you need blocking. / **Blocage / pare-feu** — Snitch *observe et explique*, il ne bloque pas. Combinez-le avec OpenSnitch ou Portmaster si vous voulez bloquer.
- **Telemetry, analytics, accounts, cloud sync** — never. / **Télémétrie, analytics, comptes, synchro cloud** — jamais.
- **Passive network-wide IDS** — Snitch watches *this* machine, not the whole network. / **IDS passif à l'échelle du réseau** — Snitch observe *cette* machine, pas tout le réseau.

## 🤝 Contributing / contribuer

Good entry points / bons points d'entrée : `good first issue` labels, tracker-list PRs (`backend/classifier/lists/`), translations (i18n ready), packaging (Linux .deb/.rpm). See [CONTRIBUTING.md](CONTRIBUTING.md).
