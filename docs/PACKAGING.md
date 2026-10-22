# Linux packaging / Empaquetage Linux

[English](PACKAGING.md) | [Français](PACKAGING.md) | [Español](PACKAGING.es.md) | [Deutsch](PACKAGING.de.md) | [Русский](PACKAGING.ru.md) | [日本語](PACKAGING.ja.md) | [Português](PACKAGING.pt-BR.md) | [中文](PACKAGING.zh-CN.md)

## Formats shipped

| Format | File | Notes |
|---|---|---|
| AppImage | `Snitch-x86_64.AppImage` | portable, needs `libfuse2`; update info via `latest-linux.yml` |
| deb | `snitch-linux-amd64.deb` | standard Debian/Ubuntu install |
| snap | `Snitch-amd64.snap` | strict confinement — see below |

## Snap — packet capture under confinement

The snap is built by electron-builder (`linux.target` includes `"snap"`) in
strict confinement. Packet capture uses `AF_PACKET` sockets, which the
`network-observe` interface grants (the same model the `tcpdump` snap
uses). After installing a local `.snap`:

```bash
sudo snap install --dangerous Snitch-amd64.snap
sudo snap connect snitch:network-observe   # grants AF_PACKET read access
```

Without the `network-observe` connection the UI still runs but capture
stays empty. Store publication would auto-connect that interface once
human-reviewed; until then the manual connect is required.

## rpm + Homebrew formula + release pipeline

The `release.yml` workflow (on every `v*` tag or `workflow_dispatch`)
runs four publish jobs:

| Job | Output |
|---|---|
| `nfpm` | `snitch-linux-amd64.rpm` — native build via nfpm v2.48 (`packaging/nfpm.yaml` + `packaging/postinstall.sh`) |
| `homebrew` | pushes `Formula/snitch.rb` to `aixisstudio/homebrew-tap` — installs the headless `snitchd` daemon (`brew install aixisstudio/tap/snitch`). Requires `HOMEBREW_TAP_TOKEN`. |
| `winget` | submits `Snitch-Setup-*.exe` via winget-releaser when the asset exists; skips cleanly otherwise. Requires `WINGET_TOKEN`. |
| `chocolatey` | `choco pack`/`push` of `installer/Snitch.nuspec` when `CHOCO_API_KEY` is set. |

## Flatpak — deliberately not shipped

Flatpak's sandbox cannot grant `AF_PACKET` access: there is no portal or
`finish-args` combination that exposes raw packet capture, and process
attribution via `psutil` needs host `/proc` visibility the sandbox denies.
Shipping a Flatpak would produce a pretty UI that can never see a packet —
we'd rather not publish a broken app than fake it. If flathub ever grows a
capture-capable permission, revisit.

---

## Français

### Formats publiés

| Format | Fichier | Notes |
|---|---|---|
| AppImage | `Snitch-x86_64.AppImage` | portable, requiert `libfuse2` ; info de mise à jour via `latest-linux.yml` |
| deb | `snitch-linux-amd64.deb` | installation Debian/Ubuntu standard |
| snap | `Snitch-amd64.snap` | confinement strict — voir ci-dessous |

### Snap — capture de paquets sous confinement

Le snap est construit par electron-builder (`linux.target` inclut
`"snap"`) en confinement strict. La capture utilise des sockets
`AF_PACKET`, que l'interface `network-observe` autorise (le même modèle
que le snap `tcpdump`). Après installation d'un `.snap` local :

```bash
sudo snap install --dangerous Snitch-amd64.snap
sudo snap connect snitch:network-observe   # autorise la lecture AF_PACKET
```

Sans cette connexion, l'UI tourne mais la capture reste vide. Une
publication sur le Store connecterait l'interface automatiquement après
revue ; en attendant, la connexion manuelle est requise.

### Flatpak — volontairement non publié

La sandbox Flatpak ne peut pas accorder l'accès `AF_PACKET` : aucun portal
ni combinaison de `finish-args` n'expose la capture de paquets brute, et
l'attribution par processus via `psutil` exige une visibilité `/proc` de
l'hôte que la sandbox refuse. Publier un Flatpak produirait une jolie UI
incapable de voir le moindre paquet — mieux vaut ne pas publier une app
cassée que de simuler. À revoir si flathub ajoute une permission de
capture.

### rpm + formule Homebrew + pipeline de release

Le workflow `release.yml` (à chaque tag `v*` ou `workflow_dispatch`)
exécute quatre jobs de publication :

| Job | Sortie |
|---|---|
| `nfpm` | `snitch-linux-amd64.rpm` — build natif via nfpm v2.48 (`packaging/nfpm.yaml` + `packaging/postinstall.sh`) |
| `homebrew` | pousse `Formula/snitch.rb` vers `aixisstudio/homebrew-tap` — installe le daemon headless `snitchd` (`brew install aixisstudio/tap/snitch`). Exige `HOMEBREW_TAP_TOKEN`. |
| `winget` | soumet `Snitch-Setup-*.exe` via winget-releaser quand l'asset existe ; sinon saute proprement. Exige `WINGET_TOKEN`. |
| `chocolatey` | `choco pack`/`push` de `installer/Snitch.nuspec` si `CHOCO_API_KEY` est posé. |
