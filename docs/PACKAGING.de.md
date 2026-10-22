# Linux-Paketierung

[English](PACKAGING.md) | [Français](PACKAGING.md) | [Español](PACKAGING.es.md) | **Deutsch** | [Русский](PACKAGING.ru.md) | [日本語](PACKAGING.ja.md) | [Português](PACKAGING.pt-BR.md) | [中文](PACKAGING.zh-CN.md)

## Ausgelieferte Formate

| Format | Datei | Hinweise |
|---|---|---|
| AppImage | `Snitch-x86_64.AppImage` | portabel, benötigt `libfuse2`; Update-Info via `latest-linux.yml` |
| deb | `snitch-linux-amd64.deb` | Standard-Installation für Debian/Ubuntu |
| snap | `Snitch-amd64.snap` | striktes Confinement — siehe unten |

## Snap — Paket-Capture unter Confinement

Das Snap wird von electron-builder gebaut (`linux.target` enthält
`"snap"`) in striktem Confinement. Die Capture nutzt `AF_PACKET`-Sockets,
die das `network-observe`-Interface gewährt (dasselbe Modell wie das
`tcpdump`-Snap). Nach Installation eines lokalen `.snap`:

```bash
sudo snap install --dangerous Snitch-amd64.snap
sudo snap connect snitch:network-observe   # gewährt AF_PACKET-Lesezugriff
```

Ohne diese Verbindung läuft die UI, aber die Capture bleibt leer. Eine
Store-Veröffentlichung würde das Interface nach menschlicher Prüfung
automatisch verbinden; bis dahin ist das manuelle Connect nötig.

## Flatpak — bewusst nicht ausgeliefert

Flatpaks Sandbox kann keinen `AF_PACKET`-Zugriff gewähren: kein Portal
und keine `finish-args`-Kombination legt rohe Paket-Capture frei, und die
Prozess-Attribution via `psutil` braucht Host-`/proc`-Sichtbarkeit, die
die Sandbox verweigert. Ein Flatpak würde eine hübsche UI liefern, die
nie ein Paket sieht — wir veröffentlichen lieber keine kaputte App, als
sie vorzutäuschen. Falls flathub je eine Capture-fähige Berechtigung
einführt, wird neu bewertet.

## rpm + Homebrew-Formel + Release-Pipeline

Der `release.yml`-Workflow (pro `v*`-Tag oder `workflow_dispatch`) führt vier Publish-Jobs aus: **nfpm** baut `snitch-linux-amd64.rpm` (nfpm v2.48, `packaging/nfpm.yaml`); **homebrew** pusht `Formula/snitch.rb` zum Tap `aixisstudio/homebrew-tap` und installiert den headless `snitchd`-Daemon (`brew install aixisstudio/tap/snitch`, benötigt `HOMEBREW_TAP_TOKEN`); **winget** reicht `Snitch-Setup-*.exe` via winget-releaser ein sobald das Asset existiert (`WINGET_TOKEN`); **chocolatey** packt/pusht `installer/Snitch.nuspec` wenn `CHOCO_API_KEY` gesetzt ist.
