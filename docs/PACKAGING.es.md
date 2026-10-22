# Empaquetado Linux

[English](PACKAGING.md) | [Français](PACKAGING.md) | **Español** | [Deutsch](PACKAGING.de.md) | [Русский](PACKAGING.ru.md) | [日本語](PACKAGING.ja.md) | [Português](PACKAGING.pt-BR.md) | [中文](PACKAGING.zh-CN.md)

## Formatos publicados

| Formato | Archivo | Notas |
|---|---|---|
| AppImage | `Snitch-x86_64.AppImage` | portable, requiere `libfuse2`; info de actualización vía `latest-linux.yml` |
| deb | `snitch-linux-amd64.deb` | instalación Debian/Ubuntu estándar |
| snap | `Snitch-amd64.snap` | confinamiento estricto — ver abajo |

## Snap — captura de paquetes bajo confinamiento

El snap lo construye electron-builder (`linux.target` incluye `"snap"`) en
confinamiento estricto. La captura usa sockets `AF_PACKET`, que la
interfaz `network-observe` concede (el mismo modelo del snap `tcpdump`).
Tras instalar un `.snap` local:

```bash
sudo snap install --dangerous Snitch-amd64.snap
sudo snap connect snitch:network-observe   # concede lectura AF_PACKET
```

Sin esa conexión la UI funciona pero la captura queda vacía. Una
publicación en la Store conectaría la interfaz automáticamente tras
revisión humana; mientras tanto se requiere la conexión manual.

## Flatpak — deliberadamente no publicado

La sandbox de Flatpak no puede conceder acceso `AF_PACKET`: ningún portal
ni combinación de `finish-args` expone la captura bruta de paquetes, y la
atribución por proceso vía `psutil` necesita visibilidad de `/proc` del
host que la sandbox niega. Publicar un Flatpak produciría una UI bonita
incapaz de ver un solo paquete — preferimos no publicar una app rota antes
que simular. Si flathub añade un permiso de captura, se reevaluará.

## rpm + fórmula Homebrew + pipeline de release

El workflow `release.yml` (en cada tag `v*` o `workflow_dispatch`) ejecuta cuatro jobs: **nfpm** construye `snitch-linux-amd64.rpm` (nfpm v2.48, `packaging/nfpm.yaml`); **homebrew** empuja `Formula/snitch.rb` al tap `aixisstudio/homebrew-tap` e instala el daemon headless `snitchd` (`brew install aixisstudio/tap/snitch`, requiere `HOMEBREW_TAP_TOKEN`); **winget** envía `Snitch-Setup-*.exe` con winget-releaser cuando el asset existe (`WINGET_TOKEN`); **chocolatey** empaqueta/publica `installer/Snitch.nuspec` si `CHOCO_API_KEY` está configurada.
