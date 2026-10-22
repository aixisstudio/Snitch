# Política de seguridad

[English](SECURITY.md) | [Français](SECURITY.md) | **Español** | [Deutsch](SECURITY.de.md) | [Русский](SECURITY.ru.md) | [日本語](SECURITY.ja.md) | [Português](SECURITY.pt-BR.md) | [中文](SECURITY.zh-CN.md)

## Reporte de vulnerabilidades

Reporta las vulnerabilidades en privado mediante la función «Report a
vulnerability» de GitHub (pestaña Security) o por email a los mantenedores
indicados en el perfil del repositorio. No abras issues públicas para
problemas de seguridad.

## Superficie de ataque local

La API expone todo tu grafo de tráfico — está protegida por diseño:

- **Autenticación por token** en cada endpoint REST y en el WebSocket
  (`X-Snitch-Token` o `?token=`). Generado por lanzamiento bajo Electron,
  persistido con permisos 0600 en los demás modos.
- **Bind en loopback** (`127.0.0.1`) por defecto en todos los modos.
- **Allowlist de Origin** en el handshake WebSocket (hosts loopback +
  `null`) para bloquear el secuestro de WebSocket cross-site.
- **CORS restringido** — solo orígenes loopback, sin credenciales.

## Privilegios

La captura de paquetes requiere privilegios elevados — pero solo el backend
los posee. La app Electron empaquetada ejecuta la UI sin privilegios en
todos los SO y eleva SOLO el backend mediante el prompt nativo:

- **Windows:** `Start-Process -Verb RunAs` (un prompt UAC por lanzamiento) + Npcap (instalado por ti desde npcap.com)
- **macOS:** `osascript … with administrator privileges` (diálogo nativo de contraseña)
- **Linux:** `pkexec` (diálogo polkit); cae a no privilegiado si polkit no existe

El hijo elevado se detiene mediante el endpoint autenticado `/shutdown`,
ya que un proceso sin privilegios no puede señalarlo. Rechazar el prompt
ofrece reintentar / continuar sin captura en lugar de salir de golpe.

## Dependencias

Scapy fue eliminado (GPL-2.0-only + gran superficie de ataque). La captura
es un binding ctypes mínimo a libpcap más nuestro propio parser acotado.
Las dependencias están fijadas y vigiladas por Dependabot.
