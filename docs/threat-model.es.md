# Modelo de amenaza

[English](threat-model.md) | [Français](threat-model.md) | **Español** | [Deutsch](threat-model.de.md) | [Русский](threat-model.ru.md) | [日本語](threat-model.ja.md) | [Português](threat-model.pt-BR.md) | [中文](threat-model.zh-CN.md)

## Qué es Snitch

Un visualizador de tráfico de red local primero. Captura paquetes en el
host, los atribuye a procesos, los enriquece **offline** (geolocalización
`.mmdb` local, mapas DNS/SNI locales) y los muestra en una UI web servida
por el mismo proceso. **Sin componente cloud, sin telemetría.**

## Activos

- Tus metadatos de tráfico (IPs de destino, puertos, volúmenes, procesos).
- El token de API (por lanzamiento en Electron, por instalación en CLI/Docker).
- La base SQLite local (`traffic`, `alerts_log`, historiales, ajustes).
- La integridad de la propia máquina (un Snitch comprometido podría mentirte).

## Fronteras de confianza

| Frontera | Amenaza | Mitigación |
|---|---|---|
| Navegador/cliente remoto → REST | Un atacante LAN o una web maliciosa lee/controla tu vista del tráfico | Token exigido en **cada** endpoint (`Authorization: Bearer`). Bind `127.0.0.1` por defecto. En Docker, `0.0.0.0` exige `SNITCH_TOKEN` explícito. |
| Página web → `/ws` | Secuestro de WebSocket cross-site (CSWSH) | Token **y** allowlist de `Origin` (loopback + origen `null` de Electron). |
| Host → terceros | Fuga de privacidad | Cero llamadas salientes por defecto. Las descargas GeoIP, el threat intel, los webhooks y las actualizaciones son **opt-in** documentados en PRIVACY.md. |
| Driver de captura → parser | Tramas malformadas tumban el proceso | El parser acota cada offset; los paquetes malformados devuelven `None`, jamás lanzan a la bucle de captura. |
| Renderer ↔ main (Electron) | Exfiltración del token desde la página | `contextIsolation` + `sandbox`; el token solo cruza vía `ipcRenderer.invoke`, jamás en el DOM ni en una URL. |
| Atacante local con acceso FS | Robo del token/historial | Fichero token `0600`; directorio de datos en el directorio del usuario; la DB no está cifrada — el cifrado de disco compete al SO. |

## Limitaciones conocidas

- **La captura requiere privilegios admin/root**, pero acotados al backend:
  la UI Electron corre sin privilegios mientras el backend se lanza elevado
  por el prompt de la plataforma (`Start-Process -Verb RunAs` en Windows,
  `osascript` en macOS, `pkexec` en Linux) y se detiene vía el endpoint
  autenticado `/shutdown`.
- El token protege HTTP/WS pero **no** contra otro proceso local bajo tu
  cuenta que lea `data/api_token.txt` o el IPC de Electron.
- Los datos SQLite en reposo no están cifrados.
- La supresión de alertas es local y silenciosa — un atacante que escriba
  en la base puede silenciar alertas (defensa: permisos FS).

## Fuera de alcance

Cargas útiles maliciosas (solo se parsean cabeceras), compromiso del
kernel/driver, administrador malicioso.
