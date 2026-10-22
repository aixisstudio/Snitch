Hace tres semanas quise responder una pregunta estúpidamente simple: **¿con quién habla mi ordenador?**

No "¿puedo capturar paquetes?" (Wireshark puede, y es un microscopio cuando yo quería un parabrisas). No "bloquear conexiones" (Little Snitch lo hace en macOS, 59 $, y nada equivalente existía en Windows). Solo: una respuesta visual y en vivo. Qué app, qué servidor, qué país — ahora mismo.

Así que construí [Snitch](https://github.com/aixisstudio/Snitch). Open source, AGPL, UI en 8 idiomas, ~400 estrellas en tres semanas. Esto es lo que aprendí — y la parte en la que desconocidos escribieron mi port de Windows.

## La construcción

La restricción que me impuse: **sin dependencias pesadas, sin telemetría, nunca.**

- Captura: `ctypes → libpcap` en macOS/Linux, Npcap en Windows. Sin Scapy — los bindings directos son más ligeros y dan control exacto de campos.
- Parsing: decodificadores IPv4/IPv6/TCP/UDP/DNS/TLS-SNI hechos a mano. ~2K líneas para todo el pipeline.
- Backend: FastAPI + WebSockets + buffer circular SQLite (retención 24 h, luego se autodestruye — la privacidad también es *no* acumular).
- Frontend: React + grafo de fuerzas D3 + mapa mundial TopoJSON.
- Geolocalización: archivo local MaxMind/DB-IP. Las IP nunca salen de la máquina.

Postura de seguridad como feature: API solo en loopback, autenticada por token, y todo llamado saliente es opt-in — descarga GeoIP, chequeos de actualización, threat intel y webhooks están todos apagados por defecto. En una herramienta de privacidad, el código *es* la promesa — la AGPL lo hace auditable.

## Lo que no planeé

Lancé primero para macOS y marqué el repo "help wanted" para Windows. En días:

- Usuarios reportaron bugs con **análisis de causa raíz incluido** — no "no funciona", sino stack traces reales y la ruta de captura defectuosa identificada
- Un desconocido con quien nunca hablé envió tres PRs: captura Npcap, selección de interfaz, un crash de arranque
- Otra persona abrió el [PR del paquete winget](https://github.com/microsoft/winget-pkgs/pull/455520)

La v1.0.5 salió la semana pasada con el port de Windows funcionando. El canal de distribución más potente que encontró el proyecto no fue un truco de marketing — fue "poner un problema real en público, y la gente con el mismo problema aparece".

## Lo que dijeron los datos de tráfico

Momento meta curioso: el propio tráfico de referidos de Snitch contó la historia. Un newsletter tech chino (ruanyifeng.com) destacó el proyecto — de pronto ~20% del tráfico eran lectores chinos mirando un README en inglés. Ahora hay un [README 中文](https://github.com/aixisstudio/Snitch/blob/main/README.zh-CN.md) completo — y traducciones a 8 idiomas en total. Los datos deciden; yo solo escucho.

## Lo que le diría a cualquiera que construya dev tools

1. **Resuelve un problema sentido.** "¿Con quién habla mi máquina?" es visceral — todos se lo preguntan, nadie puede verlo.
2. **Local-first ya es un diferenciador.** "Sin cuenta, sin telemetría" no es una limitación, es el argumento.
3. **Los docs multilingües no son caridad** — son distribución hacia audiencias sin competencia.
4. **Issues y Discussions convierten.** Respuestas rápidas convirtieron reportadores de bugs en contribuidores. Así nació mi port de Windows.

## Pruébalo

```bash
docker run --network host ghcr.io/aixisstudio/snitch   # Linux
# macOS/Windows: página de releases — SNITCH_DEMO=1 lo ejecuta sin admin
```

Repo: https://github.com/aixisstudio/Snitch — AGPL, UI + docs en EN/FR/ES/DE/RU/JA/PT-BR/中文, y la v1.2 añadió lo más pedido: bloqueo de salida vía el firewall del SO, threat intel opt-in y exportación forense en un clic. El [hilo "¿qué atrapaste?"](https://github.com/aixisstudio/Snitch/discussions/39) está abierto, y una ⭐ ayuda de verdad si se la gana.
