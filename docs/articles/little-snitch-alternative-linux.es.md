Tu ordenador habla con cientos de servidores al día. En Linux las respuestas clásicas son `tcpdump`, `ss`, `netstat` o Wireshark — potentes, pero responden "muéstrame paquetes", no "¿con quién habla mi máquina, y debería preocuparme?".

Construí [Snitch](https://github.com/aixisstudio/Snitch) para esa segunda pregunta — un visualizador de red en tiempo real open source (AGPL), con soporte completo en Linux vía Docker o el binario de release. Transparencia total: soy el autor, así que aquí va un repaso honesto de lo que existe y dónde encaja Snitch.

## El panorama Linux

| Herramienta | Qué hace | Qué no hace |
|---|---|---|
| **tcpdump / ss / netstat** | Datos crudos de conexiones | Sin UI, sin historial, sin geolocalización, sin mapeo por app |
| **Wireshark** | Disección profunda de paquetes | Excesivo para "¿quién llama a casa?" — es microscopio, no dashboard |
| **OpenSnitch** | Firewall de aplicación (prompts block/allow) | Visualización mínima — es block-first y solo Linux |
| **iftop / nethogs / nload** | Ancho de banda por interfaz o proceso | Sin mapa, sin detección de anomalías, sin persistencia |
| **Snitch** | Mapa en vivo de cada conexión: app → servidor → país, detección de anomalías, historial 24 h, bloqueo opt-in vía firewall del SO | La aplicación de reglas del SO es best-effort (requiere privilegios); no es un firewall interactivo completo |

OpenSnitch y Snitch son complementarios, no competidores: OpenSnitch es un firewall de aplicación interactivo maduro, Snitch te muestra *qué* hace tu máquina — y desde la v1.2 también puede empujar reglas (`ip`/`cidr`/`domain`/`process`/`port`) a `iptables` más un interruptor lockdown, al mejor esfuerzo.

## Lo que Snitch te da en Linux

- **Mapa mundial en vivo** de cada conexión saliente, con atribución por proceso — qué app la abrió, no solo qué IP
- **Geolocalización offline** vía base local MaxMind/DB-IP — tus IP nunca salen de la máquina
- **Detección de anomalías**: port scans en tu LAN, beaconing (callbacks a intervalos regulares, patrón clásico de C2), volumen saliente inusual, DNS tunneling, baseline deviations por proceso
- **Privacy score** + detección de trackers desde listas de sufijos editables
- **Ancho de banda por app**, timeline, retención SQLite de 24 h, reglas de supresión de alertas
- **Escaneo LAN pasivo** vía tabla ARP del sistema — cada dispositivo de tu red, sin inyectar paquetes
- **Reglas de firewall de salida + lockdown** — bloquea IP, CIDR, dominio, proceso o puerto vía el firewall nativo (`iptables` en Linux), mata/suspende procesos, exporta un bundle forense (JSON/CSV/STIX)
- **Threat intel opt-in** — reputación vía AbuseIPDB / AlienVault OTX / VirusTotal con tu propia clave API
- UI y documentación en 8 idiomas (EN/FR/ES/DE/RU/JA/PT-BR/中文)

## La parte de privacidad

Es lo primero que los usuarios Linux suelen verificar, así que: la API se ata a **127.0.0.1** y exige token. **Sin telemetría ni cuenta**, y cada llamada saliente — descarga GeoIP, chequeo de updates, threat intel, webhooks — es independientemente opt-in. Los datos de tráfico viven en un archivo SQLite local que es tuyo.

## Instalación

```bash
# Docker (host networking necesario para captura)
docker run --network host ghcr.io/aixisstudio/snitch

# o el tarball de release — necesita root/cap_net_raw como tcpdump
sudo ./snitch-backend
```

Luego abre la URL que imprime. También hay un modo demo (`SNITCH_DEMO=1`) que alimenta tráfico sintético por el pipeline real si quieres mirar antes de dar derechos de captura.

## Qué hay bajo el capó (para curiosos)

Python puro + ctypes → libpcap para la captura — sin Scapy. El parsing IPv4/IPv6/TCP/UDP/DNS/TLS-SNI está hecho a mano, ~2K líneas para el pipeline completo. Backend FastAPI + WebSocket, frontend React + D3, shell Electron en escritorio.

Si quieres una respuesta a "¿mi máquina habla con sitios raros a las 3am?" en Linux sin pagar un firewall ni correr capturas todo el día — es exactamente para eso. ⭐ en [GitHub](https://github.com/aixisstudio/Snitch) si se lo gana, y en Discussions hay un hilo "¿qué atrapaste?" donde me encantaría ver tus capturas.
