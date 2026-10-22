Si buscaste un monitor de red en Windows, te topaste con GlassWire. Es pulido, se ve bien — y luego empiezan los paywalls: historial tras suscripción, funciones de firewall por niveles, una cuenta que no para de sugerirse, sincronización cloud "elite".

No hay nada malo en pagar por software. Pero "muéstrame a qué se conecta mi ordenador" es higiene básica — discutiblemente no debería estar bloqueado. Soy el autor de [Snitch](https://github.com/aixisstudio/Snitch), una alternativa gratuita y open source (AGPL), así que aquí va la comparación honesta en vez de un pitch de ventas.

## Snitch vs GlassWire, feature por feature

| | **Snitch** | **GlassWire** |
|---|---|---|
| Precio | Gratis, para siempre | Freemium — funciones clave tras paywall |
| Licencia | AGPL open source | Propietario |
| Cuenta | **Ninguna — nunca** | Cuenta/nivel cloud promocionado |
| Telemetría | **Ningún llamado saliente sin opt-in** (GeoIP, updates, threat intel, webhooks apagados por defecto) | Phone-home para sync/features |
| Ubicación de datos | SQLite local, tuyo | Existen funciones ligadas a cloud |
| Mapa mundial en vivo de conexiones | ✅ geolocalizado offline | ✅ (niveles de pago) |
| Tráfico y ancho de banda por app | ✅ | ✅ (parcialmente gratis) |
| Historial | 24h gratis (ring buffer SQLite) | Limitado en nivel gratis |
| Alertas de anomalías (port scans, beaconing, exfil, DNS tunneling) | ✅ | ✅ (mayormente de pago) |
| Escaneo de dispositivos LAN | ✅ pasivo, vía ARP | ✅ (de pago) |
| Firewall / bloqueo | ✅ orquestación del firewall del SO + lockdown (best-effort, requiere privilegios) | ✅ (el firewall de GlassWire es más maduro) |
| Reputación threat intel | ✅ opt-in (AbuseIPDB / OTX / VirusTotal, tu propia clave) | ❌ |
| Matar / suspender proceso | ✅ integrado | ✅ |
| Exportación forense | ✅ JSON / CSV / STIX | ❌ |
| Plataformas | macOS, Windows, Linux | Windows, Android |
| Privacy score / detección de trackers | ✅ listas editables | ❌ |

## Dónde GlassWire sigue ganando

Siendo justos:

- **Madurez del bloqueo.** El firewall de aplicación de GlassWire tiene una década de refinamiento — el bloqueo de salida de Snitch (añadido en v1.2) orquesta el firewall nativo del SO al mejor esfuerzo y necesita privilegios de captura para aplicar reglas de verdad. Si los prompts interactivos "denegar esta app" son tu necesidad central, GlassWire (o el gratuito Portmaster) sigue siendo la opción más pulida.
- **Pulido.** GlassWire lleva una década de trabajo de UI. Snitch es mucho más joven — el grafo es genial, los ajustes son funcionales, espera asperezas.
- **Retención de historial larga** — Snitch guarda 24 h por diseño (privacy-first también significa *no* acumular tu tráfico).

## La diferencia de arquitectura que importa

El modelo de GlassWire es el de la industria: nivel gratis → molestia → suscripción → funciones cloud. El de Snitch es el opuesto: el binario que ejecutas es el producto completo. Nada que desbloquear porque nada está bloqueado. Tu historial vive en un archivo SQLite local — y el código es AGPL, así que no puede empezar a llamar a casa sin que el diff sea público.

Concretamente: API en loopback con auth por token, cero endpoints de telemetría, ningún SDK de analytics en el código (puedes hacer grep — es open source).

## Pruébalo

```bash
# Windows: instala Npcap, luego ejecuta el exe de release como Administrador
# Linux/Docker:
docker run --network host ghcr.io/aixisstudio/snitch
# macOS: app empaquetada o brew
# Modo demo sin admin: SNITCH_DEMO=1
```

Repo: https://github.com/aixisstudio/Snitch — issues y feature requests bienvenidos, el propio port de Windows fue contribución de la comunidad. Si reemplaza una suscripción que no querías, ese es el punto. ⭐ si lo hace.
