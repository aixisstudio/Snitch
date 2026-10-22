Se você procurou um monitor de rede no Windows, esbarrou no GlassWire. É polido, bonito — e aí começam os paywalls: histórico atrás de assinatura, firewall por níveis, uma conta que vive sendo sugerida, sync cloud "elite".

Nada contra pagar por software. Mas "me mostre com o que meu computador se conecta" é higiene básica — discutivelmente não deveria nem ser bloqueado. Sou o autor do [Snitch](https://github.com/aixisstudio/Snitch), uma alternativa gratuita e open source (AGPL), então aqui vai a comparação honesta em vez de um pitch de vendas.

## Snitch vs GlassWire, feature por feature

| | **Snitch** | **GlassWire** |
|---|---|---|
| Preço | Grátis, para sempre | Freemium — features-chave no paywall |
| Licença | AGPL open source | Proprietária |
| Conta | **Nenhuma — nunca** | Conta/nível cloud promovido |
| Telemetria | **Nenhuma chamada de saída sem opt-in** (GeoIP, updates, threat intel, webhooks desligados por padrão) | Phone-home para sync/features |
| Local dos dados | SQLite local, seu | Existem features ligadas à cloud |
| Mapa mundial ao vivo de conexões | ✅ geolocalizado offline | ✅ (níveis pagos) |
| Tráfego e banda por app | ✅ | ✅ (parcialmente grátis) |
| Histórico | 24h grátis (ring buffer SQLite) | Limitado no nível grátis |
| Alertas de anomalia (port scans, beaconing, exfil, DNS tunneling) | ✅ | ✅ (majoritariamente pago) |
| Escaneamento de dispositivos LAN | ✅ passivo, via ARP | ✅ (pago) |
| Firewall / bloqueio | ✅ orquestração do firewall do SO + lockdown (best-effort, precisa de privilégios) | ✅ (o firewall do GlassWire é mais maduro) |
| Reputação threat intel | ✅ opt-in (AbuseIPDB / OTX / VirusTotal, sua própria chave) | ❌ |
| Matar / suspender processo | ✅ embutido | ✅ |
| Exportação forense | ✅ JSON / CSV / STIX | ❌ |
| Plataformas | macOS, Windows, Linux | Windows, Android |
| Privacy score / detecção de trackers | ✅ listas editáveis | ❌ |

## Onde o GlassWire ainda vence

Sendo justo:

- **Maturidade do bloqueio.** O firewall de aplicação do GlassWire tem uma década de refinamento — o bloqueio de saída do Snitch (adicionado na v1.2) orquestra o firewall nativo do SO em best-effort e precisa de privilégios de captura para aplicar regras de verdade. Se prompts interativos de "negar este app" são sua necessidade central, GlassWire (ou o gratuito Portmaster) continua sendo a escolha mais polida.
- **Polimento.** GlassWire teve uma década de trabalho de UI. O Snitch é bem mais jovem — o grafo é ótimo, as configurações funcionais, espere arestas.
- **Retenção longa de histórico** — o Snitch guarda 24h por design (privacy-first também significa *não* acumular seu tráfego).

## A diferença de arquitetura que importa

O modelo do GlassWire é o da indústria: nível grátis → irritação → assinatura → features cloud. O do Snitch é o oposto: o binário que você roda é o produto inteiro. Nada a desbloquear porque nada está bloqueado. Seu histórico vive num arquivo SQLite local — e o código é AGPL, então não pode começar a telefonar pra casa sem o diff ficar público.

Concretamente: API em loopback com auth por token, zero endpoints de telemetria, nenhum SDK de analytics no código (pode dar grep — é open source).

## Experimente

```bash
# Windows: instale o Npcap, depois rode o exe da release como Administrador
# Linux/Docker:
docker run --network host ghcr.io/aixisstudio/snitch
# macOS: app empacotado ou brew
# Modo demo sem admin: SNITCH_DEMO=1
```

Repo: https://github.com/aixisstudio/Snitch — issues e feature requests bem-vindos, o próprio port de Windows foi contribuição da comunidade. Se substituir uma assinatura que você não queria, é esse o ponto. ⭐ se sim.
