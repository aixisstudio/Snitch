# Rascunhos de lançamento — tudo copiável

[English](drafts-launch.md) | [Français](drafts-launch.md) | [Español](drafts-launch.es.md) | [Deutsch](drafts-launch.de.md) | [Русский](drafts-launch.ru.md) | [日本語](drafts-launch.ja.md) | **Português** | [中文](drafts-launch.zh-CN.md)

> **Nota:** os textos para colar ficam em inglês — HN e Reddit são plataformas anglófonas. A versão canônica completa EN/FR está em `drafts-launch.md`; aqui o resumo operacional.

## Show HN — o pacote « buzz »

**Timing: terça 14h30-15h00 Paris** (= 8h30-9h Nova York, terça útil = melhor slot da semana). NÃO antes: a front page dos EUA precisa estar ativa.

**URL:** `https://github.com/aixisstudio/Snitch`

### Título — opção A (data hook, recomendado)

`Show HN: Snitch – my Mac talked to 347 servers in one idle hour, so I built this`

### Título — opção B (story hook, se A já foi usado)

`Show HN: I open-sourced a network monitor — strangers shipped the Windows port`

### Primeiro comentário do autor — postar EM ATÉ 60 SEGUNDOS

Usar o comentário completo do autor de `drafts-launch.md` — detalhes da stack: ctypes→libpcap, atribuição psutil, .mmdb offline, FastAPI 127.0.0.1 + token, `SNITCH_DEMO=1`, a história do port de Windows comunitário.

## Reddit — r/privacy + r/selfhosted no mesmo dia

**Título:** `Snitch — open-source app that shows every connection your PC makes (world map + process names, 100% local)`

**Corpo:** ver `drafts-launch.md` — honestidade primeiro (« I'm the author »), bullets de features, demo sem admin, link do repo. Anexe screenshot do mapa se o sub permitir.

## r/netsec — thread Show semanal

Ângulo técnico: pipeline ctypes→libpcap sem Scapy, parser próprio ~2K linhas, atribuição psutil, detecção beaconing/DNS-tunnel, orquestração do firewall do SO. Tom SOC/analista, não marketing.

## Respostas preparadas (FAQ defensivo)

Respostas completas em `drafts-launch.md` para: « e GlassWire/Portmaster/OpenSnitch? », « por que Python e não Rust? », « captura precisa de root? », « chamadas de saída? » (todas opt-in: GeoIP, updates, TI, webhooks), « assinatura de código? » (SignPath pendente + hashes publicados).
