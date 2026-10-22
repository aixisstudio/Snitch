---
title: "Uma alternativa gratuita e open source ao Little Snitch para Windows (sim, existe)"
description: "Little Snitch é só macOS. Se você está no Windows ou Linux e quer ver com quais servidores seu computador conversa, aqui vai uma comparação honesta das alternativas reais."
tags: [opensource, privacy, windows, networking]
canonical_url: https://aixisstudio.github.io/Snitch/
---

Seu computador conversa com centenas de servidores todo dia. A maioria é ok — updates, sync, telemetria que você aceitou. Parte não é. A pergunta "com quem minha máquina realmente está falando?" é a razão pela qual o Little Snitch é um clássico do macOS há 15 anos.

O problema: **Little Snitch não existe no Windows nem no Linux.** E a maioria das "alternativas" no Windows é paga, exige conta, ou é firewall-first quando você só queria visibilidade.

Sou o autor do [Snitch](https://github.com/aixisstudio/Snitch), um visualizador de rede em tempo real open source (AGPL) com port de Windows — então, transparência desde já. Aqui está o estado honesto das opções.

## Primeiro: visualizador vs bloqueador

Vale ser preciso, porque as pessoas confundem:

- **Visibilidade** = "me mostre com quem minha máquina fala" (um mapa, atribuição por app, histórico)
- **Bloqueio** = "deixe eu decidir o que é permitido" (regras de firewall, prompts)

O Little Snitch faz os dois. Algumas alternativas fazem um ou outro. O Snitch hoje faz ambos — visibilidade é seu forte, e o bloqueio orquestra o firewall do SO.

## A comparação honesta

| Ferramenta | SO | Bloqueia? | Grátis? | Conta? | Notas |
|---|---|---|---|---|---|
| **Little Snitch** | macOS | ✅ | pago (~$59) | não | A referência. Nada igual fora do macOS. |
| **Snitch** | macOS, Windows, Linux | ✅ regras no firewall do SO + lockdown (best-effort) | ✅ AGPL | não | Mapa-múndi ao vivo, detecção de anomalias, privacy score, threat intel opt-in, export forense. 100% local. |
| **Portmaster** | Win, Linux, macOS | ✅ | ✅ núcleo grátis | não | Bloqueio em nível DNS + regras por app. Mais pesado — roda como serviço. |
| **OpenSnitch** | Linux | ✅ | ✅ GPL | não | O equivalente Linux mais próximo — firewall de aplicação com prompts. |
| **GlassWire** | Windows, Android | ✅ | freemium | empurra conta/cloud | UI polida, mas features-chave + histórico no paywall e insiste no nível cloud. |
| **Wireshark** | todos | ❌ | ✅ | não | O padrão-ouro para análise *profunda* — mas é pra dissecar pacotes, não "quem está ligando pra casa agora". |
| **LuLu** | macOS | ✅ | ✅ | não | Ótimo firewall grátis do macOS — mas só macOS, block-first com visualização mínima. |

## O que o Snitch realmente faz

Numa frase: **um mapa ao vivo de cada conexão que seu computador faz — qual app, qual servidor, qual país.**

- Force-graph + mapa-múndi em tempo real, geolocalizado offline (MaxMind/DB-IP — nenhum IP sai da sua máquina)
- Atribuição por processo: qual *app* abriu a conexão, não só o IP
- Detecção de anomalias: port scans, padrões de beaconing, volumes de exfiltração, DNS tunneling
- Privacy score + detecção de trackers por listas editáveis
- Tráfego por app, timeline (15/30/60 min), histórico SQLite 24h
- Scanner LAN passivo (lê a tabela ARP — mostra cada dispositivo da rede)
- **Regras de saída + lockdown**: bloqueie IP/CIDR/domínio/processo/porta no firewall do SO (`netsh advfirewall` no Windows), kill/suspend de processos, export forense JSON/CSV/STIX
- **Threat intel opt-in**: AbuseIPDB / OTX / VirusTotal com sua chave API

A parte que importa pra quem liga pra privacidade: **tudo é local.** Sem conta, sem telemetria, e cada chamada de saída — GeoIP, updates, threat intel, webhooks — é opt-in. A API é autenticada por token e faz bind em loopback por padrão.

## O que o Snitch NÃO faz

Seção honesta, porque o HN/Reddit vai perguntar mesmo:

- **Seu bloqueio é orquestração, não um driver.** Desde a v1.2 o Snitch empurra regras `ip`/`cidr`/`domain`/`process`/`port` para o firewall nativo do SO (`netsh advfirewall` no Windows, `iptables` no Linux, `pf` no macOS) mais um interruptor lockdown — best-effort: regras precisam dos mesmos privilégios da captura para serem aplicadas de verdade, e o `pf` não consegue casar processos. A UI é honesta quando uma regra não pôde ser aplicada. Para um firewall de aplicação interativo maduro, o Portmaster (ou Little Snitch no macOS) continua sendo a referência.
- **Precisa de admin/root** para captura de pacotes (inevitável — igual ao Wireshark).
- **Dissecação profunda de pacotes** — pra isso, o Wireshark ainda ganha. O Snitch é a vista de 10.000 pés.

## Instalando no Windows

1. Instale o [Npcap](https://npcap.com) (o driver de captura do Windows — obrigatório, mesma dependência do Wireshark)
2. Baixe `Snitch Setup <versão>.exe` da [última release](https://github.com/aixisstudio/Snitch/releases) — app Electron nativo com bandeja — ou o instalador Lite só-backend
3. Rode como Administrador (o instalador trata o prompt UAC ao subir o backend)
4. A UI abre sozinha — na janela Electron, ou no navegador com o Lite

Linux: `docker run --network host ghcr.io/aixisstudio/snitch` — ou o tarball da release. macOS: app empacotado ou `brew`.

## Uma nota sobre como o port de Windows nasceu

Eu mantenho o projeto sozinho. O port de Windows não fui eu — usuários abriram bug reports com análise de causa-raiz, e um estranho mandou três PRs que consertaram captura + interface correta + crash de arranque. Open source funcionando como anunciado. A v1.0.5 saiu semana passada.

Se você testar e pegar algo interessante, há uma [discussão "O que você pegou?"](https://github.com/aixisstudio/Snitch/discussions/39) no repo. E se for útil, uma ⭐ no [GitHub](https://github.com/aixisstudio/Snitch) ajuda de verdade o projeto a ser encontrado.

**Repo:** https://github.com/aixisstudio/Snitch — AGPL, UI e docs em 8 idiomas (EN/FR/ES/DE/RU/JA/PT-BR/中文).
