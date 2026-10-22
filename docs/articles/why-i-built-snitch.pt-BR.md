Três semanas atrás eu quis responder uma pergunta estupidamente simples: **com quem meu computador está falando?**

Não "consigo capturar pacotes?" (o Wireshark consegue — e é um microscópio quando eu queria um para-brisa). Não "bloquear conexões" (o Little Snitch faz isso no macOS, $59, e nada equivalente existia no Windows). Apenas: uma resposta visual, ao vivo. Qual app, qual servidor, qual país — agora.

Então construí o [Snitch](https://github.com/aixisstudio/Snitch). Open source, AGPL, UI em 8 idiomas, ~400 estrelas em três semanas. O que aprendi — e a parte em que estranhos escreveram meu port de Windows.

## A construção

A restrição que me impus: **sem dependências pesadas, sem telemetria, nunca.**

- Captura: `ctypes → libpcap` no macOS/Linux, Npcap no Windows. Sem Scapy — bindings diretos são mais leves e dão controle exato dos campos.
- Parsing: decodificadores IPv4/IPv6/TCP/UDP/DNS/TLS-SNI feitos à mão. ~2K linhas para o pipeline inteiro.
- Backend: FastAPI + WebSockets + ring buffer SQLite (retenção de 24h, depois se autodestrói — privacidade também é *não* acumular).
- Frontend: React + grafo de forças D3 + mapa-múndi TopoJSON.
- Geolocalização: arquivo local MaxMind/DB-IP. IPs nunca saem da máquina.

Postura de segurança como feature: API só em loopback, autenticada por token, e toda chamada de saída é opt-in — download de GeoIP, checagem de updates, threat intel e webhooks estão todos desligados por padrão. Numa ferramenta de privacidade, o código *é* a promessa — a AGPL o torna auditável.

## O que eu não planejei

Lancei primeiro para macOS e marquei o repo como "help wanted" para Windows. Em dias:

- Usuários abriram bug reports com **análise de causa-raiz inclusa** — não "não funciona", mas stack traces reais e o caminho de captura defeituoso identificado
- Um estranho com quem nunca falei mandou três PRs: captura Npcap, seleção de interface, um crash de arranque
- Outra pessoa abriu o [PR do pacote winget](https://github.com/microsoft/winget-pkgs/pull/455520)

A v1.0.5 saiu semana passada com o port de Windows funcionando. O canal de distribuição mais poderoso não foi truque de marketing — foi "colocar um problema real em público, e as pessoas com o mesmo problema aparecem".

## O que os dados de tráfego disseram

Momento meta curioso: o próprio tráfego de referência do Snitch contou a história. Uma newsletter tech chinesa (ruanyifeng.com) destacou o projeto — de repente ~20% do tráfego eram leitores chineses olhando um README em inglês. Agora existe um [README 中文](https://github.com/aixisstudio/Snitch/blob/main/README.zh-CN.md) completo — e traduções em 8 idiomas no total. Os dados decidem; eu só escuto.

## O que eu diria a quem constrói dev tools

1. **Resolva um problema sentido.** "Com quem minha máquina fala" é visceral — todo mundo se pergunta, ninguém consegue ver.
2. **Local-first virou diferenciador.** "Sem conta, sem telemetria" não é limitação, é o pitch.
3. **Docs multilíngues não são caridade** — são distribuição para audiências com concorrência zero.
4. **Issues e Discussions convertem.** Respostas rápidas transformaram repórteres de bug em contribuidores. Foi assim que nasceu meu port de Windows.

## Experimente

```bash
docker run --network host ghcr.io/aixisstudio/snitch   # Linux
# macOS/Windows: página de releases — SNITCH_DEMO=1 roda sem admin
```

Repo: https://github.com/aixisstudio/Snitch — AGPL, UI + docs em EN/FR/ES/DE/RU/JA/PT-BR/中文, e a v1.2 adicionou o mais pedido: bloqueio de saída via firewall do SO, threat intel opt-in e exportação forense em um clique. O [tópico "o que você pegou?"](https://github.com/aixisstudio/Snitch/discussions/39) está aberto, e uma ⭐ ajuda de verdade se for merecida.
