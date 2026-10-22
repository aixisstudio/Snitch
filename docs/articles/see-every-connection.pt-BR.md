Seu computador está falando com a internet agora mesmo. Provavelmente dezenas de conexões — sync, telemetria, checagem de updates, suas abas abertas, o barulho de fundo dos seus apps. A pergunta "o que minha máquina está realmente fazendo?" parece básica, mas tente respondê-la e você verá que as ferramentas são microscópicas (Wireshark) ou pagas.

Aqui vai um guia prático para realmente ver isso — incluindo a ferramenta que construí pra isso, o [Snitch](https://github.com/aixisstudio/Snitch) (open source, AGPL — declaração: é meu).

## A versão de 60 segundos

```bash
# macOS / Linux — clássico mas cru
sudo tcpdump -i any -n | head -50        # cada pacote, sem contexto
netstat -anp tcp | grep ESTABLISHED      # só conexões atuais
lsof -i -nP | head                       # mapeamento processo → socket

# Windows
netstat -ano | findstr ESTABLISHED
Get-NetTCPConnection -State Established  # PowerShell
```

Elas respondem "quais conexões existem agora". Não te dizem qual app, onde está o servidor, nem se é suspeito. Essa lacuna é exatamente o que um visualizador preenche.

## A abordagem de visualização

O Snitch desenha cada conexão como um grafo ao vivo + mapa-múndi:

- **Nó = sua máquina** no centro, linhas para cada endpoint remoto
- **Cada endpoint rotulado**: hostname (via DNS reverso + TLS SNI), país/cidade geolocalizado — tudo offline, de uma base local MaxMind/DB-IP
- **Atribuição por app**: a conexão é desenhada para o *processo* que a abriu
- **Timeline**: volume de tráfego de 15/30/60 min, 24h de histórico num SQLite local

O que o diferencia do tcpdump: o dado *já está processado*. Não "pacote para 142.250.74.78" — mas "Chrome → google.com → Frankfurt".

## Lendo o mapa: normal vs suspeito

Um mapa normal: raios para Apple/Google/Microsoft/CDNs das suas abas, seu roteador, outros dispositivos LAN.

O que se destaca:

- **Beaconing** — uma conexão que dispara em intervalos regulares (o Snitch marca; é padrão clássico de C2)
- **Uploads longos para endpoints desconhecidos** — dados saindo constantemente pra algum lugar que você não reconhece
- **Port scans** — um host LAN tocando muitas portas da sua máquina é marcado
- **Apps falando com países sem sentido** pro que o app faz
- **Trackers** — o Snitch cruza hostnames com listas editáveis de sufixos de trackers e os incorpora a um privacy score
- **DNS tunneling** — queries DNS com nomes anormalmente longos ou frequência estranha

A **detecção de anomalias** embutida vigia tudo isso automaticamente, e você pode suprimir alertas por regra depois de validar um padrão.

## Instale (2 minutos)

```bash
# macOS: baixe o app das releases, ou brew
# Windows: instale o Npcap → rode snitch-backend.exe como Admin
# Linux / Docker:
docker run --network host ghcr.io/aixisstudio/snitch

# Sem direitos de admin? O modo demo mostra a UI completa com tráfego sintético:
SNITCH_DEMO=1 snitch-backend
```

Tudo fica local — API autenticada por token em loopback, zero telemetria, sem conta, e cada chamada de saída (GeoIP, updates, threat intel, webhooks) é opt-in. Não é frase de marketing; é uma codebase AGPL, você pode verificar o caminho de rede por conta própria.

E quando algo parece errado, você pode agir — desde a v1.2, o Snitch empurra regras de bloqueio para o firewall nativo do SO (netsh / iptables / pf), tem um interruptor lockdown de um clique, botões kill/suspend e exportação forense (JSON/CSV/STIX) pro que você pegou.

## E depois?

Quando você consegue *ver* o tráfego, começa a parte interessante — o passatempo favorito da comunidade é o [tópico "O que você pegou?"](https://github.com/aixisstudio/Snitch/discussions/39): impressoras falando com servidores cloud às 3 da manhã, telemetria de TV, o pacote completo.

Repo: https://github.com/aixisstudio/Snitch — ⭐ se ele responder a pergunta que se propôs a responder.
