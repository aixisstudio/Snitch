Seu computador conversa com centenas de servidores por dia. No Linux as respostas clássicas são `tcpdump`, `ss`, `netstat` ou Wireshark — poderosos, mas respondem "me mostre pacotes", não "com quem minha máquina está falando, e devo me preocupar?".

Construí o [Snitch](https://github.com/aixisstudio/Snitch) para essa segunda pergunta — um visualizador de rede em tempo real open source (AGPL), com suporte completo no Linux via Docker ou o binário da release. Transparência total: sou o autor, então aqui vai um panorama honesto do que existe e onde o Snitch se encaixa.

## O cenário Linux

| Ferramenta | O que faz | O que não faz |
|---|---|---|
| **tcpdump / ss / netstat** | Dados brutos de conexões | Sem UI, sem histórico, sem geolocalização, sem mapeamento por app |
| **Wireshark** | Dissecação profunda de pacotes | Overkill para "quem está ligando pra casa?" — é microscópio, não dashboard |
| **OpenSnitch** | Firewall de aplicação (prompts block/allow) | Visualização mínima — é block-first e só Linux |
| **iftop / nethogs / nload** | Banda por interface ou processo | Sem mapa-múndi, sem detecção de anomalias, sem persistência |
| **Snitch** | Mapa ao vivo de cada conexão: app → servidor → país, detecção de anomalias, histórico 24h, bloqueio opt-in via firewall do SO | Aplicação de regras do SO é best-effort (precisa privilégios); não é um firewall interativo completo |

OpenSnitch e Snitch são complementares, não concorrentes: o OpenSnitch é um firewall de aplicação interativo maduro, o Snitch mostra *o que* sua máquina está fazendo — e desde a v1.2 também empurra regras (`ip`/`cidr`/`domain`/`process`/`port`) para o `iptables` mais um interruptor lockdown, em best-effort.

## O que o Snitch te dá no Linux

- **Mapa-múndi ao vivo** de cada conexão de saída, com atribuição por processo — qual app abriu, não só qual IP
- **Geolocalização offline** via base local MaxMind/DB-IP — seus IPs nunca saem da máquina
- **Detecção de anomalias**: port scans na sua LAN, beaconing (callbacks em intervalos regulares, padrão clássico de C2), volume de saída anormal, DNS tunneling, desvios de baseline por processo
- **Privacy score** + detecção de trackers por listas de sufixos editáveis
- **Banda por app**, timeline, retenção SQLite de 24h, regras de supressão de alertas
- **Escaneamento LAN passivo** via tabela ARP do sistema — cada dispositivo da sua rede, zero pacotes injetados
- **Regras de firewall de saída + lockdown** — bloqueie IP, CIDR, domínio, processo ou porta via firewall nativo (`iptables` no Linux), mate/suspenda processos, exporte um bundle forense (JSON/CSV/STIX)
- **Threat intel opt-in** — reputação via AbuseIPDB / AlienVault OTX / VirusTotal com sua própria chave API
- UI e documentação em 8 idiomas (EN/FR/ES/DE/RU/JA/PT-BR/中文)

## A parte da privacidade

É o que usuários Linux costumam verificar primeiro, então: a API faz bind em **127.0.0.1** e exige token. **Sem telemetria nem conta**, e cada chamada de saída — download de GeoIP, checagem de updates, threat intel, webhooks — é independentemente opt-in. Os dados de tráfego vivem num arquivo SQLite local que é seu.

## Instalação

```bash
# Docker (host networking necessário para captura)
docker run --network host ghcr.io/aixisstudio/snitch

# ou o tarball da release — precisa root/cap_net_raw como o tcpdump
sudo ./snitch-backend
```

Depois abra a URL impressa. Há também um modo demo (`SNITCH_DEMO=1`) que alimenta tráfego sintético pelo pipeline real se quiser olhar antes de conceder direitos de captura.

## O que tem no motor (para curiosos)

Python puro + ctypes → libpcap para captura — sem dependência de Scapy. O parsing IPv4/IPv6/TCP/UDP/DNS/TLS-SNI é feito à mão, ~2K linhas para o pipeline inteiro. Backend FastAPI + WebSocket, frontend React + D3, shell Electron no desktop.

Se você quer uma resposta para "minha máquina conversa com lugares estranhos às 3 da manhã?" no Linux sem pagar por um firewall nem rodar capturas o dia todo — é exatamente pra isso. ⭐ no [GitHub](https://github.com/aixisstudio/Snitch) se merecer, e nas Discussions tem um tópico "o que você pegou?" onde adoraria ver seus screenshots.
