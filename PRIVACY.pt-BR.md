# Privacidade

[English](PRIVACY.md) | [Français](PRIVACY.md) | [Español](PRIVACY.es.md) | [Deutsch](PRIVACY.de.md) | [Русский](PRIVACY.ru.md) | [日本語](PRIVACY.ja.md) | **Português** | [中文](PRIVACY.zh-CN.md)

O Snitch é uma ferramenta de privacidade — ele nunca deve vazar os
próprios dados que te ajuda a monitorar.

**Telemetria: nenhuma.** Sem analytics, sem relatórios de crash, nenhuma
chamada «para casa» de qualquer tipo.

**Chamadas de rede feitas pelo Snitch: todas opcionais, todas desligadas
por padrão.** Todo o resto é observação passiva ou acionado por você —
não há tráfego silencioso:

- captura pacotes nas suas interfaces locais (observação passiva),
- lê a tabela ARP/vizinhos do sistema (sem varredura ativa),
- resolve DNS reverso pelo resolvedor do SO — consultas PTR padrão que já
  acontecem implicitamente com qualquer atividade de rede
  (`SNITCH_DISABLE_PTR=1` desativa totalmente),
- serve uma UI web em `127.0.0.1` para o seu próprio navegador.

**O app desktop verifica novas versões no github.com** ao iniciar e a cada
6 h (electron-updater, lê os `latest-*.yml` públicos). É a única chamada
periódica. Desativa em *Configurações → Atualizações → Verificar
automaticamente* (persistido) ou via `SNITCH_NO_UPDATE=1`. O build Docker
e o backend nunca verificam.

**O download da base GeoIP** (*Configurações → Geolocalização*) baixa ~50
MB do db-ip.com — apenas quando você clica, com consentimento explícito.

**Threat intelligence (opt-in, desligado por padrão).** Quando você
configura um provedor (AbuseIPDB, AlienVault OTX ou VirusTotal) *e* cola
sua própria chave de API em Configurações, o Snitch consulta a reputação
de novos hosts públicos — enviando somente o IP consultado. Os vereditos
são cacheados localmente; a chave fica em `snitch.db` (nunca em logs,
mascarada na UI). Sem provedor nem chave, zero consultas — `ti.check()`
é inerte.

**Webhooks externos (opt-in, desligados por padrão).** Quando você cola
uma URL de webhook (Discord, Slack, endpoint de bot Telegram ou qualquer
URL) e liga o interruptor, os textos de alertas warning/críticos são
POSTados ao endpoint em tempo real. Nada é enviado com o interruptor
desligado.

**Enriquecimento LLM local (opt-in, desligado por padrão).** Com
`slm_enabled`, os *metadados* de alertas (tipo, processo, destino) podem
ser enviados a um modelo compatível com Ollama — **somente loopback**:
o backend rejeita qualquer endpoint que não resolva para 127.0.0.1 /
::1. Os gabarits determinísticos continuam como padrão.

**Pacotes IOC nunca são transmitidos pelo Snitch.**
`GET /security/iocpack` codifica seus indicadores em filtro de Bloom +
randomized response (ε≈4,6) e entrega o arquivo — você decide se
compartilha. A importação só devolve pistas probabilísticas; nunca
bloqueia automaticamente.

**As sondas de inspeção são somente leitura e locais.** A sonda eBPF,
a inspeção Frida, contadores `perf_event_open`, varreduras de
integridade de módulos e o respondedor sinkhole apenas *leem* estado
local e escutam em 127.0.0.1 — nenhuma envia dados.

**A geolocalização é 100 % offline.** Com um `.mmdb` de DB-IP Lite ou
MaxMind GeoLite2 em `<data_dir>/geo/`, as consultas são locais. Sem base,
os IPs simplesmente não mostram localização. Não existe serviço HTTP de
geolocalização — o ip-api.com foi removido justamente porque enviava os
IPs visitados a terceiros em claro.

**O que é armazenado localmente:**

| Dado | Local | Retenção |
|---|---|---|
| Agregados de tráfego por minuto | `snitch.db` | 24 h (configurável: `retention_hours`) |
| Histórico de alertas | `snitch.db` | mesma janela |
| Configurações (filtros, whitelist, idioma…) | `snitch.db` | até você mudar |
| Token de API | `api_token.txt` (0600) | regerado por execução no Electron |
| Logs | `logs/snitch.log` (rotativo) | ~5 MB máx. |

Diretório de dados: `data/` em dev/Docker, `%LOCALAPPDATA%\Snitch` no
Windows, `~/Library/Application Support/Snitch` no macOS,
`~/.local/share/snitch` no Linux quando instalado.
