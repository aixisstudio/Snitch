# Funcionalidades de segurança

[English](FIREWALL.md) | [Français](FIREWALL.md) | [Español](FIREWALL.es.md) | [Deutsch](FIREWALL.de.md) | [Русский](FIREWALL.ru.md) | [日本語](FIREWALL.ja.md) | **Português** | [中文](FIREWALL.zh-CN.md)

O Snitch adiciona uma camada de threat-hunting sobre a observação
passiva. **O que ela faz — e, tão importante, o que não faz:**

## Orquestração do firewall de saída

O Snitch **não** filtra pacotes em user-space. As regras são aplicadas
ao firewall nativo do SO, best-effort:

| SO | Mecanismo |
|---|---|
| Windows | regras de bloqueio de saída `netsh advfirewall` |
| Linux | `iptables -A OUTPUT -j DROP` (cadeia própria `SNITCH_LOCK` para o lockdown) |
| macOS | âncora `pf` gerada carregada com `pfctl` |

Tipos de regra: `ip`, `cidr`, `domain` (resolvido uma vez na aplicação),
`process`, `port`. As regras persistem em `snitch.db` e são reaplicadas
na inicialização.

**Limites honestos:**

- Aplicar regras exige os mesmos privilégios da captura. Sem elevação,
  `applied=False` fica registrado na regra — a UI mostra «somente
  visibilidade». O matching continua: pacotes que violam uma regra
  emitem alertas `BLOCKED_ATTEMPT` com contadores por regra.
- O `pf` no macOS não casa *processo* — regras de processo lá são, por
  design, apenas visibilidade.
- Regras `domain` resolvem o nome uma vez; uma CDN que troca de IP
  escapa da regra até recriá-la.
- **Lockdown** corta tráfego de saída apenas para IPs *públicos* —
  loopback e LAN continuam para a UI seguir acessível.

## Resposta a incidentes

- `POST /processes/kill` / `POST /processes/suspend` — por PID, recusa
  PID ≤ 3 e o próprio Snitch. Privilégios normais do SO.
- `POST /firewall/rules`, `DELETE /firewall/rules/{id}`,
  `POST /firewall/rules/{id}/toggle`, `POST /firewall/lockdown` —
  autenticados como todo endpoint.
- `GET /forensics/export?process=<nome>&ip=<ip>` — pacote de
  investigação: árvore de processos (até 8 ancestrais), SHA-256 do
  executável, linha de comando, alertas relacionados, histórico por
  minuto. `format=json|csv|stix` escolhe a saída (STIX = bundle 2.1
  mínimo para SIEM). Apenas dados locais; a exportação é um download,
  nunca um upload.

## Threat intelligence — opt-in, desligado por padrão

*Configurações → Threat intelligence* aceita um provedor (`abuseipdb`,
`otx`, `virustotal`) mais **sua própria chave de API**. Ligado, cada novo
IP público é verificado uma vez por TTL de 24 h; vereditos são cacheados
e `suspicious`/`malicious` dispara `THREAT_HIT`. Sem provedor nem chave,
**zero chamadas externas**. `GET /security/ti` mostra a configuração
mascarada; `POST /security/threat_check` roda uma verificação manual
(também ciente do cache).

## Webhooks — opt-in, desligados por padrão

*Configurações → Webhook externo* aceita URL e interruptor. Alertas
warning e críticos são POSTados ao vivo: Discord/Slack `{content}`,
Telegram `{chat_id, text}` (campo chat ID se a URL for telegram),
qualquer outro endpoint recebe `{alert, source, text}`. Falhas são
logadas, nunca fatais.

## Novas detecções

- `DNS_TUNNEL` — nomes/rótulos DNS superdimensionados (>60 car. / rótulo
  >40), padrão clássico de exfiltração; uma vez por host a cada 10 min.
- `CLEARTEXT` — TCP de saída para portas não criptografadas por natureza
  (80, 21, 23, 25, 110, 143…), nível INFO, alimenta a auditoria.
- `BASELINE_DEVIATION` — cada processo aprende seus países de destino
  usuais nos primeiros pacotes, depois avisa uma vez ao alcançar um novo.
  Baselines persistem (`app_baselines`).
- `BEACON` — já entregue: detecção de intervalos regulares (CV dos
  tempos de inter-chegada) mesmo com tráfego mínimo.
- `BLOCKED_ATTEMPT`, `LOCKDOWN`, `THREAT_HIT` — tipos adicionados pelos
  módulos acima.

## Auditoria de segurança

`GET /security/audit` calcula um score 0–100 a partir dos últimos 500
alertas e do grafo ao vivo: contagens por tipo, contatos com países de
risco, hosts não resolvidos, postura do firewall — e devolve
recomendações em linguagem clara. É um *relatório de achados*, não uma
certificação.

### Novidades v1.2 / Nouveautés v1.2

- **Ação `sinkhole`** — regras `domain`/`ip` podem redirecionar para loopback em vez de bloquear: domínios via bloco marcado `# snitch-sinkhole` no arquivo hosts (todos os SOs), IPs/CIDRs via `DNAT` iptables (somente Linux). `sinkhole` em `process`/`port` é rejeitado; plataformas não suportadas → `applied=False` honesto.
- **Re-resolução de domínios** — regras `domain` são re-resolvidas a cada ~10 min e o delta de IP é aplicado por SO, para que a rotação de CDN não desbloqueie um nome silenciosamente.
- **Vigilância de integridade** (ativada por padrão, somente leitura, local) — baselines SHA-256 de executáveis em rede (`BINARY_CHANGED`), divergência nome/exe (`NAME_MISMATCH`), scan `rwxp` somente Linux (`MEM_RWX`, nível info para apps JIT conhecidas). `GET /security/integrity`, `POST /security/integrity/check`.
- **Explicações de alertas** — `GET /security/explain?type=X` retorna explicações bilíngues (EN/FR) escritas à mão; determinísticas e offline — não é um modelo. A UI mostra atrás do botão "Por quê?".
