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

### Sondas opcionais (v1.3)

Todas estão **desativadas por padrão ou autolimitadas**, degradam honestamente e nunca enviam dados para fora da máquina:

- **Sonda eBPF connect** (Linux, `ebpf_probe`) — kprobe BCC tipo `tcpconnect` atribui `connect()` de processos efêmeros demais para a tabela de sockets. Requer `python3-bcc` + root; destinos ambíguos nunca são adivinhados. `GET /security/ebpf`.
- **Inspeção Frida** — `POST /security/deep_inspect {pid,seconds}` anexa a UM pid por ≤60 s e reporta qual módulo carregado emitiu cada `connect()`. Caminhos de staging → `INJECT_SUSPECT`.
- **Respondedor sinkhole** — com uma regra `sinkhole` ativa, listeners loopback em :80/:443 transformam cada tentativa em alerta `SINKHOLE_HIT` com Host/URI ou SNI + processo.
- **Integridade de módulos** — raiz Merkle sobre mapeamentos executáveis → `MODULE_CHANGED`; caminhos em `/tmp`/memfd → `MODULE_SUSPECT`.
- **Detecção de mineração** — JSON stratum no cabeçalho do payload → `MINING_STRATUM`; portas de pools + CPU sustentada → `MINING_SUSPECT`.
- **Contadores de hardware** — `POST /security/perf` amostra ciclos/instruções via `perf_event_open` (Linux).
- **LLM local** — opt-in (`slm_enabled`): `/security/explain` chama um endpoint Ollama **somente loopback** — endpoints remotos rejeitados.
- **Pacotes IOC** — `GET /security/iocpack` exporta Bloom + randomized response (nunca em claro); `POST /security/iocpack/import` verifica destinos probabilisticamente.

### Novidades de política e resposta (v1.4)

- **Perfis nomeados** — `POST /firewall/profile`: `permissive` (tábua rasa), `balanced` (base de saída prudente) ou `strict` (base + lockdown); expandem em regras comuns com deduplicação.
- **Regras de alerta personalizadas** — `GET/POST/DELETE /alerts/rules`: campo + operador + valor → alertas `CUSTOM_RULE` (só alerta, nunca bloqueia).
- **Importar blocklist** — `POST /firewall/blocklist`: arquivo local (leitura puramente local) ou URL opt-in (fetch HTTPS ≤4 MiB, marcado `remote_fetch`) → regras `domain`, deduplicadas, teto 500–5000.
- **Exportar PCAP** — `GET /forensics/pcap` (filtros `ip`/`process`): anel de ~4 MiB como `.pcap` para Wireshark.
- **Pareamento remoto** — `POST /remote/pairing` persiste `lan_bind` para a próxima inicialização; token continua obrigatório. `GET /remote/pairing` reporta bind + IPs da LAN.
- **Sandbox sem rede** — `POST /security/sandbox` executa um binário com egress zero (`unshare -n` Linux, `sandbox-exec` macOS; `contrib/snitch-contain` manual).
- **Modelo embutido** — `slm_mode=embedded` carrega um `.gguf` do usuário via `llama-cpp-python` — zero rede.
- **Esqueletos nativos** — `contrib/wfp-callout/` (callout WFP em C + assinatura) e `contrib/macos-filter/` (`NEFilterDataProvider` Swift + entitlements): scaffolding de pesquisa, não distribuídos.
- **ASN** — com `GeoLite2-ASN.mmdb`/`dbip-asn-lite.mmdb`, os nós carregam `asn` além de `org`.

## v1.5 — Inspeção passiva, vereditos em kernel e sincronização de frota

- **Inspeção passiva do certificado TLS** — remontagem TCP limitada (≤16 KiB/fluxo, TTL 30 s) lê a mensagem `Certificate`: CN+O emissor/sujeito, autoassinado, SANs, validade, `san_mismatch` → `TLS_CERT`. **TLS 1.3 permanece opaco** — honestamente inobservável em vez de adivinhado.
- **Guarda de alta entropia** — payloads ≥48 B em canais não TLS com ≥4,7 bits/byte → `HIGH_ENTROPY`; cooldown de 10 min por host.
- **Heurística de túnel ICMP** — tipos echo com ≥24 B de payload, ≥3× em 5 min → `ICMP_TUNNEL`.
- **Anomalia ML de fluxo** — isolation forest em Python puro (64 árvores, zero deps) sobre seus próprios resumos; inerte <384 fluxos, `ML_ANOMALY` a 0,62. Desvio de baseline, **não** um classificador.
- **Ask-on-connect (Linux, opt-in)** — `ask_enabled` + root + `python-netfilterqueue`: novos fluxos de saída retidos na NFQUEUE 7 até `POST /security/ask/verdict`; timeout 15 s, fail-closed (`ask_failopen=1` inverte). Windows/macOS precisam dos esqueletos assinados em `contrib/`.
- **Enforcement eBPF cgroup (Linux, opt-in)** — `POST /security/ebpf/isolate {pid}` + `/security/ebpf/block {ip}`: programa attach ao cgroup snitch — drops em kernel SÓ para processos isolados.
- **Check de hollowing (Linux)** — `POST /security/hollow {pid}` compara páginas executáveis file-backed de `/proc/<pid>/mem` com o disco.
- **Sincronização IOC entre pares (opt-in)** — `gossip_peers` ≤32 + `gossip_enabled`: pacotes Merkle a cada 5 min via HTTP(S) autenticado — sem discovery, não é ZK.
- **Syslog (opt-in)** — `syslog_addr` (`host:porta` UDP ou `tcp://`) → RFC 3164 `local4`.
- **Contenção Firejail** — `firejail --net=none` preferido, `unshare` como fallback.
- **Backend nftables** — tabela `inet snitch` dedicada em vez de iptables onde existe `nft`.
- **Alertas acionáveis** — `actions` estruturadas (bloquear IP, matar/suspender, veredito ask) como botões de um clique.
- **`asn`/`country` em regras custom** — base geo local, combinável com `action=block` como geo-fence.
