# Roteiro

[English](ROADMAP.md) | [Français](ROADMAP.md) | [Español](ROADMAP.es.md) | [Deutsch](ROADMAP.de.md) | [Русский](ROADMAP.ru.md) | [日本語](ROADMAP.ja.md) | **Português** | [中文](ROADMAP.zh-CN.md)

> Sugira ou vote em funcionalidades nas [GitHub Discussions](https://github.com/aixisstudio/Snitch/discussions) — categoria *Ideas*. Para bugs concretos, use as [Issues](https://github.com/aixisstudio/Snitch/issues).

## ✅ Entregue

| Versão | O que chegou |
|---|---|
| **v1.0.4** | Primeira release pública — grafo em tempo real + mapa mundial, atribuição por processo, geolocalização offline (.mmdb), alertas de anomalias, privacy score, descoberta LAN passiva (ARP/OUI), monitoramento mic/câmera (Windows/Linux), modo demo, UI EN/FR |
| **v1.0.5** | **Suporte Windows** (Npcap, backend empacotado), ícones de processo, +24 domínios tracker, correções |
| **v1.2 (main, sem tag)** | **Suíte de segurança e threat-hunting** — orquestração do firewall do SO (regras IP/CIDR/domínio/processo/porta via `netsh`/`iptables`/`pf`, best-effort), botão lockdown, ações kill/suspend, threat intel opt-in (AbuseIPDB/OTX/VirusTotal), webhooks opt-in (Discord/Slack/Telegram/genérico), detecção de túnel DNS / tráfego em claro / desvio de país, auditoria de segurança, exportação forense (árvore de processos + SHA-256, JSON/CSV/STIX), UI em 8 idiomas |
| **v1.5.x** | **Camada enterprise/SOC** — `snitch.toml` declarativo, syslog CEF + RFC 3164 + `format=ecs` NDJSON, importação Sigma + exportação YARA-L, visão `/remote/fleet` + chart Helm, deploys Ansible/Puppet/Salt/GPO, unidade systemd endurecida + nfpm `.deb`/`.rpm`, feeds TI gratuitos, MkDocs + `INTEGRATIONS.md` em 7 idiomas |
| **v1.6.x** | **Agente e identidade da frota** — agente Rust sem dependências (`agent/`, atribuição `/proc` socket→PID no Linux), enrollment por agente (tokens `sagt_…` hasheados, `/ingest/revoke`), worker de refresh `ti_feeds` automático, CI do agente em 3 SOs, fórmula headless `snitchd`, todos os alertas CodeQL fechados, 235 testes backend |

Também no ar: imagem Docker no GHCR, tap do Homebrew (`brew install --cask aixisstudio/tap/snitch` + fórmula headless `snitchd`), pacote winget [enviado](https://github.com/microsoft/winget-pkgs/pull/455520), README em 8 idiomas, GitHub Discussions.

## 🚧 v1.x — em andamento

- [x] **Instalador Windows assinado** — CI preparada para [SignPath](https://signpath.org) OSS (Authenticode gratuito para projetos aprovados); ativa quando o pedido for aceito — ver `docs/SIGNING.md`
- [ ] **Build macOS assinado e notarizado** — exige conta Apple Developer (US$ 99/ano), não há caminho gratuito. Até lá, o [tap](https://github.com/aixisstudio/homebrew-tap) remove a quarentena
- [ ] **Homebrew upstream** (`brew install --cask snitch`) — bloqueado: o nome `snitch` já é usado por outro projeto; revisitado quando houver assinatura Developer ID
- [ ] **Publicação no winget** — [PR #455520](https://github.com/microsoft/winget-pkgs/pull/455520) (v1.0.8) aberta; o pipeline envia builds NSIS novos a cada tag
- [ ] **Chocolatey** — pacote pronto; aguarda o segredo `CHOCO_API_KEY`
- [ ] **Atribuição do agente no Windows/macOS** — backends `GetExtendedTcpTable`/`libproc`
- [ ] **Escala da frota** — coletor com fila + PostgreSQL/TimescaleDB para >1 000 agentes
- [x] **Instaladores Windows de 1 clique** — NSIS Electron + Inno Lite, construídos na CI por tag; desde v1.0.6
- [x] **Pacotes Linux** — .deb / AppImage / **snap** além do Docker (sem Flatpak: a sandbox não consegue expor a captura de pacotes)
- [x] **Atualização automática** — electron-updater sobre os feeds `latest-*.yml`, desativável em Configurações
- [x] **Formatos de exportação** — grafo + alertas para JSON/CSV na UI
- [ ] **Maior cobertura de trackers** — listas editáveis pela comunidade em `backend/classifier/lists/`
- [ ] **Exportação PCAP** — por host ou sessão

## 💭 Em estudo

- Regras de alerta personalizadas na UI
- Pareamento remoto opcional para hosts sem tela — com consentimento e token
- Camadas do mapa: visão ASN / organização
- Importação de blocklists (StevenBlack hosts, EasyList) — precisa de revisão de privacidade/licença
- Perfis de firewall (estrito/viagem vs desenvolvedor/permissivo)

## 🔬 Pesquisa — documentado, não implementado

Ideias que levariam o Snitch rumo a um EDR/XDR de desktop. Listadas com
honestidade — **nenhuma está implementada**; cada uma exige design próprio,
componentes nativos e muitas vezes um segundo artefato binário:

- **Sondas eBPF (Linux)** — captura kernel-space de `sys_enter_connect`/`accept`, resistente a evasão; exige programa BPF compilado + root
- **Callout WFP (Windows)** — filtragem real em kernel em vez de orquestrar `netsh`; exige driver assinado
- **NetworkExtension (macOS)** — `NEFilterProvider` para filtrar por bundle; exige Apple Developer ID + entitlements
- **Correlação memória/fluxo** — inspeção de DLLs não assinadas / regiões `PAGE_EXECUTE_READWRITE` cruzada com conexões suspeitas
- **Dynamic Taint Analysis** — provar exfiltração byte a byte; pesquisa pesada
- **SLM SecOps local** — modelo de 1–3 B parâmetros explicando alertas em linguagem natural
- **Intel de frota com ZKP** — compartilhar detecções entre pares sem revelar endpoints
- **Contadores PMU/hardware** — sinais de ransomware abaixo do SO (especulação, rajadas de cripto)
- **Integridade Merkle dos módulos carregados** — detectar DLLs adulteradas a quente antes do primeiro pacote
- **Sinkholing / micro-contenção** — redirecionar um fluxo suspeito para um honeypot local em vez de matá-lo
- **Exportação PCAP** permanece no escopo acima

## 🚫 Fora de escopo

Deliberadamente, por design:

- **Telemetria, analytics, contas, sincronização cloud** — nunca.
- **IDS passivo em escala de rede** — o Snitch observa *esta* máquina, não a rede inteira.
- **Filtragem de pacotes em user-space** — o bloqueio é delegado ao firewall nativo do SO (ou a futuros componentes de kernel), nunca reimplementado.

## 🤝 Contribuindo

Bons pontos de entrada: etiquetas `good first issue`, PRs de listas de trackers (`backend/classifier/lists/`), traduções (i18n pronta, um arquivo por idioma), empacotamento (Linux .deb/.rpm). Ver [CONTRIBUTING.md](CONTRIBUTING.md).
