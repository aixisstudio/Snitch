# Registro de alterações

[English](CHANGELOG.md) | [Français](CHANGELOG.md) | [Español](CHANGELOG.es.md) | [Deutsch](CHANGELOG.de.md) | [Русский](CHANGELOG.ru.md) | [日本語](CHANGELOG.ja.md) | **Português** | [中文](CHANGELOG.zh-CN.md)

Todas as mudanças notáveis do Snitch.

O formato segue o [Keep a Changelog](https://keepachangelog.com/).

## [1.5.0] — 2026-10-22

### Adicionado

- **Inspeção passiva do certificado TLS** — `capture/tlscert.py` remonta a mensagem `Certificate` do servidor através de segmentos TCP (limite 16 KiB/fluxo) e lê o DER folha: emissor/sujeito, flag autoassinado, SANs, validade → `TLS_CERT` se autoassinado ou mismatch SAN/SNI. TLS 1.3 é reportado honestamente como inobservável — sem MITM, sem decriptação.
- **Heurística de túnel ICMP** — ecos repetidos com payloads grandes (≥24 B, 3+ em 5 min) → `ICMP_TUNNEL` (assinatura ptunnel/icmpsh).
- **Detecção de alta entropia** — cabeças de payload quase aleatórias (≥4,7 bits/byte) em sockets em claro → `HIGH_ENTROPY` (indício de cripto encoberta/estego).
- **Isolation Forest (Python puro)** — `detection/iforest.py` + `mlflow.py` pontuam fluxos de saída em 6 features; `ML_ANOMALY` a partir de score 0,62, inerte abaixo de 384 fluxos aprendidos.
- **Ask-on-connect (Linux NFQUEUE, opt-in)** — `ask_enabled` retém novos fluxos de saída na fila 7 até `POST /security/ask/verdict` — veredito real, timeout dropa por padrão.
- **Enforcement eBPF de egress** — `detection/ebpf_enforce.py` + `POST /security/ebpf/isolate|block` — drops em kernel apenas para processos no cgroup snitch.
- **Prova de hollowing** — `POST /security/hollow` compara páginas executáveis em RAM com o ficheiro em disco (Linux, `/proc`).
- **Sincronização IOC entre pares** — `gossip_peers` + `gossip_enabled`: pacotes Merkle com sal a cada 5 min para pares explicitamente listados — só compromissos hash, sem discovery.
- **Syslog** — `syslog_addr` (UDP ou `tcp://`) encaminha alertas warning/críticos como RFC 3164 — caminho SIEM/Wazuh.
- **Regras geo + auto-bloqueio** — regras custom com `asn`/`country` (mmdb local) e `action:"block"` instalam regras de firewall reais por IP correspondido.
- **Alertas acionáveis + UI de ajustes** — Bloquear IP / Matar / Suspender / Permitir-Negar por alerta; novos controles nos ajustes (syslog, ask, pares).
- **Backend nftables + firejail** — `nft` quando falta iptables (tabela `inet snitch` dedicada); `firejail --net=none` como fallback de sandbox.

## [Unreleased]

### Adicionado

- **Orquestração de firewall de saída** — regras de usuário (`ip`, `cidr`, `domain`, `process`, `port`) aplicadas ao firewall nativo do SO em best-effort: `netsh advfirewall` no Windows, `iptables` no Linux, âncora `pf` gerada no macOS. Persistidas, reaplicadas no arranque, `applied=False` honesto sem privilégios (matching + contadores `BLOCKED_ATTEMPT` continuam ativos).
- **Lockdown** — botão de pânico que derruba tráfego de saída para IPs públicos mantendo loopback/LAN vivos (cadeia `SNITCH_LOCK` no Linux, regras `netsh`, âncora `pf`).
- **Ações de processo** — `POST /processes/kill` e `POST /processes/suspend` (por PID, recusa PIDs ≤ 3 e o próprio Snitch); botões kill/suspend na lista de processos.
- **Threat intelligence (opt-in)** — verificações de reputação contra AbuseIPDB, AlienVault OTX ou VirusTotal com sua própria chave API; desligado por padrão, uma chamada por IP público novo, cache LRU limitado + dedup, alertas `THREAT_HIT` em veredictos suspeitos/maliciosos.
- **Webhooks externos (opt-in)** — alertas warning/critical enviados por POST ao vivo para Discord, Slack, Telegram (com chat ID) ou qualquer endpoint; desligado por padrão.
- **Novas detecções** — `DNS_TUNNEL` (nomes/labels DNS grandes demais), `CLEARTEXT` (egresso FTP/Telnet/HTTP/e-mail em claro), `BASELINE_DEVIATION` (perfil de países aprendido por processo, persistido).
- **Auditoria de segurança** — `GET /security/audit` calcula um score 0–100 mais recomendações em linguagem clara a partir de alertas recentes e do grafo ao vivo; exibido no painel Firewall.
- **Exportação forense** — `GET /forensics/export?format=json|csv|stix` empacota árvore de processos, SHA-256 do executável, alertas correspondentes e histórico de tráfego; STIX é um bundle 2.1 mínimo (indicators + observed-data) para importação em SIEM.
- **UI de firewall e segurança** — painel dedicado: interruptor lockdown, criar/alternar/excluir regras, contadores de bloqueio por regra, honestidade de suporte por plataforma, relatório de auditoria, botões de download forense; ação Bloquear por conexão na barra lateral.
- **Cinco novas locales de UI** — de, ru, ja, pt-BR, zh-CN (8 no total, paridade de 280 chaves verificada); dicionários movidos para `frontend/src/locales/*.js` — um idioma novo = PR de um arquivo.

## [1.1.0] — 2026-10-22

### Adicionado

- **Auto-atualização** — o app desktop verifica GitHub Releases no arranque e a cada 6 h via electron-updater (os feeds `latest-*.yml` já eram publicados). Downloads instalam ao reiniciar; bandeja e Configurações mostram o status ao vivo. Opt-out em Configurações ou via `SNITCH_NO_UPDATE=1`.
- **Visibilidade QUIC / HTTP/3** — fluxos UDP/443 passam a ser rotulados `QUIC/HTTP3` em vez de cair em HTTPS ou desconhecido. O SNI do Initial QUIC é cifrado e nunca lido — o rótulo é honesto sobre o observável.
- **Watchlist** — fixe IPs ou sufixos de domínio (`example.com` também casa `api.example.com`); um alerta dedicado `WATCHLIST_HIT` dispara no primeiro contato, limitado por (entrada, host). Persistido, gerenciado em Configurações.
- **Alerta de upload por processo** — `UPLOAD_SPIKE` avisa quando um processo excede um teto MB/min configurável (padrão 50, 0 = off) — cobre exfiltração que o `VOLUME_SPIKE` relativo à baseline perde em processos recém-iniciados.
- **Seletor de interface de captura** — `GET/POST /capture/interfaces` + dropdown em Configurações listando dispositivos libpcap; a troca reinicia a captura na hora. Substitui a variável `SNITCH_IFACE` para usuários desktop.
- **Contexto Wi-Fi** — a barra mostra o SSID atual (ou a interface de captura fora do Wi-Fi). Best-effort por SO, cache de 60 s.
- **UI em espanhol** — dicionário `es` completo (194 chaves, paridade verificada); o seletor vira EN/FR/ES.
- **Pacote snap** — o electron-builder agora emite um `.snap` em confinamento estrito (com o plug `network-observe` para captura AF_PACKET). Flatpak deliberadamente não publicado — a sandbox não expõe captura bruta (documentado em `docs/PACKAGING.md`).
- **Caminho gratuito de assinatura** — integração opcional da SignPath Foundation OSS na CI (`vars.SIGNPATH_*` + `secrets.SIGNPATH_API_TOKEN`): o instalador Windows é assinado com Authenticode automaticamente quando o projeto for aceito. Documentado em `docs/SIGNING.md`, incluindo a situação honesta do macOS (não existe notarização gratuita).

## [1.0.8] — 2026-10-22

### Alterado

- **Tema claro nativo de verdade** — substitui o filtro de inversão da v1.0.7 por um sistema completo de design tokens: cada superfície, texto, borda e cor de destaque é pintada via propriedades CSS customizadas com uma paleta clara escolhida a dedo. Mapa, grafo de força, timeline e aurora WebGL seguem o tema, e o toggle persiste sua escolha.

## [1.0.7] — 2026-10-22

### Adicionado

- **Tema claro** — honra `prefers-color-scheme` por padrão e pode ser sobreposto pelo toggle sol/lua da barra; a escolha persiste em `localStorage`. Implementado como inversão que preserva o tom da paleta escura, mantendo grafos, mapa e aurora coerentes.

### Corrigido

- **Conformidade com o catálogo AppImage** — o asset Linux agora se chama `Snitch-x86_64.AppImage` (nomenclatura de arquitetura correta) e o electron-builder publica metadados de atualização (`latest-linux.yml` + `.zsync`), habilitando auto-atualização por ferramentas compatíveis com AppImageUpdate.

## [1.0.6] — 2026-10-21

### Adicionado

- **Um download por SO** — cada tag publica apps prontos construídos pela CI:
  - **Windows** — `Snitch Setup <versão>.exe` (Electron + NSIS: janela nativa, bandeja, verificação Npcap embutida, prompt UAC ao subir o backend) e `Snitch-Lite-Setup-<versão>-windows-x64.exe` (Inno Setup: só backend, a UI abre no navegador).
  - **macOS (Apple Silicon)** — `Snitch-<versão>-macos-arm64.zip` + `.dmg` construídos na CI (antes manual).
  - **Linux** — `Snitch-<versão>.AppImage` + `.deb` — Docker não é mais obrigatório para o app desktop.
- **Modo backend `--launcher`** — escolhe uma porta loopback livre, calcula o token da API e abre o navegador; usado pelo atalho do instalador Lite.

### Corrigido

- **Bundles backend standalone agora incluem a UI** — `frontend_dist` é embutido no bundle PyInstaller em todos os SOs; o tarball puro servia apenas a API.

### Alterado

- O job `package` da CI constrói os instaladores Electron nos três SOs e um job `release` publica todos os artefatos na release do GitHub automaticamente.

## [1.0.5] — 2026-10-17

### Adicionado

- **Suporte a Windows** — o app empacotado inicia e captura no Windows (Npcap).
- **Ícones de processo** — ícones Lucide por processo na tabela de Apps (contribuição externa).
- **24 novos domínios de tracker** na lista do classificador (contribuição externa).

### Corrigido

- Crash do backend em builds PyInstaller `console=False` (`sys.stdout`/`sys.stderr` = None) — issue #25.
- Seleção de interface de captura no Windows — o Snitch agora escolhe a interface da rota padrão em vez de `vEthernet (WSL)`.
- `NaNh ago` nos timestamps de alertas com offsets de fuso.
- O splash do Electron não esconde mais diálogos de erro; a mensagem de timeout lista causas + pasta de logs.
- Quatro strings inglesas restantes traduzidas no dicionário francês (contribuição externa).
- Versão agora em fonte única em `backend/version.py`.

### Alterado

- React 18 → 19, uvicorn 0.30 → 0.54, fastapi → 0.143, psutil → 7.2, websockets → 17.2, maxminddb → 3.2, aiofiles → 25.1, lucide-react → 1.55, vite → 8.3.4, electron → 44.7 (+ dev deps).

## [1.0.4] — 2026-10-05

- Primeira release pública.
