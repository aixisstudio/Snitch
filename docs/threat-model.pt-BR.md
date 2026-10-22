# Modelo de ameaças

[English](threat-model.md) | [Français](threat-model.md) | [Español](threat-model.es.md) | [Deutsch](threat-model.de.md) | [Русский](threat-model.ru.md) | [日本語](threat-model.ja.md) | **Português** | [中文](threat-model.zh-CN.md)

## O que é o Snitch

Um visualizador de tráfego de rede local-first. Captura pacotes no host,
atribui a processos, enriquece **offline** (geolocalização `.mmdb` local,
mapas DNS/SNI locais) e renderiza numa UI web servida pelo mesmo processo.
**Sem componente cloud, sem telemetria.**

## Ativos

- Seus metadados de tráfego (IPs de destino, portas, volumes, processos).
- O token de API (por execução no Electron, por instalação em CLI/Docker).
- A base SQLite local (`traffic`, `alerts_log`, históricos, configurações).
- A integridade da própria máquina (um Snitch comprometido poderia mentir).

## Fronteiras de confiança

| Fronteira | Ameaça | Mitigação |
|---|---|---|
| Navegador/cliente remoto → REST | Um atacante na LAN ou página maliciosa lê/controla sua visão do tráfego | Token exigido em **todo** endpoint (`Authorization: Bearer`). Bind `127.0.0.1` por padrão. Em Docker, `0.0.0.0` exige `SNITCH_TOKEN` explícito. |
| Página web → `/ws` | Sequestro de WebSocket cross-site (CSWSH) | Token **e** allowlist de `Origin` (loopback + origem `null` do Electron). |
| Host → terceiros | Vazamento de privacidade | Zero chamadas externas por padrão. Download GeoIP, threat intel, webhooks e atualizações são **opt-in** documentados em PRIVACY.md. |
| Driver de captura → parser | Frames malformados derrubam o processo | O parser limita cada offset; pacotes malformados retornam `None`, nunca lançam exceção no loop de captura. |
| Renderer ↔ main (Electron) | Exfiltração do token a partir da página | `contextIsolation` + `sandbox`; o token só atravessa via `ipcRenderer.invoke`, nunca no DOM nem numa URL. |
| Atacante local com acesso ao FS | Roubo do token/histórico | Arquivo de token `0600`; diretório de dados no diretório do usuário; DB não criptografada — criptografia de disco é papel do SO. |

## Limitações conhecidas

- **A captura exige privilégios admin/root**, mas restritos ao backend: a
  UI Electron roda sem privilégios enquanto o backend é iniciado elevado
  pelo prompt da plataforma (`Start-Process -Verb RunAs` no Windows,
  `osascript` no macOS, `pkexec` no Linux) e parado via endpoint
  autenticado `/shutdown`.
- O token protege HTTP/WS mas **não** contra outro processo local na sua
  conta que leia `data/api_token.txt` ou o IPC do Electron.
- Dados SQLite em repouso não são criptografados.
- A supressão de alertas é local e silenciosa — um atacante com escrita na
  base pode silenciar alertas (defesa: permissões de FS).

## Fora de escopo

Payloads maliciosos (apenas cabeçalhos são parseados), comprometimento de
kernel/driver, administrador malicioso.
