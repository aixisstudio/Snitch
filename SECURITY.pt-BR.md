# Política de segurança

[English](SECURITY.md) | [Français](SECURITY.md) | [Español](SECURITY.es.md) | [Deutsch](SECURITY.de.md) | [Русский](SECURITY.ru.md) | [日本語](SECURITY.ja.md) | **Português** | [中文](SECURITY.zh-CN.md)

## Relato de vulnerabilidades

Relate vulnerabilidades em privado pelo recurso «Report a vulnerability»
do GitHub (aba Security) ou por email aos mantenedores indicados no perfil
do repositório. Não abra issues públicas para problemas de segurança.

## Superfície de ataque local

A API expõe todo o seu grafo de tráfego — é protegida por design:

- **Autenticação por token** em todo endpoint REST e no WebSocket
  (`X-Snitch-Token` ou `?token=`). Gerado por execução no Electron,
  persistido com permissões 0600 nos demais modos.
- **Bind em loopback** (`127.0.0.1`) por padrão em todos os modos.
- **Allowlist de Origin** no handshake WebSocket (hosts loopback + `null`)
  para bloquear sequestro de WebSocket cross-site.
- **CORS restrito** — apenas origens loopback, sem credenciais.

## Privilégios

A captura de pacotes exige privilégios elevados — mas só o backend os
detém. O app Electron empacotado roda a UI sem privilégios em qualquer SO
e eleva APENAS o backend pelo prompt nativo da plataforma:

- **Windows:** `Start-Process -Verb RunAs` (um prompt UAC por execução) + Npcap (instalado por você em npcap.com)
- **macOS:** `osascript … with administrator privileges` (diálogo nativo de senha)
- **Linux:** `pkexec` (diálogo polkit); recua para sem privilégios se o polkit não existir

O filho elevado é encerrado pelo endpoint autenticado `/shutdown`, já que
um processo sem privilégios não pode sinalizá-lo. Recusar o prompt oferece
tentar de novo / continuar sem captura em vez de encerrar à força.

## Dependências

O Scapy foi removido (GPL-2.0-only + grande superfície de ataque). A
captura é um binding ctypes mínimo para libpcap mais nosso próprio parser
com limites. As dependências são fixadas e monitoradas pelo Dependabot.
