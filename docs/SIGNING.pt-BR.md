# Assinatura de código

[English](SIGNING.md) | [Français](SIGNING.md) | [Español](SIGNING.es.md) | [Deutsch](SIGNING.de.md) | [Русский](SIGNING.ru.md) | [日本語](SIGNING.ja.md) | **Português** | [中文](SIGNING.zh-CN.md)

## Estado atual

Os builds do Snitch estão **sem assinatura** no Windows e no macOS. É
honesto e deliberado: não publicaremos certificados autoassinados que
anulam o propósito da assinatura, nem compraremos um certificado enquanto
existir um caminho gratuito legítimo para open source.

## Windows — SignPath Foundation (grátis para OSS)

O [SignPath](https://signpath.org) oferece **assinatura Authenticode
gratuita** a projetos open source elegíveis. Projetos aprovados recebem
uma política `release-signing` que produz assinaturas confiáveis
publicamente — o SmartScreen para de avisar quando a reputação se
consolida.

### Configuração (uma vez, só mantenedor)

1. Candidatar-se em <https://signpath.org/apply> — formulário com nome,
   e-mail, projeto, URL do repositório e descrição. Aprovação manual
   (dias). O Snitch cumpre todas as condições publicadas: AGPL-3.0
   (aprovada OSI, sem licenciamento duplo), fonte totalmente pública,
   mantido ativamente, já publicado no GitHub Releases, documentado.
   **Candidatura enviada — em revisão.**
2. Criar a organização SignPath, um **projeto** (slug, ex. `Snitch`),
   vincular o build system confiável *GitHub.com* e instalar o app GitHub
   SignPath neste repositório (necessário para verificação de origem).
3. Criar uma **política release-signing** restrita a builds de tag, com
   configuração de artefato cobrindo `*.exe` num ZIP (o template padrão
   serve).
4. No GitHub → *Settings → Secrets and variables → Actions*:
   - Variáveis: `SIGNPATH_ORGANIZATION_ID`, `SIGNPATH_PROJECT_SLUG`,
     `SIGNPATH_POLICY_SLUG`
   - Segredo: `SIGNPATH_API_TOKEN`
5. Pronto — o job CI `SignPath — submit signing request` ativa sozinho no
   próximo tag: envia o instalador não assinado, aguarda a cópia assinada
   e substitui o artefato antes do upload da release. **Tudo inerte até o
   passo 4.**

## macOS — não existe caminho gratuito

A Apple exige uma assinatura paga do **Developer Program** ($99/ano) para
certificado Developer ID + notarização. Não há alternativa gratuita
legal. Até lá:

- os builds `.zip`/`.dmg` ficam sem assinatura — primeira execução via
  **clique direito → Abrir**, ou `xattr -d com.apple.quarantine Snitch.app`
- checksums SHA256 de cada release permitem verificar integridade
- logs públicos de CI fornecem procedência (pipeline reproduzível)

Se um dia forem configurados `APPLE_ID` / `APPLE_TEAM_ID` /
`APPLE_APP_PASSWORD` / `MACOS_CERT_P12`, os passos placeholder
`ENABLE_CODESIGNING` na CI são o gancho.

## Alternativas avaliadas e rejeitadas

| Opção | Por que não |
|---|---|
| Azure Trusted Signing | ~$10/mês — não grátis; subs Azure gratuitas/trial/patrocinadas explicitamente não suportadas |
| Microsoft Store (MSIX) | Microsoft reassina grátis após certificação — só para distribuição Store; canal futuro |
| Certificado autoassinado | Anula a confiança SmartScreen/Gatekeeper — pior que sem assinatura |
| Certificados comunitários/compartilhados | Ilegal pelos termos das CAs — jamais |
