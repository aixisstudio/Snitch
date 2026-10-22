# Code signing / Signature de code

[English](SIGNING.md) | [Français](SIGNING.md) | [Español](SIGNING.es.md) | [Deutsch](SIGNING.de.md) | [Русский](SIGNING.ru.md) | [日本語](SIGNING.ja.md) | [Português](SIGNING.pt-BR.md) | [中文](SIGNING.zh-CN.md)

## Current state / État actuel

Snitch builds are **unsigned** on Windows and macOS. This is honest and
deliberate: we will not ship self-signed certificates that defeat the point
of signing, and we will not buy a certificate while a legitimate free path
exists for open-source projects.

Les builds Snitch sont **non signés** sous Windows et macOS. C'est honnête et
volontaire : pas de certificat auto-signé qui viderait la signature de son
sens, et pas d'achat de certificat tant qu'une voie gratuite légitime existe
pour l'open source.

## Windows — SignPath Foundation (free for OSS)

[SignPath](https://signpath.org) offers **free Authenticode signing** to
qualifying open-source projects. Approved projects get a `release-signing`
policy that produces publicly trusted signatures — SmartScreen stops
warning once reputation builds.

### Setup (one-time, maintainer only)

1. Apply at <https://signpath.org/apply> — a HubSpot form asking for your
   name, email, project name, repository URL and a description. Approval is
   manual (days). Snitch meets every published condition: AGPL-3.0
   (OSI-approved, no dual licensing), all-source public, actively
   maintained, already released on GitHub Releases, documented.
2. Create the SignPath organization, a **project** (slug, e.g. `Snitch`),
   link the *GitHub.com* trusted build system to it, and install the
   SignPath GitHub App on this repository (required for origin verification).
3. Create a **release-signing policy** restricted to tag builds, with an
   artifact configuration matching `*.exe` in a ZIP (the standard template
   works).
4. In GitHub → repo *Settings → Secrets and variables → Actions*:
   - Variables: `SIGNPATH_ORGANIZATION_ID`, `SIGNPATH_PROJECT_SLUG`,
     `SIGNPATH_POLICY_SLUG`
   - Secret: `SIGNPATH_API_TOKEN`
5. Done — the CI job `SignPath — submit signing request` in
   `.github/workflows/ci.yml` activates automatically on the next tag: it
   uploads the unsigned installer, waits for the signed copy, and replaces
   the artifact before release upload. **Everything is inert until step 4.**

### Ready-to-paste application text / Texte de candidature prêt à coller

```
Project name: Snitch
Repository: https://github.com/aixisstudio/Snitch
License: AGPL-3.0-or-later
Website: https://aixisstudio.github.io/Snitch/

Snitch is a local-first network traffic visualizer for Windows, macOS and
Linux — a free, privacy-focused alternative to Little Snitch's monitoring
side. It captures packets via libpcap/Npcap through a custom ctypes
binding, attributes traffic to processes, geolocates IPs offline against
local .mmdb databases, and detects anomalies (port scans, beaconing,
exfiltration spikes). All analysis happens on-device: no telemetry, no
analytics, no account.

Release artifacts are built entirely by public GitHub Actions workflows
(.github/workflows/ci.yml) from tagged commits. We want to sign the
Windows NSIS installer (Snitch-Setup-windows.exe) so users stop seeing
SmartScreen warnings on install. The signing request will be submitted
from the tagged-release CI job via the signpath/github-action-submit-
signing-request action, signing only artifacts built from this repository.
```

## macOS — no free path exists

Apple requires a paid **Developer Program** membership ($99/yr) for a
Developer ID certificate + notarization. There is no legal free
alternative. Until/unless the project funds one:

- the `.zip`/`.dmg` builds stay unsigned — first launch needs
  **right-click → Open**, or `xattr -d com.apple.quarantine Snitch.app`
- SHA256 checksums are published on every release for integrity checking
- public CI build logs provide provenance (reproducible pipeline)

If `APPLE_ID` / `APPLE_TEAM_ID` / `APPLE_APP_PASSWORD` / `MACOS_CERT_P12`
secrets are ever configured, the `ENABLE_CODESIGNING` placeholder steps in
CI are the hook.

## Alternatives evaluated and rejected

| Option | Why not |
|---|---|
| Azure Trusted Signing | ~$10/mo — not free; free/trial/sponsored Azure subs are explicitly unsupported |
| Microsoft Store (MSIX) | Microsoft re-signs for free after certification — but only for Store distribution; kept as a future channel |
| Self-signed cert | Defeats SmartScreen/Gatekeeper trust — worse than unsigned |
| Community/shared certs | Illegal under CA terms — never |

---

## Français

### Windows — Fondation SignPath (gratuit pour l'open source)

[SignPath](https://signpath.org) offre la **signature Authenticode gratuite**
aux projets open source éligibles. Les projets acceptés obtiennent une
politique `release-signing` produisant des signatures publiquement
reconnues — SmartScreen cesse d'avertir une fois la réputation établie.

#### Installation (une fois, mainteneur)

1. Postuler sur <https://signpath.org> → *Open Source*. Approbation manuelle.
2. Créer l'organisation SignPath, un **projet** (slug ex. `Snitch`), lier le
   build system de confiance *GitHub.com* et installer l'app GitHub SignPath
   sur ce dépôt (requis pour la vérification d'origine).
3. Créer une **politique release-signing** restreinte aux builds de tag, avec
   une configuration d'artefact couvrant `*.exe` dans un ZIP.
4. Dans GitHub → *Settings → Secrets and variables → Actions* :
   - Variables : `SIGNPATH_ORGANIZATION_ID`, `SIGNPATH_PROJECT_SLUG`,
     `SIGNPATH_POLICY_SLUG`
   - Secret : `SIGNPATH_API_TOKEN`
5. Terminé — le job CI `SignPath — submit signing request` s'active tout
   seul au prochain tag. **Tout reste inerte tant que l'étape 4 n'est pas faite.**

### macOS — aucune voie gratuite

Apple exige un compte **Developer Program** payant (99 $/an) pour un
certificat Developer ID + notarisation. Pas d'alternative gratuite légale.
En attendant :

- les builds `.zip`/`.dmg` restent non signés — premier lancement via
  **clic droit → Ouvrir**, ou `xattr -d com.apple.quarantine Snitch.app`
- les SHA256 de chaque release permettent de vérifier l'intégrité
- les logs CI publics fournissent la provenance (pipeline reproductible)

### Alternatives évaluées et rejetées

| Option | Pourquoi non |
|---|---|
| Azure Trusted Signing | ~10 $/mois — pas gratuit ; abonnements Azure gratuits/sponsorisés explicitement non supportés |
| Microsoft Store (MSIX) | Microsoft re-signe gratuitement après certification — distribution Store seulement ; piste future |
| Certificat auto-signé | Neutralise la confiance SmartScreen/Gatekeeper — pire que non signé |
| Certificats partagés/communautaires | Illégal selon les termes des CA — jamais |
