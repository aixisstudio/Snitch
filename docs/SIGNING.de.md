# Code-Signierung

[English](SIGNING.md) | [Français](SIGNING.md) | [Español](SIGNING.es.md) | **Deutsch** | [Русский](SIGNING.ru.md) | [日本語](SIGNING.ja.md) | [Português](SIGNING.pt-BR.md) | [中文](SIGNING.zh-CN.md)

## Aktueller Stand

Snitch-Builds sind unter Windows und macOS **unsigniert**. Das ist ehrlich
und bewusst so: keine selbstsignierten Zertifikate, die den Sinn der
Signierung unterlaufen, und kein Zertifikatskauf, solange ein legitimer
kostenloser Weg für Open Source existiert.

## Windows — SignPath Foundation (kostenlos für OSS)

[SignPath](https://signpath.org) bietet qualifizierten Open-Source-Projekten
**kostenlose Authenticode-Signierung**. Genehmigte Projekte erhalten eine
`release-signing`-Policy mit öffentlich vertrauenswürdigen Signaturen —
SmartScreen hört auf zu warnen, sobald Reputation aufgebaut ist.

### Einrichtung (einmalig, nur Maintainer)

1. Bewerben auf <https://signpath.org/apply> — Formular mit Name, E-Mail,
   Projekt, Repository-URL und Beschreibung. Manuelle Genehmigung (Tage).
   Snitch erfüllt jede veröffentlichte Bedingung: AGPL-3.0 (OSI-approved,
   kein Dual Licensing), vollständig öffentliche Quellen, aktiv gepflegt,
   bereits auf GitHub Releases veröffentlicht, dokumentiert.
   **Bewerbung eingereicht — Prüfung läuft.**
2. SignPath-Organisation anlegen, ein **Projekt** (Slug, z. B. `Snitch`),
   das Trusted Build System *GitHub.com* verknüpfen und die SignPath
   GitHub App auf diesem Repo installieren (für Origin-Verifikation nötig).
3. **Release-Signing-Policy** auf Tag-Builds beschränkt anlegen, mit
   Artifact-Konfiguration für `*.exe` in einem ZIP (Standardvorlage).
4. In GitHub → *Settings → Secrets and variables → Actions*:
   - Variablen: `SIGNPATH_ORGANIZATION_ID`, `SIGNPATH_PROJECT_SLUG`,
     `SIGNPATH_POLICY_SLUG`
   - Secret: `SIGNPATH_API_TOKEN`
5. Fertig — der CI-Job `SignPath — submit signing request` aktiviert sich
   beim nächsten Tag: lädt den unsignierten Installer hoch, wartet auf die
   signierte Kopie und ersetzt das Artefakt vor dem Release-Upload.
   **Alles inert bis Schritt 4.**

## macOS — kein kostenloser Weg

Apple verlangt eine bezahlte **Developer-Program**-Mitgliedschaft
($99/Jahr) für Developer-ID-Zertifikat + Notarisierung. Keine legale
kostenlose Alternative. Bis dahin:

- `.zip`/`.dmg`-Builds bleiben unsigniert — erster Start per
  **Rechtsklick → Öffnen** oder `xattr -d com.apple.quarantine Snitch.app`
- SHA256-Checksums jeder Release erlauben Integritätsprüfung
- öffentliche CI-Buildlogs liefern Provenienz (reproduzierbare Pipeline)

Falls je `APPLE_ID` / `APPLE_TEAM_ID` / `APPLE_APP_PASSWORD` /
`MACOS_CERT_P12` konfiguriert werden, sind die `ENABLE_CODESIGNING`-
Platzhalter-Schritte in CI der Ankerpunkt.

## Geprüfte und verworfene Alternativen

| Option | Warum nicht |
|---|---|
| Azure Trusted Signing | ~$10/Monat — nicht gratis; Free-/Trial-/gesponserte Azure-Subs explizit nicht unterstützt |
| Microsoft Store (MSIX) | Microsoft resigniert gratis nach Zertifizierung — nur für Store-Vertrieb; Zukunftskanal |
| Selbstsigniertes Zertifikat | Unterläuft SmartScreen/Gatekeeper — schlechter als unsigniert |
| Community-/geteilte Zertifikate | Illegal nach CA-Bedingungen — niemals |
