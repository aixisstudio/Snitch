# Firma de código

[English](SIGNING.md) | [Français](SIGNING.md) | **Español** | [Deutsch](SIGNING.de.md) | [Русский](SIGNING.ru.md) | [日本語](SIGNING.ja.md) | [Português](SIGNING.pt-BR.md) | [中文](SIGNING.zh-CN.md)

## Estado actual

Los builds de Snitch están **sin firmar** en Windows y macOS. Es honesto y
deliberado: no publicaremos certificados autofirmados que anularían el
sentido de la firma, ni compraremos un certificado mientras exista una vía
gratuita legítima para el open source.

## Windows — SignPath Foundation (gratis para OSS)

[SignPath](https://signpath.org) ofrece **firma Authenticode gratuita** a
proyectos open source elegibles. Los proyectos aprobados obtienen una
política `release-signing` que produce firmas públicamente confiables —
SmartScreen deja de avisar cuando se construye reputación.

### Configuración (una vez, solo mantenedor)

1. Solicitar en <https://signpath.org/apply> — formulario con nombre,
   email, proyecto, URL del repositorio y descripción. Aprobación manual
   (días). Snitch cumple cada condición publicada: AGPL-3.0 (aprobada OSI,
   sin doble licencia), fuente pública, mantenido, ya publicado en GitHub
   Releases, documentado. **Candidatura enviada — pendiente de revisión.**
2. Crear la organización SignPath, un **proyecto** (slug, p.ej. `Snitch`),
   vincular el build system de confianza *GitHub.com* e instalar la app
   GitHub SignPath en este repositorio (requerida para verificación de
   origen).
3. Crear una **política release-signing** restringida a builds de tag, con
   una configuración de artefacto que cubra `*.exe` en un ZIP (la plantilla
   estándar funciona).
4. En GitHub → *Settings → Secrets and variables → Actions*:
   - Variables: `SIGNPATH_ORGANIZATION_ID`, `SIGNPATH_PROJECT_SLUG`,
     `SIGNPATH_POLICY_SLUG`
   - Secreto: `SIGNPATH_API_TOKEN`
5. Listo — el job CI `SignPath — submit signing request` se activa solo en
   el próximo tag: sube el instalador sin firmar, espera la copia firmada y
   reemplaza el artefacto antes de subirlo a la release. **Todo es inerte
   hasta el paso 4.**

## macOS — no existe vía gratuita

Apple exige una membresía **Developer Program** de pago ($99/año) para un
certificado Developer ID + notarización. No hay alternativa gratuita
legal. Mientras tanto:

- los builds `.zip`/`.dmg` quedan sin firmar — primer arranque con
  **clic derecho → Abrir**, o `xattr -d com.apple.quarantine Snitch.app`
- los checksums SHA256 de cada release permiten verificar la integridad
- los logs CI públicos dan procedencia (pipeline reproducible)

Si algún día se configuran `APPLE_ID` / `APPLE_TEAM_ID` /
`APPLE_APP_PASSWORD` / `MACOS_CERT_P12`, los pasos placeholder
`ENABLE_CODESIGNING` de CI son el punto de enganche.

## Alternativas evaluadas y rechazadas

| Opción | Por qué no |
|---|---|
| Azure Trusted Signing | ~$10/mes — no gratis; subs Azure gratuitas/trial/patrocinadas no soportadas explícitamente |
| Microsoft Store (MSIX) | Microsoft refirma gratis tras certificación — pero solo para distribución Store; canal futuro |
| Certificado autofirmado | Anula la confianza SmartScreen/Gatekeeper — peor que sin firmar |
| Certificados comunitarios/compartidos | Ilegal según términos de las CA — jamás |
