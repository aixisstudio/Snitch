# Snitch macOS content filter — skeleton

[English](#english) · [Français](#français)

---

## English

This directory contains a **reference skeleton** for a NetworkExtension
`NEFilterDataProvider` — the only Apple-supported way to filter
**outbound** traffic per-application on macOS. Snitch's built-in
enforcement uses `pf` (destination-level, not process-aware); this
extension is what real per-app outbound control would require.

### Honest status

**Scaffolding, not a shipping component.** To actually run this you need:

- A paid **Apple Developer** account (the Network Extension entitlements
  `com.apple.developer.networking.networkextension` with
  `content-filter` are entitlement-gated).
- A **system extension** host app + activation flow (`OSSystemExtensionRequest`),
  notarization for distribution outside the App Store, and — on macOS —
  user approval in System Settings → Network Filters.
- `NEFilterDataProvider` decisions are per-flow verdicts
  (`allow`/`drop`/`filterRules`); Snitch's user-mode rule engine would
  feed verdicts over XPC to this provider.

Verified alternative assessment: `socketfilterfw` (Application Firewall)
only filters **inbound** connections — it cannot do per-app outbound.
There is no user-mode equivalent.

### Authoritative references

- Apple `SimpleFirewall` sample (WWDC) → `cntrump/SimpleFirewall` mirror
- Apple `SimpleTunnel` → `partyspy/SimpleTunnel` (NE packaging flow)
- `elastic/endpoint` — a real `NEFilterDataProvider` in production
- `nufuturo-ufcg/NuAppFirewall` — a full open-source macOS firewall built
  on this API (**GPL-2.0** — reference only, do not copy code into this
  AGPL project without a licence review)

### Shape

`FilterDataProvider.swift` shows the two decision points:

- `handleNewFlow(_:)` — inspect `flow.remoteEndpoint` + the audit-token
  → process mapping, return a `NEFilterNewFlowVerdict`.
- Rule updates arrive over XPC from the Snitch backend (not shown —
  that transport is the real work).

---

## Français

Ce répertoire contient un **squelette de référence** pour un
`NEFilterDataProvider` NetworkExtension — la seule voie prise en charge
par Apple pour filtrer le trafic **sortant** par application sur macOS.
L'application des règles intégrée de Snitch utilise `pf` (au niveau
destination, sans notion de processus) ; cette extension est ce que le
contrôle sortant par-app réel exigerait.

### État honnête

**Échafaudage, pas un composant livré.** Pour l'exécuter réellement il
faut :

- Un compte **Apple Developer** payant (les entitlements
  `com.apple.developer.networking.networkextension` avec
  `content-filter` sont restreints).
- Une app hôte **system extension** + le flux d'activation
  (`OSSystemExtensionRequest`), la notarization, et l'approbation
  utilisateur dans Réglages Système → Filtres réseau.
- Les verdicts `NEFilterDataProvider` sont par flux
  (`allow`/`drop`) ; le moteur de règles Snitch les alimenterait via XPC.

Alternative vérifiée : `socketfilterfw` (pare-feu applicatif) ne filtre
que l'**entrant** — aucun équivalent user-mode pour le sortant par-app.

### Références

- Sample Apple `SimpleFirewall` (WWDC) → miroir `cntrump/SimpleFirewall`
- `partyspy/SimpleTunnel` (flux packaging NE)
- `elastic/endpoint` — vrai `NEFilterDataProvider` en production
- `nufuturo-ufcg/NuAppFirewall` — pare-feu macOS complet sur cette API
  (**GPL-2.0** — référence seulement, ne pas copier dans ce projet AGPL)

### Structure

`FilterDataProvider.swift` montre le point de décision
`handleNewFlow(_:)` : inspecter `flow.remoteEndpoint` + le mapping
audit-token → processus, puis renvoyer un verdict.
