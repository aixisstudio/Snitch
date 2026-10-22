# Snitch WFP kernel callout — skeleton

[English](#english) · [Français](#français)

---

## English

This directory contains a **reference skeleton** for a real Windows
Filtering Platform kernel callout driver — the piece the user-mode
`fwpuclnt.dll` filters in `backend/detection/wfp.py` deliberately are
*not*. A callout runs inside the kernel's classify path and can inspect,
block, or modify traffic per-connection with guarantees user-mode
filters cannot give.

### Honest status

**This is scaffolding, not a production driver.** It compiles against
the WDK and registers/unregisters a callout correctly, but:

- It does **not** ship in Snitch releases. Snitch's Windows enforcement
  today is the user-mode WFP filter layer — no driver required.
- A real callout driver must be **signed**: test-signed for your own
  machine (`bcdedit /set testsigning on` + a self-signed cert), or
  attestation/EV-signed for distribution. Unsigned drivers do not load
  on retail Windows.
- The classify callback here only permits traffic — deciding *what* to
  block is policy, and policy belongs in user mode where Snitch rules
  already live.

### Authoritative references (read before writing callout code)

- Microsoft `Windows-driver-samples` → `network/trans/inspect`
  (the canonical traffic-inspection callout: classify → clone →
  block → inject-later pattern)
- `JaredWright/WFPStarterKit` — a minimal ~100-line callout that is
  much easier to learn from than the full sample
- `docs.microsoft.com` WFP architecture docs: callouts, layers
  (`FWPS_LAYER_ALE_AUTH_CONNECT_V4` is the layer Snitch cares about —
  outbound connect authorization), filter conditions

### Build (for research only)

1. Install Visual Studio + the WDK (matching SDK/WDK versions).
2. Add this `callout.c` to a **KMDF/Empty WDM driver** project — or
   simpler, start from `WFPStarterKit`'s project and replace its
   classify body.
3. Test-sign, enable `testsigning`, `sc create` / `sc start`.
4. Register the callout at `FWPS_LAYER_ALE_AUTH_CONNECT_V4`, then add a
   user-mode filter referencing it (`FWPM_FILTER` with
   `providerContext`/`calloutKey`) from `fwpuclnt.dll` — the same DLL
   `backend/detection/wfp.py` already drives.

---

## Français

Ce répertoire contient un **squelette de référence** pour un vrai
pilote callout WFP noyau — la pièce que les filtres user-mode
`fwpuclnt.dll` de `backend/detection/wfp.py` ne sont *volontairement
pas*. Un callout s'exécute dans le chemin de classification du noyau et
peut inspecter, bloquer ou modifier le trafic par connexion avec des
garanties qu'un filtre user-mode ne donne pas.

### État honnête

**C'est un échafaudage, pas un pilote de production.** Il compile avec
le WDK et enregistre/désenregistre un callout correctement, mais :

- Il n'est **pas** livré dans les releases Snitch. L'application des
  règles Windows aujourd'hui = la couche de filtres WFP user-mode — sans
  pilote.
- Un vrai pilote callout exige une **signature** : test-signing sur sa
  propre machine (`bcdedit /set testsigning on` + certificat
  auto-signé), ou signature attestation/EV pour distribuer. Windows
  retail refuse les pilotes non signés.
- Le callback ici ne fait qu'autoriser — décider *quoi* bloquer est de
  la politique, et la politique appartient au user-mode où vivent déjà
  les règles Snitch.

### Références autorisées (à lire avant d'écrire un callout)

- `Windows-driver-samples` de Microsoft → `network/trans/inspect`
- `JaredWright/WFPStarterKit` — callout minimal ~100 lignes
- Documentation WFP Microsoft : callouts, couches
  (`FWPS_LAYER_ALE_AUTH_CONNECT_V4` est celle qui intéresse Snitch —
  autorisation de connexion sortante)

### Build (recherche uniquement)

1. Visual Studio + WDK (versions SDK/WDK concordantes).
2. Ajouter `callout.c` à un projet pilote WDM vide — ou partir de
   `WFPStarterKit` et remplacer le corps de classify.
3. Test-signer, activer `testsigning`, `sc create` / `sc start`.
4. Enregistrer le callout sur `FWPS_LAYER_ALE_AUTH_CONNECT_V4`, puis
   ajouter un filtre user-mode qui le référence depuis `fwpuclnt.dll` —
   la même DLL que `backend/detection/wfp.py` pilote déjà.
