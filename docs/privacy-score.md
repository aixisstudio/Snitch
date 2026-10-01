# Privacy Score — Methodology / Méthodologie

## English

The score (A–F, displayed top-right) is computed in
`frontend/src/scoring/privacy.js` from the live node/edge/alert state.
It is a **heuristic**, not a formal guarantee — document your threat model
before relying on the letter grade.

Inputs and weights:

| Signal | Effect |
|---|---|
| Tracker-category nodes (known ad/analytics domains via DNS/SNI) | −8 pts each |
| `critical`/`warning` alerts in the window | −10 / −4 pts each |
| Share of bytes going to tracker-flagged destinations | proportional penalty |
| Distinct remote hosts count | mild penalty above ~30 |
| HTTPS share (port 443 traffic) | small bonus |

Known limitations:

- Tracker matching relies on observed DNS/SNI names only — a tracker reached
  by bare IP won't match. This is intentional (no substring matching on
  reverse PTR, which produced false positives like `notfacebook.com`).
- The A–F letter is an ordinal summary, not a measurement. Treat it as a
  trend indicator over time, not an absolute score.

## Français

Le score (A–F, en haut à droite) est calculé dans
`frontend/src/scoring/privacy.js` à partir de l'état nœuds/arêtes/alertes.
C'est une **heuristique**, pas une garantie formelle.

Entrées et pondérations : voir le tableau ci-dessus (identique).

Limites connues : la correspondance trackers repose uniquement sur les noms
DNS/SNI observés — un tracker joint par IP brute n'est pas détecté. C'est
volontaire (pas de correspondance par sous-chaîne sur le PTR inverse, qui
produisait des faux positifs du type `notfacebook.com`). La lettre est un
résumé ordinal : à lire comme une tendance, pas une mesure absolue.
