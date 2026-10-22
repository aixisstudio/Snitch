# Privacy Score — Methodik

[English](privacy-score.md) | [Français](privacy-score.md) | [Español](privacy-score.es.md) | **Deutsch** | [Русский](privacy-score.ru.md) | [日本語](privacy-score.ja.md) | [Português](privacy-score.pt-BR.md) | [中文](privacy-score.zh-CN.md)

Der Score (A–F, oben rechts) wird in
`frontend/src/scoring/privacy.js` aus dem Live-Zustand von
Knoten/Kanten/Alarmen berechnet. Er ist eine **Heuristik**, keine formale
Garantie — dokumentiere dein Threat Model, bevor du dich auf die Note
verlässt.

Eingaben und Gewichte:

| Signal | Effekt |
|---|---|
| Knoten der Tracker-Kategorie (bekannte Ad-/Analytics-Domains via DNS/SNI) | −8 Pkt. je |
| `critical`/`warning`-Alarme im Fenster | −10 / −4 Pkt. je |
| Anteil der Bytes zu Tracker-Zielen | proportionale Strafe |
| Anzahl unterschiedlicher Remote-Hosts | milde Strafe oberhalb ~30 |
| HTTPS-Anteil (Port-443-Traffic) | kleiner Bonus |

Bekannte Grenzen:

- Tracker-Matching nutzt nur beobachtete DNS/SNI-Namen — ein Tracker per
  nackter IP matcht nicht. Das ist Absicht (kein Substring-Matching auf dem
  Reverse-PTR, das False Positives wie `notfacebook.com` erzeugte).
- Die A–F-Note ist eine ordinale Zusammenfassung, keine Messung. Als
  Zeittrend lesen, nicht als absoluter Wert.
