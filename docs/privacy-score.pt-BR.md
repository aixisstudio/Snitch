# Privacy Score — Metodologia

[English](privacy-score.md) | [Français](privacy-score.md) | [Español](privacy-score.es.md) | [Deutsch](privacy-score.de.md) | [Русский](privacy-score.ru.md) | [日本語](privacy-score.ja.md) | **Português** | [中文](privacy-score.zh-CN.md)

O score (A–F, no canto superior direito) é calculado em
`frontend/src/scoring/privacy.js` a partir do estado de
nós/arestas/alertas. É uma **heurística**, não uma garantia formal —
documente seu modelo de ameaças antes de confiar na letra.

Entradas e pesos:

| Sinal | Efeito |
|---|---|
| Nós de categoria tracker (domínios ad/analytics conhecidos via DNS/SNI) | −8 pts cada |
| Alertas `critical`/`warning` na janela | −10 / −4 pts cada |
| Parcela de bytes para destinos marcados como tracker | penalidade proporcional |
| Número de hosts remotos distintos | penalidade leve acima de ~30 |
| Parcela de HTTPS (tráfego porta 443) | pequeno bônus |

Limitações conhecidas:

- A correspondência de trackers usa apenas nomes DNS/SNI observados — um
  tracker alcançado por IP puro não casa. É intencional (sem correspondência
  por substring no PTR reverso, que produzia falsos positivos como
  `notfacebook.com`).
- A letra A–F é um resumo ordinal, não uma medição. Leia como tendência
  ao longo do tempo, não como score absoluto.
