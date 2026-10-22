# Privacy Score — Metodología

[English](privacy-score.md) | [Français](privacy-score.md) | **Español** | [Deutsch](privacy-score.de.md) | [Русский](privacy-score.ru.md) | [日本語](privacy-score.ja.md) | [Português](privacy-score.pt-BR.md) | [中文](privacy-score.zh-CN.md)

El score (A–F, arriba a la derecha) se calcula en
`frontend/src/scoring/privacy.js` a partir del estado de
nodos/aristas/alertas. Es una **heurística**, no una garantía formal —
documenta tu modelo de amenazas antes de fiarte de la letra.

Entradas y pesos:

| Señal | Efecto |
|---|---|
| Nodos de categoría tracker (dominios ad/analytics conocidos vía DNS/SNI) | −8 pts c/u |
| Alertas `critical`/`warning` en la ventana | −10 / −4 pts c/u |
| Proporción de bytes hacia destinos marcados como tracker | penalización proporcional |
| Número de hosts remotos distintos | penalización leve por encima de ~30 |
| Proporción de HTTPS (tráfico puerto 443) | pequeño bonus |

Limitaciones conocidas:

- La detección de trackers solo usa nombres DNS/SNI observados — un tracker
  alcanzado por IP directa no casa. Es intencional (sin coincidencia por
  subcadena sobre el PTR inverso, que producía falsos positivos tipo
  `notfacebook.com`).
- La letra A–F es un resumen ordinal, no una medida. Léela como tendencia
  en el tiempo, no como score absoluto.
