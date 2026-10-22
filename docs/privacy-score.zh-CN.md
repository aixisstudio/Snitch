# Privacy Score —— 方法论

[English](privacy-score.md) | [Français](privacy-score.md) | [Español](privacy-score.es.md) | [Deutsch](privacy-score.de.md) | [Русский](privacy-score.ru.md) | [日本語](privacy-score.ja.md) | [Português](privacy-score.pt-BR.md) | **中文**

评分（A–F，右上角显示）在
`frontend/src/scoring/privacy.js` 中根据节点/边/告警的实时状态计算。
它是**启发式指标**，不是正式保证——在依赖该评级之前请先明确你的
威胁模型。

输入与权重：

| 信号 | 影响 |
|---|---|
| 跟踪器类节点（经 DNS/SNI 观测到的已知广告/分析域名） | 每个 −8 分 |
| 窗口内 `critical`/`warning` 告警 | 每条 −10 / −4 分 |
| 流向被标记为跟踪器的字节占比 | 按比例扣分 |
| 不同远程主机数量 | 超过 ~30 轻微扣分 |
| HTTPS 占比（443 端口流量） | 少量加分 |

已知局限：

- 跟踪器匹配仅依赖观测到的 DNS/SNI 名称——用裸 IP 访问的跟踪器
  不会命中。这是有意为之（不对反向 PTR 做子串匹配，否则会产生
  `notfacebook.com` 这类误报）。
- A–F 评级是序数汇总，不是测量值。请把它当作随时间的趋势指示，
  而非绝对分数。
