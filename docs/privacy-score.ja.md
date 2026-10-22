# Privacy Score — 方法論

[English](privacy-score.md) | [Français](privacy-score.md) | [Español](privacy-score.es.md) | [Deutsch](privacy-score.de.md) | [Русский](privacy-score.ru.md) | **日本語** | [Português](privacy-score.pt-BR.md) | [中文](privacy-score.zh-CN.md)

スコア（A–F、右上に表示）は
`frontend/src/scoring/privacy.js` でノード/エッジ/アラートのライブ状態
から計算される。これは**ヒューリスティック**であり正式な保証ではない
— 評価に頼る前に脅威モデルを文書化してほしい。

入力と重み:

| シグナル | 効果 |
|---|---|
| トラッカーカテゴリのノード（DNS/SNI で観測される既知 ad/analytics ドメイン） | 各 −8 pt |
| ウィンドウ内の `critical`/`warning` アラート | 各 −10 / −4 pt |
| トラッカー判定宛先へのバイト割合 | 比例的ペナルティ |
| 相異なるリモートホスト数 | ~30 超で軽いペナルティ |
| HTTPS 割合（ポート 443 トラフィック） | 小さなボーナス |

既知の限界:

- トラッカーのマッチは観測された DNS/SNI 名のみに依存 — 素の IP で
  到達したトラッカーはマッチしない。これは意図的（逆引き PTR への
  部分一致は `notfacebook.com` のような誤検出を生んだため）。
- A–F の評価は序数的な要約であって測定値ではない。絶対スコアではなく
  時系列のトレンドとして読むこと。
