# 貢献ガイド

[English](CONTRIBUTING.md) | [Français](CONTRIBUTING.md) | [Español](CONTRIBUTING.es.md) | [Deutsch](CONTRIBUTING.de.md) | [Русский](CONTRIBUTING.ru.md) | **日本語** | [Português](CONTRIBUTING.pt-BR.md) | [中文](CONTRIBUTING.zh-CN.md)

ご関心ありがとうございます！Snitch はバイリンガル（EN/FR）プロジェクト
です — コードコメントとユーザー向けテキストは可能な限り両言語で用意
します。UI には `frontend/src/locales/` に 8 ロケールがあります —
新しい言語は `en.js` をコピーしたファイル（キーの一致を維持）＋
`frontend/src/i18n.jsx` の `LANGS`/`LANG_NAMES` への 1 エントリで追加
できます。翻訳 PR は大歓迎です。

**基本ルール**

- **ライセンス互換性**: 新しい依存は AGPL-3.0 互換であること
  （MIT、BSD、ISC、Apache-2.0、LGPL）。GPL-2.0-only は不可。
- **外向き呼び出し禁止**: ユーザーの明示的なオプトイン同意なしに
  第三者サービスへ接続するコードは追加しない。
- **バイリンガル**: docstring と UI 文字列は英語 AND フランス語。
- **テスト**: バグ修正には必ずテストを添付。`pytest backend/tests` と
  `frontend/` の `npm test` が通ること。
- **フォーカスした diff** — 1 PR 1 テーマ。

**開発環境**

```bash
cd backend && pip install -r requirements.txt -r requirements-dev.txt
cd frontend && npm install
```

バックエンド: `python run_backend.py`（キャプチャ権限が必要）。
フロントエンド: `npm run dev` → http://localhost:5173/?token=<バックエンド出力のトークン>。
