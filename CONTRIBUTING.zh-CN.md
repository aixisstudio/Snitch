# 贡献指南

[English](CONTRIBUTING.md) | [Français](CONTRIBUTING.md) | [Español](CONTRIBUTING.es.md) | [Deutsch](CONTRIBUTING.de.md) | [Русский](CONTRIBUTING.ru.md) | [日本語](CONTRIBUTING.ja.md) | [Português](CONTRIBUTING.pt-BR.md) | **中文**

感谢你的关注！Snitch 是一个双语（EN/FR）项目——代码注释和面向用户的
文本应尽可能同时提供两种语言版本。UI 在 `frontend/src/locales/` 下有
8 个语言包——新增语言只需从 `en.js` 复制一个文件（保持键一致）并在
`frontend/src/i18n.jsx` 的 `LANGS`/`LANG_NAMES` 中添加一项。非常欢迎
翻译 PR。

**基本规则**

- **许可证兼容性**：新依赖必须兼容 AGPL-3.0（MIT、BSD、ISC、
  Apache-2.0、LGPL）。GPL-2.0-only 不接受。
- **禁止对外调用**：未经用户明确的选择性同意，不得添加联系第三方
  服务的代码。
- **双语**：docstring 与 UI 字符串需同时有英文和法文。
- **测试**：每个修复都要附带测试。`pytest backend/tests` 和
  `frontend/` 下的 `npm test` 必须通过。
- **聚焦的 diff**——一个 PR 只处理一个主题。

**开发环境**

```bash
cd backend && pip install -r requirements.txt -r requirements-dev.txt
cd frontend && npm install
```

后端：`python run_backend.py`（需要抓包权限）。
前端：`npm run dev` → http://localhost:5173/?token=<后端输出中的令牌>。
