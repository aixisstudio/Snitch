# Contribuindo

[English](CONTRIBUTING.md) | [Français](CONTRIBUTING.md) | [Español](CONTRIBUTING.es.md) | [Deutsch](CONTRIBUTING.de.md) | [Русский](CONTRIBUTING.ru.md) | [日本語](CONTRIBUTING.ja.md) | **Português** | [中文](CONTRIBUTING.zh-CN.md)

Obrigado pelo interesse! Snitch é um projeto bilíngue (EN/FR) — comentários
de código e textos de usuário devem existir nos dois idiomas sempre que
possível. A UI tem 8 locales em `frontend/src/locales/` — um novo idioma é
um arquivo copiado de `en.js` (mantendo a paridade de chaves) mais uma
entrada em `LANGS`/`LANG_NAMES` no `frontend/src/i18n.jsx`. PRs de
tradução são muito bem-vindos.

**Regras básicas**

- **Compatibilidade de licença**: novas dependências devem ser compatíveis
  com AGPL-3.0 (MIT, BSD, ISC, Apache-2.0, LGPL). GPL-2.0-only é excluída.
- **Nenhuma chamada externa**: nunca adicione código que contate serviços
  de terceiros sem consentimento explícito e opt-in do usuário.
- **Bilíngue**: docstrings e strings de UI em inglês E francês.
- **Testes**: toda correção vem com um teste. `pytest backend/tests` e
  `npm test` em `frontend/` devem passar.
- **Diffs focados** — um assunto por PR.

**Ambiente de desenvolvimento**

```bash
cd backend && pip install -r requirements.txt -r requirements-dev.txt
cd frontend && npm install
```

Backend: `python run_backend.py` (precisa de privilégios de captura).
Frontend: `npm run dev` → http://localhost:5173/?token=<token da saída do backend>.
