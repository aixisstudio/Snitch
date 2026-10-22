# Участие в проекте

[English](CONTRIBUTING.md) | [Français](CONTRIBUTING.md) | [Español](CONTRIBUTING.es.md) | [Deutsch](CONTRIBUTING.de.md) | **Русский** | [日本語](CONTRIBUTING.ja.md) | [Português](CONTRIBUTING.pt-BR.md) | [中文](CONTRIBUTING.zh-CN.md)

Спасибо за интерес! Snitch — двуязычный проект (EN/FR): комментарии к коду
и пользовательские тексты должны существовать на обоих языках по
возможности. В UI 8 локалей в `frontend/src/locales/` — новый язык это
файл, скопированный с `en.js` (сохраняйте паритет ключей), плюс запись в
`LANGS`/`LANG_NAMES` в `frontend/src/i18n.jsx`. PR с переводами очень
приветствуются.

**Основные правила**

- **Совместимость лицензий**: новые зависимости должны быть совместимы с
  AGPL-3.0 (MIT, BSD, ISC, Apache-2.0, LGPL). GPL-2.0-only исключена.
- **Никаких исходящих вызовов**: не добавляйте код, обращающийся к сторонним
  сервисам без явного opt-in-согласия пользователя.
- **Двуязычность**: docstrings и UI-строки на английском И французском.
- **Тесты**: каждое исправление идёт с тестом. `pytest backend/tests` и
  `npm test` в `frontend/` должны проходить.
- **Сфокусированные диффы** — одна тема на PR.

**Окружение разработки**

```bash
cd backend && pip install -r requirements.txt -r requirements-dev.txt
cd frontend && npm install
```

Бэкенд: `python run_backend.py` (нужны привилегии захвата).
Фронтенд: `npm run dev` → http://localhost:5173/?token=<токен из вывода бэкенда>.
