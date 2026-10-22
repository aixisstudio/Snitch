# Contribuir

[English](CONTRIBUTING.md) | [Français](CONTRIBUTING.md) | **Español** | [Deutsch](CONTRIBUTING.de.md) | [Русский](CONTRIBUTING.ru.md) | [日本語](CONTRIBUTING.ja.md) | [Português](CONTRIBUTING.pt-BR.md) | [中文](CONTRIBUTING.zh-CN.md)

¡Gracias por tu interés! Snitch es un proyecto bilingüe (EN/FR): los
comentarios del código y los textos de usuario deben existir en ambos
idiomas siempre que sea posible. La UI tiene 8 locales en
`frontend/src/locales/` — un idioma nuevo = un archivo copiado de `en.js`
(mantén la paridad de claves) más una entrada en `LANGS`/`LANG_NAMES` de
`frontend/src/i18n.jsx`. Las PR de traducción son muy bienvenidas.

**Reglas básicas**

- **Compatibilidad de licencia**: las nuevas dependencias deben ser
  compatibles con AGPL-3.0 (MIT, BSD, ISC, Apache-2.0, LGPL). GPL-2.0-only
  queda excluida.
- **Ninguna llamada externa**: nunca añadas código que contacte un servicio
  de terceros sin consentimiento explícito y opt-in del usuario.
- **Bilingüe**: docstrings y cadenas de UI en inglés Y en francés.
- **Tests**: cada corrección incluye un test. Deben pasar `pytest
  backend/tests` y `npm test` en `frontend/`.
- **Diffs enfocados** — un tema por PR.

**Entorno de desarrollo**

```bash
cd backend && pip install -r requirements.txt -r requirements-dev.txt
cd frontend && npm install
```

Backend: `python run_backend.py` (requiere privilegios de captura).
Frontend: `npm run dev` → http://localhost:5173/?token=<token de la salida del backend>.
