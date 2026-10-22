# Mitwirken

[English](CONTRIBUTING.md) | [Français](CONTRIBUTING.md) | [Español](CONTRIBUTING.es.md) | **Deutsch** | [Русский](CONTRIBUTING.ru.md) | [日本語](CONTRIBUTING.ja.md) | [Português](CONTRIBUTING.pt-BR.md) | [中文](CONTRIBUTING.zh-CN.md)

Danke für dein Interesse! Snitch ist ein zweisprachiges Projekt (EN/FR) —
Code-Kommentare und Nutzertexte sollten wo möglich in beiden Sprachen
vorliegen. Die UI hat 8 Locales in `frontend/src/locales/` — eine neue
Sprache ist eine von `en.js` kopierte Datei (Schlüsselparität beachten)
plus ein Eintrag in `LANGS`/`LANG_NAMES` in `frontend/src/i18n.jsx`.
Übersetzungs-PRs sind sehr willkommen.

**Grundregeln**

- **Lizenzkompatibilität**: neue Abhängigkeiten müssen AGPL-3.0-kompatibel
  sein (MIT, BSD, ISC, Apache-2.0, LGPL). GPL-2.0-only ist ausgeschlossen.
- **Keine ausgehenden Aufrufe**: nie Code hinzufügen, der ohne explizites,
  Opt-in-Einverständnis des Nutzers einen Drittdienst kontaktiert.
- **Zweisprachig**: Docstrings und UI-Strings auf Englisch UND Französisch.
- **Tests**: jeder Bugfix bringt einen Test mit. `pytest backend/tests`
  und `npm test` in `frontend/` müssen bestehen.
- **Fokussierte Diffs** — ein Thema pro PR.

**Dev-Setup**

```bash
cd backend && pip install -r requirements.txt -r requirements-dev.txt
cd frontend && npm install
```

Backend: `python run_backend.py` (benötigt Capture-Privilegien).
Frontend: `npm run dev` → http://localhost:5173/?token=<Token aus der Backend-Ausgabe>.
