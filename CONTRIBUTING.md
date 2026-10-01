# Contributing / Contribuer

## English

Thanks for your interest! Snitch is a bilingual (EN/FR) project — code
comments and user-facing text should exist in both languages where practical.

**Ground rules**

- **License compatibility**: new dependencies must be AGPL-3.0-compatible
  (MIT, BSD, ISC, Apache-2.0, LGPL). GPL-2.0-only is a hard no.
- **No outbound calls**: never add code that contacts a third-party service
  without explicit, opt-in user consent.
- **Bilingual**: docstrings and UI strings in English AND French.
- **Tests**: every bug fix ships a test. `pytest backend/tests` and
  `npm test` in `frontend/` must pass.
- **Keep diffs focused** — one concern per PR.

**Dev setup**

```bash
cd backend && pip install -r requirements.txt -r requirements-dev.txt
cd frontend && npm install
```

Backend: `python run_backend.py` (needs capture privileges).
Frontend: `npm run dev` → http://localhost:5173/?token=<token from backend output>.

## Français

Merci de votre intérêt ! Snitch est un projet bilingue (EN/FR) — les
commentaires de code et les textes utilisateur doivent exister dans les deux
langues autant que possible.

**Règles de base**

- **Compatibilité de licence** : les nouvelles dépendances doivent être
  compatibles AGPL-3.0 (MIT, BSD, ISC, Apache-2.0, LGPL). GPL-2.0-only est
  exclu.
- **Aucun appel sortant** : jamais de code contactant un service tiers sans
  consentement explicite et opt-in de l'utilisateur.
- **Bilingue** : docstrings et chaînes UI en anglais ET en français.
- **Tests** : chaque correction s'accompagne d'un test. `pytest
  backend/tests` et `npm test` dans `frontend/` doivent passer.
- **Diffs ciblées** — un sujet par PR.
