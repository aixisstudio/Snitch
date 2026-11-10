// EN: Snitch install — two halves:
//       1. Python backend into backend/env (uv venv, managed by shell.run).
//       2. Frontend build → frontend_dist/ at repo root, which the backend
//          then serves at http://127.0.0.1:<port>/ (single-port app).
//     Everything runs local-only; the only downloads are pip/npm deps.
// FR: Installation de Snitch — deux moitiés :
//       1. Backend Python dans backend/env (venv uv, géré par shell.run).
//       2. Build frontend → frontend_dist/ à la racine, que le backend sert
//          ensuite sur http://127.0.0.1:<port>/ (appli mono-port).
//     Tout reste local ; seuls les paquets pip/npm sont téléchargés.
module.exports = {
  run: [
    {
      // EN: Python deps — venv auto-created at backend/env.
      // FR: Dépendances Python — le venv est créé automatiquement dans backend/env.
      method: "shell.run",
      params: {
        venv: "env",
        // EN: Pin the interpreter — websockets 17.x and the codebase's
        //     `X | None` annotations require Python >= 3.11 (pyproject
        //     requires-python); Pinokio's default may be older.
        // FR: Épingle l'interpréteur — websockets 17.x et les annotations
        //     `X | None` du code exigent Python >= 3.11 (requires-python
        //     du pyproject) ; le défaut Pinokio peut être plus vieux.
        python: "3.12",
        path: "backend",
        message: "uv pip install -r requirements.txt"
      }
    },
    {
      // EN: Frontend deps + production build into frontend/dist.
      // FR: Dépendances frontend + build de production dans frontend/dist.
      method: "shell.run",
      params: {
        path: "frontend",
        message: [
          "npm install",
          "npm run build"
        ]
      }
    },
    {
      // EN: Publish the build where the backend serves it (repo-root
      //     frontend_dist — see backend/api/main.py).
      // FR: Publier le build là où le backend le sert (frontend_dist à la
      //     racine — voir backend/api/main.py).
      method: "fs.copy",
      params: {
        src: "frontend/dist",
        dest: "frontend_dist"
      }
    }
  ]
}
