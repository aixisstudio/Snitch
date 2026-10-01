// EN: Update — pull the launcher+app (single repo), refresh Python and npm
//     deps in case they changed, rebuild the frontend and republish
//     frontend_dist so the backend serves the new UI.
// FR: Mise à jour — pull du launcher+app (dépôt unique), rafraîchit les deps
//     Python et npm au cas où, rebuilde le frontend et republie
//     frontend_dist pour que le backend serve la nouvelle UI.
module.exports = {
  run: [
    {
      method: "shell.run",
      params: {
        message: "git pull"
      }
    },
    {
      method: "shell.run",
      params: {
        venv: "env",
        path: "backend",
        message: "uv pip install -r requirements.txt"
      }
    },
    {
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
      method: "fs.copy",
      params: {
        src: "frontend/dist",
        dest: "frontend_dist"
      }
    }
  ]
}
