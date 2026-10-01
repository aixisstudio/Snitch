// EN: Reset — removes everything install.js created plus runtime state:
//     the uv venv, node_modules, frontend build outputs, the served bundle,
//     and the local data dir (SQLite DB, API token, extracted geo DBs, logs).
//     After reset, the menu falls back to "Install" automatically.
// FR: Réinitialisation — supprime tout ce qu'install.js a créé plus l'état
//     d'exécution : le venv uv, node_modules, les builds frontend, le bundle
//     servi, et le dossier de données local (BDD SQLite, jeton API, bases
//     géo extraites, logs). Ensuite le menu repasse sur « Install ».
module.exports = {
  run: [
    {
      method: "fs.rm",
      params: { path: "backend/env" }
    },
    {
      method: "fs.rm",
      params: { path: "frontend/node_modules" }
    },
    {
      method: "fs.rm",
      params: { path: "frontend/dist" }
    },
    {
      method: "fs.rm",
      params: { path: "frontend_dist" }
    },
    {
      method: "fs.rm",
      params: { path: "data" }
    }
  ]
}
