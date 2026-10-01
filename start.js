// EN: Snitch start — launches backend/cli.py which picks the port given via
//     --port, prints the full token URL on one line
//     ("http://127.0.0.1:<port>/?token=<hex>"), then serves API + built UI.
//
//     Packet capture needs elevated privileges, so on macOS/Linux the
//     interpreter runs through sudo (Pinokio's `sudo: true` prefixes the
//     command). argv flags are used instead of env vars because sudo strips
//     the environment. env/bin/python is called explicitly for the same
//     reason — sudo resets PATH and would lose the venv.
//     On Windows there is no sudo — run Pinokio as Administrator (Npcap
//     required) for capture; the UI still works without it.
//
// FR: Démarrage de Snitch — lance backend/cli.py qui prend le port via
//     --port, affiche l'URL complète avec jeton sur une ligne
//     (« http://127.0.0.1:<port>/?token=<hex> »), puis sert API + UI buildée.
//
//     La capture de paquets exige des privilèges élevés : sur macOS/Linux
//     l'interpréteur passe par sudo (`sudo: true` préfixe la commande). On
//     utilise les flags argv plutôt que des variables d'env car sudo purge
//     l'environnement. env/bin/python est appelé explicitement pour la même
//     raison — sudo réinitialise PATH et perdrait le venv.
//     Sous Windows pas de sudo — lancer Pinokio en Administrateur (Npcap
//     requis) pour la capture ; l'UI fonctionne quand même sans.
module.exports = {
  daemon: true,
  run: [
    {
      when: "{{platform !== 'win32'}}",
      method: "shell.run",
      params: {
        sudo: true,
        path: "backend",
        message: "env/bin/python cli.py --port {{port}} --no-browser",
        on: [{
          // EN: cli.py prints the full authenticated URL on one line.
          // FR: cli.py affiche l'URL authentifiée complète sur une ligne.
          "event": "/(http:\\/\\/[0-9.:]+\\/\\?token=[0-9a-f]+)/",
          "done": true
        }]
      }
    },
    {
      when: "{{platform === 'win32'}}",
      method: "shell.run",
      params: {
        path: "backend",
        message: "env\\Scripts\\python.exe cli.py --port {{port}} --no-browser",
        on: [{
          "event": "/(http:\\/\\/[0-9.:]+\\/\\?token=[0-9a-f]+)/",
          "done": true
        }]
      }
    },
    {
      method: "local.set",
      params: {
        url: "{{input.event[1]}}"
      }
    }
  ]
}
