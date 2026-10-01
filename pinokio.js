// EN: Snitch launcher UI — mirrors the standard Pinokio server pattern:
//     Install → Start (daemon) → "Open Web UI" once local.url is set.
//     install.js creates backend/env (uv venv) and frontend_dist, so the
//     presence of backend/env marks a completed install.
// FR: UI du launcher Snitch — reprend le pattern serveur standard Pinokio :
//     Install → Start (daemon) → « Open Web UI » une fois local.url posée.
//     install.js crée backend/env (venv uv) et frontend_dist, donc la
//     présence de backend/env marque une installation terminée.
module.exports = {
  version: "7.0",
  title: "Snitch",
  description: "Real-time network traffic visualizer — see who your computer talks to. / Visualiseur de trafic réseau en temps réel — voyez à qui parle votre ordinateur.",
  icon: "icon.png",
  menu: async (kernel, info) => {
    let installed = info.exists("backend/env")
    let running = {
      install: info.running("install.js"),
      start: info.running("start.js"),
      update: info.running("update.js"),
      reset: info.running("reset.js")
    }
    if (running.install) {
      return [{
        default: true,
        icon: "fa-solid fa-plug",
        text: "Installing",
        href: "install.js",
      }]
    } else if (installed) {
      if (running.start) {
        let local = info.local("start.js")
        if (local && local.url) {
          return [{
            default: true,
            icon: "fa-solid fa-rocket",
            text: "Open Web UI",
            href: local.url,
          }, {
            icon: 'fa-solid fa-terminal',
            text: "Terminal",
            href: "start.js",
          }]
        } else {
          return [{
            default: true,
            icon: 'fa-solid fa-terminal',
            text: "Terminal",
            href: "start.js",
          }]
        }
      } else if (running.update) {
        return [{
          default: true,
          icon: 'fa-solid fa-terminal',
          text: "Updating",
          href: "update.js",
        }]
      } else if (running.reset) {
        return [{
          default: true,
          icon: 'fa-solid fa-terminal',
          text: "Resetting",
          href: "reset.js",
        }]
      } else {
        return [{
          default: true,
          icon: "fa-solid fa-power-off",
          text: "Start",
          href: "start.js",
        }, {
          icon: "fa-solid fa-plug",
          text: "Update",
          href: "update.js",
        }, {
          icon: "fa-regular fa-circle-xmark",
          text: "Reset",
          href: "reset.js",
        }]
      }
    } else {
      return [{
        default: true,
        icon: "fa-solid fa-plug",
        text: "Install",
        href: "install.js",
      }]
    }
  }
}
