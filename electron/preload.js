/**
 * Snitch — Electron preload script.
 *
 * EN: Minimal bridge between the sandboxed renderer and the main process.
 *     `contextIsolation` is enabled, so this is the ONLY surface the web
 *     page can see — keep it that way.
 *     `getToken` / `getPort` let the renderer reach the backend API without
 *     the token ever appearing in the page, the DOM, or logs. `getVersion`
 *     resolves via app.getVersion() in the main process — the old
 *     npm_package_version read returned "1.0.0" forever in production.
 * FR: Pont minimal entre le renderer en sandbox et le processus principal.
 *     `contextIsolation` est activé : c'est la SEULE surface visible par la
 *     page web — gardons-la ainsi.
 *     `getToken` / `getPort` permettent au renderer de joindre l'API backend
 *     sans que le jeton apparaisse jamais dans la page, le DOM ou les logs.
 *     `getVersion` se résout via app.getVersion() dans le processus
 *     principal — l'ancienne lecture de npm_package_version renvoyait « 1.0.0 »
 *     pour toujours en production.
 */

const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('snitch', {
  // EN: Async — resolves to the per-launch API token held by the main process.
  // FR: Asynchrone — résout vers le jeton API par lancement détenu par le processus principal.
  getToken:   () => ipcRenderer.invoke('snitch:get-token'),
  // EN: Async — resolves to the free port the backend was spawned on.
  // FR: Asynchrone — résout vers le port libre sur lequel le backend a été lancé.
  getPort:    () => ipcRenderer.invoke('snitch:get-port'),
  // EN: Async — real app version (package.json via app.getVersion()).
  // FR: Asynchrone — vraie version de l'app (package.json via app.getVersion()).
  getVersion: () => ipcRenderer.invoke('snitch:get-version'),
})
