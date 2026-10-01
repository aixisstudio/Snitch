/**
 * Snitch — Electron preload script.
 *
 * EN: Minimal bridge between the sandboxed renderer and the main process.
 *     `contextIsolation` is enabled, so this is the ONLY surface the web
 *     page can see — keep it that way.
 *     `getToken` lets the renderer authenticate to the backend API without
 *     the token ever appearing in the page, the DOM, or logs.
 * FR: Pont minimal entre le renderer en sandbox et le processus principal.
 *     `contextIsolation` est activé : c'est la SEULE surface visible par la
 *     page web — gardons-la ainsi.
 *     `getToken` permet au renderer de s'authentifier auprès de l'API backend
 *     sans que le jeton apparaisse jamais dans la page, le DOM ou les logs.
 */

const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('snitch', {
  version: process.env.npm_package_version || '1.0.0',
  // EN: Async — resolves to the per-launch API token held by the main process.
  // FR: Asynchrone — résout vers le jeton API par lancement détenu par le processus principal.
  getToken: () => ipcRenderer.invoke('snitch:get-token'),
})
