/**
 * Snitch — Electron preload script.
 *
 * EN: Minimal bridge between the sandboxed renderer and the main process.
 *     `contextIsolation` is enabled, so this is the ONLY surface the web
 *     page can see — keep it that way.
 * FR: Pont minimal entre le renderer en sandbox et le processus principal.
 *     `contextIsolation` est activé : c'est la SEULE surface visible par la
 *     page web — gardons-la ainsi.
 */

const { contextBridge } = require('electron')

contextBridge.exposeInMainWorld('snitch', {
  version: process.env.npm_package_version || '1.0.0',
})
