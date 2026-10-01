/**
 * Snitch — API endpoint helpers.
 *
 * EN: Under Electron the app is loaded from file://, so there is no dev-server
 *     proxy — all backend calls must use the absolute loopback URL.
 *     In dev/browser mode we rely on the Vite proxy and use relative URLs.
 * FR: Sous Electron, l'app est chargée depuis file://, donc pas de proxy de
 *     dev-server — tous les appels backend doivent utiliser l'URL loopback
 *     absolue. En mode dev/navigateur on s'appuie sur le proxy Vite avec des
 *     URL relatives.
 */
const isElectron = window.location.protocol === 'file:'

export const API_BASE = isElectron ? 'http://127.0.0.1:8000' : ''
export const WS_URL   = isElectron
  ? 'ws://127.0.0.1:8000/ws'
  : `ws://${window.location.host}/ws`
