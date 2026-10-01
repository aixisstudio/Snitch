/**
 * Snitch — API endpoint helpers + auth token plumbing.
 *
 * EN: Under Electron the app is loaded from file://, so there is no dev-server
 *     proxy — all backend calls use the absolute loopback URL.
 *     In dev/browser mode we rely on the Vite proxy and relative URLs.
 *
 *     AUTH: every request needs the API token. Resolution order:
 *       1. window.snitch.getToken()  — Electron preload bridge (IPC)
 *       2. ?token= URL param         — Docker/browser first open
 *       3. sessionStorage            — survives reloads in the same tab
 *       4. window.prompt()           — last-resort manual entry
 *     The resolved promise is cached — only ONE prompt can ever appear.
 *
 * FR: Sous Electron, l'app est chargée depuis file://, donc pas de proxy de
 *     dev-server — tous les appels backend utilisent l'URL loopback absolue.
 *     En mode dev/navigateur on s'appuie sur le proxy Vite avec des URL
 *     relatives.
 *
 *     AUTH : chaque requête exige le jeton API. Ordre de résolution :
 *       1. window.snitch.getToken()  — pont preload Electron (IPC)
 *       2. paramètre ?token= d'URL   — première ouverture Docker/navigateur
 *       3. sessionStorage            — survit aux rechargements de l'onglet
 *       4. window.prompt()           — saisie manuelle en dernier recours
 *     La promesse résolue est mise en cache — une SEULE invite peut apparaître.
 */
const isElectron = window.location.protocol === 'file:'

export const API_BASE = isElectron ? 'http://127.0.0.1:8000' : ''
export const WS_URL   = isElectron
  ? 'ws://127.0.0.1:8000/ws'
  : `ws://${window.location.host}/ws`

let _tokenPromise = null

/**
 * EN: Resolve the API token once — see module docstring for the order.
 * FR: Résoudre le jeton API une fois — voir le docstring du module pour
 *     l'ordre.
 */
export function getToken() {
  if (_tokenPromise) return _tokenPromise
  _tokenPromise = (async () => {
    // EN: Electron — the token never touches the URL or the DOM.
    // FR: Electron — le jeton ne touche jamais l'URL ni le DOM.
    if (window.snitch?.getToken) {
      return await window.snitch.getToken()
    }
    const fromUrl = new URLSearchParams(window.location.search).get('token')
    if (fromUrl) {
      sessionStorage.setItem('snitch_token', fromUrl)
      return fromUrl
    }
    const stored = sessionStorage.getItem('snitch_token')
    if (stored) return stored
    const manual = window.prompt('Snitch API token / Jeton API Snitch :')
    if (manual) {
      const t = manual.trim()
      sessionStorage.setItem('snitch_token', t)
      return t
    }
    return null
  })()
  return _tokenPromise
}

/**
 * EN: Headers for an authenticated fetch — merges X-Snitch-Token into `extra`.
 * FR: En-têtes pour un fetch authentifié — fusionne X-Snitch-Token dans `extra`.
 */
export async function authHeaders(extra = {}) {
  const token = await getToken()
  return token ? { ...extra, 'X-Snitch-Token': token } : extra
}

/**
 * EN: WebSocket URL with the token as a query param — the browser WS API
 *     can't set headers, so ?token= is the transport.
 * FR: URL WebSocket avec le jeton en paramètre de requête — l'API WS du
 *     navigateur ne peut pas poser d'en-têtes, donc ?token= fait le transport.
 */
export async function wsUrlWithToken(base) {
  const token = await getToken()
  return token ? `${base}?token=${encodeURIComponent(token)}` : base
}
