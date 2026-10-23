/**
 * Snitch — Electron main process.
 *
 * EN: Orchestrates the desktop app:
 *       1. check for Npcap (Windows only, needed for raw capture) — NOT
 *          bundled: the free Npcap license forbids external redistribution,
 *          so we guide the user to npcap.com instead
 *       2. show a splash screen
 *       3. pick a FREE loopback port, generate a per-launch API token
 *          (crypto-random) and spawn the PyInstaller backend with
 *          SNITCH_PORT + SNITCH_TOKEN in its environment
 *       4. wait for the API to answer, then open the main window
 *       5. kill only OUR backend child on quit — never a port sweep
 *
 *     Token + port reach the renderer ONLY via the preload bridge
 *     (ipcMain.handle → window.snitch.getToken() / getPort()) — never in the
 *     page, the URL, or logs.
 *
 *     Why the free port: the old code bound a fixed :8000 and ran a netstat
 *     sweep that matched ANY line containing ":8000" — including outbound
 *     connections to a remote port 8000 — and taskkilled innocent processes.
 *     A random port + killing only our own child removes that whole class.
 *
 * FR: Orchestre l'application bureau :
 *       1. vérifier Npcap (Windows uniquement, requis pour la capture brute)
 *          — NON embarqué : la licence gratuite de Npcap interdit la
 *          redistribution externe, donc on guide vers npcap.com
 *       2. afficher un écran de démarrage
 *       3. choisir un port loopback LIBRE, générer un jeton API par lancement
 *          (crypto-aléatoire) et lancer le backend PyInstaller avec
 *          SNITCH_PORT + SNITCH_TOKEN dans son environnement
 *       4. attendre que l'API réponde, puis ouvrir la fenêtre principale
 *       5. tuer uniquement NOTRE enfant backend à la fermeture — jamais de
 *          balayage de port
 *
 *     Jeton + port arrivent au renderer UNIQUEMENT via le pont preload
 *     (ipcMain.handle → window.snitch.getToken() / getPort()) — jamais dans
 *     la page, l'URL ou les logs.
 *
 *     Pourquoi le port libre : l'ancien code fixait :8000 et lançait un
 *     netstat qui retenait TOUTE ligne contenant « :8000 » — y compris les
 *     connexions sortantes vers un port distant 8000 — et taskkill tuait des
 *     processus innocents. Un port aléatoire + tuer seulement notre enfant
 *     supprime toute cette classe de bug.
 */

const _electron        = require('electron')
const { app, BrowserWindow, dialog, ipcMain, shell, Tray, Menu } = _electron.default || _electron
const { spawn, execSync }            = require('child_process')
const crypto = require('crypto')
const path = require('path')
const http = require('http')
const net  = require('net')
const fs   = require('fs')

// ── Paths / Chemins ──────────────────────────────────────────────────────────
// EN: In dev, resources resolve against the repo root; in packaged builds they
//     live inside process.resourcesPath.
// FR: En dev, les ressources sont résolues depuis la racine du dépôt ; en build
//     packagé elles vivent dans process.resourcesPath.
const isDev        = !app.isPackaged
const resourcesDir = isDev ? path.join(__dirname, '..') : process.resourcesPath

const isWindows = process.platform === 'win32'
const backendName = isWindows ? 'snitch-backend.exe' : 'snitch-backend'
// EN: ONEDIR PyInstaller layout — the exe lives inside a snitch-backend/ dir.
// FR: Layout ONEDIR de PyInstaller — l'exe vit dans un dossier snitch-backend/.
const backendExe = isDev
  ? path.join(resourcesDir, 'dist', 'backend', 'snitch-backend', backendName)
  : path.join(resourcesDir, 'snitch-backend', backendName)

const frontendDist   = isDev
  ? path.join(resourcesDir, 'frontend', 'dist')
  : path.join(resourcesDir, 'frontend_dist')

const iconPath = isDev
  ? path.join(__dirname, 'icon.png')
  : path.join(resourcesDir, 'icon.png')

// EN: Log dir = the backend's own data dir (LOCALAPPDATA\Snitch on Windows,
//     etc.) so "Open logs" and the /diagnostics log_tail read the SAME file
//     the backend writes to — even when the backend runs elevated and gets
//     no SNITCH_USER_DATA env (frozen builds resolve the platform dir).
// FR: Dossier de logs = le dossier de données du backend lui-même
//     (LOCALAPPDATA\Snitch sous Windows, etc.) pour que « Ouvrir les logs »
//     et le log_tail de /diagnostics lisent le MÊME fichier que celui écrit
//     par le backend — même quand il tourne élevé et ne reçoit pas
//     SNITCH_USER_DATA (les builds figés résolvent le dossier plateforme).
// EN: backendDataDir() is hoisted (function declaration below) — safe to
//     call here at module level.
// FR: backendDataDir() est hissée (déclaration de fonction plus bas) —
//     appelable ici au niveau module.
const logDir  = path.join(backendDataDir(), 'logs')
const logFile = path.join(logDir, 'backend.log')

// EN: Tiny main-process logger — appends to backend.log next to the backend's
//     own output so update errors land where "Open logs" points.
// FR: Mini-logger du processus principal — ajoute dans backend.log à côté de
//     la sortie du backend, pour que les erreurs de mise à jour arrivent là
//     où « Ouvrir les logs » pointe.
const log = {
  warn: (...args) => {
    const line = `[main] ${args.join(' ')}`
    try { fs.appendFileSync(logFile, `${new Date().toISOString()} ${line}\n`) } catch { /* log dir not writable yet */ }
    console.warn(line)
  },
}

let mainWindow   = null
let splashWindow = null
let backendProc  = null
let tray         = null
let backendPort  = 0            // EN: chosen at launch / FR: choisi au lancement
let isQuitting   = false
let backendElevated = false     // EN: Elevated spawn (RunAs/osascript/pkexec)
                                //     — we can't kill it, /shutdown is the
                                //     exit path.
                                // FR: Spawn élevé (RunAs/osascript/pkexec) —
                                //     impossible à tuer, /shutdown est le
                                //     chemin d'arrêt.

// ── API token + port / Jeton API + port ─────────────────────────────────────
// EN: 48-hex-char secret generated once per app launch. Passed to the backend
//     via SNITCH_TOKEN and served to the renderer through ipcMain — the web
//     page can only obtain it via the preload bridge.
// FR: Secret hexadécimal de 48 caractères généré une fois par lancement.
//     Transmis au backend via SNITCH_TOKEN et servi au renderer via ipcMain —
//     la page web ne peut l'obtenir que par le pont preload.
const API_TOKEN = crypto.randomBytes(24).toString('hex')

// EN: IPC handlers — the ONLY way the renderer learns token/port/version.
// FR: Handlers IPC — la SEULE façon pour le renderer d'apprendre jeton/port/version.
ipcMain.handle('snitch:get-token',   () => API_TOKEN)
ipcMain.handle('snitch:get-port',    () => backendPort)
ipcMain.handle('snitch:get-version', () => app.getVersion())
// EN: "Open logs" — opens the platform log dir in the file manager. Returns
//     a non-empty error string on failure (shell.openPath contract).
// FR: « Ouvrir les logs » — ouvre le dossier de logs dans le gestionnaire de
//     fichiers. Renvoie une chaîne d'erreur non vide en cas d'échec
//     (contrat de shell.openPath).
ipcMain.handle('snitch:open-logs', () => shell.openPath(logDir))

// EN: "Launch at login" toggle — app.setLoginItemSettings is cross-platform
//     (Windows registry Run key, macOS login items); a no-op on Linux where
//     the API doesn't apply. The renderer reads the state with the same IPC.
// FR: Bascule « lancer au démarrage » — app.setLoginItemSettings est
//     multi-OS (clé Run Windows, login items macOS) ; sans effet sous Linux
//     où l'API ne s'applique pas. Le renderer lit l'état via le même IPC.
ipcMain.handle('snitch:get-auto-launch', () =>
  process.platform === 'linux' ? false : app.getLoginItemSettings().openAtLogin)
ipcMain.handle('snitch:set-auto-launch', (_evt, enabled) => {
  if (process.platform === 'linux') return false
  app.setLoginItemSettings({ openAtLogin: !!enabled })
  return app.getLoginItemSettings().openAtLogin
})

// ── Auto-update / Mise à jour automatique ────────────────────────────────────
// EN: electron-updater against the public GitHub Releases feed
//     (latest.yml / latest-mac.yml / latest-linux.yml are already published
//     by CI). Privacy note: checking for updates is an OUTBOUND call to
//     github.com — it is on by default but can be disabled in Settings,
//     persisted in userData/update-prefs.json, or killed wholesale via
//     SNITCH_NO_UPDATE=1. Never runs in unpackaged dev builds.
// FR: electron-updater sur le flux GitHub Releases public
//     (latest.yml / latest-mac.yml / latest-linux.yml déjà publiés par la
//     CI). Note vie privée : la vérification de mise à jour est un appel
//     SORTANT vers github.com — activée par défaut mais désactivable dans
//     les Réglages, persistée dans userData/update-prefs.json, ou coupée
//     entièrement via SNITCH_NO_UPDATE=1. Jamais en dev non empaqueté.
let autoUpdater = null
let updateStatus = { state: 'idle' }   // EN: idle|checking|available|downloading|downloaded|none|error|dev
const updatePrefsPath = path.join(app.getPath('userData'), 'update-prefs.json')

function updateCheckEnabled() {
  if (process.env.SNITCH_NO_UPDATE) return false
  try {
    return JSON.parse(fs.readFileSync(updatePrefsPath, 'utf8')).enabled !== false
  } catch { return true }   // EN: default on / FR: activé par défaut
}

function setUpdateCheckEnabled(enabled) {
  try {
    fs.writeFileSync(updatePrefsPath, JSON.stringify({ enabled: !!enabled }))
  } catch (e) { log.warn('update prefs write failed:', e.message) }
  rebuildTrayMenu()
}

function reportUpdate(state, extra = {}) {
  updateStatus = { state, ...extra }
  // EN: Forward to the renderer (Settings panel shows it) — guarded, the
  //     window may not exist yet when the first check fires.
  // FR: Relayer au renderer (le panneau Réglages l'affiche) — protégé, la
  //     fenêtre peut ne pas encore exister au premier contrôle.
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('snitch:update-status', updateStatus)
  }
  rebuildTrayMenu()
}

function initAutoUpdater() {
  try {
    ({ autoUpdater } = require('electron-updater'))
  } catch {
    log.warn('electron-updater not bundled — update checks disabled')
    return
  }
  autoUpdater.autoDownload = true        // EN: download in background / FR: télécharger en tâche de fond
  autoUpdater.autoInstallOnAppQuit = true
  autoUpdater.on('checking-for-update', () => reportUpdate('checking'))
  autoUpdater.on('update-available', (info) => reportUpdate('available', { version: info.version }))
  autoUpdater.on('update-not-available', () => reportUpdate('none'))
  autoUpdater.on('download-progress', (p) => reportUpdate('downloading', { percent: Math.round(p.percent) }))
  autoUpdater.on('update-downloaded', (info) => reportUpdate('downloaded', { version: info.version }))
  autoUpdater.on('error', (err) => {
    log.warn('auto-update error:', err.message)
    reportUpdate('error', { message: err.message })
  })
}

function checkForUpdates(manual = false) {
  if (!autoUpdater || !app.isPackaged) {
    // EN: Dev builds have no update feed — don't pretend to check.
    // FR: Les builds dev n'ont pas de flux de mise à jour — ne pas faire semblant.
    if (manual) reportUpdate('dev')
    return
  }
  if (!manual && !updateCheckEnabled()) return
  autoUpdater.checkForUpdates().catch(err => {
    log.warn('update check failed:', err.message)
    reportUpdate('error', { message: err.message })
  })
}

ipcMain.handle('snitch:get-update-status', () => updateStatus)
ipcMain.handle('snitch:get-update-check', () => updateCheckEnabled())
ipcMain.handle('snitch:set-update-check', (_e, on) => { setUpdateCheckEnabled(on); return on })
ipcMain.handle('snitch:check-updates', () => { checkForUpdates(true); return updateStatus })
ipcMain.handle('snitch:install-update', () => {
  if (autoUpdater && updateStatus.state === 'downloaded') autoUpdater.quitAndInstall()
})

/**
 * EN: Find a free loopback port by binding :0 and releasing — the backend
 *     then binds the same number. A tiny race window remains (another
 *     process could grab it between release and bind); waitForBackend's
 *     timeout surfaces it instead of silently stealing someone else's port.
 * FR: Trouver un port loopback libre en liant :0 puis en relâchant — le
 *     backend lie ensuite le même numéro. Une minuscule fenêtre de course
 *     subsiste (un autre processus pourrait le prendre entre relâche et
 *     bind) ; le timeout de waitForBackend la fait surface plutôt que de
 *     voler silencieusement le port d'un autre.
 */
function findFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address()
      srv.close(() => resolve(port))
    })
    srv.on('error', reject)
  })
}

// ── Npcap ────────────────────────────────────────────────────────────────────
/**
 * EN: Npcap is the Windows packet-capture driver libpcap needs. Detected via
 *     its DLL presence in System32\Npcap — NOT its registry keys, and NOT a
 *     bundled installer (which the free license forbids redistributing).
 * FR: Npcap est le pilote de capture Windows requis par libpcap. Détecté via
 *     la présence de sa DLL dans System32\Npcap — PAS via ses clés de
 *     registre, et PAS via un installateur embarqué (que la licence gratuite
 *     interdit de redistribuer).
 */
function isNpcapInstalled() {
  try {
    const sysRoot = process.env.SystemRoot || 'C:\\Windows'
    return fs.existsSync(path.join(sysRoot, 'System32', 'Npcap', 'wpcap.dll'))
  } catch { return false }
}

/**
 * EN: Offer to open npcap.com in the user's browser. There is intentionally
 *     NO silent install — the free installer has no silent mode, and bundling
 *     it is a license violation.
 * FR: Proposer d'ouvrir npcap.com dans le navigateur. AUCUNE installation
 *     silencieuse — l'installateur gratuit n'a pas de mode silencieux, et
 *     l'embarquer violerait la licence.
 */
async function offerNpcapDownload() {
  const choice = await dialog.showMessageBox({
    type: 'info', title: 'Snitch — Npcap required / Npcap requis',
    message: 'Snitch needs Npcap to capture network traffic on Windows.\n' +
             'Snitch a besoin de Npcap pour capturer le trafic réseau sous Windows.\n\n' +
             'Download it free from npcap.com, install it, then restart Snitch.\n' +
             'Téléchargez-le gratuitement sur npcap.com, installez-le, puis relancez Snitch.',
    buttons: ['Open npcap.com / Ouvrir npcap.com', 'Quit / Quitter'], defaultId: 0,
  })
  if (choice.response === 0) {
    await shell.openExternal('https://npcap.com')
  }
  app.quit()
}

// ── Windows / Fenêtres ───────────────────────────────────────────────────────
/**
 * EN: The splash is always-on-top — drop it below dialogs, otherwise it hides
 *     the very error the user needs to read.
 * FR: Le splash est toujours au premier plan — le passer sous les dialogues,
 *     sinon il masque justement l'erreur que l'utilisateur doit lire.
 */
function lowerSplash() {
  if (splashWindow && !splashWindow.isDestroyed()) {
    splashWindow.setAlwaysOnTop(false)
    splashWindow.hide()
  }
}

/** EN: Bring the splash back after a dialog (retry path).
 *  FR: Réafficher le splash après un dialogue (chemin « réessayer »). */
function raiseSplash() {
  if (splashWindow && !splashWindow.isDestroyed()) {
    splashWindow.setAlwaysOnTop(true)
    splashWindow.show()
  }
}

function createSplash() {
  /** EN: Frameless transparent splash shown while the backend boots.
   *  FR: Splash sans cadre et transparent affiché pendant le démarrage du backend. */
  splashWindow = new BrowserWindow({
    width: 380, height: 310, frame: false,
    resizable: false, alwaysOnTop: true, center: true,
    transparent: true, icon: iconPath,
    webPreferences: { nodeIntegration: false, sandbox: true },
  })
  splashWindow.loadFile(path.join(__dirname, 'splash.html'))
}

function createMain() {
  /** EN: Main window — loads the Vite dev server in dev, or the compiled
   *      frontend otherwise. Sandbox on: the preload only needs ipcRenderer.
   *  FR: Fenêtre principale — charge le serveur de dev Vite en dev, ou le
   *      frontend compilé sinon. Sandbox activé : le preload n'a besoin que
   *      d'ipcRenderer. */
  mainWindow = new BrowserWindow({
    width: 1400, height: 860, minWidth: 900, minHeight: 600,
    show: false, title: 'Snitch', backgroundColor: '#000000',
    icon: iconPath,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true, nodeIntegration: false, sandbox: true,
    },
  })

  if (isDev && process.env.VITE_DEV === '1') {
    mainWindow.loadURL('http://localhost:5173')
    mainWindow.webContents.openDevTools()
  } else {
    mainWindow.loadFile(path.join(frontendDist, 'index.html'))
  }

  mainWindow.once('ready-to-show', () => {
    if (splashWindow) { splashWindow.destroy(); splashWindow = null }
    mainWindow.show()
    mainWindow.focus()
  })

  // EN: Minimize to tray instead of quitting — a network monitor is meant
  //     to keep watching. Real exit happens via the tray menu's Quit item.
  // FR: Réduire dans la zone de notification au lieu de quitter — un
  //     moniteur réseau est fait pour continuer à observer. La vraie sortie
  //     passe par l'entrée Quitter du menu de la zone de notification.
  mainWindow.on('close', (e) => {
    if (!isQuitting && tray) {
      e.preventDefault()
      mainWindow.hide()
    }
  })
  mainWindow.on('closed', () => { mainWindow = null })
}

/**
 * EN: System tray — bilingual menu with Show / Open logs / Quit. The icon
 *     is the generated 512px PNG; Electron scales it per platform.
 * FR: Zone de notification — menu bilingue Afficher / Ouvrir les logs /
 *     Quitter. L'icône est le PNG 512 px généré ; Electron l'adapte selon
 *     la plateforme.
 */
function rebuildTrayMenu() {
  if (!tray) return
  const items = [
    {
      label: 'Show Snitch / Afficher Snitch',
      click: () => { if (mainWindow) { mainWindow.show(); mainWindow.focus() } },
    },
  ]
  // EN: Update entries reflect live state — "restart to update" once the
  //     new version is staged, "check now" otherwise.
  // FR: Les entrées de mise à jour reflètent l'état courant — « redémarrer
  //     pour mettre à jour » une fois la version prête, « vérifier » sinon.
  if (updateStatus.state === 'downloaded') {
    items.push({
      label: `Restart to update to v${updateStatus.version} / Redémarrer pour v${updateStatus.version}`,
      click: () => autoUpdater && autoUpdater.quitAndInstall(),
    })
  } else if (updateStatus.state === 'downloading') {
    items.push({ label: `Downloading update… ${updateStatus.percent ?? 0}% / Téléchargement…`, enabled: false })
  } else if (app.isPackaged) {
    items.push({
      label: 'Check for updates / Vérifier les mises à jour',
      click: () => checkForUpdates(true),
    })
  }
  items.push(
    {
      label: 'Open logs / Ouvrir les logs',
      click: () => shell.openPath(logDir),
    },
    { type: 'separator' },
    {
      label: 'Quit / Quitter',
      click: () => { isQuitting = true; app.quit() },
    },
  )
  tray.setContextMenu(Menu.buildFromTemplate(items))
}

function createTray() {
  tray = new Tray(iconPath)
  tray.setToolTip('Snitch')
  rebuildTrayMenu()
  // EN: A plain click (Windows/Linux) or double-click restores the window.
  // FR: Un simple clic (Windows/Linux) ou double-clic restaure la fenêtre.
  tray.on('click', () => { if (mainWindow) { mainWindow.show(); mainWindow.focus() } })
}

// ── Backend process / Processus backend ──────────────────────────────────────
/**
 * EN: Poll the REST API until it answers or we run out of attempts. The
 *     token is sent so we get a real 200 rather than a 401.
 * FR: Interroger l'API REST jusqu'à réponse ou épuisement des essais. Le jeton
 *     est envoyé pour obtenir un vrai 200 plutôt qu'un 401.
 */
function waitForBackend(maxAttempts = 40) {
  return new Promise((resolve, reject) => {
    let n = 0
    function poll() {
      const req = http.request(
        `http://127.0.0.1:${backendPort}/graph`,
        { headers: { 'X-Snitch-Token': API_TOKEN } },
        res => { res.resume(); res.statusCode === 200 ? resolve() : retry() }
      )
      req.on('error', retry)
      req.end()
    }
    function retry() {
      if (++n >= maxAttempts) reject(new Error('Backend timeout'))
      else setTimeout(poll, 1000)
    }
    poll()
  })
}

/**
 * EN: Kill ONLY our own backend child — `taskkill /F /T` takes the whole
 *     process tree on Windows, POSIX kills the detached process group. No
 *     netstat port sweep: with a random port there is no zombie-port problem
 *     to clean up, and sweeping by port number was what killed unrelated
 *     processes.
 * FR: Tuer UNIQUEMENT notre enfant backend — `taskkill /F /T` prend tout
 *     l'arbre sous Windows, POSIX tue le groupe détaché. Pas de balayage
 *     netstat : avec un port aléatoire il n'y a plus de zombie à nettoyer, et
 *     le balayage par numéro de port était ce qui tuait des processus
 *     innocents.
 */
function killBackend() {
  if (backendProc) {
    try {
      if (isWindows) {
        execSync(`taskkill /PID ${backendProc.pid} /T /F`, { stdio: 'pipe' })
      } else {
        process.kill(-backendProc.pid, 'SIGKILL')  // EN: kill the process group
      }                                          // FR: tuer le groupe de processus
    } catch {
      try { backendProc.kill('SIGKILL') } catch {}
    }
    backendProc = null
  }
}

/**
 * EN: The writable dir the FROZEN backend resolves on each platform —
 *     mirrors paths.py so the token file we drop lands where it looks.
 *     Windows: %LOCALAPPDATA%\Snitch. macOS: ~/Library/Application Support/Snitch.
 *     Linux: $XDG_DATA_HOME/snitch or ~/.local/share/snitch.
 * FR: Le dossier inscriptible que le backend FIGÉ résout sur chaque
 *     plateforme — reflète paths.py pour que le fichier de jeton qu'on
 *     dépose atterrisse là où il le cherche.
 */
function backendDataDir() {
  if (isWindows) return path.join(process.env.LOCALAPPDATA || path.join(app.getPath('home'), 'AppData', 'Local'), 'Snitch')
  if (process.platform === 'darwin') return path.join(app.getPath('home'), 'Library', 'Application Support', 'Snitch')
  return path.join(process.env.XDG_DATA_HOME || path.join(app.getPath('home'), '.local', 'share'), 'snitch')
}

/**
 * EN: Privilege split — the UI runs UNPRIVILEGED on every OS; only the
 *     backend asks for elevation, once per launch, through the platform's
 *     native prompt:
 *       Windows : Start-Process -Verb RunAs  (UAC dialog)
 *       macOS   : osascript "do shell script … with administrator privileges"
 *                 (native password dialog — same as sudo, GUI-flavoured)
 *       Linux   : pkexec                      (polkit dialog)
 *
 *     Elevated processes get a different $HOME (root), so SNITCH_DATA_DIR is
 *     passed explicitly on macOS/Linux — the token file, DB and logs must
 *     land in the USER's data dir, not /var/root. On Windows env can't
 *     cross UAC, so the pre-written api_token.txt does the job and the
 *     frozen binary resolves %LOCALAPPDATA% itself.
 *
 *     All elevated children are unreachable by kill() — /shutdown is the
 *     only exit path (see shutdownBackend).
 *
 * FR: Séparation de privilèges — l'UI tourne SANS privilèges sur tous les
 *     OS ; seul le backend demande l'élévation, une fois par lancement, via
 *     l'invite native de la plateforme :
 *       Windows : Start-Process -Verb RunAs  (dialogue UAC)
 *       macOS   : osascript « do shell script … with administrator
 *                 privileges » (dialogue mot de passe natif — comme sudo,
 *                 en version graphique)
 *       Linux   : pkexec                      (dialogue polkit)
 *
 *     Les processus élevés reçoivent un $HOME différent (root), donc
 *     SNITCH_DATA_DIR est passé explicitement sous macOS/Linux — le fichier
 *     de jeton, la DB et les logs doivent atterrir dans le dossier de
 *     données de L'UTILISATEUR, pas dans /var/root. Sous Windows l'env ne
 *     traverse pas l'UAC, donc le api_token.txt pré-écrit fait le travail
 *     et le binaire figé résout %LOCALAPPDATA% lui-même.
 *
 *     Tous les enfants élevés sont inaccessibles à kill() — /shutdown est
 *     le seul chemin d'arrêt (voir shutdownBackend).
 */
function launchBackendElevated() {
  const dataDir = backendDataDir()
  fs.mkdirSync(dataDir, { recursive: true })
  // EN: The token file is the Windows auth path (env can't cross UAC). It can
  //     fail with EACCES when a previous ELEVATED run left the data dir
  //     root-owned — on POSIX the env vars below carry the token anyway, so a
  //     failed write must not abort the launch.
  // FR: Le fichier de jeton est le chemin d'auth Windows (l'env ne traverse
  //     pas l'UAC). Il peut échouer en EACCES quand un lancement ÉLEVÉ
  //     précédent a laissé le dossier de données en root — sous POSIX les
  //     variables d'environnement ci-dessous portent le jeton de toute façon,
  //     donc une écriture ratée ne doit pas interrompre le démarrage.
  let tokenFileWritten = false
  try {
    fs.writeFileSync(path.join(dataDir, 'api_token.txt'), API_TOKEN, { mode: 0o600 })
    tokenFileWritten = true
  } catch { /* EN: token still reaches the backend via env / FR: le jeton arrive quand même via l'env */ }

  if (isWindows) {
    // EN: PowerShell SINGLE-quoted strings — a " in the exe path would
    //     break out of a double-quoted -FilePath and inject commands;
    //     single quotes only need ' → '' escaping.
    // FR: Chaînes PowerShell en APOSTROPHES — un " dans le chemin de
    //     l'exe sortirait d'un -FilePath entre guillemets et injecterait
    //     des commandes ; les apostrophes n'exigent que ' → ''.
    const psq = s => `'${String(s).replace(/'/g, "''")}'`
    const ps = `Start-Process -FilePath ${psq(backendExe)} -ArgumentList '--port ${backendPort}' -Verb RunAs -WindowStyle Hidden`
    backendProc = spawn('powershell.exe', [
      '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-Command', ps,
    ], { windowsHide: true, stdio: 'ignore' })
  } else if (process.platform === 'darwin') {
    // EN: Escape for the AppleScript double-quoted string, then the shell.
    //     The token normally travels via the api_token.txt file written above
    //     so it never appears in `ps`; the SNITCH_TOKEN env prefix is only a
    //     fallback for when that write failed (root-owned data dir).
    // FR: Échapper pour la chaîne AppleScript entre guillemets, puis le shell.
    //     Le jeton voyage normalement via le fichier api_token.txt écrit
    //     ci-dessus et n'apparaît donc jamais dans `ps` ; le préfixe
    //     SNITCH_TOKEN n'est qu'un repli quand cette écriture a échoué
    //     (dossier de données possédé par root).
    const esc = s => s.replace(/(["\\$`])/g, '\\$1')
    // EN: TWO escaping layers — the command crosses AppleScript THEN
    //     /bin/sh. esc() only quotes for AppleScript: a " or $ in dataDir
    //     or backendExe would survive it and hit the shell raw → inject
    //     first at the shell layer with single quotes (' → '\''), which
    //     sh cannot break out of.
    // FR: DEUX couches d'échappement — la commande traverse AppleScript
    //     PUIS /bin/sh. esc() ne quote que pour AppleScript : un " ou $
    //     dans dataDir/backendExe le traverserait et arriverait brut au
    //     shell → échapper d'abord à la couche shell en apostrophes
    //     (' → '\''), incassables pour sh.
    const shq = s => `'${String(s).replace(/'/g, `'\\''`)}'`
    const tokenPrefix = tokenFileWritten ? '' : `SNITCH_TOKEN=${shq(API_TOKEN)} `
    // EN: SNITCH_OWNER_* tells the ELEVATED backend which real uid/gid to
    //     chown its files back to — otherwise logs/db/token stay root-owned
    //     inside the user's data dir and the next launch dies with EACCES.
    // FR: SNITCH_OWNER_* indique au backend ÉLEVÉ vers quel uid/gid réel
    //     chown ses fichiers — sinon logs/db/jeton restent en root dans le
    //     dossier utilisateur et le lancement suivant meurt en EACCES.
    const ownerPrefix = `SNITCH_OWNER_UID=${process.getuid()} SNITCH_OWNER_GID=${process.getgid()} `
    const shellCmd = `SNITCH_DATA_DIR=${shq(dataDir)} ${ownerPrefix}${tokenPrefix}${shq(backendExe)} --port ${backendPort}`
    backendProc = spawn('osascript', [
      '-e', `do shell script "${esc(shellCmd)}" with administrator privileges`,
    ], { stdio: 'ignore' })
  } else {
    // EN: pkexec strips the environment — `env` re-injects both vars.
    //     If polkit isn't installed (minimal distros), fall back to a plain
    //     spawn: the UI still works, capture just won't start.
    // FR: pkexec purge l'environnement — `env` réinjecte les deux variables.
    //     Si polkit n'est pas installé (distros minimales), repli sur un
    //     spawn simple : l'UI marche, la capture ne démarrera juste pas.
    const pkexecBin = ['/usr/bin/pkexec', '/bin/pkexec', '/usr/local/bin/pkexec']
      .find(p => fs.existsSync(p))
    if (!pkexecBin) { spawnBackendPlain(); return }
    // EN: Same rule as macOS — prefer the token file over an env assignment
    //     visible in /proc/<pid>/cmdline; env only when the write failed.
    // FR: Même règle que macOS — préférer le fichier de jeton à une
    //     affectation d'env visible dans /proc/<pid>/cmdline ; l'env sert
    //     seulement si l'écriture a échoué.
    const envArgs = [
      `SNITCH_DATA_DIR=${dataDir}`,
      // EN: same ownership hand-back as macOS (see above)
      // FR: même rétrocession de propriété que macOS (voir ci-dessus)
      `SNITCH_OWNER_UID=${process.getuid()}`,
      `SNITCH_OWNER_GID=${process.getgid()}`,
    ]
    if (!tokenFileWritten) envArgs.push(`SNITCH_TOKEN=${API_TOKEN}`)
    backendProc = spawn(pkexecBin, [
      'env', ...envArgs,
      backendExe, '--port', String(backendPort),
    ], { stdio: 'ignore' })
  }
  backendElevated = true

  backendProc.on('error', err => {
    if (isQuitting) return
    dialog.showErrorBox('Snitch', `Failed to start backend / Échec du démarrage du backend :\n${err.message}`)
    app.quit()
  })
  // EN: No 'exit' crash-watch here — the wrapper exits as soon as the
  //     elevated child is up; waitForBackend() is the liveness check.
  // FR: Pas de surveillance 'exit' ici — le wrapper sort dès que l'enfant
  //     élevé est lancé ; waitForBackend() est le test de vie.
}

function launchBackend() {
  /** EN: Dispatcher — packaged builds elevate the backend on EVERY platform
   *      (capture needs it); dev mode spawns plain so developers can iterate
   *      without password prompts (capture fails without rights, UI works).
   *  FR: Répartiteur — les builds packagées élèvent le backend sur TOUS les
   *      OS (la capture l'exige) ; le mode dev lance sans privilèges pour
   *      itérer sans invite mot de passe (la capture échoue, l'UI marche). */
  if (!fs.existsSync(backendExe)) {
    dialog.showErrorBox('Snitch', `Backend not found / Backend introuvable :\n${backendExe}`)
    app.quit(); return
  }

  if (isDev) {
    spawnBackendPlain()
    return
  }
  launchBackendElevated()
}

function spawnBackendPlain() {
  /** EN: Spawn the compiled backend with SNITCH_TOKEN + SNITCH_PORT in its
   *      environment; windowsHide keeps a console window from flashing;
   *      stdout/stderr stream to the log file for diagnostics.
   *  FR: Lancer le backend compilé avec SNITCH_TOKEN + SNITCH_PORT dans son
   *      environnement ; windowsHide évite l'éclair d'une fenêtre console ;
   *      stdout/stderr vont dans le fichier de log pour le diagnostic. */
  fs.mkdirSync(logDir, { recursive: true })
  const logFd = fs.openSync(logFile, 'a')

  const env = Object.assign({}, process.env)
  env.SNITCH_TOKEN = API_TOKEN
  env.SNITCH_PORT  = String(backendPort)
  env.SNITCH_USER_DATA = '1'   // EN: per-OS user data dir, not the bundle
                               // FR: dossier de données utilisateur, pas le bundle
  // EN: Prevent the child from being interpreted as an Electron/Node process.
  // FR: Empêcher le processus enfant d'être interprété comme un processus Electron/Node.
  delete env.ELECTRON_RUN_AS_NODE

  backendProc = spawn(backendExe, [], {
    detached: !isWindows,
    windowsHide: true,
    stdio: ['ignore', logFd, logFd],
    env,
  })
  backendProc.on('error', err => {
    if (isQuitting) return
    dialog.showErrorBox('Snitch', `Failed to start backend / Échec du démarrage du backend :\n${err.message}`)
    app.quit()
  })
  backendProc.on('exit', (code) => {
    if (isQuitting) return  // EN: normal shutdown — don't alert / FR: arrêt normal — ne pas alerter
    if (mainWindow) {
      dialog.showErrorBox('Snitch', `Backend stopped (code ${code}) / Backend arrêté (code ${code}).`)
      app.quit()
    }
  })
}

/**
 * EN: Ask the backend to exit through its authenticated /shutdown endpoint —
 *     the ONLY way to stop an elevated child we can't signal. Falls back to
 *     killing our own child tree for the unprivileged path.
 * FR: Demander au backend de quitter via son endpoint authentifié /shutdown
 *     — le SEUL moyen d'arrêter un enfant élevé qu'on ne peut pas signaler.
 *     Repli : tuer notre propre arbre de processus pour le chemin non élevé.
 */
function shutdownBackend() {
  if (backendElevated) {
    try {
      const req = http.request(
        `http://127.0.0.1:${backendPort}/shutdown`,
        { method: 'POST', headers: { 'X-Snitch-Token': API_TOKEN }, timeout: 3000 },
        res => res.resume())
      req.on('error', () => {})       // EN: best-effort — app is exiting anyway
      req.on('timeout', () => req.destroy())
      req.end()
    } catch { /* EN: nothing more we can do / FR: rien de plus à faire */ }
    return
  }
  killBackend()
}

// ── App lifecycle / Cycle de vie de l'application ────────────────────────────
app.whenReady().then(async () => {
  // EN: Guard: when a previous ELEVATED run left the data dir root-owned,
  //     Chromium cannot write its caches and the app dies SILENTLY — no
  //     window, no error. Detect it up front and tell the user how to fix.
  // FR: Garde-fou : quand un lancement ÉLEVÉ précédent a laissé le dossier
  //     de données possédé par root, Chromium ne peut plus écrire ses caches
  //     et l'app meurt EN SILENCE — pas de fenêtre, pas d'erreur. Détecter
  //     en amont et expliquer la réparation.
  try {
    fs.accessSync(app.getPath('userData'), fs.constants.W_OK)
  } catch {
    const dataPath = app.getPath('userData')
    dialog.showErrorBox('Snitch',
      `Cannot write to the data folder (leftover root-owned files from an earlier elevated run).\n` +
      `Impossible d'écrire dans le dossier de données (fichiers restés propriété de root après un lancement élevé).\n\n` +
      `Fix / Réparer :\n  sudo chown -R $USER "${dataPath}"\n  ${'or / ou'} : rm -rf "${dataPath}"`)
    app.quit()
    return
  }

  // EN: On Windows, Npcap is a hard requirement — guide the user to npcap.com
  //     (it is deliberately NOT bundled; see licensing notes).
  // FR: Sous Windows, Npcap est obligatoire — guider l'utilisateur vers
  //     npcap.com (volontairement NON embarqué ; voir les notes de licence).
  if (isWindows && !isNpcapInstalled()) {
    await offerNpcapDownload()
    return
  }

  createSplash()
  backendPort = await findFreePort()

  // EN: Boot loop — if the elevated backend never answers (declined admin
  //     prompt is the usual cause), offer: retry elevation, continue
  //     unprivileged (UI works, capture stays off), or quit.
  // FR: Boucle de démarrage — si le backend élevé ne répond jamais (invite
  //     admin refusée, cause habituelle), proposer : réessayer l'élévation,
  //     continuer sans privilèges (l'UI marche, la capture reste coupée),
  //     ou quitter.
  let booted = false
  while (!booted) {
    launchBackend()
    try {
      // EN: 90 s of patience when elevated — the user may type a password.
      // FR: 90 s de patience quand élevé — l'utilisateur tape son mot de passe.
      await waitForBackend(backendElevated ? 90 : 40)
      booted = true
    } catch (e) {
      lowerSplash()
      if (!backendElevated) {
        dialog.showErrorBox('Snitch', `Backend unavailable / Backend indisponible :\n${e.message}`)
        app.quit(); return
      }
      const choice = await dialog.showMessageBox({
        type: 'warning', title: 'Snitch',
        // EN: Don't guess the cause — a crashing backend looks exactly like a
        //     declined prompt from here. Point to the log that tells which.
        // FR: Ne pas deviner la cause — un backend qui plante ressemble ici
        //     exactement à une invite refusée. Pointer vers le log qui le dit.
        message: 'The capture backend did not start (admin prompt declined or timed out, or backend error).\n' +
                 'Le backend de capture n\'a pas démarré (invite administrateur refusée ou expirée, ou erreur du backend).',
        detail: `Backend unavailable / Backend indisponible : ${e.message}\n` +
                `Logs / Journaux : ${logDir}`,
        buttons: [
          'Retry / Réessayer',
          'Continue without capture / Continuer sans capture',
          'Quit / Quitter',
        ],
        defaultId: 0, cancelId: 2,
      })
      if (choice.response === 2) { app.quit(); return }
      if (choice.response === 1) {
        backendElevated = false
        spawnBackendPlain()
        try {
          await waitForBackend()
          booted = true
        } catch (e2) {
          dialog.showErrorBox('Snitch', `Backend unavailable / Backend indisponible :\n${e2.message}`)
          app.quit(); return
        }
      }
      raiseSplash()
      // EN: response 0 loops back to launchBackend() → fresh admin prompt.
      // FR: la réponse 0 reboucle vers launchBackend() → nouvelle invite admin.
    }
  }

  createMain()
  createTray()

  // EN: Kick the updater once the UI is up — first check now, then every
  //     6 h while running. Honors the user opt-out (see updateCheckEnabled).
  // FR: Lancer l'updater une fois l'UI prête — premier contrôle maintenant,
  //     puis toutes les 6 h. Respecte l'opt-out (voir updateCheckEnabled).
  initAutoUpdater()
  checkForUpdates()
  setInterval(() => checkForUpdates(), 6 * 3600 * 1000).unref()
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    // EN: Set the flag before quit so spurious exit dialogs are suppressed.
    // FR: Positionner le drapeau avant quit pour supprimer les dialogues parasites.
    isQuitting = true
    app.quit()
  }
})

app.on('before-quit', () => {
  isQuitting = true
  // EN: /shutdown API call for the elevated backend; direct kill otherwise.
  // FR: Appel API /shutdown pour le backend élevé ; kill direct sinon.
  shutdownBackend()
})
