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
const { app, BrowserWindow, dialog, ipcMain, shell } = _electron.default || _electron
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

// EN: Backend stdout/stderr go to a real log file — never stdio:'ignore',
//     so crashes leave a trace the diagnostics export can pick up.
// FR: stdout/stderr du backend vont dans un vrai fichier de log — jamais
//     stdio:'ignore', pour qu'un crash laisse une trace récupérable par
//     l'export de diagnostic.
const logDir  = path.join(app.getPath('userData'), 'logs')
const logFile = path.join(logDir, 'backend.log')

let mainWindow   = null
let splashWindow = null
let backendProc  = null
let backendPort  = 0            // EN: chosen at launch / FR: choisi au lancement
let isQuitting   = false

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
  mainWindow.on('closed', () => { mainWindow = null })
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

function launchBackend() {
  /** EN: Spawn the compiled backend with SNITCH_TOKEN + SNITCH_PORT in its
   *      environment; windowsHide keeps a console window from flashing;
   *      stdout/stderr stream to the log file for diagnostics.
   *  FR: Lancer le backend compilé avec SNITCH_TOKEN + SNITCH_PORT dans son
   *      environnement ; windowsHide évite l'éclair d'une fenêtre console ;
   *      stdout/stderr vont dans le fichier de log pour le diagnostic. */
  if (!fs.existsSync(backendExe)) {
    dialog.showErrorBox('Snitch', `Backend not found / Backend introuvable :\n${backendExe}`)
    app.quit(); return
  }

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

// ── App lifecycle / Cycle de vie de l'application ────────────────────────────
app.whenReady().then(async () => {
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
  launchBackend()

  try {
    await waitForBackend()
  } catch (e) {
    dialog.showErrorBox('Snitch', `Backend unavailable / Backend indisponible :\n${e.message}`)
    app.quit(); return
  }

  createMain()
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
  killBackend()
})
