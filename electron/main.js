/**
 * Snitch — Electron main process.
 *
 * EN: Orchestrates the desktop app:
 *       1. ensure Npcap is installed (Windows only, needed for raw capture)
 *       2. show a splash screen
 *       3. generate a per-launch API token (crypto-random) and spawn the
 *          PyInstaller-compiled backend with SNITCH_TOKEN set
 *       4. wait for the API to answer, then open the main window
 *       5. kill the backend cleanly on quit
 *
 *     The token is the heart of the local-API trust model: it is created in
 *     the main process, passed to the backend via its environment, and given
 *     to the renderer ONLY through the ipcMain.handle('snitch:get-token')
 *     bridge — never logged, never embedded in the page.
 *
 * FR: Orchestre l'application bureau :
 *       1. vérifier que Npcap est installé (Windows uniquement, requis pour
 *          la capture brute)
 *       2. afficher un écran de démarrage
 *       3. générer un jeton API par lancement (crypto-aléatoire) et lancer le
 *          backend compilé par PyInstaller avec SNITCH_TOKEN défini
 *       4. attendre que l'API réponde, puis ouvrir la fenêtre principale
 *       5. tuer proprement le backend à la fermeture
 *
 *     Le jeton est le cœur du modèle de confiance de l'API locale : créé dans
 *     le processus principal, transmis au backend via son environnement, et
 *     donné au renderer UNIQUEMENT via le pont ipcMain.handle('snitch:get-token')
 *     — jamais loggué, jamais embarqué dans la page.
 */

const _electron        = require('electron')
const { app, BrowserWindow, dialog, ipcMain } = _electron.default || _electron
const { spawn, execSync }            = require('child_process')
const crypto = require('crypto')
const path = require('path')
const http = require('http')
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
const backendExe = isDev
  ? path.join(resourcesDir, 'dist', 'backend', backendName)
  : path.join(resourcesDir, backendName)

const npcapInstaller = path.join(resourcesDir, 'resources', 'npcap-installer.exe')
const frontendDist   = isDev
  ? path.join(resourcesDir, 'frontend', 'dist')
  : path.join(resourcesDir, 'frontend_dist')

const BACKEND_URL  = 'http://127.0.0.1:8000'
const BACKEND_PORT = 8000

const iconPath = isDev
  ? path.join(__dirname, 'icon.png')
  : path.join(resourcesDir, 'icon.png')

let mainWindow   = null
let splashWindow = null
let backendProc  = null
let isQuitting   = false

// ── API token / Jeton API ────────────────────────────────────────────────────
// EN: 48-hex-char secret generated once per app launch. Passed to the backend
//     via SNITCH_TOKEN and served to the renderer through ipcMain — the web
//     page can only obtain it via the preload bridge.
// FR: Secret hexadécimal de 48 caractères généré une fois par lancement.
//     Transmis au backend via SNITCH_TOKEN et servi au renderer via ipcMain —
//     la page web ne peut l'obtenir que par le pont preload.
const API_TOKEN = crypto.randomBytes(24).toString('hex')

// EN: IPC handler — the ONLY way the renderer learns the token.
// FR: Handler IPC — la SEULE façon pour le renderer d'apprendre le jeton.
ipcMain.handle('snitch:get-token', () => API_TOKEN)

// ── Port management / Gestion du port ────────────────────────────────────────
/**
 * EN: Free the backend port — kills any leftover process still listening on
 *     it (zombies from crashed sessions). Windows uses netstat/taskkill;
 *     POSIX uses lsof + kill.
 * FR: Libérer le port du backend — tue tout processus résiduel qui écoute
 *     encore dessus (zombies de sessions plantées). Windows utilise
 *     netstat/taskkill ; POSIX utilise lsof + kill.
 */
function killPort(port) {
  try {
    if (isWindows) {
      const out = execSync(`netstat -ano`, { encoding: 'utf8', stdio: 'pipe' })
      const pids = new Set()
      for (const line of out.split('\n')) {
        // EN: Match lines whose local address ends with :PORT.
        // FR: Garder les lignes dont l'adresse locale finit par :PORT.
        if (!line.includes(`:${port} `) && !line.includes(`:${port}\t`)) continue
        const m = line.trim().match(/(\d+)\s*$/)
        if (m && m[1] !== '0') pids.add(m[1])
      }
      for (const pid of pids) {
        try { execSync(`taskkill /PID ${pid} /F`, { stdio: 'pipe' }) } catch {}
      }
      if (pids.size > 0) {
        // EN: Brief wait for the OS to release the port (~1s via ping).
        // FR: Petite attente pour que l'OS libère le port (~1 s via ping).
        try { execSync('ping -n 2 127.0.0.1', { stdio: 'pipe' }) } catch {}
      }
    } else {
      // EN: POSIX — lsof reports PIDs listening on the port, kill them.
      // FR: POSIX — lsof rapporte les PID qui écoutent sur le port, on les tue.
      try {
        const out = execSync(`lsof -ti tcp:${port} -sTCP:LISTEN`, { encoding: 'utf8', stdio: 'pipe' })
        for (const pid of out.split('\n').map(s => s.trim()).filter(Boolean)) {
          try { process.kill(Number(pid), 'SIGKILL') } catch {}
        }
      } catch {}
    }
  } catch {}
}

// ── Npcap ────────────────────────────────────────────────────────────────────
/**
 * EN: Npcap is the Windows packet-capture driver Scapy needs. We detect it
 *     through its registry keys.
 * FR: Npcap est le pilote de capture Windows dont Scapy a besoin. On le détecte
 *     via ses clés de registre.
 */
function isNpcapInstalled() {
  const keys = [
    'HKLM\\SOFTWARE\\Npcap',
    'HKLM\\SOFTWARE\\WOW6432Node\\Npcap',
  ]
  for (const key of keys) {
    try {
      const out = execSync(`reg query "${key}"`, { stdio: 'pipe', encoding: 'utf8' })
      if (out.includes('Npcap') || out.includes(key)) return true
    } catch {}
  }
  return false
}

/**
 * EN: Run the bundled Npcap installer. Silent mode requires a paid OEM
 *     license, so we launch the standard GUI installer.
 * FR: Lancer l'installateur Npcap fourni. Le mode silencieux exige une licence
 *     OEM payante, donc on lance l'installateur GUI standard.
 */
function installNpcap() {
  if (!fs.existsSync(npcapInstaller)) return false
  try {
    execSync(`"${npcapInstaller}"`, { stdio: 'inherit' })
    return true
  } catch { return false }
}

// ── Windows / Fenêtres ───────────────────────────────────────────────────────
function createSplash() {
  /** EN: Frameless transparent splash shown while the backend boots.
   *  FR: Splash sans cadre et transparent affiché pendant le démarrage du backend. */
  splashWindow = new BrowserWindow({
    width: 380, height: 310, frame: false,
    resizable: false, alwaysOnTop: true, center: true,
    transparent: true, icon: iconPath,
    webPreferences: { nodeIntegration: false },
  })
  splashWindow.loadFile(path.join(__dirname, 'splash.html'))
}

function createMain() {
  /** EN: Main window — loads the Vite dev server in dev, or the compiled
   *      frontend otherwise.
   *  FR: Fenêtre principale — charge le serveur de dev Vite en dev, ou le
   *      frontend compilé sinon. */
  mainWindow = new BrowserWindow({
    width: 1400, height: 860, minWidth: 900, minHeight: 600,
    show: false, title: 'Snitch', backgroundColor: '#000000',
    icon: iconPath,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true, nodeIntegration: false,
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
        BACKEND_URL + '/graph',
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
 * EN: Kill the backend child process and free its port.
 *     `taskkill /F /T` is more reliable than .kill() on Windows and takes
 *     the whole process tree; POSIX gets SIGKILL.
 * FR: Tuer le processus enfant du backend et libérer son port.
 *     `taskkill /F /T` est plus fiable que .kill() sous Windows et prend tout
 *     l'arbre de processus ; POSIX reçoit SIGKILL.
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
  killPort(BACKEND_PORT)
}

function launchBackend() {
  /** EN: Spawn the compiled backend with SNITCH_TOKEN in its environment;
   *      show a dialog and quit on failure.
   *  FR: Lancer le backend compilé avec SNITCH_TOKEN dans son environnement ;
   *      afficher une boîte de dialogue et quitter en cas d'échec. */
  if (!fs.existsSync(backendExe)) {
    dialog.showErrorBox('Snitch', `Backend not found / Backend introuvable :\n${backendExe}`)
    app.quit(); return
  }

  // EN: Free the port first — handles zombies from crashed sessions.
  // FR: Libérer le port d'abord — gère les zombies de sessions plantées.
  killPort(BACKEND_PORT)

  const env = Object.assign({}, process.env)
  // EN: Inject the API token — the backend will require it on every request.
  // FR: Injecter le jeton API — le backend l'exigera sur chaque requête.
  env.SNITCH_TOKEN = API_TOKEN
  // EN: Prevent the child from being interpreted as an Electron/Node process.
  // FR: Empêcher le processus enfant d'être interprété comme un processus Electron/Node.
  delete env.ELECTRON_RUN_AS_NODE

  backendProc = spawn(backendExe, [], { detached: !isWindows, stdio: 'ignore', env })
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
  // EN: On Windows, Npcap is a hard requirement — offer to install it.
  // FR: Sous Windows, Npcap est obligatoire — proposer son installation.
  if (isWindows && !isNpcapInstalled()) {
    if (fs.existsSync(npcapInstaller)) {
      const choice = dialog.showMessageBoxSync({
        type: 'question', title: 'Snitch — Npcap required / Npcap requis',
        message: 'Snitch needs Npcap to capture network traffic. Install it now?\n' +
                 'Snitch a besoin de Npcap pour capturer le trafic réseau. Installer maintenant ?',
        buttons: ['Install / Installer', 'Quit / Quitter'], defaultId: 0,
      })
      if (choice === 1) { app.quit(); return }
      if (!installNpcap()) {
        dialog.showErrorBox('Snitch', 'Npcap installation failed. Install it manually from https://npcap.com\n' +
                                     "L'installation de Npcap a échoué. Installez-le depuis https://npcap.com")
        app.quit(); return
      }
    }
  }

  createSplash()
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
