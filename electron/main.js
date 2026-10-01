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

let mainWindow   = null
let splashWindow = null
let backendProc  = null
let tray         = null
let backendPort  = 0            // EN: chosen at launch / FR: choisi au lancement
let isQuitting   = false
let backendElevated = false     // EN: Windows RunAs spawn — we can't kill it,
                                //     /shutdown is the exit path.
                                // FR: spawn élevé Windows — on ne peut pas
                                //     le tuer, /shutdown est le chemin d'arrêt.

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
function createTray() {
  tray = new Tray(iconPath)
  tray.setToolTip('Snitch')
  const menu = Menu.buildFromTemplate([
    {
      label: 'Show Snitch / Afficher Snitch',
      click: () => { if (mainWindow) { mainWindow.show(); mainWindow.focus() } },
    },
    {
      label: 'Open logs / Ouvrir les logs',
      click: () => shell.openPath(logDir),
    },
    { type: 'separator' },
    {
      label: 'Quit / Quitter',
      click: () => { isQuitting = true; app.quit() },
    },
  ])
  tray.setContextMenu(menu)
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
 * EN: Windows privilege split — the UI runs UNPRIVILEGED (asInvoker); only
 *     the backend asks for admin via `Start-Process -Verb RunAs` (one UAC
 *     prompt per launch). Env vars can't cross UAC, so we pass the port as
 *     an argv flag and pre-write the token to api_token.txt — the backend's
 *     own resolution order picks it up. In dev we spawn normally: capture
 *     will fail without rights but the UI stays usable.
 * FR: Séparation de privilèges Windows — l'UI tourne SANS privilèges
 *     (asInvoker) ; seul le backend demande l'admin via `Start-Process -Verb
 *     RunAs` (une invite UAC par lancement). Les variables d'env ne
 *     traversent pas l'UAC, donc on passe le port en argument argv et on
 *     pré-écrit le jeton dans api_token.txt — l'ordre de résolution du
 *     backend le récupère. En dev on lance normalement : la capture échouera
 *     sans droits mais l'UI reste utilisable.
 */
function launchBackendElevated() {
  const dataDir = backendDataDir()
  fs.mkdirSync(dataDir, { recursive: true })
  fs.writeFileSync(path.join(dataDir, 'api_token.txt'), API_TOKEN, { mode: 0o600 })

  // EN: -FilePath/-ArgumentList carefully quoted (paths may contain spaces).
  // FR: -FilePath/-ArgumentList soigneusement entre guillemets (chemins avec espaces).
  const ps = `Start-Process -FilePath "${backendExe}" -ArgumentList '--port ${backendPort}' -Verb RunAs -WindowStyle Hidden`
  backendProc = spawn('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-WindowStyle', 'Hidden', '-Command', ps,
  ], { windowsHide: true, stdio: 'ignore' })
  backendElevated = true

  backendProc.on('error', err => {
    if (isQuitting) return
    dialog.showErrorBox('Snitch', `Failed to start backend / Échec du démarrage du backend :\n${err.message}`)
    app.quit()
  })
  // EN: No 'exit' crash-watch here — the powershell wrapper exits as soon as
  //     the elevated child is up; waitForBackend() is the liveness check.
  // FR: Pas de surveillance 'exit' ici — le wrapper powershell sort dès que
  //     l'enfant élevé est lancé ; waitForBackend() est le test de vie.
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

  // EN: Windows packaged build → elevated child, unprivileged UI.
  //     Everything else → normal spawn, same privilege as the UI.
  // FR: Build packagé Windows → enfant élevé, UI non privilégiée.
  //     Le reste → spawn normal, même privilège que l'UI.
  if (isWindows && !isDev) {
    launchBackendElevated()
    return
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
    // EN: On Windows an elevated backend that never answers usually means
    //     the UAC prompt was declined — say so explicitly.
    // FR: Sous Windows un backend élevé qui ne répond jamais signifie
    //     généralement une invite UAC refusée — le dire explicitement.
    const extra = backendElevated
      ? '\n\nDid you decline the admin (UAC) prompt? Capture requires it.\nAvez-vous refusé l\'invite administrateur (UAC) ? La capture l\'exige.'
      : ''
    dialog.showErrorBox('Snitch', `Backend unavailable / Backend indisponible :\n${e.message}${extra}`)
    app.quit(); return
  }

  createMain()
  createTray()
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
