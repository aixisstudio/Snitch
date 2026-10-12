/**
 * Snitch — per-process icon picker.
 *
 * EN: The apps table (AppsView) shows the raw process name in a monospace cell.
 *     Unknown processes used to render with no visual affordance at all.
 *     This module maps well-known process names to a Lucide icon so a glance
 *     at the table already tells you "that's a browser" vs "that's a container
 *     runtime" without reading the name.
 *
 *     The matcher is deliberately keyword-based and case-insensitive: process
 *     names come from the OS in wildly different forms (`code`, `Code`,
 *     `Visual Studio Code`, `slack.exe`, ...). A process that matches nothing
 *     falls back to `AppWindow`, the same generic icon the sidebar already
 *     uses for the whole "Apps" view.
 *
 * FR: Le tableau des applications (AppsView) affiche le nom brut du processus
 *     dans une cellule monospace. Les processus inconnus ne donnaient aucun
 *     indice visuel. Ce module associe les noms de processus bien connus à une
 *     icône Lucide afin d'identifier au premier coup d'œil « c'est un
 *     navigateur » vs « c'est un runtime conteneur ». Le matcheur est volontairement
 *     fondé sur des mots-clés et insensible à la casse ; un processus qui ne
 *     correspond à rien retombe sur `AppWindow`, la même icône générique que
 *     la barre latérale utilise pour la vue « Applications ».
 */
import {
  AppWindow,
  Bot,
  Boxes,
  Box,
  Cpu,
  Gamepad,
  GitBranch,
  Globe,
  MessageSquare,
  MessageSquareText,
  Music,
  SquareCode,
  Terminal,
  Video,
} from 'lucide-react'

// EN: Keyword → icon rules, evaluated top to bottom; first hit wins.
//     Keywords are lower-cased substrings matched against the process name.
// FR: Règles mot-clé → icône, évaluées de haut en bas ; la première correspondance l'emporte.
const RULES = [
  // Video / meeting apps
  [['zoom', 'teams', 'skype', 'facetime', 'meet'], Video],
  // Game / game-launcher
  [['steam', 'epic', 'game', 'unity', 'blender'], Gamepad],
  // Code editors / IDEs
  [['vscode', 'code', 'code-oss', 'cursor', 'sublime', 'notepad++', 'vim', 'emacs', 'jetbrains', 'intellij', 'pycharm', 'webstorm'], SquareCode],
  // Browsers
  [['firefox', 'chrome', 'chromium', 'brave', 'edge', 'safari', 'opera', 'browser'], Globe],
  // Chats / messaging
  [['slack', 'discord', 'telegram', 'whatsapp', 'messenger', 'signal', 'teamspeak'], MessageSquareText],
  // Music / media
  [['spotify', 'vlc', 'mpv', 'foobar', 'music', 'mediaplayer', 'youtube', 'netflix', 'twitch'], Music],
  // Containers / dev tooling
  [['docker', 'container', 'podman', 'kubernetes', 'kubectl'], Boxes],
  // AI / model runtimes
  [['ollama', 'llama', 'llm', 'claude', 'gemini', 'openai', 'langchain'], Bot],
  // Version control
  [['git', 'github', 'gitlab', 'gh_'], GitBranch],
  // Shells / terminals
  [['terminal', 'powershell', 'pwsh', 'cmd', 'bash', 'zsh', 'ssh', 'console', 'cmdline'], Terminal],
  // Language runtimes / build tools
  [['node', 'npm', 'yarn', 'pnpm', 'python', 'pip', 'java', 'rust', 'cargo', 'go', 'golang', 'deno', 'bun', 'ruby', 'php'], Cpu],
  // Office suite
  [['word', 'excel', 'powerpoint', 'outlook', 'office'], Box],
  // Messaging fallback (generic chat)
  [['chat', 'im', 'communicator'], MessageSquare],
]

/**
 * EN: Return the Lucide icon component that best represents `name`.
 * FR: Renvoyer le composant d'icône Lucide qui représente le mieux `name`.
 *
 * @param {string} name  raw process name from the OS
 * @returns {LucideIcon} a Lucide icon component (AppWindow when nothing matches)
 */
export function processIcon(name) {
  const n = String(name == null ? '' : name).toLowerCase()
  for (const [keys, Icon] of RULES) {
    if (keys.some((k) => n.includes(k))) return Icon
  }
  return AppWindow
}

export default processIcon
