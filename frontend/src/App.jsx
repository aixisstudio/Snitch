/**
 * Snitch — root application component.
 *
 * EN: Owns the top-level layout (sidebar | main view | timeline) and the
 *     toolbar (language toggle, view switch, export, filters, capture
 *     start/stop, alerts, status). All realtime state comes from
 *     `useWebSocket`; UI-only state (selected node, view, panel toggles)
 *     lives here.
 * FR: Définit la mise en page principale (barre latérale | vue centrale |
 *     timeline) et la barre d'outils (sélecteur de langue, changement de vue,
 *     export, filtres, start/stop capture, alertes, statut). Tout l'état temps
 *     réel vient de `useWebSocket` ; l'état purement UI (nœud sélectionné,
 *     vue, panneaux) vit ici.
 */
import { useState, useMemo } from 'react'
import { Hexagon, Globe, Wifi, Smartphone, Monitor, Cpu, ShieldCheck, Radio, Zap, HelpCircle, AlertTriangle, Square, Play, Filter, Mic, Camera, Download, ShieldOff, AppWindow, Sun, Moon } from 'lucide-react'
import ForceGraph from './graph/ForceGraph'
import AuroraCurtain from './components/AuroraCurtain'
import MapView from './map/MapView'
import AppsView from './components/AppsView'
import Sidebar, { matchesFilter } from './components/Sidebar'
import SearchBar from './components/SearchBar'
import { AlertBell, AlertPanel, AlertToasts } from './components/AlertPanel'
import { SettingsButton, SettingsPanel } from './components/Settings'
import { FirewallButton, FirewallPanel } from './components/Firewall'
import Onboarding from './components/Onboarding'
import Timeline from './components/Timeline'
import Dropdown from './components/Dropdown'
import { apiBase, authHeaders } from './api'
import { useWebSocket } from './hooks/useWebSocket'
import { computePrivacyScore } from './scoring/privacy'
// EN: WS URL is resolved dynamically (port + ws/wss) via api.js wsBase().
// FR: L'URL WS est résolue dynamiquement (port + ws/wss) via wsBase() d'api.js.
import { useT, LANGS, LANG_NAMES } from './i18n'

export default function App() {
  const { nodes, edges, lanDevices, packets, alerts, unread, clearUnread, status, bandwidth, capturing, captureError, toggleCapture, portFilter, updatePortFilter, excludedProcesses, updateProcessFilter, whitelistedIps, updateIpWhitelist, media, ssid, iface, watchlist, updateWatchlist } = useWebSocket(null)  // EN: null → resolves the dynamic port/scheme via wsBase()
                    // FR: null → résout port/schéma dynamiques via wsBase()
  const [selected, setSelected] = useState(null)
  const [view, setView] = useState('graph')
  const [showAlerts, setShowAlerts] = useState(false)
  const [showSettings, setShowSettings] = useState(false)
  const [showFirewall, setShowFirewall] = useState(false)
  const [lockdown, setLockdown] = useState(false)
  // EN: First-run explainer — shown once, flag persisted in localStorage.
  // FR: Explications de premier lancement — affichées une fois, drapeau
  //     persisté en localStorage.
  const [showOnboarding, setShowOnboarding] = useState(
    () => !localStorage.getItem('snitch_onboarded'))
  const [filter, setFilter] = useState({ text: '', category: 'all' })
  const { lang, setLang } = useT()

  // EN: Node ids → worst alert severity, info alerts EXCLUDED — a "new
  //     device seen" notice is informational, not a red alarm. The map
  //     drives ring color (critical → red, warning → amber).
  // FR: Ids de nœuds → pire sévérité d'alerte, alertes info EXCLUES — une
  //     notification « nouvel appareil vu » est informative, pas une alarme
  //     rouge. La map pilote la couleur de l'anneau (critique → rouge,
  //     warning → orange).
  const alertedNodes = useMemo(() => {
    const m = new Map()
    for (const a of alerts) {
      if (!a.node_id || a.severity === 'info') continue
      if (a.severity === 'critical' || m.get(a.node_id) !== 'critical') {
        m.set(a.node_id, a.severity)
      }
    }
    return m
  }, [alerts])

  // EN: The graph shows ONLY what matches the active filter — a selected
  //     category ("Tracking", "HTTPS"…) or search text hides every other
  //     node, so the view shows just that slice. The "local" node always
  //     stays (it anchors the star layout). Process exclusions still apply.
  // FR: Le graphe n'affiche QUE ce qui correspond au filtre actif — une
  //     catégorie choisie (« Tracking », « HTTPS »…) ou un texte masque
  //     tous les autres nœuds. Le nœud « local » reste toujours (il ancre
  //     la disposition en étoile). Les exclusions de processus s'appliquent.
  const filteredNodes = useMemo(() => {
    const out = {}
    for (const [id, node] of Object.entries(nodes)) {
      if (id === 'local') { out[id] = node; continue }
      const procs = node.processes ? Object.keys(node.processes) : []
      if (procs.length > 0 && procs.every(p => excludedProcesses.includes(p))) continue
      if (!matchesFilter(node, filter, alertedNodes)) continue
      out[id] = node
    }
    return out
  }, [nodes, excludedProcesses, filter, alertedNodes])

  // EN: LAN devices obey the same filter in the graph — picking "Tracking"
  //     hides the local devices too; the sidebar keeps its own filtering.
  // FR: Les appareils LAN obéissent au même filtre dans le graphe —
  //     choisir « Tracking » masque aussi les appareils locaux ; la sidebar
  //     garde son propre filtrage.
  const filteredLanDevices = useMemo(() => {
    if (!filter || (filter.category === 'all' && !filter.text)) return lanDevices
    const out = {}
    for (const [id, d] of Object.entries(lanDevices)) {
      if (matchesFilter({ ...d, label: d.hostname }, filter, alertedNodes)) out[id] = d
    }
    return out
  }, [lanDevices, filter, alertedNodes])

  const filteredEdges = useMemo(() => {
    const visibleIds = new Set([...Object.keys(filteredNodes), ...Object.keys(filteredLanDevices)])
    const out = {}
    for (const [id, edge] of Object.entries(edges)) {
      if (visibleIds.has(edge.source) && visibleIds.has(edge.target)) out[id] = edge
    }
    return out
  }, [edges, filteredNodes, filteredLanDevices])

  const filteredPackets = useMemo(() =>
    excludedProcesses.length === 0
      ? packets
      : packets.filter(p => !p.process || !excludedProcesses.includes(p.process)),
    [packets, excludedProcesses]
  )

  const privacyScore = useMemo(() =>
    computePrivacyScore(nodes, alerts),
    [nodes, alerts]
  )

  function handleBell() {
    setShowAlerts(v => !v)
    clearUnread()
  }

  function handleWhitelist(ip) {
    if (!ip || whitelistedIps.includes(ip)) return
    updateIpWhitelist([...whitelistedIps, ip])
    setSelected(null)
  }

  // EN: Persisted "ignore this host/type" — POST /alerts/ignore.
  // FR: « Ignorer cet hôte/ce type » persisté — POST /alerts/ignore.
  async function handleIgnoreAlert(alert) {
    const base = await apiBase()
    await fetch(`${base}/alerts/ignore`, {
      method: 'POST',
      headers: await authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ type: alert.type, ip: alert.details?.ip }),
    })
  }

  return (
    /* EN: Aurora backdrop covers the WHOLE page — the canvas sits behind
           every view and every bento card glows against the ribbons.
       FR: La toile aurore couvre TOUTE la page — le canvas est derrière
           chaque vue et chaque carte bento ressort sur les rubans. */
    <AuroraCurtain
      bands={5}
      noise={0.35}
      colors={['var(--aurora-a)', 'var(--aurora-b)', 'var(--aurora-c)']}
      style={{ height: '100vh', width: '100vw' }}
    >
    <div style={{ display: 'flex', height: '100%', width: '100%', overflow: 'hidden' }}>
      <Sidebar
        nodes={filteredNodes}
        lanDevices={lanDevices}
        packets={filteredPackets}
        selected={selected}
        onClose={() => setSelected(null)}
        privacyScore={privacyScore}
        bandwidth={bandwidth}
        filter={filter}
        onFilterChange={setFilter}
        onWhitelist={handleWhitelist}
        alertedNodes={alertedNodes}
      />

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ flex: 1, position: 'relative', overflow: 'hidden' }}>
          {view === 'graph' && (
            <ForceGraph
              nodes={filteredNodes}
              edges={filteredEdges}
              lanDevices={filteredLanDevices}
              alertedNodes={alertedNodes}
              onNodeClick={setSelected}
              filter={filter}
            />
          )}
          {view === 'map' && (
            <MapView nodes={filteredNodes} onNodeClick={setSelected} />
          )}
          {view === 'apps' && <AppsView nodes={filteredNodes} />}

          {/* EN: Top-right toolbar / FR: Barre d'outils en haut à droite */}
          <div style={{
            position: 'absolute', top: 16, right: 16,
            display: 'flex', alignItems: 'center', gap: 8,
          }}>
            <MediaBadge media={media} />
            <NetworkBadge ssid={ssid} iface={iface} />
            <ThemeToggle />
            <LangToggle />
            <ViewToggle view={view} onChange={setView} />
            <ExportButton nodes={nodes} edges={edges} lanDevices={lanDevices} alerts={alerts} />
            <ProcessFilter excluded={excludedProcesses} onChange={updateProcessFilter} nodes={nodes} />
            <PortFilter ports={portFilter} onUpdate={updatePortFilter} />
            <IPWhitelist ips={whitelistedIps} onUpdate={updateIpWhitelist} />
            <FirewallButton onClick={() => setShowFirewall(v => !v)} lockdown={lockdown} />
            <CaptureToggle capturing={capturing} onToggle={toggleCapture} />
            <AlertBell unread={unread} onClick={handleBell} />
            <SettingsButton onClick={() => setShowSettings(v => !v)} />
            <StatusBadge status={status} />
          </div>

          {/* EN: Fatal capture failure banner — without it a dead pcap
                  session showed "devices but no traffic" with no hint why.
              FR: Bannière d'échec fatal de capture — sans elle une session
                  pcap morte affichait « des appareils mais pas de trafic »
                  sans aucune indication. */}
          {captureError && <CaptureErrorBanner error={captureError} />}

          {showAlerts && (
            <AlertPanel alerts={alerts} onClose={() => setShowAlerts(false)} onIgnore={handleIgnoreAlert} />
          )}

          {showSettings && (
            <SettingsPanel onClose={() => setShowSettings(false)} lang={lang} setLang={setLang}
              watchlist={watchlist} onWatchlist={updateWatchlist} iface={iface} />
          )}

          {showFirewall && (
            <FirewallPanel onClose={() => setShowFirewall(false)} onLockdownChange={setLockdown} />
          )}

          {showOnboarding && <Onboarding onDone={() => setShowOnboarding(false)} />}

          {/* EN: Floating toasts for warning/critical alerts.
              FR: Toasts flottants pour les alertes warning/critiques. */}
          <AlertToasts alerts={alerts.filter(a => a.severity !== 'info').slice(0, 3)} />

          {/* EN: Bottom-right bento column — search/filter card floats
                  ABOVE the legend card, both over the graph.
              FR: Colonne bento en bas à droite — la carte recherche/filtres
                  flotte AU-DESSUS de la carte légende, sur le graphe. */}
          {view === 'graph' && (
            <div style={{
              position: 'absolute', top: '50%', right: 8,
              transform: 'translateY(-50%)',
              display: 'flex', flexDirection: 'column', gap: 8,
              alignItems: 'stretch', width: 205,
            }}>
              <div style={{
                width: '100%', boxSizing: 'border-box',
                background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 12,
              }}>
                <SearchBar filter={filter} onChange={setFilter} />
              </div>
              <Legend />
            </div>
          )}
        </div>

        <Timeline />
      </div>
    </div>
    </AuroraCurtain>
  )
}

// ── Export helpers / Aides d'export ──────────────────────────────────────────

/** EN: Trigger a browser download of a text payload. / FR: Déclencher un téléchargement navigateur d'un contenu texte. */
function downloadFile(content, filename) {
  const a = document.createElement('a')
  a.href = URL.createObjectURL(new Blob([content], { type: 'text/plain' }))
  a.download = filename
  a.click()
  URL.revokeObjectURL(a.href)
}

/** EN: Serialize rows to CSV with proper quoting. / FR: Sérialiser des lignes en CSV avec échappement correct. */
function toCSV(rows, cols) {
  const header = cols.join(',')
  const lines = rows.map(r => cols.map(c => {
    const v = r[c] ?? ''
    const s = typeof v === 'object' ? JSON.stringify(v) : String(v)
    return s.includes(',') || s.includes('"') || s.includes('\n')
      ? `"${s.replace(/"/g, '""')}"` : s
  }).join(','))
  return [header, ...lines].join('\n')
}

/** EN: Dropdown offering graph/alerts export in JSON and CSV — built on the
 *      shared `Dropdown` component (outside-click handling included).
 *  FR: Menu déroulant d'export du graphe/des alertes en JSON et CSV — basé
 *      sur le composant `Dropdown` partagé (clic extérieur inclus). */
function ExportButton({ nodes, edges, lanDevices, alerts }) {
  const { t } = useT()

  const stamp = () => new Date().toISOString().slice(0, 16).replace(':', '-')

  function exportGraphJSON() {
    const data = {
      exported_at: new Date().toISOString(),
      nodes: [...Object.values(nodes), ...Object.values(lanDevices)],
      edges: Object.values(edges),
    }
    downloadFile(JSON.stringify(data, null, 2), `snitch-graph-${stamp()}.json`)
  }

  function exportGraphCSV() {
    const allNodes = [...Object.values(nodes), ...Object.values(lanDevices)]
    const cols = ['id', 'label', 'ip', 'category', 'country', 'city', 'org', 'bytes', 'packets']
    downloadFile(toCSV(allNodes, cols), `snitch-graph-${stamp()}.csv`)
  }

  function exportAlertsJSON() {
    downloadFile(JSON.stringify(alerts, null, 2), `snitch-alerts-${stamp()}.json`)
  }

  function exportAlertsCSV() {
    const cols = ['id', 'type', 'severity', 'message', 'node_id', 'timestamp']
    downloadFile(toCSV(alerts, cols), `snitch-alerts-${stamp()}.csv`)
  }

  const items = [
    { label: t('export_graph_json'),  action: exportGraphJSON  },
    { label: t('export_graph_csv'),   action: exportGraphCSV   },
    { label: t('export_alerts_json'), action: exportAlertsJSON },
    { label: t('export_alerts_csv'),  action: exportAlertsCSV  },
  ]

  return (
    <Dropdown
      panelStyle={{ overflow: 'hidden' }}
      button={
        <button style={{
          display: 'flex', alignItems: 'center', gap: 6,
          background: 'var(--surface)', border: '1px solid var(--border)',
          borderRadius: 20, padding: '5px 14px',
          cursor: 'pointer', color: 'var(--text-muted)',
          fontSize: 11, fontWeight: 600, transition: 'all 0.15s',
        }}>
          <Download size={11} />
          {t('export_btn')}
        </button>
      }
    >
      {(close) => items.map(({ label, action }) => (
        <button key={label} onClick={() => { action(); close() }} style={{
          display: 'block', width: '100%', textAlign: 'left',
          background: 'none', border: 'none', borderBottom: '1px solid var(--bg)',
          padding: '9px 14px', color: 'var(--text)',
          fontSize: 11, cursor: 'pointer',
        }}
        onMouseEnter={e => e.target.style.background = 'var(--border)'}
        onMouseLeave={e => e.target.style.background = 'none'}>
          {label}
        </button>
      ))}
    </Dropdown>
  )
}

/** EN: Red badge shown while a process holds the mic or camera.
 *  FR: Badge rouge affiché quand un processus utilise le micro ou la caméra. */
function MediaBadge({ media }) {
  // EN: supported === false means the platform has no backend (macOS) —
  //     hide the badge entirely rather than lie with empty lists.
  // FR: supported === false signifie que la plateforme n'a pas de backend
  //     (macOS) — masquer le badge plutôt que de mentir avec des listes vides.
  if (media.supported === false) return null
  const micActive = media.mic.length > 0
  const camActive = media.camera.length > 0
  if (!micActive && !camActive) return null

  return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 6,
      background: 'var(--danger-bg)', border: '1px solid #ef4444',
      borderRadius: 20, padding: '5px 12px',
    }}>
      {micActive && (
        <div title={media.mic.join(', ')} style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: 'default' }}>
          <Mic size={11} color="var(--red-text)" />
          <span style={{ fontSize: 10, color: 'var(--red-text)' }}>{media.mic[0]}</span>
        </div>
      )}
      {micActive && camActive && <span style={{ color: '#4b1f1f', fontSize: 10 }}>|</span>}
      {camActive && (
        <div title={media.camera.join(', ')} style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: 'default' }}>
          <Camera size={11} color="var(--red-text)" />
          <span style={{ fontSize: 10, color: 'var(--red-text)' }}>{media.camera[0]}</span>
        </div>
      )}
    </div>
  )
}

/** EN: Dropdown listing detected processes — toggling one hides its traffic
 *      from capture (server-side) and from the graph (client-side).
 *  FR: Menu listant les processus détectés — en cocher un masque son trafic
 *      de la capture (côté serveur) et du graphe (côté client). */
function ProcessFilter({ excluded, onChange, nodes }) {
  const { t } = useT()

  // EN: Union of every process name seen on any node.
  // FR: Union de tous les noms de processus vus sur les nœuds.
  const allProcesses = useMemo(() => {
    const set = new Set()
    Object.values(nodes).forEach(n => {
      if (n.processes) Object.keys(n.processes).forEach(p => set.add(p))
    })
    return Array.from(set).sort()
  }, [nodes])

  function toggle(proc) {
    onChange(excluded.includes(proc)
      ? excluded.filter(p => p !== proc)
      : [...excluded, proc]
    )
  }

  const active = excluded.length > 0

  return (
    <Dropdown
      panelStyle={{ padding: 12, minWidth: 220, maxHeight: 300, overflowY: 'auto' }}
      button={
        <button style={{
          display: 'flex', alignItems: 'center', gap: 6,
          background: active ? 'var(--danger-active)' : 'var(--surface)',
          border: `1px solid ${active ? 'var(--red-text)' : 'var(--border)'}`,
          borderRadius: 20, padding: '5px 14px',
          cursor: 'pointer', color: active ? 'var(--red-text)' : 'var(--text-muted)',
          fontSize: 11, fontWeight: 600, transition: 'all 0.15s',
        }}>
          {t('process_filter')}
          {active && (
            <span style={{
              background: '#ef4444', color: '#fff',
              borderRadius: 10, padding: '0 6px', fontSize: 10,
            }}>{excluded.length}</span>
          )}
        </button>
      }
    >
      <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 8 }}>
        {t('process_filter_hint')}
      </div>

      {allProcesses.length === 0 && (
        <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>{t('process_none')}</div>
      )}

      {allProcesses.map(proc => {
        const isExcluded = excluded.includes(proc)
        return (
          <div key={proc} onClick={() => toggle(proc)} style={{
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '5px 6px', borderRadius: 6, cursor: 'pointer',
            background: isExcluded ? 'var(--danger-bg)' : 'transparent',
            marginBottom: 2,
          }}>
            <div style={{
              width: 12, height: 12, borderRadius: 3, flexShrink: 0,
              border: `1px solid ${isExcluded ? '#ef4444' : 'var(--text-faint)'}`,
              background: isExcluded ? '#ef4444' : 'transparent',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              {isExcluded && <span style={{ color: '#fff', fontSize: 9, lineHeight: 1 }}>✕</span>}
            </div>
            <span style={{ fontSize: 11, color: isExcluded ? 'var(--red-text)' : 'var(--text)' }}>
              {proc}
            </span>
          </div>
        )
      })}

      {active && (
        <button onClick={() => onChange([])} style={{
          marginTop: 8, width: '100%', background: 'none',
          border: '1px solid var(--border)', borderRadius: 6,
          padding: '4px 0', color: 'var(--text-muted)', fontSize: 10,
          cursor: 'pointer',
        }}>
          {t('process_clear')}
        </button>
      )}
    </Dropdown>
  )
}

/** EN: Port filter chip — restricts capture to the listed ports.
 *  FR: Puce de filtre de ports — restreint la capture aux ports listés. */
function PortFilter({ ports, onUpdate }) {
  const { t } = useT()
  const [input, setInput] = useState('')
  const [error, setError] = useState(false)

  function addPort(e) {
    e.preventDefault()
    const p = parseInt(input, 10)
    if (!p || p < 1 || p > 65535) { setError(true); return }
    if (ports.includes(p)) { setInput(''); return }
    setError(false)
    setInput('')
    onUpdate([...ports, p])
  }

  function removePort(p) {
    onUpdate(ports.filter(x => x !== p))
  }

  const active = ports.length > 0

  return (
    <Dropdown
      panelStyle={{ padding: 12, minWidth: 220 }}
      button={
        <button style={{
          display: 'flex', alignItems: 'center', gap: 6,
          background: active ? 'var(--surface-2)' : 'var(--surface)',
          border: `1px solid ${active ? '#3b82f6' : 'var(--border)'}`,
          borderRadius: 20, padding: '5px 14px',
          cursor: 'pointer', color: active ? 'var(--blue-text)' : 'var(--text-muted)',
          fontSize: 11, fontWeight: 600, transition: 'all 0.15s',
        }}>
          <Filter size={11} />
          {t('port_filter')}
          {active && (
            <span style={{
              background: '#3b82f6', color: '#fff',
              borderRadius: 10, padding: '0 6px', fontSize: 10,
            }}>{ports.length}</span>
          )}
        </button>
      }
    >
      <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 8 }}>
        {active ? `${ports.length} port${ports.length > 1 ? 's' : ''}` : t('port_all')}
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: ports.length ? 10 : 0 }}>
        {ports.map(p => (
          <span key={p} style={{
            display: 'flex', alignItems: 'center', gap: 4,
            background: 'var(--bg)', border: '1px solid #3b82f6',
            borderRadius: 12, padding: '2px 8px',
            fontSize: 11, color: 'var(--blue-text)',
          }}>
            {p}
            <button onClick={() => removePort(p)} style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'var(--text-muted)', padding: 0, lineHeight: 1, fontSize: 13,
            }}>×</button>
          </span>
        ))}
      </div>

      <form onSubmit={addPort} style={{ display: 'flex', gap: 6 }}>
        <input
          autoFocus
          value={input}
          onChange={e => { setInput(e.target.value); setError(false) }}
          placeholder={t('port_placeholder')}
          style={{
            flex: 1, background: 'var(--bg)',
            border: `1px solid ${error ? '#ef4444' : 'var(--border)'}`,
            borderRadius: 6, padding: '5px 8px',
            color: 'var(--text)', fontSize: 11, outline: 'none',
          }}
        />
        <button type="submit" style={{
          background: '#3b82f6', border: 'none', borderRadius: 6,
          padding: '5px 10px', color: '#fff', fontSize: 11,
          cursor: 'pointer', fontWeight: 600,
        }}>+</button>
      </form>
      {error && <div style={{ fontSize: 10, color: '#ef4444', marginTop: 4 }}>{t('port_invalid')}</div>}

      {active && (
        <button onClick={() => onUpdate([])} style={{
          marginTop: 10, width: '100%', background: 'none',
          border: '1px solid var(--border)', borderRadius: 6,
          padding: '4px 0', color: 'var(--text-muted)', fontSize: 10,
          cursor: 'pointer',
        }}>
          {t('port_all')}
        </button>
      )}
    </Dropdown>
  )
}

// EN: Basic IPv4 shape + range check. / FR: Vérification basique de forme et de plage IPv4.
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

function isValidIp(ip) {
  const m = ip.match(IPV4_RE)
  return !!m && m.slice(1).every(o => +o >= 0 && +o <= 255)
}

/** EN: Trusted-IP whitelist chip — listed IPs are dropped server-side.
 *  FR: Puce de liste blanche d'IP — les IP listées sont ignorées côté serveur. */
function IPWhitelist({ ips, onUpdate }) {
  const { t } = useT()
  const [input, setInput] = useState('')
  const [error, setError] = useState(false)

  function addIp(e) {
    e.preventDefault()
    const ip = input.trim()
    if (!isValidIp(ip)) { setError(true); return }
    if (ips.includes(ip)) { setInput(''); return }
    setError(false)
    setInput('')
    onUpdate([...ips, ip])
  }

  function removeIp(ip) {
    onUpdate(ips.filter(x => x !== ip))
  }

  const active = ips.length > 0

  return (
    <Dropdown
      panelStyle={{ padding: 12, minWidth: 220 }}
      button={
        <button style={{
          display: 'flex', alignItems: 'center', gap: 6,
          background: active ? 'var(--success-active)' : 'var(--surface)',
          border: `1px solid ${active ? '#22c55e' : 'var(--border)'}`,
          borderRadius: 20, padding: '5px 14px',
          cursor: 'pointer', color: active ? 'var(--green-text)' : 'var(--text-muted)',
          fontSize: 11, fontWeight: 600, transition: 'all 0.15s',
        }}>
          <ShieldOff size={11} />
          {t('ip_whitelist')}
          {active && (
            <span style={{
              background: '#22c55e', color: '#052e16',
              borderRadius: 10, padding: '0 6px', fontSize: 10,
            }}>{ips.length}</span>
          )}
        </button>
      }
    >
      <div style={{ fontSize: 11, color: 'var(--text-dim)', marginBottom: 8 }}>
        {t('ip_whitelist_hint')}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: ips.length ? 10 : 0 }}>
        {ips.map(ip => (
          <span key={ip} style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            background: 'var(--bg)', border: '1px solid #22c55e',
            borderRadius: 6, padding: '3px 8px',
            fontSize: 11, color: 'var(--green-text)', fontFamily: 'monospace',
          }}>
            {ip}
            <button onClick={() => removeIp(ip)} style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'var(--text-muted)', padding: 0, lineHeight: 1, fontSize: 13,
            }}>×</button>
          </span>
        ))}
      </div>

      <form onSubmit={addIp} style={{ display: 'flex', gap: 6 }}>
        <input
          autoFocus
          value={input}
          onChange={e => { setInput(e.target.value); setError(false) }}
          placeholder={t('ip_placeholder')}
          style={{
            flex: 1, background: 'var(--bg)',
            border: `1px solid ${error ? '#ef4444' : 'var(--border)'}`,
            borderRadius: 6, padding: '5px 8px',
            color: 'var(--text)', fontSize: 11, outline: 'none',
          }}
        />
        <button type="submit" style={{
          background: '#22c55e', border: 'none', borderRadius: 6,
          padding: '5px 10px', color: '#052e16', fontSize: 11,
          cursor: 'pointer', fontWeight: 600,
        }}>+</button>
      </form>
      {error && <div style={{ fontSize: 10, color: '#ef4444', marginTop: 4 }}>{t('ip_invalid')}</div>}

      {active && (
        <button onClick={() => onUpdate([])} style={{
          marginTop: 10, width: '100%', background: 'none',
          border: '1px solid var(--border)', borderRadius: 6,
          padding: '4px 0', color: 'var(--text-muted)', fontSize: 10,
          cursor: 'pointer',
        }}>
          {t('ip_clear')}
        </button>
      )}
    </Dropdown>
  )
}

/** EN: Start/stop capture button. / FR: Bouton démarrer/arrêter la capture. */
function CaptureToggle({ capturing, onToggle }) {
  const { t } = useT()
  const [loading, setLoading] = useState(false)

  async function handleClick() {
    setLoading(true)
    await onToggle()
    setLoading(false)
  }

  const label = loading
    ? (capturing ? t('capture_stopping') : t('capture_starting'))
    : (capturing ? t('capture_stop') : t('capture_start'))

  const Icon = capturing ? Square : Play

  return (
    <button onClick={handleClick} disabled={loading} style={{
      display: 'flex', alignItems: 'center', gap: 6,
      background: capturing ? 'var(--surface)' : '#166534',
      border: `1px solid ${capturing ? 'var(--border)' : '#16a34a'}`,
      borderRadius: 20, padding: '5px 14px',
      cursor: loading ? 'wait' : 'pointer',
      color: capturing ? 'var(--red-text)' : '#4ade80',
      fontSize: 11, fontWeight: 600,
      transition: 'all 0.15s',
      opacity: loading ? 0.7 : 1,
    }}>
      <Icon size={11} />
      {label}
    </button>
  )
}

/** EN: Light/dark theme toggle — persists to localStorage and flips the
 *     data-theme attribute read by the CSS in index.html. The boot script
 *     there already honours the OS preference when no choice is saved.
 *  FR: Bascule de thème clair/sombre — persistée dans localStorage et agit
 *     sur l'attribut data-theme lu par le CSS d'index.html. Le script de
 *     démarrage respecte déjà la préférence OS sans choix sauvegardé. */
function ThemeToggle() {
  const { t } = useT()
  const [theme, setTheme] = useState(
    () => document.documentElement.dataset.theme || 'dark')
  const toggle = () => {
    const next = theme === 'dark' ? 'light' : 'dark'
    document.documentElement.dataset.theme = next
    try { localStorage.setItem('snitch_theme', next) } catch (e) { /* ignore */ }
    setTheme(next)
    // EN: Let WebGL/canvas consumers re-resolve their palettes.
    // FR: Laisser les consommateurs WebGL/canvas re-résoudre leurs palettes.
    window.dispatchEvent(new Event('snitch-theme'))
  }
  const Icon = theme === 'dark' ? Sun : Moon
  return (
    <button onClick={toggle} title={t('theme_toggle')} style={{
      background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 20,
      cursor: 'pointer', color: 'var(--text-muted)',
      padding: '5px 10px', display: 'flex', alignItems: 'center',
      transition: 'background 0.15s',
    }}>
      <Icon size={13} />
    </button>
  )
}

/** EN: Language picker — a compact dropdown now that eight locales exist.
 *  FR: Sélecteur de langue — menu déroulant compact désormais que huit
 *      locales existent. */
function LangToggle() {
  const { lang, setLang } = useT()
  return (
    <select value={lang} onChange={e => setLang(e.target.value)}
      aria-label="Language / Langue" style={{
        background: 'var(--surface)', border: '1px solid var(--border)',
        borderRadius: 20, color: 'var(--text-muted)',
        padding: '5px 10px', fontSize: 11, fontWeight: 600,
        cursor: 'pointer', outline: 'none',
      }}>
      {LANGS.map(l => (
        <option key={l} value={l}>{LANG_NAMES[l]}</option>
      ))}
    </select>
  )
}

/** EN: Graph/map view switcher. / FR: Bascule entre vue graphe et carte. */
function ViewToggle({ view, onChange }) {
  const { t } = useT()
  const items = [
    { id: 'graph', Icon: Hexagon,   label: t('nav_graph') },
    { id: 'map',   Icon: Globe,     label: t('nav_map')   },
    { id: 'apps',  Icon: AppWindow, label: t('nav_apps')  },
  ]
  return (
    <div style={{
      display: 'flex', background: 'var(--surface)',
      border: '1px solid var(--border)', borderRadius: 20, overflow: 'hidden',
    }}>
      {items.map(({ id, Icon, label }) => (
        <button key={id} onClick={() => onChange(id)} style={{
          background: view === id ? '#3b82f6' : 'transparent',
          border: 'none', cursor: 'pointer',
          color: view === id ? '#fff' : 'var(--text-muted)',
          padding: '5px 14px', fontSize: 11, fontWeight: 600,
          display: 'flex', alignItems: 'center', gap: 5,
          transition: 'background 0.15s',
        }}>
          <Icon size={12} /> {label}
        </button>
      ))}
    </div>
  )
}

/** EN: Network-context chip — current Wi-Fi SSID when known, otherwise the
 *      capture interface name. Lets the user see "hotel wifi" vs "home" and
 *      which adapter is sniffed, at a glance. Renders nothing when neither
 *      is known.
 *  FR: Pastille de contexte réseau — SSID Wi-Fi courant quand il est connu,
 *      sinon le nom de l'interface de capture. Permet de voir « wifi hôtel »
 *      vs « maison » et quelle carte est écoutée, d'un coup d'œil. Ne rend
 *      rien quand ni l'un ni l'autre n'est connu. */
function NetworkBadge({ ssid, iface }) {
  const label = ssid || iface
  if (!label) return null
  return (
    <div title={ssid ? `${iface || ''} · ${ssid}` : iface} style={{
      display: 'flex', alignItems: 'center', gap: 6,
      background: 'var(--surface)', border: '1px solid var(--border)',
      borderRadius: 20, padding: '5px 12px', cursor: 'default',
      maxWidth: 180, overflow: 'hidden',
    }}>
      <Wifi size={11} color="var(--text-muted)" />
      <span style={{
        fontSize: 10, color: 'var(--text-muted)', fontWeight: 600,
        whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden',
      }}>{label}</span>
    </div>
  )
}

/** EN: Fatal capture failure banner — pcap died (no privileges, missing
 *      Npcap, unplugged interface) while the UI kept saying "capturing".
 *      Shows the raw libpcap message plus the fix hint.
 *  FR: Bannière d'échec fatal de capture — pcap est mort (droits manquants,
 *      Npcap absent, interface débranchée) alors que l'UI continuait
 *      d'afficher « capture en cours ». Affiche le message libpcap brut plus
 *      l'indice de résolution. */
function CaptureErrorBanner({ error }) {
  const { t } = useT()
  return (
    <div role="alert" style={{
      position: 'absolute', top: 16, left: '50%', transform: 'translateX(-50%)',
      zIndex: 60, maxWidth: 620,
      background: 'var(--surface)', border: '1px solid #ef4444',
      borderRadius: 10, padding: '10px 16px',
      display: 'flex', alignItems: 'flex-start', gap: 10,
      boxShadow: '0 4px 24px rgba(0,0,0,0.35)',
    }}>
      <AlertTriangle size={16} color="#ef4444" style={{ flexShrink: 0, marginTop: 2 }} />
      <div>
        <div style={{ fontSize: 12, fontWeight: 600, color: '#ef4444' }}>{t('capture_error_title')}</div>
        <div style={{ fontSize: 11, color: 'var(--text)', marginTop: 2, wordBreak: 'break-word' }}>{error}</div>
        <div style={{ fontSize: 11, color: 'var(--text-dim)', marginTop: 4 }}>{t('capture_error_hint')}</div>
      </div>
    </div>
  )
}

/** EN: WebSocket status badge.
 *  FR: Badge de statut WebSocket. */
function StatusBadge({ status }) {
  const { t } = useT()
  const colors = { connected: '#22c55e', connecting: '#f59e0b', disconnected: '#ef4444', error: '#ef4444' }
  const labels = {
    connected:    t('status_connected'),
    connecting:   t('status_connecting'),
    disconnected: t('status_disconnected'),
    error:        t('status_error'),
  }
  return (
    <div style={{
      background: 'var(--surface)', border: '1px solid var(--border)',
      borderRadius: 20, padding: '5px 14px',
      display: 'flex', alignItems: 'center', gap: 8,
    }}>
      <div style={{ width: 7, height: 7, borderRadius: '50%', background: colors[status] || 'var(--text-dim)' }} />
      <span style={{ fontSize: 11, color: 'var(--text)' }}>{labels[status] || status}</span>
    </div>
  )
}

/** EN: Bottom-right color legend for node categories.
 *  FR: Légende de couleurs en bas à droite pour les catégories de nœuds. */
function Legend() {
  const { t } = useT()
  const items = [
    { Icon: Wifi,          color: '#f97316', label: t('legend_router')   },
    { Icon: Smartphone,    color: '#a855f7', label: t('legend_phone')    },
    { Icon: Monitor,       color: '#06b6d4', label: t('legend_pc')       },
    { Icon: Cpu,           color: '#84cc16', label: t('legend_iot')      },
    { Icon: ShieldCheck,   color: '#22c55e', label: t('legend_https')    },
    { Icon: Radio,         color: '#f59e0b', label: t('legend_tracking') },
    { Icon: Zap,           color: '#6366f1', label: t('legend_cdn')      },
    { Icon: Globe,         color: '#38bdf8', label: t('legend_dns')      },
    { Icon: AlertTriangle, color: '#ef4444', label: t('legend_alert') },
    { Icon: HelpCircle,    color: 'var(--text-dim)', label: t('legend_unknown') },
  ]
  return (
    <div style={{
      width: '100%', boxSizing: 'border-box',
      background: 'var(--surface)', border: '1px solid var(--border)',
      borderRadius: 12, padding: '10px 14px',
    }}>
      {items.map(({ Icon, color, label }) => (
        <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <Icon size={12} color={color} />
          <span style={{ fontSize: 10, color: 'var(--text-dim)' }}>{label}</span>
        </div>
      ))}
      {/* EN: Edge semantics — the dashed/solid distinction is what tells a
              newcomer "seen" from "actually exchanging data".
          FR: Sémantique des arêtes — la distinction pointillés/plein dit au
              néophyte « vu » versus « échange réel de données ». */}
      <div style={{ borderTop: '1px solid var(--border)', marginTop: 6, paddingTop: 6 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <span style={{ width: 14, borderTop: '2px solid var(--text-muted)', flexShrink: 0 }} />
          <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>{t('legend_edge_solid')}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ width: 14, borderTop: '2px dashed var(--text-muted)', flexShrink: 0 }} />
          <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>{t('legend_edge_dashed')}</span>
        </div>
      </div>
      {/* EN: Ring semantics — the colored halo around a node is the safety
              verdict at a glance: green = known & quiet, amber/red pulsing
              = something to look at. Matches paintAlertRings in ForceGraph.
          FR: Sémantique des anneaux — le halo coloré autour d'un nœud est
              le verdict de sûreté d'un coup d'œil : vert = connu et calme,
              orange/rouge pulsant = à regarder. Correspond à
              paintAlertRings dans ForceGraph. */}
      <div style={{ borderTop: '1px solid var(--border)', marginTop: 6, paddingTop: 6 }}>
        {[
          { color: '#22c55e', label: t('legend_ring_safe') },
          { color: '#f59e0b', label: t('legend_ring_warn') },
          { color: '#ef4444', label: t('legend_ring_crit') },
          // EN: A dashed gray swatch for the ABSENCE of ring — unidentified
          //     or simply unremarkable devices wear no verdict at all.
          // FR: Une pastille grise en pointillés pour l'ABSENCE d'anneau —
          //     les appareils non identifiés ou sans particularité ne
          //     portent aucun verdict.
          { color: 'var(--text-faint)', label: t('legend_ring_none'), dashed: true },
          // EN: Dashed orange swatch = the LAN perimeter circle.
          // FR: Pastille orange en pointillés = le cercle du périmètre LAN.
          { color: '#f97316', label: t('legend_perimeter'), dashed: true },
        ].map(({ color, label, dashed }) => (
          <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span style={{
              width: 10, height: 10, borderRadius: '50%', flexShrink: 0,
              border: `1.5px ${dashed ? 'dashed' : 'solid'} ${color}`,
            }} />
            <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>{label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
