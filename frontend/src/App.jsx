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
import { Hexagon, Globe, Wifi, Smartphone, Monitor, Cpu, ShieldCheck, Radio, Zap, HelpCircle, AlertTriangle, Square, Play, Filter, Mic, Camera, Download, ShieldOff, AppWindow } from 'lucide-react'
import ForceGraph from './graph/ForceGraph'
import AuroraCurtain from './components/AuroraCurtain'
import MapView from './map/MapView'
import AppsView from './components/AppsView'
import Sidebar from './components/Sidebar'
import { AlertBell, AlertPanel, AlertToasts } from './components/AlertPanel'
import { SettingsButton, SettingsPanel } from './components/Settings'
import Onboarding from './components/Onboarding'
import Timeline from './components/Timeline'
import Dropdown from './components/Dropdown'
import { apiBase, authHeaders } from './api'
import { useWebSocket } from './hooks/useWebSocket'
import { computePrivacyScore } from './scoring/privacy'
// EN: WS URL is resolved dynamically (port + ws/wss) via api.js wsBase().
// FR: L'URL WS est résolue dynamiquement (port + ws/wss) via wsBase() d'api.js.
import { useT } from './i18n'

export default function App() {
  const { nodes, edges, lanDevices, packets, alerts, unread, clearUnread, status, bandwidth, capturing, toggleCapture, portFilter, updatePortFilter, excludedProcesses, updateProcessFilter, whitelistedIps, updateIpWhitelist, media } = useWebSocket(null)  // EN: null → resolves the dynamic port/scheme via wsBase()
                    // FR: null → résout port/schéma dynamiques via wsBase()
  const [selected, setSelected] = useState(null)
  const [view, setView] = useState('graph')
  const [showAlerts, setShowAlerts] = useState(false)
  const [showSettings, setShowSettings] = useState(false)
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

  // EN: When processes are excluded, hide nodes whose traffic comes ONLY from
  //     excluded apps — keeps the graph honest about what's filtered.
  // FR: Quand des processus sont exclus, masquer les nœuds dont le trafic vient
  //     UNIQUEMENT d'apps exclues — le graphe reflète honnêtement le filtre.
  const filteredNodes = useMemo(() => {
    if (excludedProcesses.length === 0) return nodes
    const out = {}
    for (const [id, node] of Object.entries(nodes)) {
      if (id === 'local') { out[id] = node; continue }
      const procs = node.processes ? Object.keys(node.processes) : []
      if (procs.length > 0 && procs.every(p => excludedProcesses.includes(p))) continue
      out[id] = node
    }
    return out
  }, [nodes, excludedProcesses])

  const filteredEdges = useMemo(() => {
    if (excludedProcesses.length === 0) return edges
    const visibleIds = new Set([...Object.keys(filteredNodes), ...Object.keys(lanDevices)])
    const out = {}
    for (const [id, edge] of Object.entries(edges)) {
      if (visibleIds.has(edge.source) && visibleIds.has(edge.target)) out[id] = edge
    }
    return out
  }, [edges, filteredNodes, lanDevices, excludedProcesses])

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
    <div style={{ display: 'flex', height: '100vh', width: '100vw', overflow: 'hidden' }}>
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
      />

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ flex: 1, position: 'relative', overflow: 'hidden', background: '#0f172a' }}>
          {view === 'graph' && (
            /* EN: Aurora backdrop behind the graph — orange/pink ribbons,
                   fine film grain (0.35), dimmed to 55% so nodes and edges
                   stay perfectly readable.
               FR: Toile de fond aurore derrière le graphe — rubans
                   orangés/rosés, grain de film fin (0.35), atténuée à 55 %
                   pour que nœuds et arêtes restent parfaitement lisibles. */
            <AuroraCurtain
              bands={5}
              noise={0.35}
              intensity={0.55}
              speed={0.7}
              colors={['#fb923c', '#f472b6', '#e879f9']}
              style={{ position: 'absolute', inset: 0 }}
            >
              <ForceGraph
                nodes={filteredNodes}
                edges={filteredEdges}
                lanDevices={lanDevices}
                alertedNodes={alertedNodes}
                onNodeClick={setSelected}
                filter={filter}
              />
            </AuroraCurtain>
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
            <LangToggle />
            <ViewToggle view={view} onChange={setView} />
            <ExportButton nodes={nodes} edges={edges} lanDevices={lanDevices} alerts={alerts} />
            <ProcessFilter excluded={excludedProcesses} onChange={updateProcessFilter} nodes={nodes} />
            <PortFilter ports={portFilter} onUpdate={updatePortFilter} />
            <IPWhitelist ips={whitelistedIps} onUpdate={updateIpWhitelist} />
            <CaptureToggle capturing={capturing} onToggle={toggleCapture} />
            <AlertBell unread={unread} onClick={handleBell} />
            <SettingsButton onClick={() => setShowSettings(v => !v)} />
            <StatusBadge status={status} lanCount={Object.keys(lanDevices).length} />
          </div>

          {showAlerts && (
            <AlertPanel alerts={alerts} onClose={() => setShowAlerts(false)} onIgnore={handleIgnoreAlert} />
          )}

          {showSettings && (
            <SettingsPanel onClose={() => setShowSettings(false)} lang={lang} setLang={setLang} />
          )}

          {showOnboarding && <Onboarding onDone={() => setShowOnboarding(false)} />}

          {/* EN: Floating toasts for warning/critical alerts.
              FR: Toasts flottants pour les alertes warning/critiques. */}
          <AlertToasts alerts={alerts.filter(a => a.severity !== 'info').slice(0, 3)} />

          {view === 'graph' && <Legend />}
        </div>

        <Timeline />
      </div>
    </div>
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
          background: '#1e293b', border: '1px solid #334155',
          borderRadius: 20, padding: '5px 14px',
          cursor: 'pointer', color: '#64748b',
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
          background: 'none', border: 'none', borderBottom: '1px solid #0f172a',
          padding: '9px 14px', color: '#e2e8f0',
          fontSize: 11, cursor: 'pointer',
        }}
        onMouseEnter={e => e.target.style.background = '#334155'}
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
      background: '#2d1b1b', border: '1px solid #ef4444',
      borderRadius: 20, padding: '5px 12px',
    }}>
      {micActive && (
        <div title={media.mic.join(', ')} style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: 'default' }}>
          <Mic size={11} color="#f87171" />
          <span style={{ fontSize: 10, color: '#fca5a5' }}>{media.mic[0]}</span>
        </div>
      )}
      {micActive && camActive && <span style={{ color: '#4b1f1f', fontSize: 10 }}>|</span>}
      {camActive && (
        <div title={media.camera.join(', ')} style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: 'default' }}>
          <Camera size={11} color="#f87171" />
          <span style={{ fontSize: 10, color: '#fca5a5' }}>{media.camera[0]}</span>
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
          background: active ? '#3b1f2b' : '#1e293b',
          border: `1px solid ${active ? '#f87171' : '#334155'}`,
          borderRadius: 20, padding: '5px 14px',
          cursor: 'pointer', color: active ? '#fca5a5' : '#64748b',
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
      <div style={{ fontSize: 11, color: '#94a3b8', marginBottom: 8 }}>
        {t('process_filter_hint')}
      </div>

      {allProcesses.length === 0 && (
        <div style={{ fontSize: 11, color: '#475569' }}>{t('process_none')}</div>
      )}

      {allProcesses.map(proc => {
        const isExcluded = excluded.includes(proc)
        return (
          <div key={proc} onClick={() => toggle(proc)} style={{
            display: 'flex', alignItems: 'center', gap: 8,
            padding: '5px 6px', borderRadius: 6, cursor: 'pointer',
            background: isExcluded ? '#2d1b1b' : 'transparent',
            marginBottom: 2,
          }}>
            <div style={{
              width: 12, height: 12, borderRadius: 3, flexShrink: 0,
              border: `1px solid ${isExcluded ? '#ef4444' : '#475569'}`,
              background: isExcluded ? '#ef4444' : 'transparent',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              {isExcluded && <span style={{ color: '#fff', fontSize: 9, lineHeight: 1 }}>✕</span>}
            </div>
            <span style={{ fontSize: 11, color: isExcluded ? '#fca5a5' : '#e2e8f0' }}>
              {proc}
            </span>
          </div>
        )
      })}

      {active && (
        <button onClick={() => onChange([])} style={{
          marginTop: 8, width: '100%', background: 'none',
          border: '1px solid #334155', borderRadius: 6,
          padding: '4px 0', color: '#64748b', fontSize: 10,
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
          background: active ? '#1e3a5f' : '#1e293b',
          border: `1px solid ${active ? '#3b82f6' : '#334155'}`,
          borderRadius: 20, padding: '5px 14px',
          cursor: 'pointer', color: active ? '#93c5fd' : '#64748b',
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
      <div style={{ fontSize: 11, color: '#94a3b8', marginBottom: 8 }}>
        {active ? `${ports.length} port${ports.length > 1 ? 's' : ''}` : t('port_all')}
      </div>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginBottom: ports.length ? 10 : 0 }}>
        {ports.map(p => (
          <span key={p} style={{
            display: 'flex', alignItems: 'center', gap: 4,
            background: '#0f172a', border: '1px solid #3b82f6',
            borderRadius: 12, padding: '2px 8px',
            fontSize: 11, color: '#93c5fd',
          }}>
            {p}
            <button onClick={() => removePort(p)} style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: '#64748b', padding: 0, lineHeight: 1, fontSize: 13,
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
            flex: 1, background: '#0f172a',
            border: `1px solid ${error ? '#ef4444' : '#334155'}`,
            borderRadius: 6, padding: '5px 8px',
            color: '#e2e8f0', fontSize: 11, outline: 'none',
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
          border: '1px solid #334155', borderRadius: 6,
          padding: '4px 0', color: '#64748b', fontSize: 10,
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
          background: active ? '#153824' : '#1e293b',
          border: `1px solid ${active ? '#22c55e' : '#334155'}`,
          borderRadius: 20, padding: '5px 14px',
          cursor: 'pointer', color: active ? '#86efac' : '#64748b',
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
      <div style={{ fontSize: 11, color: '#94a3b8', marginBottom: 8 }}>
        {t('ip_whitelist_hint')}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: ips.length ? 10 : 0 }}>
        {ips.map(ip => (
          <span key={ip} style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            background: '#0f172a', border: '1px solid #22c55e',
            borderRadius: 6, padding: '3px 8px',
            fontSize: 11, color: '#86efac', fontFamily: 'monospace',
          }}>
            {ip}
            <button onClick={() => removeIp(ip)} style={{
              background: 'none', border: 'none', cursor: 'pointer',
              color: '#64748b', padding: 0, lineHeight: 1, fontSize: 13,
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
            flex: 1, background: '#0f172a',
            border: `1px solid ${error ? '#ef4444' : '#334155'}`,
            borderRadius: 6, padding: '5px 8px',
            color: '#e2e8f0', fontSize: 11, outline: 'none',
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
          border: '1px solid #334155', borderRadius: 6,
          padding: '4px 0', color: '#64748b', fontSize: 10,
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
      background: capturing ? '#1e293b' : '#166534',
      border: `1px solid ${capturing ? '#334155' : '#16a34a'}`,
      borderRadius: 20, padding: '5px 14px',
      cursor: loading ? 'wait' : 'pointer',
      color: capturing ? '#f87171' : '#4ade80',
      fontSize: 11, fontWeight: 600,
      transition: 'all 0.15s',
      opacity: loading ? 0.7 : 1,
    }}>
      <Icon size={11} />
      {label}
    </button>
  )
}

/** EN: EN/FR language toggle — the headline feature.
 *  FR: Bascule de langue EN/FR — la fonctionnalité vedette. */
function LangToggle() {
  const { lang, setLang } = useT()
  return (
    <div style={{
      display: 'flex', background: '#1e293b',
      border: '1px solid #334155', borderRadius: 20, overflow: 'hidden',
    }}>
      {['en', 'fr'].map(l => (
        <button key={l} onClick={() => setLang(l)} style={{
          background: lang === l ? '#3b82f6' : 'transparent',
          border: 'none', cursor: 'pointer',
          color: lang === l ? '#fff' : '#64748b',
          padding: '5px 12px', fontSize: 11, fontWeight: 600,
          textTransform: 'uppercase',
          transition: 'background 0.15s',
        }}>
          {l}
        </button>
      ))}
    </div>
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
      display: 'flex', background: '#1e293b',
      border: '1px solid #334155', borderRadius: 20, overflow: 'hidden',
    }}>
      {items.map(({ id, Icon, label }) => (
        <button key={id} onClick={() => onChange(id)} style={{
          background: view === id ? '#3b82f6' : 'transparent',
          border: 'none', cursor: 'pointer',
          color: view === id ? '#fff' : '#64748b',
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

/** EN: WebSocket status badge + LAN device count.
 *  FR: Badge de statut WebSocket + compteur d'appareils LAN. */
function StatusBadge({ status, lanCount }) {
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
      background: '#1e293b', border: '1px solid #334155',
      borderRadius: 20, padding: '5px 14px',
      display: 'flex', alignItems: 'center', gap: 8,
    }}>
      <div style={{ width: 7, height: 7, borderRadius: '50%', background: colors[status] || '#94a3b8' }} />
      <span style={{ fontSize: 11, color: '#e2e8f0' }}>{labels[status] || status}</span>
      {lanCount > 0 && (
        <span style={{ fontSize: 11, color: '#f97316', borderLeft: '1px solid #334155', paddingLeft: 8 }}>
          {t('lan_devices', lanCount)}
        </span>
      )}
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
    { Icon: HelpCircle,    color: '#94a3b8', label: t('legend_unknown') },
  ]
  return (
    <div style={{
      position: 'absolute', bottom: 16, right: 16,
      background: '#1e293b', border: '1px solid #334155',
      borderRadius: 8, padding: '10px 14px',
    }}>
      {items.map(({ Icon, color, label }) => (
        <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <Icon size={12} color={color} />
          <span style={{ fontSize: 10, color: '#94a3b8' }}>{label}</span>
        </div>
      ))}
      {/* EN: Edge semantics — the dashed/solid distinction is what tells a
              newcomer "seen" from "actually exchanging data".
          FR: Sémantique des arêtes — la distinction pointillés/plein dit au
              néophyte « vu » versus « échange réel de données ». */}
      <div style={{ borderTop: '1px solid #334155', marginTop: 6, paddingTop: 6 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <span style={{ width: 14, borderTop: '2px solid #64748b', flexShrink: 0 }} />
          <span style={{ fontSize: 9, color: '#64748b' }}>{t('legend_edge_solid')}</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ width: 14, borderTop: '2px dashed #64748b', flexShrink: 0 }} />
          <span style={{ fontSize: 9, color: '#64748b' }}>{t('legend_edge_dashed')}</span>
        </div>
      </div>
      {/* EN: Ring semantics — the colored halo around a node is the safety
              verdict at a glance: green = known & quiet, amber/red pulsing
              = something to look at. Matches paintAlertRings in ForceGraph.
          FR: Sémantique des anneaux — le halo coloré autour d'un nœud est
              le verdict de sûreté d'un coup d'œil : vert = connu et calme,
              orange/rouge pulsant = à regarder. Correspond à
              paintAlertRings dans ForceGraph. */}
      <div style={{ borderTop: '1px solid #334155', marginTop: 6, paddingTop: 6 }}>
        {[
          { color: '#22c55e', label: t('legend_ring_safe') },
          { color: '#f59e0b', label: t('legend_ring_warn') },
          { color: '#ef4444', label: t('legend_ring_crit') },
          // EN: A dashed gray swatch for the ABSENCE of ring — unidentified
          //     or simply unremarkable devices wear no verdict at all.
          // FR: Une pastille grise en pointillés pour l'ABSENCE d'anneau —
          //     les appareils non identifiés ou sans particularité ne
          //     portent aucun verdict.
          { color: '#475569', label: t('legend_ring_none'), dashed: true },
        ].map(({ color, label, dashed }) => (
          <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span style={{
              width: 10, height: 10, borderRadius: '50%', flexShrink: 0,
              border: `1.5px ${dashed ? 'dashed' : 'solid'} ${color}`,
            }} />
            <span style={{ fontSize: 9, color: '#64748b' }}>{label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
