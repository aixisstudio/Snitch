/**
 * Snitch — per-application view.
 *
 * EN: Aggregates live node "processes" maps into a per-process table:
 *     destinations reached, volumes, and a click-through to per-process
 *     history (bytes/minute from the /history/process endpoint).
 * FR: Agrège les tables « processes » des nœuds en un tableau par processus :
 *     destinations jointes, volumes, et historique par processus au clic
 *     (octets/minute depuis l'endpoint /history/process).
 */
import { useState, useEffect, useMemo, Fragment } from 'react'
import { useT } from '../i18n'
import { apiBase, authHeaders } from '../api'

function fmtBytes(b) {
  if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB'
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB'
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB'
  return b + ' B'
}

export default function AppsView({ nodes }) {
  const { t } = useT()
  const [expanded, setExpanded] = useState(null)
  const [history, setHistory] = useState([])

  // EN: Per-process rollup across all nodes.
  // FR: Agrégat par processus sur tous les nœuds.
  const apps = useMemo(() => {
    const map = {}
    for (const node of Object.values(nodes)) {
      if (!node.processes) continue
      for (const [proc, stats] of Object.entries(node.processes)) {
        const a = map[proc] ||= { name: proc, bytes: 0, packets: 0, destinations: [] }
        a.bytes += stats.bytes
        a.packets += stats.packets
        a.destinations.push({ ip: node.ip, label: node.label, bytes: stats.bytes })
      }
    }
    for (const a of Object.values(map)) {
      a.destinations.sort((x, y) => y.bytes - x.bytes)
    }
    return Object.values(map).sort((x, y) => y.bytes - x.bytes)
  }, [nodes])

  useEffect(() => {
    if (!expanded) { setHistory([]); return }
    ;(async () => {
      try {
        const base = await apiBase()
        const res = await fetch(
          `${base}/history/process/${encodeURIComponent(expanded)}?minutes=60`,
          { headers: await authHeaders() }).then(r => r.json())
        setHistory(res.history || [])
      } catch { setHistory([]) }
    })()
  }, [expanded])

  if (apps.length === 0) {
    return <div style={{ padding: 40, textAlign: 'center', color: '#64748b', fontSize: 12 }}>{t('apps_empty')}</div>
  }

  const maxBytes = apps[0].bytes || 1
  const maxHist = Math.max(...history.map(h => h.bytes), 1)

  return (
    <div style={{ height: '100%', overflowY: 'auto', padding: '16px 24px' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
        <thead>
          <tr style={{ color: '#64748b', fontSize: 10, textTransform: 'uppercase', letterSpacing: 0.5 }}>
            <th style={{ textAlign: 'left', padding: '6px 8px' }}>{t('apps_process')}</th>
            <th style={{ textAlign: 'right', padding: '6px 8px' }}>{t('apps_destinations')}</th>
            <th style={{ textAlign: 'right', padding: '6px 8px' }}>{t('apps_packets')}</th>
            <th style={{ textAlign: 'left', padding: '6px 8px', width: '40%' }}>{t('apps_volume')}</th>
          </tr>
        </thead>
        <tbody>
          {apps.map(app => (
            <Fragment key={app.name}>
              <tr
                onClick={() => setExpanded(expanded === app.name ? null : app.name)}
                style={{ cursor: 'pointer', borderTop: '1px solid #0f0f0f' }}
              >
                <td style={{ padding: '8px', color: '#e2e8f0', fontFamily: 'monospace' }}>{app.name}</td>
                <td style={{ padding: '8px', textAlign: 'right', color: '#94a3b8' }}>{app.destinations.length}</td>
                <td style={{ padding: '8px', textAlign: 'right', color: '#94a3b8' }}>{app.packets}</td>
                <td style={{ padding: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div style={{ flex: 1, height: 6, background: '#000000', borderRadius: 3, overflow: 'hidden' }}>
                      <div style={{ width: `${(app.bytes / maxBytes) * 100}%`, height: '100%', background: '#3b82f6' }} />
                    </div>
                    <span style={{ color: '#94a3b8', minWidth: 60, textAlign: 'right' }}>{fmtBytes(app.bytes)}</span>
                  </div>
                </td>
              </tr>
              {expanded === app.name && (
                <tr>
                  <td colSpan={4} style={{ padding: '8px 8px 16px 24px', background: '#000000' }}>
                    <div style={{ fontSize: 10, color: '#64748b', marginBottom: 6 }}>{t('apps_top_dest')}</div>
                    {app.destinations.slice(0, 5).map(d => (
                      <div key={d.ip} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: '#94a3b8', padding: '2px 0' }}>
                        <span style={{ fontFamily: 'monospace' }}>{d.label || d.ip}</span>
                        <span>{fmtBytes(d.bytes)}</span>
                      </div>
                    ))}
                    {history.length > 0 && (
                      <>
                        <div style={{ fontSize: 10, color: '#64748b', margin: '10px 0 6px' }}>{t('apps_history_60m')}</div>
                        <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height: 40 }}>
                          {history.slice(-30).map((h, i) => (
                            <div key={i} title={`${h.minute} — ${fmtBytes(h.bytes)}`}
                              style={{ flex: 1, background: '#3b82f6', height: `${(h.bytes / maxHist) * 100}%`, minHeight: 1, borderRadius: 1 }} />
                          ))}
                        </div>
                      </>
                    )}
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  )
}
