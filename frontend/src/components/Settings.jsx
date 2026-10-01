/**
 * Snitch — settings panel.
 *
 * EN: A slide-over panel for persisted settings: language, port filter,
 *     excluded processes, IP whitelist, retention hours, and the opt-in
 *     GeoIP database download (the app's ONLY outbound call — requires an
 *     explicit click + consent flag). Under Electron, an "Open logs" action
 *     reaches the preload bridge.
 * FR: Panneau latéral pour les réglages persistés : langue, filtre de ports,
 *     processus exclus, whitelist IP, durée de rétention, et le téléchargement
 *     opt-in de la base GeoIP (le SEUL appel sortant de l'app — exige un clic
 *     explicite + le drapeau consent). Sous Electron, « Ouvrir les logs »
 *     passe par le pont preload.
 */
import { useState, useEffect } from 'react'
import { Settings as SettingsIcon, X, FolderOpen, Download, ShieldCheck } from 'lucide-react'
import { useT } from '../i18n'
import { apiBase, authHeaders } from '../api'

export function SettingsButton({ onClick }) {
  return (
    <button onClick={onClick} aria-label="Settings / Réglages" style={{
      display: 'flex', alignItems: 'center', gap: 6,
      background: '#1e293b', border: '1px solid #334155',
      borderRadius: 20, padding: '5px 14px',
      cursor: 'pointer', color: '#64748b',
      fontSize: 11, fontWeight: 600,
    }}>
      <SettingsIcon size={11} />
    </button>
  )
}

export function SettingsPanel({ onClose, lang, setLang }) {
  const { t } = useT()
  const [settings, setSettings] = useState(null)
  const [retention, setRetention] = useState(24)
  const [geoStatus, setGeoStatus] = useState(null)
  const [geoMsg, setGeoMsg] = useState('')
  const [saved, setSaved] = useState(false)
  const [autoLaunch, setAutoLaunch] = useState(false)

  useEffect(() => {
    ;(async () => {
      const base = await apiBase()
      const headers = await authHeaders()
      try {
        const [s, g] = await Promise.all([
          fetch(`${base}/settings`, { headers }).then(r => r.json()),
          fetch(`${base}/geo/status`, { headers }).then(r => r.json()),
        ])
        setSettings(s.settings || {})
        setRetention(s.settings?.retention_hours ?? 24)
        setGeoStatus(g)
      } catch { setSettings({}) }
      if (window.snitch?.getAutoLaunch) {
        setAutoLaunch(await window.snitch.getAutoLaunch())
      }
    })()
  }, [])

  async function save(key, value) {
    const base = await apiBase()
    await fetch(`${base}/settings`, {
      method: 'POST',
      headers: await authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ settings: { [key]: value } }),
    })
    setSaved(true)
    setTimeout(() => setSaved(false), 1500)
  }

  async function downloadGeo() {
    setGeoMsg(t('geo_downloading'))
    const base = await apiBase()
    try {
      const res = await fetch(`${base}/geo/download`, {
        method: 'POST',
        headers: await authHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ consent: true }),
      }).then(r => r.json())
      setGeoMsg(res.ok ? t('geo_done', res.downloaded.length) : t('geo_failed'))
      const g = await fetch(`${base}/geo/status`, { headers: await authHeaders() }).then(r => r.json())
      setGeoStatus(g)
    } catch {
      setGeoMsg(t('geo_failed'))
    }
  }

  async function openLogs() {
    // EN: Electron only — via preload bridge. / FR: Electron seulement — via le pont preload.
    if (window.snitch?.openLogs) await window.snitch.openLogs()
  }

  async function exportDiagnostics() {
    const base = await apiBase()
    const data = await fetch(`${base}/diagnostics`, { headers: await authHeaders() }).then(r => r.json())
    const a = document.createElement('a')
    a.href = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }))
    a.download = `snitch-diagnostics-${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(a.href)
  }

  const row = { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 0', borderBottom: '1px solid #0f172a' }
  const label = { fontSize: 12, color: '#e2e8f0', fontWeight: 600 }
  const hint = { fontSize: 10, color: '#64748b', marginTop: 2 }

  return (
    <div role="dialog" aria-label="Settings / Réglages" style={{
      position: 'absolute', top: 56, right: 16, zIndex: 200,
      width: 380, maxHeight: 'calc(100vh - 80px)',
      background: '#1e293b', border: '1px solid #334155',
      borderRadius: 12, overflow: 'hidden auto',
      boxShadow: '0 8px 40px rgba(0,0,0,0.6)',
      display: 'flex', flexDirection: 'column',
    }}>
      <div style={{
        padding: '14px 18px', borderBottom: '1px solid #334155',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        position: 'sticky', top: 0, background: '#1e293b', zIndex: 1,
      }}>
        <span style={{ fontWeight: 700, fontSize: 13, color: '#f1f5f9' }}>{t('settings_title')}</span>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {saved && <span style={{ fontSize: 10, color: '#4ade80' }}>{t('settings_saved')}</span>}
          <button onClick={onClose} aria-label={t('close')} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer' }}>
            <X size={16} />
          </button>
        </div>
      </div>

      <div style={{ padding: '4px 18px 16px' }}>
        {/* Language / Langue */}
        <div style={row}>
          <div><div style={label}>{t('settings_language')}</div></div>
          <div style={{ display: 'flex', gap: 4 }}>
            {['en', 'fr'].map(l => (
              <button key={l} onClick={() => { setLang(l); save('language', l) }} style={{
                background: lang === l ? '#3b82f6' : '#0f172a',
                border: '1px solid #334155', borderRadius: 6,
                color: lang === l ? '#fff' : '#64748b',
                padding: '4px 12px', fontSize: 11, cursor: 'pointer',
                textTransform: 'uppercase', fontWeight: 600,
              }}>{l}</button>
            ))}
          </div>
        </div>

        {/* Retention / Rétention */}
        <div style={row}>
          <div>
            <div style={label}>{t('settings_retention')}</div>
            <div style={hint}>{t('settings_retention_hint')}</div>
          </div>
          <select
            value={retention}
            onChange={e => { const v = +e.target.value; setRetention(v); save('retention_hours', v) }}
            style={{ background: '#0f172a', border: '1px solid #334155', borderRadius: 6, color: '#e2e8f0', padding: '4px 8px', fontSize: 11 }}
          >
            {[6, 12, 24, 48, 72, 168].map(h => <option key={h} value={h}>{h}h</option>)}
          </select>
        </div>

        {/* Auto-launch (Electron only) / Lancement auto (Electron seul) */}
        {window.snitch?.setAutoLaunch && (
          <div style={row}>
            <div>
              <div style={label}>{t('settings_autolaunch')}</div>
              <div style={hint}>{t('settings_autolaunch_hint')}</div>
            </div>
            <button onClick={async () => setAutoLaunch(await window.snitch.setAutoLaunch(!autoLaunch))}
              role="switch" aria-checked={autoLaunch}
              style={{
                width: 36, height: 20, borderRadius: 10, border: 'none',
                background: autoLaunch ? '#3b82f6' : '#0f172a',
                outline: '1px solid #334155', cursor: 'pointer',
                position: 'relative', flexShrink: 0,
              }}>
              <div style={{
                width: 14, height: 14, borderRadius: '50%', background: '#e2e8f0',
                position: 'absolute', top: 3, left: autoLaunch ? 19 : 3,
                transition: 'left 0.15s',
              }} />
            </button>
          </div>
        )}

        {/* GeoIP / GeoIP */}
        <div style={{ ...row, display: 'block' }}>
          <div style={label}>{t('geo_title')}</div>
          <div style={hint}>
            {geoStatus?.databases?.length
              ? t('geo_present', geoStatus.databases.join(', '))
              : t('geo_none')}
          </div>
          <button onClick={downloadGeo} style={{
            marginTop: 8, display: 'flex', alignItems: 'center', gap: 6,
            background: '#0f172a', border: '1px solid #3b82f6', borderRadius: 6,
            color: '#93c5fd', padding: '6px 12px', fontSize: 11, cursor: 'pointer',
          }}>
            <Download size={11} /> {t('geo_download_btn')}
          </button>
          <div style={{ ...hint, marginTop: 4 }}>{t('geo_consent')}</div>
          {geoMsg && <div style={{ fontSize: 10, color: '#93c5fd', marginTop: 4 }}>{geoMsg}</div>}
        </div>

        {/* Diagnostics / Diagnostic */}
        <div style={row}>
          <div>
            <div style={label}>{t('diag_title')}</div>
            <div style={hint}>{t('diag_hint')}</div>
          </div>
          <div style={{ display: 'flex', gap: 6 }}>
            {window.snitch?.openLogs && (
              <button onClick={openLogs} aria-label={t('diag_open_logs')} style={{
                background: '#0f172a', border: '1px solid #334155', borderRadius: 6,
                color: '#94a3b8', padding: '5px 10px', fontSize: 11, cursor: 'pointer',
                display: 'flex', alignItems: 'center', gap: 4,
              }}>
                <FolderOpen size={11} /> {t('diag_open_logs')}
              </button>
            )}
            <button onClick={exportDiagnostics} style={{
              background: '#0f172a', border: '1px solid #334155', borderRadius: 6,
              color: '#94a3b8', padding: '5px 10px', fontSize: 11, cursor: 'pointer',
            }}>
              {t('diag_export')}
            </button>
          </div>
        </div>

        <div style={{ fontSize: 10, color: '#475569', marginTop: 12, display: 'flex', alignItems: 'center', gap: 4 }}>
          <ShieldCheck size={11} /> {t('settings_note')}
        </div>
      </div>
    </div>
  )
}
