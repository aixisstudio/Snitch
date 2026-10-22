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
import { useT, LANGS, LANG_NAMES } from '../i18n'
import { apiBase, authHeaders } from '../api'

export function SettingsButton({ onClick }) {
  return (
    <button onClick={onClick} aria-label="Settings / Réglages" style={{
      display: 'flex', alignItems: 'center', gap: 6,
      background: 'var(--surface)', border: '1px solid var(--border)',
      borderRadius: 20, padding: '5px 14px',
      cursor: 'pointer', color: 'var(--text-muted)',
      fontSize: 11, fontWeight: 600,
    }}>
      <SettingsIcon size={11} />
    </button>
  )
}

export function SettingsPanel({ onClose, lang, setLang, watchlist = [], onWatchlist, iface }) {
  const { t } = useT()
  const [settings, setSettings] = useState(null)
  const [retention, setRetention] = useState(24)
  const [uploadMb, setUploadMb] = useState(50)
  const [geoStatus, setGeoStatus] = useState(null)
  const [geoMsg, setGeoMsg] = useState('')
  const [saved, setSaved] = useState(false)
  const [autoLaunch, setAutoLaunch] = useState(false)
  const [ifaces, setIfaces] = useState(null)
  const [watchInput, setWatchInput] = useState('')
  const [updStatus, setUpdStatus] = useState(null)
  const [updCheck, setUpdCheck] = useState(true)
  const [pairing, setPairing] = useState(null)
  const [sbPath, setSbPath] = useState('')
  const [sbResult, setSbResult] = useState(null)
  const [askStatus, setAskStatus] = useState(null)

  useEffect(() => {
    ;(async () => {
      const base = await apiBase()
      const headers = await authHeaders()
      try {
        const [s, g, i, p, a] = await Promise.all([
          fetch(`${base}/settings`, { headers }).then(r => r.json()),
          fetch(`${base}/geo/status`, { headers }).then(r => r.json()),
          fetch(`${base}/capture/interfaces`, { headers }).then(r => r.json()),
          fetch(`${base}/remote/pairing`, { headers }).then(r => r.json()),
          fetch(`${base}/security/ask`, { headers }).then(r => r.json())
            .catch(() => null),
        ])
        setSettings(s.settings || {})
        setRetention(s.settings?.retention_hours ?? 24)
        setUploadMb(s.settings?.upload_threshold_mb ?? 50)
        setGeoStatus(g)
        setIfaces(i.interfaces || [])
        setPairing(p)
        setAskStatus(a)
      } catch { setSettings({}) }
      if (window.snitch?.getAutoLaunch) {
        setAutoLaunch(await window.snitch.getAutoLaunch())
      }
      if (window.snitch?.getUpdateStatus) {
        setUpdStatus(await window.snitch.getUpdateStatus())
        setUpdCheck(await window.snitch.getUpdateCheck())
      }
    })()
    // EN: Live update progress pushed by the main process.
    // FR: Progression des mises à jour poussée par le processus principal.
    const off = window.snitch?.onUpdateStatus?.(setUpdStatus)
    return () => off?.()
  }, [])

  async function setInterface(name) {
    const base = await apiBase()
    await fetch(`${base}/capture/interface`, {
      method: 'POST',
      headers: await authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ name }),
    })
    setSaved(true)
    setTimeout(() => setSaved(false), 1500)
  }

  function addWatch(e) {
    e.preventDefault()
    const item = watchInput.trim()
    if (!item || watchlist.includes(item)) { setWatchInput(''); return }
    onWatchlist?.([...watchlist, item])
    setWatchInput('')
  }

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

  /**
   * EN: Remote pairing — opt-in LAN exposure persisted as `lan_bind`.
   *     The backend cannot rebind a live socket, so the answer's
   *     `restart_required` is surfaced verbatim.
   * FR: Pairing distant — exposition LAN opt-in persistée en `lan_bind`.
   *     Le backend ne peut pas re-binder un socket actif, donc
   *     `restart_required` est affiché tel quel.
   */
  async function setPairingOn(on) {
    const base = await apiBase()
    const res = await fetch(`${base}/remote/pairing`, {
      method: 'POST',
      headers: await authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ enabled: on, bind: '0.0.0.0' }),
    }).then(r => r.json())
    const p = await fetch(`${base}/remote/pairing`, { headers: await authHeaders() }).then(r => r.json())
    setPairing({ ...p, _justSet: res.lan_bind })
  }

  /**
   * EN: Sandbox detonation — run a binary with zero network egress
   *     (network namespace on Linux, sandbox-exec on macOS). Bounded
   *     runtime; the result says honestly whether egress was denied.
   * FR: Détonation en sandbox — exécuter un binaire avec zéro égress
   *     réseau (namespace réseau sous Linux, sandbox-exec sous macOS).
   *     Durée bornée ; le résultat dit honnêtement si l'égress était
   *     bloqué.
   */
  async function detonate(e) {
    e.preventDefault()
    if (!sbPath.trim()) return
    setSbResult({ running: true })
    const base = await apiBase()
    try {
      const res = await fetch(`${base}/security/sandbox`, {
        method: 'POST',
        headers: await authHeaders({ 'Content-Type': 'application/json' }),
        body: JSON.stringify({ path: sbPath.trim(), seconds: 10 }),
      }).then(r => r.json())
      setSbResult(res)
    } catch (ex) { setSbResult({ ok: false, error: String(ex.message || ex) }) }
  }

  const row = { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 0', borderBottom: '1px solid var(--bg)' }
  const label = { fontSize: 12, color: 'var(--text)', fontWeight: 600 }
  const hint = { fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }

  return (
    <div role="dialog" aria-label="Settings / Réglages" style={{
      position: 'absolute', top: 56, right: 16, zIndex: 200,
      width: 380, maxHeight: 'calc(100vh - 80px)',
      background: 'var(--surface)', border: '1px solid var(--border)',
      borderRadius: 12, overflow: 'hidden auto',
      boxShadow: '0 8px 40px rgba(0,0,0,0.6)',
      display: 'flex', flexDirection: 'column',
    }}>
      <div style={{
        padding: '14px 18px', borderBottom: '1px solid var(--border)',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        position: 'sticky', top: 0, background: 'var(--surface)', zIndex: 1,
      }}>
        <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--text)' }}>{t('settings_title')}</span>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {saved && <span style={{ fontSize: 10, color: '#4ade80' }}>{t('settings_saved')}</span>}
          <button onClick={onClose} aria-label={t('close')} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
            <X size={16} />
          </button>
        </div>
      </div>

      <div style={{ padding: '4px 18px 16px' }}>
        {/* Language / Langue */}
        <div style={row}>
          <div><div style={label}>{t('settings_language')}</div></div>
          <select
            value={lang}
            onChange={e => { setLang(e.target.value); save('language', e.target.value) }}
            style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', padding: '4px 8px', fontSize: 11 }}
          >
            {LANGS.map(l => <option key={l} value={l}>{LANG_NAMES[l]}</option>)}
          </select>
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
            style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', padding: '4px 8px', fontSize: 11 }}
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
                background: autoLaunch ? '#3b82f6' : 'var(--bg)',
                outline: '1px solid var(--border)', cursor: 'pointer',
                position: 'relative', flexShrink: 0,
              }}>
              <div style={{
                width: 14, height: 14, borderRadius: '50%', background: 'var(--text)',
                position: 'absolute', top: 3, left: autoLaunch ? 19 : 3,
                transition: 'left 0.15s',
              }} />
            </button>
          </div>
        )}

        {/* Capture interface / Interface de capture */}
        <div style={row}>
          <div>
            <div style={label}>{t('settings_interface')}</div>
            <div style={hint}>{t('settings_interface_hint')}</div>
          </div>
          <select
            value={settings?.interface ?? ''}
            onChange={e => {
              const v = e.target.value || null
              setSettings(s => ({ ...s, interface: v }))
              setInterface(v)
            }}
            style={{
              background: 'var(--bg)', border: '1px solid var(--border)',
              borderRadius: 6, color: 'var(--text)', padding: '4px 8px',
              fontSize: 11, maxWidth: 180,
            }}
          >
            <option value="">{t('settings_interface_auto')}</option>
            {(ifaces || []).map(d => (
              <option key={d.name} value={d.name}>
                {d.name}{d.description ? ` — ${d.description}` : ''}
              </option>
            ))}
          </select>
        </div>

        {/* Upload alert threshold / Seuil d'alerte d'envoi */}
        <div style={row}>
          <div>
            <div style={label}>{t('settings_upload')}</div>
            <div style={hint}>{t('settings_upload_hint')}</div>
          </div>
          <select
            value={uploadMb}
            onChange={e => { const v = +e.target.value; setUploadMb(v); save('upload_threshold_mb', v) }}
            style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', padding: '4px 8px', fontSize: 11 }}
          >
            {[10, 25, 50, 100, 250, 500, 0].map(v => (
              <option key={v} value={v}>{v === 0 ? t('settings_off') : `${v} MB/min`}</option>
            ))}
          </select>
        </div>

        {/* Watchlist / Liste de surveillance */}
        <div style={{ ...row, display: 'block' }}>
          <div style={label}>{t('watchlist_title')}</div>
          <div style={hint}>{t('watchlist_hint')}</div>
          <form onSubmit={addWatch} style={{ display: 'flex', gap: 6, marginTop: 8 }}>
            <input
              value={watchInput}
              onChange={e => setWatchInput(e.target.value)}
              placeholder={t('watchlist_placeholder')}
              aria-label={t('watchlist_title')}
              style={{
                flex: 1, background: 'var(--bg)', border: '1px solid var(--border)',
                borderRadius: 6, color: 'var(--text)', padding: '6px 10px',
                fontSize: 11, outline: 'none',
              }}
            />
            <button type="submit" style={{
              background: 'var(--bg)', border: '1px solid var(--border)',
              borderRadius: 6, color: 'var(--text-dim)', padding: '6px 12px',
              fontSize: 11, cursor: 'pointer',
            }}>{t('watchlist_add')}</button>
          </form>
          {watchlist.length > 0 && (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 8 }}>
              {watchlist.map(item => (
                <button key={item} title={t('watchlist_remove')}
                  onClick={() => onWatchlist?.(watchlist.filter(i => i !== item))}
                  style={{
                    background: 'var(--bg)', border: '1px solid var(--border)',
                    borderRadius: 10, color: 'var(--text)', padding: '3px 9px',
                    fontSize: 10, cursor: 'pointer', display: 'flex', gap: 5,
                    alignItems: 'center',
                  }}>
                  {item} <X size={9} />
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Threat intelligence / Renseignement sur les menaces */}
        <div style={{ ...row, display: 'block' }}>
          <div style={label}>{t('ti_title')}</div>
          <div style={hint}>{t('ti_hint')}</div>
          <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
            <select
              value={settings?.ti_provider ?? 'none'}
              onChange={e => {
                const v = e.target.value
                setSettings(s => ({ ...s, ti_provider: v }))
                save('ti_provider', v)
              }}
              style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', padding: '4px 8px', fontSize: 11 }}
            >
              <option value="none">{t('ti_none')}</option>
              <option value="abuseipdb">AbuseIPDB</option>
              <option value="otx">AlienVault OTX</option>
              <option value="virustotal">VirusTotal</option>
            </select>
            <form onSubmit={e => {
              e.preventDefault()
              const v = e.target.elements.tikey.value.trim()
              save('ti_api_key', v)
            }} style={{ flex: 1, display: 'flex', gap: 6 }}>
              <input
                name="tikey"
                type="password"
                defaultValue={settings?.ti_api_key ?? ''}
                placeholder={t('ti_key_ph')}
                aria-label={t('ti_key')}
                autoComplete="off"
                style={{ flex: 1, background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', padding: '4px 8px', fontSize: 11, outline: 'none' }}
              />
              <button type="submit" style={{
                background: 'var(--bg)', border: '1px solid var(--border)',
                borderRadius: 6, color: 'var(--text-dim)', padding: '4px 10px',
                fontSize: 10, cursor: 'pointer',
              }}>{t('save')}</button>
            </form>
          </div>
          <div style={{ ...hint, marginTop: 4 }}>{t('ti_privacy')}</div>
        </div>

        {/* External webhook / Webhook externe */}
        <div style={{ ...row, display: 'block' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={label}>{t('wh_title')}</div>
              <div style={hint}>{t('wh_hint')}</div>
            </div>
            <button
              onClick={() => {
                const v = !settings?.webhook_enabled
                setSettings(s => ({ ...s, webhook_enabled: v }))
                save('webhook_enabled', v)
              }}
              role="switch" aria-checked={!!settings?.webhook_enabled}
              style={{
                width: 36, height: 20, borderRadius: 10, border: 'none',
                background: settings?.webhook_enabled ? '#3b82f6' : 'var(--bg)',
                outline: '1px solid var(--border)', cursor: 'pointer',
                position: 'relative', flexShrink: 0,
              }}>
              <div style={{
                width: 14, height: 14, borderRadius: '50%', background: 'var(--text)',
                position: 'absolute', top: 3, left: settings?.webhook_enabled ? 19 : 3,
                transition: 'left 0.15s',
              }} />
            </button>
          </div>
          <form onSubmit={e => {
            e.preventDefault()
            save('webhook_url', e.target.elements.whurl.value.trim())
            save('telegram_chat_id', e.target.elements.whchat?.value.trim() || '')
          }} style={{ display: 'flex', gap: 6, marginTop: 8 }}>
            <input
              name="whurl"
              defaultValue={settings?.webhook_url ?? ''}
              placeholder={t('wh_url_ph')}
              aria-label={t('wh_url')}
              style={{ flex: 1, background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', padding: '6px 10px', fontSize: 11, outline: 'none' }}
            />
            {(settings?.webhook_url || '').includes('telegram') && (
              <input
                name="whchat"
                defaultValue={settings?.telegram_chat_id ?? ''}
                placeholder={t('wh_chat_ph')}
                aria-label={t('wh_chat')}
                style={{ width: 90, background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', padding: '6px 10px', fontSize: 11, outline: 'none' }}
              />
            )}
            <button type="submit" style={{
              background: 'var(--bg)', border: '1px solid var(--border)',
              borderRadius: 6, color: 'var(--text-dim)', padding: '6px 12px',
              fontSize: 10, cursor: 'pointer',
            }}>{t('save')}</button>
          </form>
          <div style={{ ...hint, marginTop: 4 }}>{t('wh_privacy')}</div>
        </div>

        {/* Syslog output / Sortie syslog */}
        <div style={{ ...row, display: 'block' }}>
          <div style={label}>{t('sl_title')}</div>
          <div style={hint}>{t('sl_hint')}</div>
          <form onSubmit={e => {
            e.preventDefault()
            save('syslog_addr', e.target.elements.sladdr.value.trim())
          }} style={{ display: 'flex', gap: 6, marginTop: 8 }}>
            <input
              name="sladdr"
              defaultValue={settings?.syslog_addr ?? ''}
              placeholder={t('sl_ph')}
              aria-label={t('sl_title')}
              style={{ flex: 1, background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', padding: '6px 10px', fontSize: 11, outline: 'none' }}
            />
            <button type="submit" style={{
              background: 'var(--bg)', border: '1px solid var(--border)',
              borderRadius: 6, color: 'var(--text-dim)', padding: '6px 12px',
              fontSize: 10, cursor: 'pointer',
            }}>{t('save')}</button>
          </form>
        </div>

        {/* Ask-on-connect (NFQUEUE) / Ask-on-connect (NFQUEUE) */}
        <div style={{ ...row, display: 'block' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={label}>{t('ask_title')}</div>
              <div style={hint}>{t('ask_hint')}</div>
            </div>
            <button
              onClick={() => {
                const v = !settings?.ask_enabled
                setSettings(s => ({ ...s, ask_enabled: v }))
                save('ask_enabled', v)
              }}
              role="switch" aria-checked={!!settings?.ask_enabled}
              style={{
                width: 36, height: 20, borderRadius: 10, border: 'none',
                background: settings?.ask_enabled ? '#3b82f6' : 'var(--bg)',
                outline: '1px solid var(--border)', cursor: 'pointer',
                position: 'relative', flexShrink: 0,
              }}>
              <div style={{
                width: 14, height: 14, borderRadius: '50%', background: 'var(--text)',
                position: 'absolute', top: 3, left: settings?.ask_enabled ? 19 : 3,
                transition: 'left 0.15s',
              }} />
            </button>
          </div>
          {settings?.ask_enabled && (
            <div style={{ display: 'flex', gap: 8, marginTop: 8, alignItems: 'center' }}>
              <select
                value={settings?.ask_timeout ?? 15}
                onChange={e => {
                  const v = +e.target.value
                  setSettings(s => ({ ...s, ask_timeout: v }))
                  save('ask_timeout', v)
                }}
                aria-label={t('ask_timeout')}
                style={{ background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', padding: '4px 8px', fontSize: 11 }}
              >
                {[10, 15, 30, 60].map(v => (
                  <option key={v} value={v}>{t('ask_timeout')}: {v}s</option>
                ))}
              </select>
              <label style={{ ...hint, display: 'flex', gap: 5, alignItems: 'center', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={!!settings?.ask_failopen}
                  onChange={e => {
                    setSettings(s => ({ ...s, ask_failopen: e.target.checked }))
                    save('ask_failopen', e.target.checked)
                  }}
                />
                {t('ask_failopen')}
              </label>
            </div>
          )}
          {askStatus && !askStatus.available && (
            <div style={{ ...hint, marginTop: 4 }}>{t('ask_unavailable')}: {askStatus.reason}</div>
          )}
          {askStatus?.available && askStatus?.running === false && settings?.ask_enabled && (
            <div style={{ ...hint, marginTop: 4 }}>{t('ask_not_running')}</div>
          )}
        </div>

        {/* IOC peer sync / Sync IOC entre pairs */}
        <div style={{ ...row, display: 'block' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={label}>{t('gs_title')}</div>
              <div style={hint}>{t('gs_hint')}</div>
            </div>
            <button
              onClick={() => {
                const v = !settings?.gossip_enabled
                setSettings(s => ({ ...s, gossip_enabled: v }))
                save('gossip_enabled', v)
              }}
              role="switch" aria-checked={!!settings?.gossip_enabled}
              style={{
                width: 36, height: 20, borderRadius: 10, border: 'none',
                background: settings?.gossip_enabled ? '#3b82f6' : 'var(--bg)',
                outline: '1px solid var(--border)', cursor: 'pointer',
                position: 'relative', flexShrink: 0,
              }}>
              <div style={{
                width: 14, height: 14, borderRadius: '50%', background: 'var(--text)',
                position: 'absolute', top: 3, left: settings?.gossip_enabled ? 19 : 3,
                transition: 'left 0.15s',
              }} />
            </button>
          </div>
          <form onSubmit={e => {
            e.preventDefault()
            const peers = e.target.elements.gpeers.value
              .split(/[\s,]+/).map(s => s.trim()).filter(Boolean).slice(0, 32)
            setSettings(s => ({ ...s, gossip_peers: peers }))
            save('gossip_peers', peers)
          }} style={{ display: 'flex', gap: 6, marginTop: 8 }}>
            <input
              name="gpeers"
              defaultValue={(settings?.gossip_peers || []).join(', ')}
              placeholder={t('gs_peers_ph')}
              aria-label={t('gs_title')}
              style={{ flex: 1, background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', padding: '6px 10px', fontSize: 11, outline: 'none' }}
            />
            <button type="submit" style={{
              background: 'var(--bg)', border: '1px solid var(--border)',
              borderRadius: 6, color: 'var(--text-dim)', padding: '6px 12px',
              fontSize: 10, cursor: 'pointer',
            }}>{t('save')}</button>
          </form>
          <div style={{ ...hint, marginTop: 4 }}>{t('gs_privacy')}</div>
        </div>

        {/* Volume kill-switch / Kill-switch de volume */}
        <div style={{ ...row, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={label}>{t('ks_title')}</div>
            <div style={hint}>{t('ks_hint')}</div>
          </div>
          <button
            onClick={() => {
              const v = !settings?.kill_switch_enabled
              setSettings(s => ({ ...s, kill_switch_enabled: v }))
              save('kill_switch_enabled', v)
            }}
            role="switch" aria-checked={!!settings?.kill_switch_enabled}
            style={{
              width: 36, height: 20, borderRadius: 10, border: 'none',
              background: settings?.kill_switch_enabled ? '#3b82f6' : 'var(--bg)',
              outline: '1px solid var(--border)', cursor: 'pointer',
              position: 'relative', flexShrink: 0,
            }}>
            <div style={{
              width: 14, height: 14, borderRadius: '50%', background: 'var(--text)',
              position: 'absolute', top: 3, left: settings?.kill_switch_enabled ? 19 : 3,
              transition: 'left 0.15s',
            }} />
          </button>
        </div>

        {/* Integrity watch / Veille d'intégrité */}
        <div style={{ ...row, display: 'block' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={label}>{t('iw_title')}</div>
              <div style={hint}>{t('iw_hint')}</div>
            </div>
            <button
              onClick={() => {
                const v = settings?.integrity_watch === false
                setSettings(s => ({ ...s, integrity_watch: v }))
                save('integrity_watch', v)
              }}
              role="switch" aria-checked={settings?.integrity_watch !== false}
              style={{
                width: 36, height: 20, borderRadius: 10, border: 'none',
                background: settings?.integrity_watch !== false ? '#3b82f6' : 'var(--bg)',
                outline: '1px solid var(--border)', cursor: 'pointer',
                position: 'relative', flexShrink: 0,
              }}>
              <div style={{
                width: 14, height: 14, borderRadius: '50%', background: 'var(--text)',
                position: 'absolute', top: 3, left: settings?.integrity_watch !== false ? 19 : 3,
                transition: 'left 0.15s',
              }} />
            </button>
          </div>
          <div style={{ ...hint, marginTop: 4 }}>{t('iw_privacy')}</div>
        </div>

        {/* eBPF probe / Sonde eBPF */}
        <div style={{ ...row, display: 'block' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={label}>{t('ebpf_title')}</div>
              <div style={hint}>{t('ebpf_hint')}</div>
            </div>
            <button
              onClick={() => {
                const v = settings?.ebpf_probe === false
                setSettings(s => ({ ...s, ebpf_probe: v }))
                save('ebpf_probe', v)
              }}
              role="switch" aria-checked={settings?.ebpf_probe !== false}
              style={{
                width: 36, height: 20, borderRadius: 10, border: 'none',
                background: settings?.ebpf_probe !== false ? '#3b82f6' : 'var(--bg)',
                outline: '1px solid var(--border)', cursor: 'pointer',
                position: 'relative', flexShrink: 0,
              }}>
              <div style={{
                width: 14, height: 14, borderRadius: '50%', background: 'var(--text)',
                position: 'absolute', top: 3, left: settings?.ebpf_probe !== false ? 19 : 3,
                transition: 'left 0.15s',
              }} />
            </button>
          </div>
          <div style={{ ...hint, marginTop: 4 }}>{t('ebpf_privacy')}</div>
        </div>

        {/* Local SLM (Ollama) / SLM local (Ollama) */}
        <div style={{ ...row, display: 'block' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={label}>{t('slm_title')}</div>
              <div style={hint}>{t('slm_hint')}</div>
            </div>
            <button
              onClick={() => {
                const v = !settings?.slm_enabled
                setSettings(s => ({ ...s, slm_enabled: v }))
                save('slm_enabled', v)
              }}
              role="switch" aria-checked={!!settings?.slm_enabled}
              style={{
                width: 36, height: 20, borderRadius: 10, border: 'none',
                background: settings?.slm_enabled ? '#3b82f6' : 'var(--bg)',
                outline: '1px solid var(--border)', cursor: 'pointer',
                position: 'relative', flexShrink: 0,
              }}>
              <div style={{
                width: 14, height: 14, borderRadius: '50%', background: 'var(--text)',
                position: 'absolute', top: 3, left: settings?.slm_enabled ? 19 : 3,
                transition: 'left 0.15s',
              }} />
            </button>
          </div>
          {settings?.slm_enabled && (
            <>
              {/* EN: Backend choice — `ollama` reaches a loopback server;
                      `embedded` loads a user-provided GGUF via
                      llama-cpp-python (zero network at all).
                  FR: Choix du backend — `ollama` joint un serveur
                      loopback ; `embedded` charge un GGUF fourni par
                      l'utilisateur via llama-cpp-python (zéro réseau). */}
              <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
                {['ollama', 'embedded'].map(m => (
                  <button key={m} onClick={() => {
                    setSettings(s => ({ ...s, slm_mode: m }))
                    save('slm_mode', m)
                  }} style={{
                    flex: 1, background: (settings?.slm_mode ?? 'ollama') === m ? '#3b82f6' : 'var(--bg)',
                    border: '1px solid var(--border)', borderRadius: 6,
                    color: (settings?.slm_mode ?? 'ollama') === m ? '#fff' : 'var(--text-dim)',
                    padding: '5px 0', fontSize: 10, cursor: 'pointer', fontWeight: 600,
                  }}>{m === 'ollama' ? t('slm_mode_ollama') : t('slm_mode_embedded')}</button>
                ))}
              </div>
              {(settings?.slm_mode ?? 'ollama') === 'embedded' ? (
                <form onSubmit={e => {
                  e.preventDefault()
                  save('slm_model_path', e.target.elements.slmp.value.trim())
                }} style={{ display: 'flex', gap: 6, marginTop: 6 }}>
                  <input
                    name="slmp"
                    defaultValue={settings?.slm_model_path ?? ''}
                    placeholder="/path/to/model.gguf"
                    aria-label={t('slm_model_path')}
                    style={{ flex: 1, background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', padding: '6px 10px', fontSize: 11, outline: 'none' }}
                  />
                  <button type="submit" style={{
                    background: 'var(--bg)', border: '1px solid var(--border)',
                    borderRadius: 6, color: 'var(--text-dim)', padding: '6px 12px',
                    fontSize: 10, cursor: 'pointer',
                  }}>{t('save')}</button>
                </form>
              ) : (
                <form onSubmit={e => {
                  e.preventDefault()
                  save('slm_endpoint', e.target.elements.slme.value.trim())
                  save('slm_model', e.target.elements.slmm.value.trim())
                }} style={{ display: 'flex', gap: 6, marginTop: 6 }}>
                  <input
                    name="slme"
                    defaultValue={settings?.slm_endpoint ?? ''}
                    placeholder="http://127.0.0.1:11434"
                    aria-label={t('slm_endpoint')}
                    style={{ flex: 2, background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', padding: '6px 10px', fontSize: 11, outline: 'none' }}
                  />
                  <input
                    name="slmm"
                    defaultValue={settings?.slm_model ?? ''}
                    placeholder="llama3.2"
                    aria-label={t('slm_model')}
                    style={{ flex: 1, background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', padding: '6px 10px', fontSize: 11, outline: 'none' }}
                  />
                  <button type="submit" style={{
                    background: 'var(--bg)', border: '1px solid var(--border)',
                    borderRadius: 6, color: 'var(--text-dim)', padding: '6px 12px',
                    fontSize: 10, cursor: 'pointer',
                  }}>{t('save')}</button>
                </form>
              )}
            </>
          )}
          <div style={{ ...hint, marginTop: 4 }}>{t('slm_privacy')}</div>
        </div>

        {/* Remote pairing / Pairing distant */}
        <div style={{ ...row, display: 'block' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={label}>{t('pair_title')}</div>
              <div style={hint}>{t('pair_hint')}</div>
            </div>
            <button
              onClick={() => setPairingOn(!(pairing?.persisted_bind))}
              role="switch" aria-checked={!!pairing?.persisted_bind}
              style={{
                width: 36, height: 20, borderRadius: 10, border: 'none',
                background: pairing?.persisted_bind ? '#3b82f6' : 'var(--bg)',
                outline: '1px solid var(--border)', cursor: 'pointer',
                position: 'relative', flexShrink: 0,
              }}>
              <div style={{
                width: 14, height: 14, borderRadius: '50%', background: 'var(--text)',
                position: 'absolute', top: 3, left: pairing?.persisted_bind ? 19 : 3,
                transition: 'left 0.15s',
              }} />
            </button>
          </div>
          {pairing?.persisted_bind && (
            <div style={{ ...hint, marginTop: 6 }}>
              {t('pair_lan_ips', (pairing.lan_ips || []).join(', ') || '—')}
              {' · '}{t('pair_port', pairing.port)}
              {pairing.restart_required && (
                <div style={{ color: '#f59e0b', marginTop: 3 }}>{t('pair_restart')}</div>
              )}
            </div>
          )}
          <div style={{ ...hint, marginTop: 4 }}>{t('pair_privacy')}</div>
        </div>

        {/* Sandbox detonation / Détonation en sandbox */}
        <div style={{ ...row, display: 'block' }}>
          <div style={label}>{t('sb_title')}</div>
          <div style={hint}>{t('sb_hint')}</div>
          <form onSubmit={detonate} style={{ display: 'flex', gap: 6, marginTop: 8 }}>
            <input value={sbPath} onChange={e => setSbPath(e.target.value)}
              placeholder="/path/to/binary" aria-label={t('sb_path')}
              style={{ flex: 1, background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6, color: 'var(--text)', padding: '6px 10px', fontSize: 11, outline: 'none' }} />
            <button type="submit" disabled={!sbPath.trim() || sbResult?.running} style={{
              background: sbPath.trim() ? '#3b82f6' : 'var(--bg)', border: 'none',
              borderRadius: 6, color: sbPath.trim() ? '#fff' : 'var(--text-faint)',
              padding: '6px 12px', fontSize: 10, cursor: 'pointer', fontWeight: 600,
            }}>{sbResult?.running ? '…' : t('sb_run')}</button>
          </form>
          {sbResult && !sbResult.running && (
            <div style={{ ...hint, marginTop: 4, color: sbResult.ok ? '#4ade80' : '#f59e0b' }}>
              {sbResult.ok
                ? t('sb_done', sbResult.exit_code ?? '?')
                : (sbResult.error || t('sb_failed'))}
              {sbResult.stderr && (
                <div style={{ fontFamily: 'monospace', marginTop: 2, color: 'var(--text-muted)' }}>
                  {String(sbResult.stderr).slice(0, 200)}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Updates (Electron only) / Mises à jour (Electron seul) */}
        {window.snitch?.getUpdateStatus && (
          <div style={{ ...row, display: 'block' }}>
            <div style={label}>{t('update_title')}</div>
            <div style={hint}>
              {updStatus?.state === 'checking'   && t('update_checking')}
              {updStatus?.state === 'available'  && t('update_available', updStatus.version)}
              {updStatus?.state === 'downloading' && t('update_downloading', updStatus.percent ?? 0)}
              {updStatus?.state === 'downloaded' && t('update_ready', updStatus.version)}
              {updStatus?.state === 'none'       && t('update_none')}
              {updStatus?.state === 'error'      && t('update_error')}
              {(!updStatus || updStatus.state === 'idle' || updStatus.state === 'dev') && t('update_idle')}
            </div>
            <div style={{ display: 'flex', gap: 6, marginTop: 8, alignItems: 'center' }}>
              {updStatus?.state === 'downloaded' ? (
                <button onClick={() => window.snitch.installUpdate()} style={{
                  background: '#3b82f6', border: 'none', borderRadius: 6,
                  color: '#fff', padding: '6px 12px', fontSize: 11,
                  cursor: 'pointer', fontWeight: 600,
                }}>{t('update_restart')}</button>
              ) : (
                <button onClick={() => window.snitch.checkUpdates()} style={{
                  background: 'var(--bg)', border: '1px solid var(--border)',
                  borderRadius: 6, color: 'var(--text-dim)',
                  padding: '6px 12px', fontSize: 11, cursor: 'pointer',
                }}>{t('update_check_btn')}</button>
              )}
              <label style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10, color: 'var(--text-muted)', cursor: 'pointer' }}>
                <input type="checkbox" checked={updCheck}
                  onChange={async e => setUpdCheck(await window.snitch.setUpdateCheck(e.target.checked))} />
                {t('update_auto')}
              </label>
            </div>
            <div style={{ ...hint, marginTop: 4 }}>{t('update_privacy')}</div>
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
            background: 'var(--bg)', border: '1px solid #3b82f6', borderRadius: 6,
            color: 'var(--blue-text)', padding: '6px 12px', fontSize: 11, cursor: 'pointer',
          }}>
            <Download size={11} /> {t('geo_download_btn')}
          </button>
          <div style={{ ...hint, marginTop: 4 }}>{t('geo_consent')}</div>
          {geoMsg && <div style={{ fontSize: 10, color: 'var(--blue-text)', marginTop: 4 }}>{geoMsg}</div>}
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
                background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6,
                color: 'var(--text-dim)', padding: '5px 10px', fontSize: 11, cursor: 'pointer',
                display: 'flex', alignItems: 'center', gap: 4,
              }}>
                <FolderOpen size={11} /> {t('diag_open_logs')}
              </button>
            )}
            <button onClick={exportDiagnostics} style={{
              background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6,
              color: 'var(--text-dim)', padding: '5px 10px', fontSize: 11, cursor: 'pointer',
            }}>
              {t('diag_export')}
            </button>
          </div>
        </div>

        <div style={{ fontSize: 10, color: 'var(--text-faint)', marginTop: 12, display: 'flex', alignItems: 'center', gap: 4 }}>
          <ShieldCheck size={11} /> {t('settings_note')}
        </div>
      </div>
    </div>
  )
}
