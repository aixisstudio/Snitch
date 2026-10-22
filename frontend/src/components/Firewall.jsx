/**
 * Snitch — firewall & security panel.
 *
 * EN: Slide-over panel for the outbound-firewall orchestration: a lockdown
 *     panic switch, user rules (IP / domain / process / port) with
 *     enable-toggle and delete, blocked-attempt counters, and the security
 *     audit report (score + findings + recommendations). Rules are applied
 *     to the OS firewall best-effort by the backend — an un-applied rule is
 *     marked honestly instead of pretending enforcement.
 * FR: Panneau latéral pour l'orchestration du pare-feu sortant : bouton
 *     panique lockdown, règles utilisateur (IP / domaine / processus / port)
 *     avec bascule et suppression, compteurs de tentatives bloquées, et le
 *     rapport d'audit sécurité (score + constats + recommandations). Les
 *     règles sont appliquées au pare-feu OS au mieux par le backend — une
 *     règle non appliquée est marquée honnêtement au lieu de simuler.
 */
import { useState, useEffect, useCallback } from 'react'
import { ShieldCheck, X, Trash2, RefreshCw, Lock, Plus, AlertTriangle } from 'lucide-react'
import { useT } from '../i18n'
import { apiBase, authHeaders } from '../api'

const RULE_KINDS = ['ip', 'domain', 'process', 'port']

export function FirewallButton({ onClick, lockdown }) {
  const { t } = useT()
  return (
    <button onClick={onClick} aria-label="Firewall / Pare-feu"
      title={t('fw_title')} style={{
        display: 'flex', alignItems: 'center', gap: 6,
        background: lockdown ? 'var(--danger-active)' : 'var(--surface)',
        border: `1px solid ${lockdown ? '#ef4444' : 'var(--border)'}`,
        borderRadius: 20, padding: '5px 14px',
        cursor: 'pointer', color: lockdown ? 'var(--red-text)' : 'var(--text-muted)',
        fontSize: 11, fontWeight: 600,
      }}>
      <ShieldCheck size={11} />
      {lockdown ? t('fw_lockdown_on') : 'FW'}
    </button>
  )
}

export function FirewallPanel({ onClose, onLockdownChange }) {
  const { t } = useT()
  const [rules, setRules] = useState([])
  const [lockdown, setLockdown] = useState(false)
  const [status, setStatus] = useState(null)
  const [kind, setKind] = useState('ip')
  const [value, setValue] = useState('')
  const [action, setAction] = useState('block')
  const [rate, setRate] = useState(64)
  const [iocText, setIocText] = useState('')
  const [iocResult, setIocResult] = useState(null)
  const [err, setErr] = useState('')
  const [audit, setAudit] = useState(null)
  const [blSource, setBlSource] = useState('path')
  const [blValue, setBlValue] = useState('')
  const [blAction, setBlAction] = useState('block')
  const [blResult, setBlResult] = useState(null)
  const [aRules, setARules] = useState([])
  const [arName, setArName] = useState('')
  const [arField, setArField] = useState('host')
  const [arOp, setArOp] = useState('contains')
  const [arValue, setArValue] = useState('')
  const [arSev, setArSev] = useState('warning')

  const refresh = useCallback(async () => {
    const base = await apiBase()
    const headers = await authHeaders()
    try {
      const [r, s, ar] = await Promise.all([
        fetch(`${base}/firewall/rules`, { headers }).then(x => x.json()),
        fetch(`${base}/firewall/status`, { headers }).then(x => x.json()),
        fetch(`${base}/alerts/rules`, { headers }).then(x => x.json()),
      ])
      setRules(r.rules || [])
      setLockdown(!!r.lockdown)
      setStatus(s)
      setARules(ar.rules || [])
      onLockdownChange?.(!!r.lockdown)
    } catch { /* leave previous state */ }
  }, [onLockdownChange])

  const refreshAudit = useCallback(async () => {
    const base = await apiBase()
    try {
      setAudit(await fetch(`${base}/security/audit`, { headers: await authHeaders() }).then(r => r.json()))
    } catch { setAudit(null) }
  }, [])

  useEffect(() => { refresh(); refreshAudit() }, [refresh, refreshAudit])

  async function post(path, body, method = 'POST') {
    const base = await apiBase()
    const res = await fetch(`${base}${path}`, {
      method,
      headers: await authHeaders({ 'Content-Type': 'application/json' }),
      body: body ? JSON.stringify(body) : undefined,
    })
    if (!res.ok) {
      const j = await res.json().catch(() => ({}))
      throw new Error(j.detail || res.statusText)
    }
    return res.json()
  }

  async function addRule(e) {
    e.preventDefault()
    const v = value.trim()
    if (!v) return
    setErr('')
    try {
      await post('/firewall/rules', { kind, value: v, action, rate })
      setValue('')
      refresh()
    } catch (ex) { setErr(String(ex.message || ex)) }
  }

  /**
   * EN: Download this machine's privacy-preserving IOC pack (Bloom +
   *     randomized response) — the user decides where it goes.
   * FR: Télécharger le paquet IOC préservant la vie privée de cette
   *     machine (Bloom + randomized response) — l'utilisateur décide où
   *     il va.
   */
  async function exportIoc() {
    const base = await apiBase()
    const res = await fetch(`${base}/security/iocpack`,
      { headers: await authHeaders() })
    if (!res.ok) { setErr(res.statusText); return }
    const blob = await res.blob()
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'snitch-ioc-pack.json'
    a.click()
    URL.revokeObjectURL(a.href)
  }

  async function importIoc() {
    setIocResult(null)
    try {
      const pack = JSON.parse(iocText)
      const r = await post('/security/iocpack/import', { pack })
      setIocResult(r)
    } catch (ex) { setIocResult({ ok: false, error: String(ex.message || ex) }) }
  }

  async function toggleRule(id, enabled) {
    await post(`/firewall/rules/${encodeURIComponent(id)}/toggle`, { enabled })
    refresh()
  }

  async function deleteRule(id) {
    await post(`/firewall/rules/${encodeURIComponent(id)}`, null, 'DELETE')
    refresh()
  }

  async function exportForensics(format) {
    // EN: Authenticated download — fetch the bundle, then hand it to the
    //     browser as a blob (a bare <a href> can't carry the token header).
    // FR: Téléchargement authentifié — fetch du bundle puis remise au
    //     navigateur en blob (un <a href> nu ne porte pas le token).
    const base = await apiBase()
    const res = await fetch(`${base}/forensics/export?format=${format}`,
      { headers: await authHeaders() })
    if (!res.ok) { setErr(res.statusText); return }
    const blob = await res.blob()
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `snitch-forensics.${format === 'stix' ? 'stix.json' : format}`
    a.click()
    URL.revokeObjectURL(a.href)
  }

  async function toggleLockdown() {
    const on = !lockdown
    // EN: Engaging lockdown is disruptive — a confirmation is mandatory.
    // FR: Activer le lockdown est perturbant — une confirmation est requise.
    if (on && !window.confirm(t('fw_lockdown_confirm'))) return
    try {
      await post('/firewall/lockdown', { on })
      setLockdown(on)
      onLockdownChange?.(on)
      refresh()
    } catch (ex) { setErr(String(ex.message || ex)) }
  }

  /**
   * EN: Named profiles expand to ordinary rules + lockdown state —
   *     `strict` enables lockdown, so it gets the same confirmation.
   * FR: Les profils nommés se déplient en règles ordinaires + état
   *     lockdown — `strict` active le lockdown, donc même confirmation.
   */
  async function applyProfile(name) {
    if (name === 'strict' && !lockdown
        && !window.confirm(t('fw_lockdown_confirm'))) return
    setErr('')
    try {
      await post('/firewall/profile', { name })
      refresh()
    } catch (ex) { setErr(String(ex.message || ex)) }
  }

  /**
   * EN: Blocklist import — a local file is purely local; a URL is an
   *     OPT-IN outbound fetch the backend flags as `remote_fetch`.
   *     The user must opt in explicitly before we allow it.
   * FR: Import de blocklist — un fichier local est purement local ;
   *     une URL est un fetch sortant OPT-IN que le backend signale via
   *     `remote_fetch`. Opt-in explicite exigé.
   */
  async function importBlocklist() {
    setBlResult(null)
    setErr('')
    const body = { action: blAction, max_entries: 500 }
    if (blSource === 'url') {
      if (!window.confirm(t('bl_url_confirm'))) return
      body.url = blValue.trim()
    } else {
      body.path = blValue.trim()
    }
    if (!body.url && !body.path) return
    try {
      setBlResult(await post('/firewall/blocklist', body))
      setBlValue('')
      refresh()
    } catch (ex) { setErr(String(ex.message || ex)) }
  }

  async function addAlertRule(e) {
    e.preventDefault()
    if (!arValue.trim()) return
    setErr('')
    try {
      await post('/alerts/rules', {
        name: arName.trim(), field: arField, op: arOp,
        value: arValue.trim(), severity: arSev,
      })
      setArName(''); setArValue('')
      refresh()
    } catch (ex) { setErr(String(ex.message || ex)) }
  }

  async function deleteAlertRule(id) {
    await post(`/alerts/rules/${encodeURIComponent(id)}`, null, 'DELETE')
    refresh()
  }

  async function exportPcap() {
    // EN: Forensic pcap — raw frames from the bounded ring buffer,
    //     exactly what was on the wire. Same authenticated-blob pattern.
    // FR: Pcap forensique — trames brutes du tampon borné, exactement ce
    //     qui était sur le fil. Même motif blob authentifié.
    const base = await apiBase()
    const res = await fetch(`${base}/forensics/pcap`,
      { headers: await authHeaders() })
    if (res.status === 204) { setErr(t('fw_pcap_empty')); return }
    if (!res.ok) { setErr(res.statusText); return }
    const blob = await res.blob()
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'snitch-capture.pcap'
    a.click()
    URL.revokeObjectURL(a.href)
  }

  const row = { display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 0', borderBottom: '1px solid var(--bg)' }
  const label = { fontSize: 12, color: 'var(--text)', fontWeight: 600 }
  const hint = { fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }
  const input = {
    background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 6,
    color: 'var(--text)', padding: '6px 10px', fontSize: 11, outline: 'none',
  }

  return (
    <div role="dialog" aria-label="Firewall / Pare-feu" style={{
      position: 'absolute', top: 56, right: 16, zIndex: 200,
      width: 400, maxHeight: 'calc(100vh - 80px)',
      background: 'var(--surface)', border: '1px solid var(--border)',
      borderRadius: 12, overflow: 'hidden auto',
      boxShadow: '0 8px 40px rgba(0,0,0,0.6)',
    }}>
      <div style={{
        padding: '14px 18px', borderBottom: '1px solid var(--border)',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        position: 'sticky', top: 0, background: 'var(--surface)', zIndex: 1,
      }}>
        <span style={{ fontWeight: 700, fontSize: 13, color: 'var(--text)' }}>{t('fw_title')}</span>
        <button onClick={onClose} aria-label={t('close')} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}>
          <X size={16} />
        </button>
      </div>

      <div style={{ padding: '4px 18px 16px' }}>
        {/* Lockdown / Confinement */}
        <div style={row}>
          <div>
            <div style={{ ...label, display: 'flex', alignItems: 'center', gap: 6 }}>
              <Lock size={11} /> {t('fw_lockdown')}
            </div>
            <div style={hint}>{t('fw_lockdown_hint')}</div>
          </div>
          <button onClick={toggleLockdown} role="switch" aria-checked={lockdown} style={{
            width: 36, height: 20, borderRadius: 10, border: 'none',
            background: lockdown ? '#ef4444' : 'var(--bg)',
            outline: `1px solid ${lockdown ? '#ef4444' : 'var(--border)'}`,
            cursor: 'pointer', position: 'relative', flexShrink: 0,
          }}>
            <div style={{
              width: 14, height: 14, borderRadius: '50%', background: 'var(--text)',
              position: 'absolute', top: 3, left: lockdown ? 19 : 3,
              transition: 'left 0.15s',
            }} />
          </button>
        </div>

        {/* EN: Named profiles — one-tap policy bundles expanded into
                ordinary rules by the backend (no hidden code path).
            FR: Profils nommés — lots de règles en un clic dépliés par le
                backend en règles ordinaires (aucun chemin caché). */}
        <div style={{ ...row, borderBottom: 'none', paddingTop: 0 }}>
          <div>
            <div style={label}>{t('fw_profiles')}</div>
            <div style={hint}>{t('fw_profiles_hint')}</div>
          </div>
          <div style={{ display: 'flex', gap: 4 }}>
            {['permissive', 'balanced', 'strict'].map(p => (
              <button key={p} onClick={() => applyProfile(p)} style={{
                background: 'var(--bg)', border: '1px solid var(--border)',
                borderRadius: 5, color: p === 'strict' ? '#ef4444' : 'var(--text-muted)',
                fontSize: 9, fontWeight: 700, padding: '4px 7px',
                cursor: 'pointer', textTransform: 'uppercase',
              }}>{t(`fw_profile_${p}`)}</button>
            ))}
          </div>
        </div>

        {/* EN: Platform honesty — the backend reports whether native
                enforcement is available on this OS/privilege level.
            FR: Honnêteté plateforme — le backend rapporte si l'application
                native est disponible sur cet OS/niveau de privilège. */}
        {status && (
          <div style={{ ...hint, marginBottom: 4 }}>
            {status.supported
              ? t('fw_supported', status.platform)
              : t('fw_unsupported')}
            {status.demo && ` · ${t('fw_demo')}`}
          </div>
        )}

        {/* Add rule / Ajouter une règle */}
        <form onSubmit={addRule} style={{ display: 'flex', gap: 6, margin: '10px 0 4px' }}>
          <select value={kind} onChange={e => { setKind(e.target.value); if (e.target.value === 'process' || e.target.value === 'port') setAction('block') }} aria-label={t('fw_kind')} style={{ ...input, maxWidth: 110 }}>
            {RULE_KINDS.map(k => <option key={k} value={k}>{t(`fw_kind_${k}`)}</option>)}
          </select>
          {(kind === 'ip' || kind === 'domain') && (
            <select value={action} onChange={e => setAction(e.target.value)} aria-label={t('fw_action')} style={{ ...input, maxWidth: 90 }}>
              <option value="block">{t('fw_action_block')}</option>
              <option value="sinkhole">{t('fw_action_sinkhole')}</option>
              <option value="throttle">{t('fw_action_throttle')}</option>
            </select>
          )}
          {action === 'throttle' && (kind === 'ip' || kind === 'domain') && (
            <input type="number" min="8" max="1000000" value={rate}
              onChange={e => setRate(Number(e.target.value) || 64)}
              title={t('fw_rate_hint')} aria-label={t('fw_rate')}
              style={{ ...input, width: 56 }} />
          )}
          <input value={value} onChange={e => setValue(e.target.value)}
            placeholder={t(`fw_ph_${kind}`)} aria-label={t('fw_value')}
            style={{ ...input, flex: 1 }} />
          <button type="submit" style={{
            background: '#3b82f6', border: 'none', borderRadius: 6,
            color: '#fff', padding: '6px 10px', cursor: 'pointer',
            display: 'flex', alignItems: 'center',
          }}><Plus size={12} /></button>
        </form>
        {err && <div style={{ fontSize: 10, color: '#ef4444', marginBottom: 4 }}>{err}</div>}

        {/* Rules list / Liste des règles */}
        <div style={{ ...label, marginTop: 10, marginBottom: 4 }}>{t('fw_rules')}</div>
        {rules.length === 0 && <div style={{ ...hint, padding: '6px 0' }}>{t('fw_empty')}</div>}
        {rules.map(r => (
          <div key={r.id} style={{ ...row, gap: 8 }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{
                  fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
                  color: r.enabled ? 'var(--blue-text)' : 'var(--text-faint)',
                  background: 'var(--bg)', borderRadius: 4, padding: '1px 5px',
                }}>{r.kind}</span>
                {r.action && r.action !== 'block' && (
                  <span style={{
                    fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
                    color: r.action === 'sinkhole' ? '#a855f7' : '#f59e0b',
                    background: 'var(--bg)', borderRadius: 4,
                    padding: '1px 5px',
                  }}>{t(`fw_action_${r.action}`)}{r.action === 'throttle' && r.rate ? ` ${r.rate}k` : ''}</span>
                )}
                <span style={{ fontSize: 11, color: r.enabled ? 'var(--text)' : 'var(--text-faint)', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {r.value}
                </span>
              </div>
              <div style={hint}>
                {r.blocked > 0 && `${t('fw_blocked', r.blocked)} · `}
                {r.applied ? t('fw_applied') : t('fw_not_applied')}
              </div>
            </div>
            <button onClick={() => toggleRule(r.id, !r.enabled)} title={r.enabled ? t('fw_disable') : t('fw_enable')} style={{
              width: 30, height: 17, borderRadius: 9, border: 'none', flexShrink: 0,
              background: r.enabled ? '#3b82f6' : 'var(--bg)',
              outline: '1px solid var(--border)', cursor: 'pointer', position: 'relative',
            }}>
              <div style={{
                width: 11, height: 11, borderRadius: '50%', background: 'var(--text)',
                position: 'absolute', top: 3, left: r.enabled ? 16 : 3,
              }} />
            </button>
            <button onClick={() => deleteRule(r.id)} aria-label={t('fw_delete')} style={{
              background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 2,
            }}><Trash2 size={12} /></button>
          </div>
        ))}

        {/* EN: Blocklist import — a local hosts/domain file is a pure
                local read; a URL is an OPT-IN outbound fetch (confirmed
                before sending; the response flags `remote_fetch`).
            FR: Import de blocklist — un fichier hosts/domaines local est
                une lecture purement locale ; une URL est un fetch
                sortant OPT-IN (confirmé avant envoi ; `remote_fetch`
                signalé dans la réponse). */}
        <div style={{ borderTop: '1px solid var(--border)', marginTop: 10, paddingTop: 8 }}>
          <div style={label}>{t('bl_title')}</div>
          <div style={hint}>{t('bl_hint')}</div>
          <div style={{ display: 'flex', gap: 6, marginTop: 6 }}>
            <select value={blSource} onChange={e => setBlSource(e.target.value)} aria-label={t('bl_source')} style={{ ...input, maxWidth: 76 }}>
              <option value="path">{t('bl_src_file')}</option>
              <option value="url">{t('bl_src_url')}</option>
            </select>
            <input value={blValue} onChange={e => setBlValue(e.target.value)}
              placeholder={blSource === 'url' ? 'https://…' : '/path/to/hosts'}
              aria-label={t('bl_source')} style={{ ...input, flex: 1 }} />
            <select value={blAction} onChange={e => setBlAction(e.target.value)} aria-label={t('fw_action')} style={{ ...input, maxWidth: 80 }}>
              <option value="block">{t('fw_action_block')}</option>
              <option value="sinkhole">{t('fw_action_sinkhole')}</option>
            </select>
            <button onClick={importBlocklist} disabled={!blValue.trim()} style={{
              background: blValue.trim() ? '#3b82f6' : 'var(--bg)', border: 'none',
              borderRadius: 6, color: blValue.trim() ? '#fff' : 'var(--text-faint)',
              padding: '6px 10px', cursor: 'pointer', fontSize: 10, fontWeight: 700,
            }}>{t('bl_import')}</button>
          </div>
          {blResult && (
            <div style={{ ...hint, marginTop: 4 }}>
              {t('bl_result', blResult.added, blResult.skipped)}
              {blResult.truncated && ` · ${t('bl_truncated')}`}
              {blResult.remote_fetch && ` · ${t('bl_remote')}`}
            </div>
          )}
        </div>

        {/* EN: Custom alert rules — user-defined matchers that raise
                CUSTOM_RULE alerts (alert-only, never block).
            FR: Règles d'alerte personnalisées — filtres définis par
                l'utilisateur qui lèvent des alertes CUSTOM_RULE (alerte
                seule, jamais de blocage). */}
        <div style={{ borderTop: '1px solid var(--border)', marginTop: 10, paddingTop: 8 }}>
          <div style={label}>{t('ar_title')}</div>
          <div style={hint}>{t('ar_hint')}</div>
          <form onSubmit={addAlertRule} style={{ display: 'flex', gap: 4, marginTop: 6, flexWrap: 'wrap' }}>
            <input value={arName} onChange={e => setArName(e.target.value)}
              placeholder={t('ar_name_ph')} aria-label={t('ar_name_ph')}
              style={{ ...input, flex: '1 1 100%' }} />
            <select value={arField} onChange={e => setArField(e.target.value)} aria-label={t('ar_field')} style={{ ...input }}>
              {['remote_ip', 'host', 'process_name', 'remote_port', 'protocol', 'direction', 'size'].map(f =>
                <option key={f} value={f}>{f}</option>)}
            </select>
            <select value={arOp} onChange={e => setArOp(e.target.value)} aria-label={t('ar_op')} style={{ ...input }}>
              {['eq', 'ne', 'contains', 'regex', 'gt', 'lt', 'cidr'].map(o =>
                <option key={o} value={o}>{o}</option>)}
            </select>
            <input value={arValue} onChange={e => setArValue(e.target.value)}
              placeholder={t('ar_value_ph')} aria-label={t('ar_value_ph')}
              style={{ ...input, flex: 1 }} />
            <select value={arSev} onChange={e => setArSev(e.target.value)} aria-label={t('ar_sev')} style={{ ...input }}>
              <option value="info">{t('sev_info')}</option>
              <option value="warning">{t('sev_warning')}</option>
              <option value="critical">{t('sev_critical')}</option>
            </select>
            <button type="submit" style={{
              background: '#3b82f6', border: 'none', borderRadius: 6,
              color: '#fff', padding: '6px 10px', cursor: 'pointer',
              display: 'flex', alignItems: 'center',
            }}><Plus size={12} /></button>
          </form>
          {aRules.map(r => (
            <div key={r.id} style={{ ...row, padding: '5px 0' }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <span style={{ fontSize: 10, color: 'var(--text)' }}>{r.name}</span>
                <div style={hint}>
                  {r.field} {r.op} {r.value}
                  {r.hits > 0 && ` · ${t('ar_hits', r.hits)}`}
                </div>
              </div>
              <button onClick={() => deleteAlertRule(r.id)} aria-label={t('fw_delete')} style={{
                background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 2,
              }}><Trash2 size={12} /></button>
            </div>
          ))}
        </div>

        {/* Security audit / Audit de sécurité */}
        <div style={{ ...row, display: 'block', borderTop: '1px solid var(--border)', marginTop: 12 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={label}>{t('audit_title')}</div>
            <button onClick={refreshAudit} aria-label={t('audit_refresh')} style={{
              background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 2,
            }}><RefreshCw size={12} /></button>
          </div>
          {audit ? (
            <>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, margin: '6px 0' }}>
                <span style={{
                  fontSize: 26, fontWeight: 700,
                  color: audit.score >= 80 ? '#4ade80' : audit.score >= 50 ? '#f59e0b' : '#ef4444',
                }}>{audit.score}</span>
                <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>/100 · {audit.period}</span>
              </div>
              {audit.critical + audit.warning > 0 && (
                <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 6 }}>
                  {audit.critical} {t('audit_critical')} · {audit.warning} {t('audit_warning')}
                </div>
              )}
              {audit.findings?.high_risk_countries?.length > 0 && (
                <div style={{ fontSize: 10, color: '#f59e0b', marginBottom: 4 }}>
                  <AlertTriangle size={10} style={{ verticalAlign: -1 }} /> {t('audit_risky', audit.findings.high_risk_countries.length)}
                </div>
              )}
              {(audit.recommendations || []).map((r, i) => (
                <div key={i} style={{
                  fontSize: 10, lineHeight: 1.5, marginBottom: 4,
                  color: { high: '#f87171', medium: '#fbbf24', low: 'var(--text-muted)', info: 'var(--text-muted)' }[r.level] || 'var(--text-muted)',
                }}>
                  • {r.text}
                </div>
              ))}
            </>
          ) : (
            <div style={hint}>{t('audit_loading')}</div>
          )}
          {/* Forensics export / Export forensique */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
            <span style={hint}>{t('fw_forensics')}</span>
            {['json', 'csv', 'stix'].map(f => (
              <button key={f} onClick={() => exportForensics(f)} style={{
                background: 'var(--bg)', border: '1px solid var(--border)',
                borderRadius: 5, color: 'var(--text-muted)', fontSize: 9,
                fontWeight: 700, padding: '3px 8px', cursor: 'pointer',
                textTransform: 'uppercase',
              }}>{f}</button>
            ))}
            <button onClick={exportPcap} title={t('fw_pcap_hint')} style={{
              background: 'var(--bg)', border: '1px solid var(--border)',
              borderRadius: 5, color: 'var(--text-muted)', fontSize: 9,
              fontWeight: 700, padding: '3px 8px', cursor: 'pointer',
              textTransform: 'uppercase',
            }}>pcap</button>
          </div>
          {/* EN: Privacy-preserving IOC pack — export shares indicators as
                  a noised Bloom filter (never raw); import checks observed
                  destinations against a community pack, probabilistically.
              FR: Paquet IOC préservant la vie privée — l'export partage les
                  indicateurs en filtre de Bloom bruité (jamais en clair) ;
                  l'import confronte les destinations observées à un paquet
                  communautaire, de façon probabiliste. */}
          <div style={{ borderTop: '1px solid var(--border)', marginTop: 10, paddingTop: 8 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={label}>{t('ioc_title')}</span>
              <button onClick={exportIoc} style={{
                background: 'var(--bg)', border: '1px solid var(--border)',
                borderRadius: 5, color: 'var(--text-muted)', fontSize: 9,
                fontWeight: 700, padding: '3px 8px', cursor: 'pointer',
              }}>{t('ioc_export')}</button>
            </div>
            <div style={hint}>{t('ioc_hint')}</div>
            <textarea value={iocText} onChange={e => setIocText(e.target.value)}
              placeholder={t('ioc_import_ph')} rows={2}
              style={{ ...input, width: '100%', boxSizing: 'border-box', marginTop: 4, resize: 'vertical', fontFamily: 'monospace' }} />
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
              <button onClick={importIoc} disabled={!iocText.trim()} style={{
                background: iocText.trim() ? '#3b82f6' : 'var(--bg)', border: 'none',
                borderRadius: 5, color: iocText.trim() ? '#fff' : 'var(--text-faint)',
                fontSize: 9, fontWeight: 700, padding: '3px 8px', cursor: 'pointer',
              }}>{t('ioc_check')}</button>
              {iocResult && (
                <span style={{ fontSize: 10, color: iocResult.ok ? (iocResult.hints?.length ? '#f59e0b' : '#4ade80') : '#ef4444' }}>
                  {iocResult.ok
                    ? (iocResult.hints?.length
                      ? t('ioc_hints', iocResult.hints.length)
                      : t('ioc_clean'))
                    : t('ioc_bad')}
                </span>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
