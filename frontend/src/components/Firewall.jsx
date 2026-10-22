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
  const [err, setErr] = useState('')
  const [audit, setAudit] = useState(null)

  const refresh = useCallback(async () => {
    const base = await apiBase()
    const headers = await authHeaders()
    try {
      const [r, s] = await Promise.all([
        fetch(`${base}/firewall/rules`, { headers }).then(x => x.json()),
        fetch(`${base}/firewall/status`, { headers }).then(x => x.json()),
      ])
      setRules(r.rules || [])
      setLockdown(!!r.lockdown)
      setStatus(s)
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
      await post('/firewall/rules', { kind, value: v, action })
      setValue('')
      refresh()
    } catch (ex) { setErr(String(ex.message || ex)) }
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
            </select>
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
                {r.action === 'sinkhole' && (
                  <span style={{
                    fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
                    color: '#a855f7', background: 'var(--bg)', borderRadius: 4,
                    padding: '1px 5px',
                  }}>{t('fw_action_sinkhole')}</span>
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
          </div>
        </div>
      </div>
    </div>
  )
}
