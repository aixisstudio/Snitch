/**
 * Snitch — first-run onboarding modal.
 *
 * EN: Shown exactly once (localStorage flag `snitch_onboarded`). Explains the
 *     three things a privacy tool owes its user up front: what privileges the
 *     capture needs, WHAT is actually captured (headers/metadata — never
 *     payloads), and what leaves the machine (nothing, except the opt-in
 *     GeoIP download the user triggers themselves).
 * FR: Affiché une seule fois (drapeau localStorage `snitch_onboarded`).
 *     Explique les trois choses qu'un outil de vie privée doit à son
 *     utilisateur d'emblée : les privilèges requis par la capture, CE qui est
 *     réellement capturé (en-têtes/métadonnées — jamais les contenus), et ce
 *     qui quitte la machine (rien, sauf le téléchargement GeoIP opt-in
 *     déclenché par l'utilisateur).
 */
import { ShieldCheck, Eye, Download } from 'lucide-react'
import { useT } from '../i18n'

export default function Onboarding({ onDone }) {
  const { t } = useT()

  function dismiss() {
    localStorage.setItem('snitch_onboarded', '1')
    onDone()
  }

  const item = { display: 'flex', gap: 12, alignItems: 'flex-start', marginBottom: 14 }

  return (
    <div role="dialog" aria-modal="true" aria-label={t('onboard_title')} style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(2,6,23,0.85)', backdropFilter: 'blur(4px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{
        width: 440, background: '#1e293b', border: '1px solid #334155',
        borderRadius: 14, padding: '28px 28px 20px',
        boxShadow: '0 20px 60px rgba(0,0,0,0.7)',
      }}>
        <div style={{ fontSize: 18, fontWeight: 700, color: '#f1f5f9', marginBottom: 4 }}>
          {t('onboard_title')}
        </div>
        <div style={{ fontSize: 12, color: '#94a3b8', marginBottom: 20 }}>
          {t('onboard_sub')}
        </div>

        <div style={item}>
          <ShieldCheck size={18} color="#22c55e" style={{ flexShrink: 0, marginTop: 1 }} />
          <div>
            <div style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0' }}>{t('onboard_priv_title')}</div>
            <div style={{ fontSize: 11, color: '#94a3b8', lineHeight: 1.5 }}>{t('onboard_priv_body')}</div>
          </div>
        </div>

        <div style={item}>
          <Eye size={18} color="#38bdf8" style={{ flexShrink: 0, marginTop: 1 }} />
          <div>
            <div style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0' }}>{t('onboard_capture_title')}</div>
            <div style={{ fontSize: 11, color: '#94a3b8', lineHeight: 1.5 }}>{t('onboard_capture_body')}</div>
          </div>
        </div>

        <div style={item}>
          <Download size={18} color="#f59e0b" style={{ flexShrink: 0, marginTop: 1 }} />
          <div>
            <div style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0' }}>{t('onboard_out_title')}</div>
            <div style={{ fontSize: 11, color: '#94a3b8', lineHeight: 1.5 }}>{t('onboard_out_body')}</div>
          </div>
        </div>

        <button onClick={dismiss} autoFocus style={{
          width: '100%', marginTop: 8, padding: '10px 0',
          background: '#3b82f6', border: 'none', borderRadius: 8,
          color: '#fff', fontSize: 13, fontWeight: 700, cursor: 'pointer',
        }}>
          {t('onboard_go')}
        </button>
      </div>
    </div>
  )
}
