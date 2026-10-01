/**
 * Snitch — privacy score widget.
 *
 * EN: Renders the 0–100 score as an SVG donut plus the top contributing
 *     factors. `factors` entries carry an i18n `key` + `args` so the labels
 *     stay translated; `bad` flags penalties vs. positive signals.
 * FR: Affiche le score de 0 à 100 sous forme de donut SVG plus les principaux
 *     facteurs. Les entrées `factors` portent une `key` i18n + `args` pour que
 *     les libellés restent traduits ; `bad` distingue pénalités et signaux
 *     positifs.
 */
import {
  Radio, BarChart2, Target, Activity,
  AlertTriangle, Unlock, ShieldAlert, Bell,
  Lock, CheckCircle2,
} from 'lucide-react'
import { useT } from '../i18n'

// EN: Icon lookup by the string key produced by the scoring engine.
// FR: Table d'icônes indexée par la clé chaîne produite par le moteur de score.
const SCORE_ICONS = {
  'radio':          Radio,
  'bar-chart':      BarChart2,
  'target':         Target,
  'activity':       Activity,
  'alert-triangle': AlertTriangle,
  'unlock':         Unlock,
  'shield-alert':   ShieldAlert,
  'bell':           Bell,
  'lock':           Lock,
  'check-circle':   CheckCircle2,
}

const R      = 34
const CIRC   = 2 * Math.PI * R
const STROKE = 7

export default function PrivacyScore({ score, grade, color, labelKey, factors }) {
  const { t } = useT()
  const filled   = (score / 100) * CIRC
  const badCount = factors.filter(f => f.bad).length

  return (
    <div style={{ padding: '14px 16px' }}>
      <div style={{ fontSize: 10, color: '#64748b', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>
        {t('privacy_title')}
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
        {/* EN: Donut — arc length proportional to the score.
            FR: Donut — longueur d'arc proportionnelle au score. */}
        <div style={{ flexShrink: 0 }}>
          <svg width={84} height={84}>
            <circle cx={42} cy={42} r={R} fill="none" stroke="#1c1c1c" strokeWidth={STROKE} />
            <circle
              cx={42} cy={42} r={R}
              fill="none" stroke={color} strokeWidth={STROKE}
              strokeDasharray={`${filled} ${CIRC - filled}`}
              strokeLinecap="round"
              transform="rotate(-90 42 42)"
              style={{ transition: 'stroke-dasharray 0.6s ease' }}
            />
            <text x={42} y={38} textAnchor="middle" fill={color} fontSize={20} fontWeight={700} fontFamily="system-ui">
              {score}
            </text>
            <text x={42} y={54} textAnchor="middle" fill={color} fontSize={11} fontWeight={600} opacity={0.7}>
              {grade}
            </text>
          </svg>
        </div>

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 13, fontWeight: 700, color, marginBottom: 2 }}>{t(labelKey)}</div>
          <div style={{ fontSize: 10, color: '#64748b', marginBottom: 8 }}>
            {t('privacy_risk_factors', badCount)}
          </div>

          {/* EN: Top 3 factors with their point penalty.
              FR: Top 3 des facteurs avec leur pénalité en points. */}
          {factors.slice(0, 3).map((f, i) => {
            const Icon = SCORE_ICONS[f.icon]
            return (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                {Icon && <Icon size={12} color={f.bad ? '#94a3b8' : '#22c55e'} />}
                <span style={{
                  fontSize: 10, color: f.bad ? '#cbd5e1' : '#64748b',
                  flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                }}>
                  {t(f.key, ...f.args)}
                </span>
                {f.bad && f.penalty > 0 && (
                  <span style={{ fontSize: 9, color: '#ef4444', flexShrink: 0 }}>-{f.penalty}</span>
                )}
              </div>
            )
          })}

          {factors.length > 3 && (
            <div style={{ fontSize: 9, color: '#475569', marginTop: 2 }}>
              {t('privacy_more_factors', factors.length - 3)}
            </div>
          )}
        </div>
      </div>

      {/* EN: Gradient scale with the score cursor.
          FR: Échelle en dégradé avec le curseur du score. */}
      <div style={{ marginTop: 12 }}>
        <div style={{
          height: 4, borderRadius: 2,
          background: 'linear-gradient(to right, #ef4444, #f97316, #f59e0b, #84cc16, #22c55e)',
          position: 'relative',
        }}>
          <div style={{
            position: 'absolute', left: `${score}%`, top: '50%',
            transform: 'translate(-50%, -50%)',
            width: 10, height: 10, borderRadius: '50%',
            background: color, border: '2px solid #000000',
            boxShadow: `0 0 6px ${color}`,
            transition: 'left 0.6s ease',
          }} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 3 }}>
          <span style={{ fontSize: 8, color: '#ef4444' }}>{t('privacy_critical_label')}</span>
          <span style={{ fontSize: 8, color: '#22c55e' }}>{t('privacy_excellent_label')}</span>
        </div>
      </div>
    </div>
  )
}
