/**
 * Snitch — search & category filter bar.
 *
 * EN: Text search (matches label/IP/country/org/hostname) plus a row of
 *     category chips. Controlled component: state lives in App, this just
 *     reports changes.
 * FR: Recherche texte (correspond à label/IP/pays/org/hostname) plus une
 *     rangée de puces de catégorie. Composant contrôlé : l'état vit dans App,
 *     il ne fait que remonter les changements.
 */
import { Search, X } from 'lucide-react'
import { useT } from '../i18n'

// EN: Category chips — `label` is a hardcoded English service name, otherwise
//     the chip falls back to an i18n key.
// FR: Puces de catégorie — `label` est un nom de service anglais fixe, sinon
//     la puce utilise une clé i18n.
const CATEGORY_IDS = [
  { id: 'all',      color: '#64748b' },
  { id: 'safe',     label: 'HTTPS',    color: '#22c55e' },
  { id: 'tracking', label: 'Tracking', color: '#f59e0b' },
  { id: 'cdn',      label: 'CDN',      color: '#6366f1' },
  { id: 'dns',      label: 'DNS',      color: '#38bdf8' },
  { id: 'unknown',  color: '#94a3b8' },
]

export default function SearchBar({ filter, onChange }) {
  const { t } = useT()
  const { text, category } = filter

  const categories = CATEGORY_IDS.map(c => ({
    ...c,
    label: c.label ?? (c.id === 'all' ? t('cat_all') : t('cat_unknown')),
  }))

  return (
    <div style={{ padding: '8px 12px' }}>
      {/* EN: Text field / FR: Champ texte */}
      <div style={{ position: 'relative', marginBottom: 7 }}>
        <Search size={11} style={{
          position: 'absolute', left: 8, top: '50%',
          transform: 'translateY(-50%)', color: '#64748b', pointerEvents: 'none',
        }} />
        <input
          value={text}
          onChange={e => onChange({ ...filter, text: e.target.value })}
          placeholder={t('search_placeholder')}
          style={{
            width: '100%', boxSizing: 'border-box',
            background: '#000000', border: '1px solid #2a2a2a',
            borderRadius: 6, padding: '5px 26px 5px 26px',
            color: '#e2e8f0', fontSize: 11, outline: 'none',
          }}
        />
        {text && (
          <button onClick={() => onChange({ ...filter, text: '' })} style={{
            position: 'absolute', right: 6, top: '50%', transform: 'translateY(-50%)',
            background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', padding: 0,
          }}>
            <X size={11} />
          </button>
        )}
      </div>

      {/* EN: Category chips / FR: Puces de catégorie */}
      <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
        {categories.map(c => (
          <button key={c.id} onClick={() => onChange({ ...filter, category: c.id })} style={{
            background: category === c.id ? c.color + '22' : 'transparent',
            border: `1px solid ${category === c.id ? c.color : '#2a2a2a'}`,
            borderRadius: 10, padding: '2px 8px',
            fontSize: 9, fontWeight: 600,
            color: category === c.id ? c.color : '#64748b',
            cursor: 'pointer', transition: 'all 0.15s',
          }}>
            {c.label}
          </button>
        ))}
      </div>
    </div>
  )
}
