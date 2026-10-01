/**
 * Snitch — left sidebar.
 *
 * EN: Column layout: brand header + bandwidth sparkline, quick stats,
 *     privacy score, selected-node detail card, search bar, scrollable
 *     LAN-device + external-host lists, and the recent-packet feed.
 * FR: Colonne : en-tête de marque + sparkline de débit, stats rapides, score
 *     de confidentialité, fiche du nœud sélectionné, barre de recherche,
 *     listes déroulantes appareils LAN + hôtes externes, et le flux de
 *     paquets récents.
 */
import { Wifi, Smartphone, Monitor, Tv, Cpu, HelpCircle, ShieldOff } from 'lucide-react'
import PrivacyScore from './PrivacyScore'
import BandwidthChart from './BandwidthChart'
import { useT } from '../i18n'

// EN: Lucide icon per LAN device type. / FR: Icône Lucide par type d'appareil LAN.
const DEVICE_ICONS = {
  router:  Wifi,
  phone:   Smartphone,
  pc:      Monitor,
  tv:      Tv,
  iot:     Cpu,
  unknown: HelpCircle,
}

// EN: Dot color per traffic category — mirrors the backend classifier.
// FR: Couleur de point par catégorie de trafic — reflète le classifieur backend.
const CATEGORY_COLORS = {
  safe: '#22c55e', tracking: '#f59e0b', cdn: '#6366f1',
  dns: '#38bdf8', admin: '#fb923c', unknown: '#94a3b8', local: '#3b82f6',
}

/**
 * EN: Display name for a node — `label_key` is a translation key resolved
 *     through t() (e.g. the "local" node), then label, then IP fallback.
 * FR: Nom d'affichage d'un nœud — `label_key` est une clé de traduction
 *     résolue via t() (ex. le nœud « local »), puis label, puis l'IP.
 */
const nodeName = (n, t) => n.label || (n.label_key ? t(n.label_key) : null) || n.ip

/**
 * EN: Translate a raw backend enum value (device_type, category) through a
 *     key prefix — falls back to the raw value when no key exists.
 * FR: Traduit une valeur brute du backend (device_type, catégorie) via un
 *     préfixe de clé — retombe sur la valeur brute si la clé n'existe pas.
 */
const enumName = (t, prefix, v) => {
  const s = t(prefix + v)
  return s === prefix + v ? v : s
}

/** EN: Human-readable byte size. / FR: Taille en octets lisible. */
function fmt(bytes) {
  if (!bytes) return '0 B'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`
}

/**
 * EN: Does a node match the active search filter? The "local" node and any
 *     node matching the category always pass unless the text fails. The
 *     special "alerted" category keeps only nodes present in `alertedIds`
 *     (warning/critical alert map), regardless of their traffic category.
 * FR: Un nœud correspond-il au filtre de recherche actif ? Le nœud « local »
 *     et tout nœud de la bonne catégorie passent sauf si le texte échoue.
 *     La catégorie spéciale « alerted » ne garde que les nœuds présents dans
 *     `alertedIds` (alertes warning/critique), quelle que soit la catégorie.
 */
export function matchesFilter(node, filter, alertedIds) {
  if (!filter || (filter.category === 'all' && !filter.text)) return true
  if (filter.category === 'alerted') {
    if (!alertedIds || !alertedIds.has(node.id)) return false
  } else if (filter.category !== 'all' && node.category !== filter.category) return false
  if (filter.text) {
    const t = filter.text.toLowerCase()
    return (node.label   || '').toLowerCase().includes(t)
        || (node.ip      || '').toLowerCase().includes(t)
        || (node.country || '').toLowerCase().includes(t)
        || (node.org     || '').toLowerCase().includes(t)
  }
  return true
}

export default function Sidebar({ nodes, lanDevices, packets, selected, onClose, privacyScore, bandwidth, filter, onFilterChange, onWhitelist, alertedNodes }) {
  const { t } = useT()
  const extNodes = Object.values(nodes).filter(n => n.id !== 'local')
  // EN: the "Alerts" chip narrows the LAN list to flagged devices too —
  //     other categories keep the full device list (they're local, not hosts).
  // FR: la puce « Alertes » réduit aussi la liste LAN aux appareils
  //     signalés — les autres catégories gardent la liste complète (ce sont
  //     des appareils locaux, pas des hôtes).
  const devList  = Object.values(lanDevices)
    .filter(d => filter?.category !== 'alerted' || (alertedNodes && alertedNodes.has(d.id)))
  const totalBytes = extNodes.reduce((a, n) => a + (n.bytes || 0), 0)

  const filteredNodes = extNodes.filter(n => matchesFilter(n, filter, alertedNodes))
  const hiddenCount = filteredNodes.length < extNodes.length ? extNodes.length : null

  return (
    /* EN: Bento layout — each section is a rounded card floating on the
           black rail, separated by gaps instead of divider lines.
       FR: Layout bento — chaque section est une carte arrondie flottant
           sur le rail noir, séparée par des espaces plutôt que des lignes. */
    <div style={{
      width: 308, height: '100vh', background: 'transparent',
      display: 'flex',
      flexDirection: 'column', overflow: 'hidden',
      padding: 8, gap: 8, boxSizing: 'border-box',
    }}>
      {/* EN: Brand floats free on the rail — the bento cards start below.
          FR: La marque flotte librement sur le rail — les cartes bento
              commencent en dessous. */}
      <div style={{ padding: '8px 8px 0' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 2 }}>
          {/* EN: Snitch mark — the white radar-eye sigil.
              FR: Emblème Snitch — le sigle radar-œil blanc. */}
          <img src="/logo.png" alt="Snitch" style={{ width: 22, height: 22, borderRadius: 5 }} />
          <span style={{ fontSize: 17, fontWeight: 800, color: '#f1f5f9', letterSpacing: 1 }}>{t('app_name')}</span>
        </div>
        <span style={{ fontSize: 10, color: '#475569', letterSpacing: 1 }}>{t('tagline')}</span>
      </div>

      {/* EN: Quick counters + live bandwidth sparkline.
          FR: Compteurs rapides + sparkline de débit en direct. */}
      <div style={{ ...CARD, padding: '10px 16px' }}>
        <BandwidthChart data={bandwidth || []} />
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8 }}>
          <Stat label={t('stat_lan')}     value={devList.length}      color="#f97316" />
          <Stat label={t('stat_ext')}     value={extNodes.length} />
          <Stat label={t('stat_traffic')} value={fmt(totalBytes)} />
        </div>
      </div>

      {privacyScore && (
        <div style={CARD}>
          <PrivacyScore
            score={privacyScore.score}
            grade={privacyScore.grade}
            color={privacyScore.color}
            labelKey={privacyScore.labelKey}
            factors={privacyScore.factors}
          />
        </div>
      )}

      {/* EN: Detail card for the clicked node. / FR: Fiche détail du nœud cliqué. */}
      {selected && (
        <div style={{ ...CARD, padding: '12px 16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: '#f1f5f9' }}>
              {nodeName(selected, t)}
            </span>
            <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', fontSize: 16 }}>x</button>
          </div>
          <NodeDetail node={selected} onWhitelist={onWhitelist} />
        </div>
      )}

      <div style={{ ...CARD, flex: 1, overflowY: 'auto', minHeight: 0 }}>
        {devList.length > 0 && (
          <>
            <SectionTitle label={t('section_lan', devList.length)} />
            {devList.map(d => <DeviceRow key={d.id} device={d} />)}
          </>
        )}

        <SectionTitle label={t('section_ext', filteredNodes.length, hiddenCount)} />
        {filteredNodes.length === 0 && (
          <div style={{ padding: '10px 20px', fontSize: 10, color: '#475569', fontStyle: 'italic' }}>
            {t('ext_empty')}
          </div>
        )}
        {filteredNodes
          .sort((a, b) => (b.bytes || 0) - (a.bytes || 0))
          .map(n => <NodeRow key={n.id} node={n} />)}
      </div>

      {/* EN: Recent packet feed / FR: Flux de paquets récents */}
      <div style={{ ...CARD, maxHeight: 160, overflowY: 'auto', flexShrink: 0 }}>
        <SectionTitle label={t('section_packets')} />
        {packets.slice(0, 25).map((p, i) => <PacketRow key={i} packet={p} />)}
      </div>
    </div>
  )
}

/** EN: Bento card chrome — near-black fill, hairline border, 12px radius.
 *  FR: Habillage carte bento — fond quasi noir, bordure fine, rayon 12 px. */
const CARD = {
  background: '#0f0f0f', border: '1px solid #1c1c1c',
  borderRadius: 12,
}

/** EN: Sticky list section header. / FR: En-tête de section de liste collant. */
function SectionTitle({ label }) {
  return (
    <div style={{ padding: '6px 16px 4px', fontSize: 10, color: '#64748b', textTransform: 'uppercase', letterSpacing: 1, background: '#0f0f0f', position: 'sticky', top: 0, borderRadius: '12px 12px 0 0' }}>
      {label}
    </div>
  )
}

function Stat({ label, value, color }) {
  return (
    <div style={{ textAlign: 'center' }}>
      <div style={{ fontSize: 16, fontWeight: 700, color: color || '#f1f5f9' }}>{value}</div>
      <div style={{ fontSize: 10, color: '#64748b' }}>{label}</div>
    </div>
  )
}

/** EN: Small explanatory note in the detail card — muted box, coloured
 *      left border. / FR: Petite note explicative dans la fiche détail —
 *      cadre discret, bordure gauche colorée. */
function Hint({ children, accent = '#2a2a2a' }) {
  return (
    <div style={{
      marginTop: 8, padding: '6px 8px', fontSize: 9, lineHeight: 1.5,
      color: '#64748b', background: '#000000', borderRadius: 6,
      borderLeft: `2px solid ${accent}`,
    }}>
      {children}
    </div>
  )
}

/** EN: One row of the LAN device list. / FR: Une ligne de la liste d'appareils LAN. */
function DeviceRow({ device }) {
  const { t } = useT()
  const Icon = DEVICE_ICONS[device.device_type] || HelpCircle
  return (
    <div style={{
      padding: '7px 16px', display: 'flex', alignItems: 'center', gap: 8,
      borderBottom: '1px solid #1a1a1a',
      opacity: device.online === false ? 0.45 : 1,
    }}>
      <Icon size={16} color={device.color} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 11, fontWeight: 600, color: '#e2e8f0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {device.hostname || device.vendor || device.ip}
          {!device.hostname && !device.vendor && (
            <span style={{ fontSize: 9, color: '#475569', fontWeight: 400 }}> · {t('unidentified')}</span>
          )}
        </div>
        <div style={{ fontSize: 9, color: '#64748b', fontFamily: 'monospace' }}>
          {/* EN: Type first — "Routeur · 192.168.1.254" tells a neophyte more
                  than a bare MAC address does.
              FR: Le type d'abord — « Routeur · 192.168.1.254 » dit plus à un
                  néophyte qu'une MAC nue. */}
          {enumName(t, 'devtype_', device.device_type)} · {device.ip}
        </div>
      </div>
      <div style={{ fontSize: 9, color: device.online === false ? '#ef4444' : '#22c55e', flexShrink: 0 }}>
        {device.online === false ? t('offline') : t('online')}
      </div>
    </div>
  )
}

/** EN: One row of the external-host list. / FR: Une ligne de la liste d'hôtes externes. */
function NodeRow({ node }) {
  const { t } = useT()
  return (
    <div style={{ padding: '6px 16px', display: 'flex', alignItems: 'center', gap: 8, borderBottom: '1px solid #1a1a1a' }}>
      <div style={{ width: 7, height: 7, borderRadius: '50%', background: CATEGORY_COLORS[node.category] || '#94a3b8', flexShrink: 0 }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 11, color: '#e2e8f0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {nodeName(node, t)}
        </div>
        <div style={{ fontSize: 9, color: '#64748b' }}>{node.country || '-'} · {node.packets || 0} pkt</div>
      </div>
      <div style={{ fontSize: 10, color: '#94a3b8', flexShrink: 0 }}>{fmt(node.bytes || 0)}</div>
    </div>
  )
}

/** EN: Selected-node fields + top processes + whitelist action.
 *  FR: Champs du nœud sélectionné + top processus + action de whitelist. */
function NodeDetail({ node, onWhitelist }) {
  const { t } = useT()
  const fields = [
    [t('field_ip'),       node.ip],
    [t('field_mac'),      node.mac],
    [t('field_hostname'), node.hostname],
    [t('field_vendor'),   node.vendor],
    [t('field_type'),     node.device_type ? enumName(t, 'devtype_', node.device_type) : null],
    [t('field_country'),  node.country],
    [t('field_city'),     node.city],
    [t('field_org'),      node.org],
    [t('field_category'), node.category ? enumName(t, 'cat_', node.category) : null],
    [t('field_traffic'),  fmt(node.bytes || 0)],
    [t('field_packets'),  node.packets],
  ]

  // EN: Is this node still anonymous? No name resolution has produced a
  //     label beyond the bare IP — shown to the user as an explanatory hint
  //     so "Unknown" nodes don't read as errors or threats.
  // FR: Ce nœud est-il encore anonyme ? Aucune résolution de nom n'a produit
  //     de label au-delà de l'IP — affiché comme indice explicatif pour que
  //     les nœuds « Inconnu » ne soient pas lus comme des erreurs ou menaces.
  const isLan = node.category === 'lan_device'
  const anonymous = node.id !== 'local' && !node.hostname && !node.vendor
    && (!node.label || node.label === node.ip)

  // EN: Top-5 processes by bytes on this node.
  // FR: Top 5 des processus par octets sur ce nœud.
  const processes = node.processes
    ? Object.entries(node.processes).sort(([, a], [, b]) => b.bytes - a.bytes).slice(0, 5)
    : []

  return (
    <div>
      {fields.filter(([, v]) => v != null && v !== '').map(([k, v]) => (
        <div key={k} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
          <span style={{ fontSize: 10, color: '#64748b' }}>{k}</span>
          <span style={{ fontSize: 10, color: '#e2e8f0', maxWidth: 170, textAlign: 'right', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v}</span>
        </div>
      ))}

      {/* EN: "What's happening" hints — teach, don't alarm. Priority order:
              gateway → LAN idle/active → still-anonymous → private MAC.
          FR: Indices « qu'est-ce qui se passe » — expliquer, pas alarmer.
              Priorité : passerelle → LAN inactif/actif → encore anonyme →
              MAC privée. */}
      {node.id === 'local' && <Hint accent="#3b82f6">{t('hint_local')}</Hint>}
      {node.is_gateway && <Hint>{t('hint_gateway')}</Hint>}
      {isLan && !node.is_gateway && (
        <Hint>
          {(node.bytes || 0) > 0 ? t('hint_lan_active', fmt(node.bytes)) : t('hint_lan_idle')}
        </Hint>
      )}
      {anonymous && (
        <Hint>{t(isLan ? 'hint_unidentified' : 'hint_unresolved')}</Hint>
      )}
      {node.private_mac && <Hint accent="#a855f7">{t('hint_private_mac')}</Hint>}

      {processes.length > 0 && (
        <>
          <div style={{ fontSize: 9, color: '#475569', textTransform: 'uppercase', letterSpacing: 0.5, marginTop: 8, marginBottom: 4 }}>
            {t('processes')}
          </div>
          {processes.map(([name, stats]) => (
            <div key={name} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3, alignItems: 'center' }}>
              <span style={{ fontSize: 10, color: '#94a3b8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 150 }}>
                {name}
              </span>
              <span style={{ fontSize: 9, color: '#475569', flexShrink: 0 }}>{fmt(stats.bytes)}</span>
            </div>
          ))}
        </>
      )}

      {/* EN: "Mark as trusted" — sends the IP to the whitelist endpoint.
          FR: « Marquer comme fiable » — envoie l'IP à l'endpoint de whitelist. */}
      {node.id !== 'local' && node.ip && onWhitelist && (
        <button onClick={() => onWhitelist(node.ip)} style={{
          marginTop: 10, width: '100%', display: 'flex', alignItems: 'center',
          justifyContent: 'center', gap: 6,
          background: 'none', border: '1px solid #22c55e', borderRadius: 6,
          padding: '5px 0', color: '#86efac', fontSize: 10, cursor: 'pointer',
        }}>
          <ShieldOff size={11} />
          {t('whitelist_action')}
        </button>
      )}
    </div>
  )
}

/** EN: One row of the packet feed — direction arrow, process, dst, size.
 *  FR: Une ligne du flux de paquets — flèche de direction, processus, dst, taille. */
function PacketRow({ packet }) {
  const out   = packet.direction === 'out'
  const color = out ? '#22c55e' : '#3b82f6'
  return (
    <div style={{ padding: '3px 16px', display: 'flex', alignItems: 'center', gap: 6 }}>
      <span style={{ color, fontSize: 10, flexShrink: 0 }}>{out ? '>' : '<'}</span>
      {packet.process && (
        <span style={{ fontSize: 9, color: '#f59e0b', flexShrink: 0, maxWidth: 80, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {packet.process}
        </span>
      )}
      <span style={{ fontSize: 9, color: '#94a3b8', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {packet.dst} · {packet.protocol}
      </span>
      <span style={{ fontSize: 9, color: '#475569', flexShrink: 0 }}>{packet.size}B</span>
    </div>
  )
}
