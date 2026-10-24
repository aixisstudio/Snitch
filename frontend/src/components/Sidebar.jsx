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
import { useState } from 'react'
import { Wifi, Smartphone, Monitor, Tv, Cpu, HelpCircle, ShieldOff, Shield, Skull, PauseCircle, Microscope, Search } from 'lucide-react'
import PrivacyScore from './PrivacyScore'
import BandwidthChart from './BandwidthChart'
import { useT } from '../i18n'
import { apiBase, authHeaders } from '../api'

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
  dns: '#38bdf8', admin: '#fb923c', unknown: 'var(--text-dim)', local: '#3b82f6',
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
  // EN: Local query narrowing the recent-traffic feed by app name,
  //     host or protocol — independent from the graph search filter.
  // FR: Requête locale qui réduit le flux de trafic récent par nom
  //     d'app, hôte ou protocole — indépendante du filtre du graphe.
  const [pktQuery, setPktQuery] = useState('')
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

  const pq = pktQuery.trim().toLowerCase()
  const visiblePackets = !pq ? packets : packets.filter(p =>
      (p.process  || '').toLowerCase().includes(pq)
      || (p.dst   || '').toLowerCase().includes(pq)
      || (p.protocol || '').toLowerCase().includes(pq))

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
          <img src="./logo.png" alt="Snitch" style={{ width: 22, height: 22, borderRadius: 5 }} />
          <span style={{ fontSize: 17, fontWeight: 800, color: 'var(--text)', letterSpacing: 1 }}>{t('app_name')}</span>
        </div>
        <span style={{ fontSize: 10, color: 'var(--text-faint)', letterSpacing: 1 }}>{t('tagline')}</span>
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

      {/* EN: Quick counters + live bandwidth sparkline — under the score card.
          FR: Compteurs rapides + sparkline de débit — sous la carte du score. */}
      <div style={{ ...CARD, padding: '10px 16px' }}>
        <BandwidthChart data={bandwidth || []} />
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8 }}>
          <Stat label={t('stat_lan')}     value={devList.length}      color="#f97316" />
          <Stat label={t('stat_ext')}     value={extNodes.length} />
          <Stat label={t('stat_traffic')} value={fmt(totalBytes)} />
        </div>
      </div>

      {/* EN: Detail card for the clicked node. / FR: Fiche détail du nœud cliqué. */}
      {selected && (
        <div style={{ ...CARD, padding: '12px 16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
            <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)' }}>
              {nodeName(selected, t)}
            </span>
            <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 16 }}>x</button>
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
          <div style={{ padding: '10px 20px', fontSize: 10, color: 'var(--text-faint)', fontStyle: 'italic' }}>
            {t('ext_empty')}
          </div>
        )}
        {filteredNodes
          .sort((a, b) => (b.bytes || 0) - (a.bytes || 0))
          .map(n => <NodeRow key={n.id} node={n} />)}
      </div>

      {/* EN: Recent packet feed / FR: Flux de paquets récents */}
      <div style={{ ...CARD, maxHeight: 190, overflowY: 'auto', flexShrink: 0 }}>
        <SectionTitle label={t('section_packets')} />
        {/* EN: Narrow the feed to one app/host/protocol — the most
                requested triage shortcut on the live feed.
            FR: Réduire le flux à une app/un hôte/un protocole — le
                raccourci de triage le plus demandé sur le flux live. */}
        <div style={{ position: 'relative', padding: '0 16px 4px' }}>
          <Search size={10} style={{
            position: 'absolute', left: 22, top: '50%',
            transform: 'translateY(-60%)', color: 'var(--text-muted)', pointerEvents: 'none',
          }} />
          <input
            value={pktQuery}
            onChange={e => setPktQuery(e.target.value)}
            placeholder={t('packets_filter')}
            style={{
              width: '100%', boxSizing: 'border-box',
              background: 'var(--bg)', border: '1px solid var(--border)',
              borderRadius: 6, padding: '3px 8px 3px 22px',
              fontSize: 10, color: 'var(--text)', outline: 'none',
            }}
          />
        </div>
        {visiblePackets.slice(0, 25).map((p, i) => <PacketRow key={i} packet={p} />)}
        {pq && visiblePackets.length === 0 && (
          <div style={{ padding: '6px 16px 10px', fontSize: 10, color: 'var(--text-faint)', fontStyle: 'italic' }}>
            {t('packets_none')}
          </div>
        )}
      </div>

      {/* EN: Tiny credit footer floating on the rail — same free-floating
              treatment as the brand block, no card.
          FR: Petit pied de page de crédit flottant sur le rail — même
              traitement libre que le bloc marque, sans carte. */}
      <div style={{ padding: '0 8px 4px', textAlign: 'center', flexShrink: 0 }}>
        <a href="https://aixis.fr/" target="_blank" rel="noopener noreferrer" style={{
          fontSize: 9, color: 'var(--text-faint)', textDecoration: 'none', letterSpacing: 0.5,
        }}>
          {t('footer_credit')} · aixis.fr
        </a>
      </div>
    </div>
  )
}

/** EN: Bento card chrome — near-black fill, hairline border, 12px radius.
 *  FR: Habillage carte bento — fond quasi noir, bordure fine, rayon 12 px. */
const CARD = {
  background: 'var(--surface)', border: '1px solid var(--surface-2)',
  borderRadius: 12,
}

/** EN: Sticky list section header. / FR: En-tête de section de liste collant. */
function SectionTitle({ label }) {
  return (
    <div style={{ padding: '6px 16px 4px', fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, background: 'var(--surface)', position: 'sticky', top: 0, borderRadius: '12px 12px 0 0' }}>
      {label}
    </div>
  )
}

function Stat({ label, value, color }) {
  return (
    <div style={{ textAlign: 'center' }}>
      <div style={{ fontSize: 16, fontWeight: 700, color: color || 'var(--text)' }}>{value}</div>
      <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{label}</div>
    </div>
  )
}

/** EN: Small explanatory note in the detail card — muted box, coloured
 *      left border. / FR: Petite note explicative dans la fiche détail —
 *      cadre discret, bordure gauche colorée. */
function Hint({ children, accent = 'var(--border)' }) {
  return (
    <div style={{
      marginTop: 8, padding: '6px 8px', fontSize: 9, lineHeight: 1.5,
      color: 'var(--text-muted)', background: 'var(--bg)', borderRadius: 6,
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
      borderBottom: '1px solid var(--surface-2)',
      opacity: device.online === false ? 0.45 : 1,
    }}>
      <Icon size={16} color={device.color} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {device.hostname || device.vendor || device.ip}
          {!device.hostname && !device.vendor && (
            <span style={{ fontSize: 9, color: 'var(--text-faint)', fontWeight: 400 }}> · {t('unidentified')}</span>
          )}
        </div>
        <div style={{ fontSize: 9, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
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
    <div style={{ padding: '6px 16px', display: 'flex', alignItems: 'center', gap: 8, borderBottom: '1px solid var(--surface-2)' }}>
      <div style={{ width: 7, height: 7, borderRadius: '50%', background: CATEGORY_COLORS[node.category] || 'var(--text-dim)', flexShrink: 0 }} />
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ fontSize: 11, color: 'var(--text)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {nodeName(node, t)}
        </div>
        <div style={{ fontSize: 9, color: 'var(--text-muted)' }}>{node.country || '-'} · {node.packets || 0} pkt</div>
      </div>
      <div style={{ fontSize: 10, color: 'var(--text-dim)', flexShrink: 0 }}>{fmt(node.bytes || 0)}</div>
    </div>
  )
}

/**
 * EN: Incident-response actions — block a remote IP via /firewall/rules and
 *     kill/suspend a process via /processes/*. Both are authenticated POSTs;
 *     failures are ignored silently (the backend returns 400 with detail).
 * FR: Actions de réponse à incident — bloquer une IP via /firewall/rules et
 *     tuer/suspendre un processus via /processes/*. POSTs authentifiés ; les
 *     échecs sont ignorés en silence (le backend renvoie 400 avec détail).
 */
async function blockIp(ip) {
  if (!ip) return
  const base = await apiBase()
  try {
    await fetch(`${base}/firewall/rules`, {
      method: 'POST',
      headers: await authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ kind: 'ip', value: ip }),
    })
  } catch { /* best effort */ }
}

async function procAction(action, pid) {
  if (!pid) return
  const base = await apiBase()
  try {
    await fetch(`${base}/processes/${action}`, {
      method: 'POST',
      headers: await authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ pid }),
    })
  } catch { /* best effort */ }
}

/**
 * EN: Bounded Frida deep-inspection — attaches to the pid for a few
 *     seconds and reports which module initiated each connect(). Shows
 *     the result in a simple dialog; errors are surfaced, not hidden.
 * FR: Inspection Frida bornée — attache au pid quelques secondes et
 *     rapporte quel module a initié chaque connect(). Résultat affiché
 *     dans une boîte simple ; les erreurs sont montrées, pas cachées.
 */
async function deepInspect(pid, t) {
  if (!pid) return
  const base = await apiBase()
  try {
    const res = await fetch(`${base}/security/deep_inspect`, {
      method: 'POST',
      headers: await authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ pid, seconds: 8 }),
    })
    const j = await res.json()
    if (!res.ok || j.ok === false) {
      window.alert(j.detail || j.error || t('di_failed'))
      return
    }
    const mods = (j.suspicious_paths || []).join('\n')
    window.alert(mods ? `${t('di_result')}\n${mods}` : t('di_clean'))
  } catch { window.alert(t('di_failed')) }
}

/** EN: Selected-node fields + top processes + whitelist/block actions.
 *  FR: Champs du nœud sélectionné + top processus + actions whitelist/blocage. */
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
          <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{k}</span>
          <span style={{ fontSize: 10, color: 'var(--text)', maxWidth: 170, textAlign: 'right', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v}</span>
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
          <div style={{ fontSize: 9, color: 'var(--text-faint)', textTransform: 'uppercase', letterSpacing: 0.5, marginTop: 8, marginBottom: 4 }}>
            {t('processes')}
          </div>
          {processes.map(([name, stats]) => (
            <div key={name} style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3, alignItems: 'center' }}>
              <span style={{ fontSize: 10, color: 'var(--text-dim)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 130 }}>
                {name}
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
                <span style={{ fontSize: 9, color: 'var(--text-faint)' }}>{fmt(stats.bytes)}</span>
                {/* EN: Kill/suspend — only when a PID is known for the process.
                    FR: Tuer/suspendre — seulement si un PID est connu. */}
                {stats.pid && (
                  <>
                    <button onClick={() => deepInspect(stats.pid, t)}
                      title={t('di_inspect')} aria-label={t('di_inspect')}
                      style={{ background: 'none', border: 'none', color: '#a855f7', cursor: 'pointer', padding: 0, display: 'flex' }}>
                      <Microscope size={11} />
                    </button>
                    <button onClick={() => procAction('suspend', stats.pid)}
                      title={t('proc_suspend')} aria-label={t('proc_suspend')}
                      style={{ background: 'none', border: 'none', color: '#f59e0b', cursor: 'pointer', padding: 0, display: 'flex' }}>
                      <PauseCircle size={11} />
                    </button>
                    <button onClick={() => procAction('kill', stats.pid)}
                      title={t('proc_kill')} aria-label={t('proc_kill')}
                      style={{ background: 'none', border: 'none', color: '#ef4444', cursor: 'pointer', padding: 0, display: 'flex' }}>
                      <Skull size={11} />
                    </button>
                  </>
                )}
              </span>
            </div>
          ))}
        </>
      )}

      {/* EN: "Mark as trusted" + "Block" — whitelist and firewall rule.
          FR: « Marquer comme fiable » + « Bloquer » — whitelist et règle pare-feu. */}
      {node.id !== 'local' && node.ip && (
        <div style={{ display: 'flex', gap: 6, marginTop: 10 }}>
          {onWhitelist && (
            <button onClick={() => onWhitelist(node.ip)} style={{
              flex: 1, display: 'flex', alignItems: 'center',
              justifyContent: 'center', gap: 6,
              background: 'none', border: '1px solid #22c55e', borderRadius: 6,
              padding: '5px 0', color: 'var(--green-text)', fontSize: 10, cursor: 'pointer',
            }}>
              <ShieldOff size={11} />
              {t('whitelist_action')}
            </button>
          )}
          <button onClick={() => blockIp(node.ip || node.id)} style={{
            flex: 1, display: 'flex', alignItems: 'center',
            justifyContent: 'center', gap: 6,
            background: 'none', border: '1px solid #ef4444', borderRadius: 6,
            padding: '5px 0', color: 'var(--red-text)', fontSize: 10, cursor: 'pointer',
          }}>
            <Shield size={11} />
            {t('block_action')}
          </button>
        </div>
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
        <span style={{ fontSize: 10, color: '#f59e0b', flexShrink: 0, maxWidth: 80, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {packet.process}
        </span>
      )}
      <span style={{ fontSize: 10, color: 'var(--text-dim)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {packet.dst} · {packet.protocol}
      </span>
      <span style={{ fontSize: 10, color: 'var(--text-faint)', flexShrink: 0 }}>{packet.size}B</span>
    </div>
  )
}
