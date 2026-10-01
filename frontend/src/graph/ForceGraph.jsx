/**
 * Snitch — D3 force-directed graph view.
 *
 * EN: The main visualization. Every remote host and LAN device is a node,
 *     every connection an edge anchored on the central "local" node.
 *
 *     PERFORMANCE (the big fix): the simulation is ONLY rebuilt when the
 *     graph *structure* changes — i.e. the SET of node ids or edge ids. On a
 *     busy link the old code rebuilt the whole sim once per WebSocket packet
 *     because `nodes`/`edges` were new objects every render. Now a
 *     `structKey` string (sorted ids) gates the rebuild effect, and a second
 *     lightweight effect updates the volatile visuals — edge width, tooltips,
 *     alert rings — by mutating the existing D3 selections in place.
 *     Node positions live in `posCache`, so rebuilds keep the layout stable.
 *
 * FR: La visualisation principale. Chaque hôte distant et appareil LAN est un
 *     nœud, chaque connexion une arête ancrée sur le nœud central « local ».
 *
 *     PERFORMANCE (la grosse correction) : la simulation n'est reconstruite
 *     QUE quand la *structure* du graphe change — c.-à-d. l'ENSEMBLE des ids
 *     de nœuds ou d'arêtes. Sur un lien actif, l'ancien code reconstruisait
 *     toute la sim à chaque paquet WebSocket car `nodes`/`edges` étaient de
 *     nouveaux objets à chaque rendu. Désormais une `structKey` (ids triés)
 *     pilote l'effet de reconstruction, et un second effet léger met à jour
 *     les visuels volatils — largeur des arêtes, infobulles, anneaux d'alerte
 *     — en mutant les sélections D3 existantes sur place.
 *     Les positions des nœuds vivent dans `posCache` : les reconstructions
 *     gardent une mise en page stable.
 */
import { useEffect, useMemo, useRef } from 'react'
import * as d3 from 'd3'
import { nodeIconURI } from './icons'
import { useT } from '../i18n'

/** EN: Edge stroke width scales with logged traffic volume.
 *  FR: La largeur d'arête suit le volume de trafic en échelle log. */
const edgeWidth = d => d.dashed ? 1 : Math.min(1 + Math.log1p((d.bytes || 0) / 1024), 6)

/** EN: Native tooltip text for a node datum. / FR: Texte d'infobulle native d'un nœud. */
const nodeTitle = (d, disp) =>
  [disp(d), d.vendor, d.mac, d.country, d.org, `${d.packets || 0} pkts`]
    .filter(Boolean).join('\n')

/** EN: Truncated label under a node. / FR: Étiquette tronquée sous un nœud. */
const nodeLabel = (d, disp) => {
  const label = disp(d) || ''
  return label.length > 20 ? label.slice(0, 18) + '…' : label
}

const radius = d => d.id === 'local' ? 22 : d.category === 'lan_device' ? 18 : 13

export default function ForceGraph({ nodes, edges, lanDevices, alertedNodes = new Set(), onNodeClick, filter }) {
  const svgRef   = useRef(null)
  const nodeSel  = useRef(null)   // EN: d3 selection of node <g>s / FR: sélection d3 des <g> nœuds
  const linkSel  = useRef(null)   // EN: d3 selection of edge <line>s / FR: sélection d3 des <line> arêtes
  const labelSel = useRef(null)   // EN: d3 selection of edge <text>s / FR: sélection d3 des <text> arêtes
  const posCache = useRef({})     // EN: { id: {x,y,fx,fy} } / FR: positions persistées
  const dataRef  = useRef({ nodes: {}, edges: {}, lanDevices: {} })

  const { t } = useT()
  // EN: Display name — `label_key` resolves through i18n (e.g. the "local"
  //     node shows "This Device"/"Cet appareil"), then label, then IP.
  // FR: Nom d'affichage — `label_key` passe par l'i18n (ex. le nœud « local »
  //     affiche « This Device »/« Cet appareil »), puis label, puis l'IP.
  const displayName = d => d.label || (d.label_key ? t(d.label_key) : null) || d.ip
  const displayNameRef = useRef(displayName)
  displayNameRef.current = displayName

  // EN: Always-latest data for effects that don't rebuild the sim.
  // FR: Données toujours à jour pour les effets qui ne reconstruisent pas la sim.
  dataRef.current = { nodes, edges, lanDevices }

  /**
   * EN: Structure signature — sorted node ids + sorted edge ids. The sim is
   *     rebuilt only when THIS string changes, no matter how often the
   *     byte/packet counters churn.
   * FR: Signature de structure — ids de nœuds triés + ids d'arêtes triés. La
   *     sim n'est reconstruite que quand CETTE chaîne change, peu importe la
   *     fréquence des changements de compteurs d'octets/paquets.
   */
  const structKey = useMemo(() => {
    const nids = [...Object.keys(nodes), ...Object.keys(lanDevices)].sort()
    const eids = Object.keys(edges).sort()
    return nids.join(',') + '|' + eids.join(',')
  }, [nodes, edges, lanDevices])

  // ── Full simulation — rebuilds ONLY on structural change ─────────────────
  // ── Simulation complète — reconstruite SEULEMENT sur changement structurel ─
  useEffect(() => {
    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()

    const width  = svgRef.current.clientWidth
    const height = svgRef.current.clientHeight

    const zoom = d3.zoom().scaleExtent([0.15, 6]).on('zoom', e => g.attr('transform', e.transform))
    svg.call(zoom)

    const g = svg.append('g')

    // EN: Arrowhead marker for directed edges. / FR: Marqueur de flèche pour les arêtes dirigées.
    svg.append('defs').append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 22).attr('refY', 0)
      .attr('markerWidth', 6).attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path').attr('fill', '#475569').attr('d', 'M0,-5L10,0L0,5')

    const allNodes = [...Object.values(nodes), ...Object.values(lanDevices)]
    const nodeIds = new Set(allNodes.map(n => n.id))
    // EN: D3 may have already replaced source/target with node objects —
    //     normalize both shapes before filtering.
    // FR: D3 peut avoir déjà remplacé source/target par des objets nœud —
    //     normaliser les deux formes avant de filtrer.
    const allEdges = Object.values(edges).filter(e => {
      const src = typeof e.source === 'object' ? e.source.id : e.source
      const tgt = typeof e.target === 'object' ? e.target.id : e.target
      return nodeIds.has(src) && nodeIds.has(tgt)
    })

    // EN: Restore cached positions — pinned nodes won't move at all.
    // FR: Restaurer les positions en cache — les nœuds épinglés ne bougent pas.
    let hasNew = false
    allNodes.forEach(n => {
      const c = posCache.current[n.id]
      if (c) { n.x = c.x; n.y = c.y; n.fx = c.fx; n.fy = c.fy }
      else    { hasNew = true }
    })

    const sim = d3.forceSimulation(allNodes)
      .alpha(hasNew ? 0.6 : 0.05)    // EN: barely reheat if nothing new
                                     // FR: réchauffer à peine si rien de nouveau
      .alphaDecay(0.04)              // EN: settle ~2× faster / FR: stabilisation ~2× plus rapide
      .velocityDecay(0.55)           // EN: more friction, less overshoot / FR: plus de friction, moins de dépassement
      .force('link', d3.forceLink(allEdges).id(d => d.id).distance(d => d.dashed ? 120 : 180).strength(0.4))
      .force('charge', d3.forceManyBody().strength(d => d.category === 'lan_device' ? -450 : -600))
      .force('center', d3.forceCenter(width / 2, height / 2).strength(0.03))
      // EN: Collision radius covers node + label below — nodes never overlap.
      // FR: Le rayon de collision couvre nœud + étiquette dessous — les nœuds
      //     ne se chevauchent jamais.
      .force('collision', d3.forceCollide(d => d.id === 'local' ? 55 : 48))
      // EN: Gentle pull toward center for LAN devices so they orbit "local" —
      //     weak enough that repulsion + collision keep them readable.
      // FR: Légère attraction centrale pour les appareils LAN afin qu'ils
      //     orbitent « local » — assez faible pour que répulsion + collision
      //     les gardent lisibles.
      .force('lan_x', d3.forceX(width / 2).strength(d => d.category === 'lan_device' ? 0.06 : 0))
      .force('lan_y', d3.forceY(height / 2).strength(d => d.category === 'lan_device' ? 0.06 : 0))

    const link = g.append('g').selectAll('line')
      .data(allEdges)
      .join('line')
      .attr('stroke', d => d.color || '#475569')
      .attr('stroke-opacity', d => d.dashed ? 0.35 : 0.55)
      .attr('stroke-width', edgeWidth)
      .attr('stroke-dasharray', d => d.dashed ? '5,4' : null)
      .attr('marker-end', d => d.dashed ? null : 'url(#arrow)')

    linkSel.current = link

    const linkLabel = g.append('g').selectAll('text')
      .data(allEdges.filter(e => !e.dashed))
      .join('text')
      .attr('fill', '#475569')
      .attr('font-size', 9)
      .attr('text-anchor', 'middle')
      .text(d => d.label)

    labelSel.current = linkLabel

    const node = g.append('g').selectAll('g')
      .data(allNodes)
      .join('g')
      .attr('cursor', 'pointer')
      .on('click', (_, d) => onNodeClick?.(d))
      .call(d3.drag()
        .on('start', (e, d) => { if (!e.active) sim.alphaTarget(0.15).restart(); d.fx = d.x; d.fy = d.y })
        .on('drag',  (e, d) => { d.fx = e.x; d.fy = e.y })
        .on('end',   (e, d) => {
          if (!e.active) sim.alphaTarget(0)
          // EN: Lock the node where the user dropped it.
          // FR: Verrouiller le nœud là où l'utilisateur l'a déposé.
          posCache.current[d.id] = { x: d.x, y: d.y, fx: d.x, fy: d.y }
        })
      )

    nodeSel.current = node

    // EN: Alert rings are added/removed by the lightweight metrics effect —
    //     painted here too for freshly-built nodes.
    // FR: Les anneaux d'alerte sont gérés par l'effet métriques léger —
    //     peints ici aussi pour les nœuds fraîchement créés.
    paintAlertRings(node, alertedNodes)

    // EN: Soft halo behind local/LAN nodes. / FR: Halo doux derrière les nœuds locaux/LAN.
    node.filter(d => d.id === 'local' || d.category === 'lan_device')
      .append('circle')
      .attr('r', d => radius(d) + 6)
      .attr('fill', d => d.color)
      .attr('fill-opacity', 0.15)

    node.append('circle')
      .attr('r', radius)
      .attr('fill', d => d.color || '#475569')
      .attr('fill-opacity', d => d.online === false ? 0.35 : 0.85)
      .attr('stroke', d => d.online === false ? '#475569' : '#1e293b')
      .attr('stroke-width', d => d.category === 'lan_device' ? 2.5 : 1.5)
      .attr('stroke-dasharray', d => d.online === false ? '4,3' : null)

    // EN: White Lucide icon inside the circle, via data-URI SVG.
    // FR: Icône Lucide blanche dans le cercle, via SVG en data-URI.
    const iconSize = d => d.id === 'local' ? 20 : d.category === 'lan_device' ? 16 : 12
    node.append('image')
      .attr('href', d => nodeIconURI(d))
      .attr('width',  d => iconSize(d))
      .attr('height', d => iconSize(d))
      .attr('x', d => -iconSize(d) / 2)
      .attr('y', d => -iconSize(d) / 2)
      .attr('pointer-events', 'none')
      .attr('opacity', d => d.online === false ? 0.4 : 0.9)

    node.append('text')
      .attr('y', d => radius(d) + 11)
      .attr('text-anchor', 'middle')
      .attr('fill', d => d.category === 'lan_device' ? '#e2e8f0' : '#94a3b8')
      .attr('font-size', d => d.category === 'lan_device' ? 10 : 9)
      .attr('font-weight', d => d.category === 'lan_device' ? '600' : '400')
      .text(d => nodeLabel(d, displayNameRef.current))

    // EN: Native tooltip with full detail on hover — kept fresh by the
    //     metrics effect below.
    // FR: Infobulle native avec le détail complet au survol — maintenue à jour
    //     par l'effet métriques ci-dessous.
    node.append('title').text(d => nodeTitle(d, displayNameRef.current))

    sim.on('tick', () => {
      link
        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y)
      linkLabel
        .attr('x', d => (d.source.x + d.target.x) / 2)
        .attr('y', d => (d.source.y + d.target.y) / 2)
      node.attr('transform', d => `translate(${d.x},${d.y})`)
    })

    // EN: Once the sim cools down, pin every node and cache its position.
    // FR: Une fois la sim refroidie, épingler chaque nœud et cacher sa position.
    sim.on('end', () => {
      allNodes.forEach(n => {
        n.fx = n.x; n.fy = n.y
        posCache.current[n.id] = { x: n.x, y: n.y, fx: n.x, fy: n.y }
      })
    })

    return () => sim.stop()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [structKey])

  // ── Metrics refresh — NO simulation restart ──────────────────────────────
  // ── Rafraîchissement des métriques — SANS relancer la simulation ──────────
  useEffect(() => {
    const link = linkSel.current
    const node = nodeSel.current
    if (!link || !node) return

    const { nodes, edges, lanDevices } = dataRef.current
    // EN: Look up the LATEST datum by id — the objects bound in the sim are
    //     stale copies from the last structural rebuild.
    // FR: Chercher la donnée LA PLUS RÉCENTE par id — les objets liés dans la
    //     sim sont des copies périmées de la dernière reconstruction.
    const edgeById = new Map(Object.values(edges).map(e => [e.id, e]))
    const nodeById = new Map(
      [...Object.values(nodes), ...Object.values(lanDevices)].map(n => [n.id, n])
    )

    link.attr('stroke-width', d => edgeWidth(edgeById.get(d.id) || d))
    node.select('title').text(d => nodeTitle(nodeById.get(d.id) || d, displayNameRef.current))
    node.select('text').text(d => nodeLabel(nodeById.get(d.id) || d, displayNameRef.current))

    paintAlertRings(node, alertedNodes)
  }, [nodes, edges, lanDevices, alertedNodes])

  // ── Filter dimming — no simulation restart ───────────────────────────────
  // ── Estompage par filtre — sans relancer la simulation ────────────────────
  useEffect(() => {
    if (!nodeSel.current || !linkSel.current) return

    function matches(d) {
      if (!filter || (filter.category === 'all' && !filter.text)) return true
      if (d.id === 'local') return true
      const { text, category } = filter
      if (category !== 'all' && d.category !== category) return false
      if (text) {
        const t = text.toLowerCase()
        return (d.label   || '').toLowerCase().includes(t)
            || (d.ip      || '').toLowerCase().includes(t)
            || (d.country || '').toLowerCase().includes(t)
            || (d.org     || '').toLowerCase().includes(t)
            || (d.hostname|| '').toLowerCase().includes(t)
      }
      return true
    }

    nodeSel.current.attr('opacity', d => matches(d) ? 1 : 0.1)

    linkSel.current.attr('stroke-opacity', d => {
      const src = typeof d.source === 'object' ? d.source : { id: d.source, category: '' }
      const tgt = typeof d.target === 'object' ? d.target : { id: d.target, category: '' }
      return (matches(src) || matches(tgt)) ? (d.dashed ? 0.35 : 0.55) : 0.04
    })
  }, [filter])

  return <svg ref={svgRef} style={{ width: '100%', height: '100%', background: '#0f172a' }} />
}

/**
 * EN: Sync pulsing red alert rings with the current alerted-node set —
 *     adds rings to newly-alerted nodes, removes them elsewhere. Works on
 *     live selections, so it costs nothing when nothing changed.
 * FR: Synchroniser les anneaux rouges pulsants avec l'ensemble actuel des
 *     nœuds en alerte — ajoute des anneaux aux nœuds nouvellement alertés,
 *     les retire ailleurs. Travaille sur les sélections vivantes, donc ne
 *     coûte rien quand rien n'a changé.
 */
function paintAlertRings(nodeSel, alertedNodes) {
  nodeSel.each(function (d) {
    const g = d3.select(this)
    const shouldAlert = alertedNodes.has(d.id) || d.alerted
    const ring = g.select('circle.alert-ring')
    if (shouldAlert && ring.empty()) {
      // EN: Insert BEFORE the body circle so the ring sits behind the node.
      // FR: Insérer AVANT le cercle du corps pour que l'anneau soit derrière.
      g.insert('circle', ':first-child')
        .attr('class', 'alert-ring')
        .attr('r', radius(d) + 9)
        .attr('fill', 'none')
        .attr('stroke', '#ef4444')
        .attr('stroke-width', 1.5)
        .attr('stroke-opacity', 0.7)
        .append('animate')
        .attr('attributeName', 'stroke-opacity')
        .attr('values', '0.7;0.1;0.7')
        .attr('dur', '1.5s').attr('repeatCount', 'indefinite')
    } else if (!shouldAlert && !ring.empty()) {
      ring.remove()
    }
  })
}
