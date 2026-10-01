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
  const gRef     = useRef(null)   // EN: root <g> (zoom target) / FR: <g> racine (cible du zoom)
  const perimG   = useRef(null)   // EN: <g> layer for the LAN perimeter ring / FR: calque <g> du périmètre LAN
  const linkG    = useRef(null)   // EN: <g> layer for edges / FR: calque <g> des arêtes
  const labelG   = useRef(null)   // EN: <g> layer for edge labels / FR: calque <g> des étiquettes d'arêtes
  const nodeG    = useRef(null)   // EN: <g> layer for nodes / FR: calque <g> des nœuds
  const simRef   = useRef(null)   // EN: the ONE persistent simulation / FR: LA simulation persistante unique
  const nodeSel  = useRef(null)   // EN: d3 selection of node <g>s / FR: sélection d3 des <g> nœuds
  const linkSel  = useRef(null)   // EN: d3 selection of edge <line>s / FR: sélection d3 des <line> arêtes
  const labelSel = useRef(null)   // EN: d3 selection of edge <text>s / FR: sélection d3 des <text> arêtes
  const floatPaint = useRef(null) // EN: drift painter shared with rebuilds / FR: peintre de dérive partagé avec les reconstructions
  const posCache = useRef({})     // EN: { id: {x,y,fx,fy} } / FR: positions persistées
  const zoomTf   = useRef(null)   // EN: last user pan/zoom transform / FR: dernière transformation pan/zoom
  const dataRef  = useRef({ nodes: {}, edges: {}, lanDevices: {} })
  const clickRef = useRef(null)   // EN: latest onNodeClick / FR: dernier onNodeClick

  const { t } = useT()
  // EN: Display name — `label_key` resolves through i18n (e.g. the "local"
  //     node shows "This Device"/"Cet appareil"), then label, then IP.
  // FR: Nom d'affichage — `label_key` passe par l'i18n (ex. le nœud « local »
  //     affiche « This Device »/« Cet appareil »), puis label, puis l'IP.
  const displayName = d => d.label || (d.label_key ? t(d.label_key) : null) || d.ip
  const displayNameRef = useRef(displayName)
  displayNameRef.current = displayName
  const tRef = useRef(t)
  tRef.current = t

  // EN: Always-latest data for effects that don't rebuild the sim.
  // FR: Données toujours à jour pour les effets qui ne reconstruisent pas la sim.
  dataRef.current = { nodes, edges, lanDevices }
  clickRef.current = onNodeClick

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

  // ── One-time scene setup — svg layers, zoom, defs. Never re-runs, so the
  //    user's pan/zoom is bound once and never touched by data updates.
  // ── Mise en place unique — calques svg, zoom, defs. Ne rejoue jamais, le
  //    pan/zoom de l'utilisateur est lié une fois et jamais touché ensuite.
  useEffect(() => {
    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()

    const zoom = d3.zoom().scaleExtent([0.15, 6]).on('zoom', e => {
      zoomTf.current = e.transform
      if (gRef.current) gRef.current.attr('transform', e.transform)
    })
    svg.call(zoom)
    // EN: Kill the default double-click→zoom-in — during a busy graph a
    //     stray dblclick feels like the app zooming by itself.
    // FR: Désactiver le double-clic→zoom par défaut — sur un graphe actif
    //     un dblclick perdu donne l'impression d'un zoom automatique.
    svg.on('dblclick.zoom', null)

    // EN: Arrowhead marker for directed edges. / FR: Marqueur de flèche pour les arêtes dirigées.
    svg.append('defs').append('marker')
      .attr('id', 'arrow')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 22).attr('refY', 0)
      .attr('markerWidth', 6).attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path').attr('fill', '#475569').attr('d', 'M0,-5L10,0L0,5')

    const g = svg.append('g')
    gRef.current    = g
    perimG.current  = g.append('g')   // EN: under edges & nodes / FR: sous les arêtes et les nœuds
    linkG.current   = g.append('g')
    labelG.current  = g.append('g')
    nodeG.current   = g.append('g')

    // EN: Reapply the saved transform — fires the handler, so it must run
    //     after g exists. / FR: Réappliquer la transformée — déclenche le
    //     handler, donc après l'existence de g.
    if (zoomTf.current) svg.call(zoom.transform, zoomTf.current)

    return () => {
      simRef.current?.stop()
      svg.selectAll('*').remove()
      svg.on('.zoom', null)
      gRef.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // ── Structural update — INCREMENTAL keyed joins, no wipe, no re-zoom ─────
  // ── Mise à jour structurelle — jointures incrémentales par clé, sans
  //    effacer le SVG ni re-lier le zoom ────────────────────────────────────
  useEffect(() => {
    // EN: Defer to the next frame — consecutive WS updates within one frame
    //     coalesce into a single layout pass instead of one join+ticks each.
    // FR: Reporter à la frame suivante — les mises à jour WS consécutives
    //     dans une même frame fusionnent en un seul passage de layout au
    //     lieu d'une jointure+ticks chacune.
    const raf = requestAnimationFrame(() => {
    const g = gRef.current
    if (!g) return

    const width  = svgRef.current.clientWidth
    const height = svgRef.current.clientHeight

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

    // EN: Concentric-ring layout — the mental model IS a star: "me" at the
    //     center, my LAN devices on an inner orbit, internet hosts on an
    //     outer orbit. forceRadial does the heavy lifting; charge spreads
    //     nodes around each ring so labels (≈90 px wide) never stack.
    // FR: Layout en anneaux concentriques — le modèle mental EST une étoile :
    //     « moi » au centre, mes appareils LAN sur une orbite interne, les
    //     hôtes internet sur une orbite externe. forceRadial fait le gros du
    //     travail ; la charge répartit les nœuds sur chaque anneau pour que
    //     les étiquettes (~90 px) ne s'empilent jamais.
    // EN: Adaptive inner ring — the LAN orbit grows with the device count so
    //     every device keeps ~95 px of arc (room for bubble + label). A
    //     school with 30 machines gets a big perimeter instead of a pile-up.
    //     The outer ring moves out with it to keep clear separation.
    // FR: Anneau interne adaptatif — l'orbite LAN grandit avec le nombre
    //     d'appareils pour que chacun garde ~95 px d'arc (bulle + étiquette).
    //     Une école avec 30 machines obtient un grand périmètre plutôt qu'un
    //     empilement. L'anneau externe recule avec lui pour garder la
    //     séparation nette.
    const lanCount = allNodes.filter(n => n.category === 'lan_device').length
    const LAN_SPACING = 95   // EN: arc px per LAN device / FR: px d'arc par appareil LAN
    const ringInner = Math.max(
      Math.min(width, height) * 0.20,
      (lanCount * LAN_SPACING) / (2 * Math.PI)
    )
    const ringOuter = Math.max(Math.min(width, height) * 0.44, ringInner + Math.min(width, height) * 0.24)
    const ringOf = d =>
      d.id === 'local' ? 0
      : d.category === 'lan_device' ? ringInner
      : ringOuter

    // EN: Restore cached positions — pinned nodes won't move at all.
    //     NEW nodes spawn ON their ring (random angle) instead of exploding
    //     out from the center — a center-burst + reheat reads as a "zoom".
    //     newCount gates the convergence loop below: with zero arrivals the
    //     layout cannot change, so burning 300 sim ticks would be pure waste.
    // FR: Restaurer les positions en cache — les nœuds épinglés ne bougent
    //     pas. Les NOUVEAUX nœuds apparaissent SUR leur anneau (angle
    //     aléatoire) au lieu d'exploser depuis le centre. newCount pilote la
    //     boucle de convergence : zéro arrivée = mise en page identique,
    //     brûler 300 ticks de sim serait du pur gaspillage.
    let newCount = 0
    allNodes.forEach(n => {
      let c = posCache.current[n.id]
      // EN: A cached position that ended up INSIDE the LAN perimeter for an
      //     external host is a layout bug — evict it so the node respawns
      //     on its proper outer ring instead of squatting in the local zone.
      // FR: Une position en cache tombée DANS le périmètre LAN pour un hôte
      //     externe est un bug de mise en page — on l'évince pour que le
      //     nœud réapparaisse sur son anneau externe au lieu de squatter
      //     la zone locale.
      if (c && n.id !== 'local') {
        const dx = c.x - width / 2, dy = c.y - height / 2
        const dist = Math.hypot(dx, dy)
        if (n.category === 'lan_device') {
          // EN: ring moved (device count changed) → re-settle on the new orbit.
          // FR: l'anneau a bougé (le nombre d'appareils a changé) → se replacer.
          if (Math.abs(dist - ringInner) > 40) c = null
        } else if (dist < ringOuter - 60) {
          c = null
        }
      }
      if (c) { n.x = c.x; n.y = c.y; n.fx = c.fx; n.fy = c.fy }
      else {
        newCount++
        const a = Math.random() * Math.PI * 2
        const r = ringOf(n)
        n.x = width / 2 + Math.cos(a) * r
        n.y = height / 2 + Math.sin(a) * r
      }
    })

    // EN: ONE persistent simulation — swap node/edge sets in place.
    // FR: UNE simulation persistante — on remplace nœuds/arêtes sur place.
    if (!simRef.current) {
      simRef.current = d3.forceSimulation()
        .alphaDecay(0.04)              // EN: settle ~2× faster / FR: stabilisation ~2× plus rapide
        .velocityDecay(0.55)           // EN: more friction, less overshoot / FR: plus de friction, moins de dépassement
    }
    const sim = simRef.current
    sim.nodes(allNodes)
    // EN: Link distances must sit AT/ABOVE the outer ring — shorter edges
    //     overpower the radial force at equilibrium and drag external hosts
    //     inside the LAN perimeter.
    // FR: Les distances de lien doivent être À/AU-DESSUS de l'anneau externe —
    //     des arêtes plus courtes battent la force radiale à l'équilibre et
    //     traînent les hôtes externes dans le périmètre LAN.
    sim.force('link', d3.forceLink(allEdges).id(d => d.id).distance(d => d.dashed ? 170 : ringOuter + 20).strength(0.25))
    sim.force('charge', d3.forceManyBody().strength(d => d.category === 'lan_device' ? -500 : -750))
    sim.force('radial', d3.forceRadial(ringOf, width / 2, height / 2)
      // EN: external hosts hold their outer ring firmly — a weak radial pull
      //     let link tension drag them INSIDE the LAN perimeter visually.
      // FR: les hôtes externes tiennent fermement leur anneau — une traction
      //     radiale trop faible laissait les liens les faire entrer dans le
      //     périmètre LAN à l'écran.
      .strength(d => d.id === 'local' ? 1 : d.category === 'lan_device' ? 0.55 : 0.6))
    // EN: LAN perimeter — dashed orange ring enclosing the center + the LAN
    //     orbit, so "my network" reads as a distinct zone from the internet
    //     ring. Redrawn each rebuild (2 elements — cheap).
    // FR: Périmètre LAN — anneau orange en pointillés englobant le centre +
    //     l'orbite des appareils locaux, pour que « mon réseau » se lise
    //     comme une zone distincte de l'anneau internet. Redessiné à chaque
    //     reconstruction (2 éléments — négligeable).
    {
      const local = allNodes.find(n => n.id === 'local')
      const cx = local?.x ?? width / 2
      const cy = local?.y ?? height / 2
      const pr = ringInner + 55
      perimG.current.selectAll('*').remove()
      perimG.current.append('circle')
        .attr('cx', cx).attr('cy', cy).attr('r', pr)
        .attr('fill', '#f97316').attr('fill-opacity', 0.03)
        .attr('stroke', '#f97316').attr('stroke-opacity', 0.4)
        .attr('stroke-width', 1.2).attr('stroke-dasharray', '5,7')
        .attr('pointer-events', 'none')
      perimG.current.append('text')
        .attr('x', cx).attr('y', cy - pr - 10)
        .attr('text-anchor', 'middle')
        .attr('font-size', 10).attr('font-weight', 700)
        .attr('letter-spacing', 3)
        .attr('fill', '#f97316').attr('fill-opacity', 0.75)
        .attr('pointer-events', 'none')
        .text(tRef.current('perim_lan'))
    }

    // EN: Collision covers node + label (~90 px wide → half-width ~45-55).
    // FR: La collision couvre nœud + étiquette (~90 px de large →
    //     demi-largeur ~45-55).
    sim.force('collision', d3.forceCollide(d => d.id === 'local' ? 62 : 55))

    // EN: Keyed joins — existing elements keep their DOM node (no flash,
    //     no zoom disruption); only genuinely new nodes enter, dead ones exit.
    // FR: Jointures par clé — les éléments existants gardent leur nœud DOM
    //     (pas de flash, pas de rupture de zoom) ; seuls les vrais nouveaux
    //     entrent, les morts sortent.
    const link = linkG.current.selectAll('line')
      .data(allEdges, d => d.id)
      .join('line')
      .attr('stroke', d => d.color || '#475569')
      .attr('stroke-opacity', d => d.dashed ? 0.35 : 0.55)
      .attr('stroke-width', edgeWidth)
      .attr('stroke-dasharray', d => d.dashed ? '5,4' : null)
      .attr('marker-end', d => d.dashed ? null : 'url(#arrow)')

    linkSel.current = link

    const linkLabel = labelG.current.selectAll('text')
      .data(allEdges.filter(e => !e.dashed), d => d.id)
      .join('text')
      .attr('fill', '#475569')
      .attr('font-size', 9)
      .attr('text-anchor', 'middle')
      .text(d => d.label)

    labelSel.current = linkLabel

    const node = nodeG.current.selectAll('g.node')
      .data(allNodes, d => d.id)
      .join(
        enter => {
          const en = enter.append('g')
            .attr('class', 'node')
            .attr('cursor', 'pointer')
            .on('click', (_, d) => clickRef.current?.(d))
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

          // EN: Soft halo behind local/LAN nodes.
          // FR: Halo doux derrière les nœuds locaux/LAN.
          en.filter(d => d.id === 'local' || d.category === 'lan_device')
            .append('circle')
            .attr('r', d => radius(d) + 6)
            .attr('fill', d => d.color)
            .attr('fill-opacity', 0.15)

          en.append('circle')
            .attr('r', radius)
            .attr('fill', d => d.color || '#475569')
            .attr('fill-opacity', d => d.online === false ? 0.35 : 0.85)
            .attr('stroke', d => d.online === false ? '#475569' : '#0f0f0f')
            .attr('stroke-width', d => d.category === 'lan_device' ? 2.5 : 1.5)
            .attr('stroke-dasharray', d => d.online === false ? '4,3' : null)

          // EN: White Lucide icon inside the circle, via data-URI SVG.
          // FR: Icône Lucide blanche dans le cercle, via SVG en data-URI.
          const iconSize = d => d.id === 'local' ? 20 : d.category === 'lan_device' ? 16 : 12
          en.append('image')
            .attr('href', d => nodeIconURI(d))
            .attr('width',  d => iconSize(d))
            .attr('height', d => iconSize(d))
            .attr('x', d => -iconSize(d) / 2)
            .attr('y', d => -iconSize(d) / 2)
            .attr('pointer-events', 'none')
            .attr('opacity', d => d.online === false ? 0.4 : 0.9)

          en.append('text')
            .attr('y', d => radius(d) + 11)
            .attr('text-anchor', 'middle')
            .attr('fill', d => d.category === 'lan_device' ? '#e2e8f0' : '#94a3b8')
            .attr('font-size', d => d.category === 'lan_device' ? 10 : 9)
            .attr('font-weight', d => d.category === 'lan_device' ? '600' : '400')
            .text(d => nodeLabel(d, displayNameRef.current))

          // EN: Native tooltip — kept fresh by the metrics effect below.
          // FR: Infobulle native — maintenue à jour par l'effet métriques.
          en.append('title').text(d => nodeTitle(d, displayNameRef.current))

          return en
        },
        update => update,
        exit => exit.remove(),
      )

    nodeSel.current = node

    // EN: Alert rings are added/removed by the lightweight metrics effect —
    //     painted here too for freshly-entered nodes.
    // FR: Les anneaux d'alerte sont gérés par l'effet métriques léger —
    //     peints ici aussi pour les nœuds fraîchement entrés.
    paintAlertRings(node, alertedNodes)

    // EN: Named so the synchronous convergence below can paint once —
    //     d3's manual tick() does NOT dispatch events (only the RAF loop
    //     does), so we must call the painter ourselves after stepping.
    // FR: Nommé pour que la convergence synchrone ci-dessous peigne une
    //     fois — le tick() manuel de d3 NE dispatche PAS les événements
    //     (seule la boucle RAF le fait), il faut donc appeler le peintre.
    const renderTick = () => {
      link
        .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y)
      linkLabel
        .attr('x', d => (d.source.x + d.target.x) / 2)
        .attr('y', d => (d.source.y + d.target.y) / 2)
      node.attr('transform', d => `translate(${d.x},${d.y})`)
    }
    sim.on('tick', renderTick)

    // EN: Converge ONLY when something actually moved — new arrivals need
    //     ~120 ticks to settle on their ring; with zero arrivals the pinned
    //     layout is already final. This is what freezes the UI during busy
    //     traffic otherwise.
    // FR: Converger SEULEMENT quand quelque chose a bougé — les nouveaux
    //     ont besoin de ~120 ticks pour se poser sur leur anneau ; sans
    //     arrivée la mise en page épinglée est déjà finale. C'est ça qui
    //     gelait l'UI pendant le trafic dense.
    sim.stop()
    if (newCount > 0) {
      sim.alpha(0.4)
      const ticks = Math.min(300, 60 + newCount * 6)
      for (let i = 0; i < ticks; i++) sim.tick()
    }
    allNodes.forEach(n => {
      n.fx = n.x; n.fy = n.y
      posCache.current[n.id] = { x: n.x, y: n.y, fx: n.x, fy: n.y }
    })
    renderTick()
    // EN: Repaint WITH drift — the plain tick above wrote base positions.
    // FR: Repeindre AVEC la dérive — le tick ci-dessus a écrit les positions de base.
    floatPaint.current?.(performance.now())
    })
    return () => cancelAnimationFrame(raf)

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

  // ── Gentle float — slow sinusoidal drift on top of the pinned layout.
  //     Each node gets a stable phase from its id, so bubbles bob organically
  //     without ever moving the layout or the user's view. Edges bend with
  //     their endpoints so links stay glued to their bubbles.
  // ── Flottement doux — dérive sinusoïdale lente par-dessus la mise en page
  //     épinglée. Chaque nœud a une phase stable dérivée de son id : les bulles
  //     ondulent organiquement sans jamais déplacer la mise en page ni la vue.
  //     Les arêtes suivent leurs extrémités — les liens restent collés.
  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return

    // EN: Deterministic phase 0..2π from the node id.
    // FR: Phase déterministe 0..2π dérivée de l'id du nœud.
    const phase = id => {
      let h = 0
      for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) | 0
      return ((h >>> 0) % 628) / 100
    }
    const AMP = 4.5                                        // EN: px of drift / FR: amplitude en px
    let t0 = 0
    const driftX = d => d.id === 'local' ? 0 : Math.sin(t0 * 0.35 + phase(d.id)) * AMP
    const driftY = d => d.id === 'local' ? 0 : Math.cos(t0 * 0.28 + phase(d.id) * 1.3) * AMP

    // EN: Exposed via ref so a structural rebuild can repaint WITH drift —
    //     otherwise its plain renderTick snaps every bubble back to base
    //     for one frame = the visible "jump" when a new host appears.
    // FR: Exposé via ref pour qu'une reconstruction peigne AVEC la dérive —
    //     sinon son renderTick nu ramène toutes les bulles à la base pendant
    //     un frame = le « saut » visible quand un nouvel hôte apparaît.
    floatPaint.current = now => {
      t0 = now / 1000
      nodeSel.current?.attr('transform', d => `translate(${d.x + driftX(d)},${d.y + driftY(d)})`)
      linkSel.current
        ?.attr('x1', d => d.source.x + driftX(d.source))
        .attr('y1', d => d.source.y + driftY(d.source))
        .attr('x2', d => d.target.x + driftX(d.target))
        .attr('y2', d => d.target.y + driftY(d.target))
      labelSel.current
        ?.attr('x', d => (d.source.x + d.target.x) / 2 + (driftX(d.source) + driftX(d.target)) / 2)
        .attr('y', d => (d.source.y + d.target.y) / 2 + (driftY(d.source) + driftY(d.target)) / 2)
    }

    let raf
    const frame = now => {
      raf = requestAnimationFrame(frame)
      if (document.hidden) return                          // EN: free when tab hidden / FR: gratuit onglet caché
      floatPaint.current(now)
    }
    raf = requestAnimationFrame(frame)
    return () => { cancelAnimationFrame(raf); floatPaint.current = null }
  }, [])

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

  // EN: Transparent SVG — the AuroraCurtain canvas underneath supplies the
  //     backdrop. / FR: SVG transparent — le canvas AuroraCurtain dessous
  //     fournit la toile de fond.
  return <svg ref={svgRef} style={{ width: '100%', height: '100%', background: 'transparent' }} />
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
  // EN: Severity theatre — a critical alert must be UNMISSABLE: a thick
  //     red ring + an expanding radar ping + a "!" badge + a red-tinted
  //     label. Warning gets a pulsing amber ring. An identified online
  //     LAN device with no alert wears a static green "safe" ring.
  //     Info alerts paint nothing.
  // FR: Théâtre de sévérité — une alerte critique doit être IMPOSSIBLE À
  //     RATER : anneau rouge épais + ping radar expansif + badge « ! » +
  //     étiquette teintée rouge. Warning = anneau orange pulsant. Un
  //     appareil LAN identifié/en ligne sans alerte porte un anneau vert
  //     « sûr » fixe. Les alertes info ne peignent rien.
  const RING_COLORS = { critical: '#ef4444', warning: '#f59e0b' }
  nodeSel.each(function (d) {
    const g = d3.select(this)
    const sev = alertedNodes.get?.(d.id)
      || (d.alerted ? (d.alert_severity || 'warning') : null)
    const safe = !sev && d.category === 'lan_device'
      && (d.hostname || d.vendor) && d.online !== false
    const want = sev ? `alert:${sev}` : (safe ? 'safe' : null)

    const ring = g.select('circle.status-ring')
    const have = ring.empty() ? null : ring.attr('data-kind')
    if (have === want) return
    // EN: Wipe every decoration layer — ring, ping, badge — then repaint
    //     for the new state.
    // FR: Effacer toutes les couches décoratives — anneau, ping, badge —
    //     puis repeindre pour le nouvel état.
    g.selectAll('.status-ring,.status-ping,.alert-badge,.alert-badge-txt').remove()

    // EN: Label tint follows the verdict.
    // FR: La teinte de l'étiquette suit le verdict.
    g.select('text').attr('fill',
      sev === 'critical' ? '#f87171'
      : sev === 'warning' ? '#fbbf24'
      : (d.category === 'lan_device' ? '#e2e8f0' : '#94a3b8'))

    if (!want) return

    const baseR = radius(d)
    const c = g.insert('circle', ':first-child')
      .attr('class', 'status-ring')
      .attr('data-kind', want)
      .attr('r', baseR + 9)
      .attr('fill', 'none')
    if (want === 'safe') {
      c.attr('stroke', '#22c55e').attr('stroke-opacity', 0.5)
        .attr('stroke-width', 1.2)
      return
    }
    if (sev === 'critical') {
      // EN: Thick steady ring …
      // FR: Anneau fixe épais …
      c.attr('stroke', '#ef4444').attr('stroke-opacity', 0.9)
        .attr('stroke-width', 2.5)
      // EN: … + radar ping expanding outward and fading — reads as an
      //     alarm, not a status.
      // FR: … + ping radar qui s'étend et s'estompe — se lit comme une
      //     alarme, pas un statut.
      const ping = g.insert('circle', ':first-child')
        .attr('class', 'status-ping')
        .attr('r', baseR + 6)
        .attr('fill', 'none')
        .attr('stroke', '#ef4444')
        .attr('stroke-width', 2)
      ping.append('animate')
        .attr('attributeName', 'r')
        .attr('values', `${baseR + 6};${baseR + 28}`)
        .attr('dur', '1.4s').attr('repeatCount', 'indefinite')
      ping.append('animate')
        .attr('attributeName', 'stroke-opacity')
        .attr('values', '0.8;0')
        .attr('dur', '1.4s').attr('repeatCount', 'indefinite')
      // EN: "!" badge pinned at the node's top-right.
      // FR: Badge « ! » épinglé en haut à droite du nœud.
      g.append('circle')
        .attr('class', 'alert-badge')
        .attr('cx', baseR - 1).attr('cy', -(baseR - 1))
        .attr('r', 5.5).attr('fill', '#ef4444')
      g.append('text')
        .attr('class', 'alert-badge-txt')
        .attr('x', baseR - 1).attr('y', -(baseR - 1) + 3)
        .attr('text-anchor', 'middle')
        .attr('fill', '#fff').attr('font-size', 8)
        .attr('font-weight', 'bold').text('!')
      return
    }
    c.attr('stroke', RING_COLORS[sev] || '#f59e0b')
      .attr('stroke-opacity', 0.7)
      .attr('stroke-width', 1.5)
      .append('animate')
      .attr('attributeName', 'stroke-opacity')
      .attr('values', '0.7;0.1;0.7')
      .attr('dur', '1.5s').attr('repeatCount', 'indefinite')
  })
}
