/**
 * Snitch — bottom timeline chart.
 *
 * EN: Collapsible per-minute bar chart of packets (with bytes and alert
 *     counts in the tooltip) over the last 15/30/60 min. Data comes from the
 *     backend's SQLite aggregates, refreshed every 15 s.
 * FR: Histogramme repliable par minute des paquets (avec octets et nombre
 *     d'alertes dans l'infobulle) sur les 15/30/60 dernières minutes. Données
 *     issues des agrégats SQLite du backend, rafraîchies toutes les 15 s.
 */
import { useEffect, useRef, useState, useCallback } from 'react'
import * as d3 from 'd3'
import { API_BASE, authHeaders } from '../api'
import { useT } from '../i18n'

const EXPANDED_H  = 110
const COLLAPSED_H = 32

/** EN: Human-readable byte size. / FR: Taille en octets lisible. */
function fmt(bytes) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

export default function Timeline() {
  const { t, lang } = useT()
  const svgRef = useRef(null)
  const [data, setData] = useState([])
  const [expanded, setExpanded] = useState(true)
  const [tooltip, setTooltip] = useState(null)
  const [range, setRange] = useState(60)

  /**
   * EN: Minute labels localized to the UI language.
   * FR: Étiquettes de minute localisées selon la langue de l'UI.
   */
  function fmtMinute(iso) {
    const d = new Date(iso + ':00Z')
    return d.toLocaleTimeString(lang === 'fr' ? 'fr-FR' : 'en-US', { hour: '2-digit', minute: '2-digit' })
  }

  const fetchTimeline = useCallback(() => {
    // EN: Auth header required — the API token protects every endpoint.
    // FR: En-tête d'auth requis — le jeton API protège tous les endpoints.
    authHeaders()
      .then(headers => fetch(`${API_BASE}/timeline?minutes=${range}`, { headers }))
      .then(r => r.json())
      .then(d => setData(d.timeline || []))
      .catch(() => {})
  }, [range])

  // EN: Poll every 15 s. / FR: Sondage toutes les 15 s.
  useEffect(() => {
    fetchTimeline()
    const id = setInterval(fetchTimeline, 15000)
    return () => clearInterval(id)
  }, [fetchTimeline])

  useEffect(() => {
    if (!expanded || !svgRef.current || data.length === 0) return
    drawChart()
  }, [data, expanded, lang])

  function drawChart() {
    const el = svgRef.current
    const W = el.clientWidth
    const H = EXPANDED_H - 32
    const margin = { top: 8, right: 16, bottom: 24, left: 40 }
    const innerW = W - margin.left - margin.right
    const innerH = H - margin.top - margin.bottom

    const svg = d3.select(el)
    svg.selectAll('*').remove()

    const g = svg.append('g').attr('transform', `translate(${margin.left},${margin.top})`)

    const x = d3.scaleBand()
      .domain(data.map(d => d.minute))
      .range([0, innerW])
      .padding(0.15)

    const maxPkts = d3.max(data, d => d.packets) || 1
    const y = d3.scaleLinear().domain([0, maxPkts]).range([innerH, 0]).nice()

    // EN: Horizontal grid lines. / FR: Lignes de grille horizontales.
    g.append('g').attr('class', 'grid')
      .call(d3.axisLeft(y).ticks(3).tickSize(-innerW).tickFormat(''))
      .selectAll('line').attr('stroke', '#1c1c1c').attr('stroke-dasharray', '3,3')
    g.select('.grid .domain').remove()

    // EN: Bars — amber when the minute produced alerts, blue otherwise.
    // FR: Barres — ambre quand la minute a produit des alertes, bleu sinon.
    g.selectAll('rect.bar')
      .data(data)
      .join('rect')
      .attr('class', 'bar')
      .attr('x', d => x(d.minute))
      .attr('y', d => y(d.packets))
      .attr('width', x.bandwidth())
      .attr('height', d => innerH - y(d.packets))
      .attr('fill', d => d.alerts > 0 ? '#f59e0b' : '#3b82f6')
      .attr('fill-opacity', d => d.alerts > 0 ? 0.85 : 0.65)
      .attr('rx', 2)
      .on('mouseover', (e, d) => setTooltip({ x: e.clientX, y: e.clientY, d }))
      .on('mousemove', (e) => setTooltip(tt => tt ? { ...tt, x: e.clientX, y: e.clientY } : null))
      .on('mouseout', () => setTooltip(null))

    // EN: Red dot on top of alert-producing minutes.
    // FR: Point rouge au-dessus des minutes à alertes.
    g.selectAll('circle.alert')
      .data(data.filter(d => d.alerts > 0))
      .join('circle')
      .attr('class', 'alert')
      .attr('cx', d => x(d.minute) + x.bandwidth() / 2)
      .attr('cy', d => y(d.packets) - 5)
      .attr('r', 3)
      .attr('fill', '#ef4444')
      .attr('pointer-events', 'none')

    // EN: Thin out x labels — ~8 ticks max.
    // FR: Espacer les étiquettes x — ~8 graduations max.
    const step = Math.max(1, Math.floor(data.length / 8))
    const xAxis = d3.axisBottom(x)
      .tickValues(data.filter((_, i) => i % step === 0).map(d => d.minute))
      .tickFormat(fmtMinute)

    g.append('g')
      .attr('transform', `translate(0,${innerH})`)
      .call(xAxis)
      .selectAll('text')
      .attr('fill', '#475569').attr('font-size', 9)
    g.selectAll('.domain, .tick line').attr('stroke', '#2a2a2a')

    g.append('g')
      .call(d3.axisLeft(y).ticks(3).tickFormat(d => d > 999 ? `${(d / 1000).toFixed(0)}k` : d))
      .selectAll('text').attr('fill', '#475569').attr('font-size', 9)
    g.select('.domain').attr('stroke', '#2a2a2a')
  }

  const totalPkts   = data.reduce((a, d) => a + d.packets, 0)
  const totalBytes  = data.reduce((a, d) => a + d.bytes,   0)
  const totalAlerts = data.reduce((a, d) => a + d.alerts,  0)

  return (
    /* EN: Bento card — floats on the black canvas, hairline border,
           12px radius matching the sidebar cards.
       FR: Carte bento — flotte sur le canevas noir, bordure fine,
           rayon 12 px assorti aux cartes de la sidebar. */
    <div style={{
      height: expanded ? EXPANDED_H : COLLAPSED_H,
      background: '#0f0f0f',
      border: '1px solid #1c1c1c',
      borderRadius: 12,
      margin: '0 8px 8px',
      transition: 'height 0.2s ease',
      overflow: 'hidden',
      flexShrink: 0,
      position: 'relative',
    }}>
      {/* EN: Header row — click to collapse/expand.
          FR: Ligne d'en-tête — cliquer pour replier/déplier. */}
      <div
        onClick={() => setExpanded(v => !v)}
        style={{
          height: COLLAPSED_H, display: 'flex', alignItems: 'center',
          padding: '0 16px', gap: 20, cursor: 'pointer',
          borderBottom: expanded ? '1px solid #1c1c1c' : 'none',
        }}
      >
        <span style={{ fontSize: 10, fontWeight: 700, color: '#64748b', textTransform: 'uppercase', letterSpacing: 1 }}>
          {expanded ? 'v' : '^'} Timeline
        </span>

        <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
          <Chip label={t('timeline_packets', totalPkts)} color="#3b82f6" />
          <Chip label={fmt(totalBytes)} color="#6366f1" />
          {totalAlerts > 0 && <Chip label={t('timeline_alerts', totalAlerts)} color="#f59e0b" />}
        </div>

        {/* EN: Range picker / FR: Sélecteur de plage */}
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 6 }}>
          {[15, 30, 60].map(m => (
            <button
              key={m}
              onClick={e => { e.stopPropagation(); setRange(m) }}
              style={{
                background: range === m ? '#1c1c1c' : 'transparent',
                border: '1px solid #1c1c1c', borderRadius: 4,
                color: range === m ? '#93c5fd' : '#475569',
                fontSize: 9, padding: '2px 7px', cursor: 'pointer',
              }}
            >
              {m}min
            </button>
          ))}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 5,
            fontSize: 9, color: '#22c55e', marginLeft: 8,
          }}>
            <div style={{ width: 5, height: 5, borderRadius: '50%', background: '#22c55e' }} />
            {t('timeline_live')}
          </div>
        </div>
      </div>

      {expanded && (
        <svg
          ref={svgRef}
          style={{ width: '100%', height: EXPANDED_H - COLLAPSED_H, display: 'block' }}
        />
      )}

      {/* EN: Hover tooltip / FR: Infobulle au survol */}
      {tooltip && (
        <div style={{
          position: 'fixed', left: tooltip.x + 12, top: tooltip.y - 60,
          background: '#0f0f0f', border: '1px solid #2a2a2a',
          borderRadius: 6, padding: '6px 10px', fontSize: 10,
          color: '#e2e8f0', pointerEvents: 'none', zIndex: 500,
        }}>
          <div style={{ fontWeight: 700, marginBottom: 3 }}>{fmtMinute(tooltip.d.minute)}</div>
          <div>{t('timeline_packets', tooltip.d.packets)}</div>
          <div style={{ color: '#64748b' }}>{fmt(tooltip.d.bytes)}</div>
          {tooltip.d.alerts > 0 && (
            <div style={{ color: '#f59e0b', marginTop: 2 }}>! {t('timeline_alerts', tooltip.d.alerts)}</div>
          )}
        </div>
      )}
    </div>
  )
}

function Chip({ label, color }) {
  return (
    <span style={{
      fontSize: 10, color, background: color + '1a',
      border: `1px solid ${color}44`, borderRadius: 10, padding: '1px 8px',
    }}>
      {label}
    </span>
  )
}
