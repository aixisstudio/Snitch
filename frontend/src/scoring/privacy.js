/**
 * Snitch — privacy score engine.
 *
 * EN: Computes a 0–100 score from the live node map and alert history.
 *     Starts at 100 and subtracts penalties: trackers contacted, share of
 *     traffic going to trackers, ad-network orgs, beaconing, suspicious
 *     processes/ports and critical alerts. Positive signals (high HTTPS
 *     ratio, zero trackers) are listed as good factors. Also returns a letter
 *     grade, a color and an i18n label key for the UI.
 *
 * FR: Calcule un score de 0 à 100 à partir de la table de nœuds en direct et
 *     de l'historique d'alertes. Départ à 100, puis pénalités : trackers
 *     contactés, part du trafic vers les trackers, régies publicitaires,
 *     beaconing, processus/ports suspects et alertes critiques. Les signaux
 *     positifs (fort ratio HTTPS, zéro tracker) sont listés comme bons
 *     facteurs. Renvoie aussi une note lettre, une couleur et une clé i18n.
 */

// EN: Substrings matched against the ASN/org name to spot ad networks.
// FR: Sous-chaînes recherchées dans le nom d'ASN/org pour repérer les régies pubs.
const AD_ORGS = [
  'google', 'doubleclick', 'facebook', 'meta', 'amazon ads',
  'amazon advertising', 'twitter', 'tiktok', 'snap', 'pinterest',
  'taboola', 'outbrain', 'criteo', 'appnexus', 'pubmatic',
  'openx', 'rubicon', 'sharethrough', 'index exchange',
]

function isAdOrg(org) {
  if (!org) return false
  const lower = org.toLowerCase()
  return AD_ORGS.some(a => lower.includes(a))
}

/**
 * EN: Main entry — pure function, safe to call on every render via useMemo.
 * FR: Point d'entrée — fonction pure, sûre à appeler à chaque rendu via useMemo.
 */
export function computePrivacyScore(nodes, alerts) {
  const extNodes = Object.values(nodes).filter(n => n.id !== 'local')
  const totalBytes   = extNodes.reduce((a, n) => a + (n.bytes   || 0), 0)
  const totalPackets = extNodes.reduce((a, n) => a + (n.packets || 0), 0)

  const trackerNodes = extNodes.filter(n => n.category === 'tracking')
  const trackerBytes = trackerNodes.reduce((a, n) => a + (n.bytes || 0), 0)
  const adOrgNodes   = extNodes.filter(n => isAdOrg(n.org))

  const byType = type => alerts.filter(a => a.type === type).length
  const bySev  = sev  => alerts.filter(a => a.severity === sev).length

  const beaconCount   = byType('BEACON')
  const suspProcCount = byType('SUSPICIOUS_PROCESS')
  const suspPortCount = byType('SUSPICIOUS_PORT')
  const criticalCount = bySev('critical')
  const warningCount  = bySev('warning')

  let score = 100
  const factors = []

  // EN: Each tracker contacted costs 4 points (cap −28).
  // FR: Chaque tracker contacté coûte 4 points (plafond −28).
  if (trackerNodes.length > 0) {
    const p = Math.min(trackerNodes.length * 4, 28)
    score -= p
    factors.push({ icon: 'radio', key: 'score_trackers', args: [trackerNodes.length], penalty: p, bad: true })
  }

  // EN: A high share of tracker traffic is worse than a high count.
  // FR: Une forte part de trafic vers les trackers est pire qu'un grand nombre.
  if (totalBytes > 0 && trackerBytes > 0) {
    const pct = (trackerBytes / totalBytes) * 100
    if (pct > 3) {
      const p = Math.min(Math.floor(pct / 3), 15)
      score -= p
      factors.push({ icon: 'bar-chart', key: 'score_tracker_traffic', args: [pct.toFixed(0)], penalty: p, bad: true })
    }
  }

  // EN: Ad-network orgs not already counted as trackers get a smaller penalty.
  // FR: Les régies pubs non déjà comptées comme trackers ont une pénalité réduite.
  if (adOrgNodes.length > trackerNodes.length) {
    const extra = adOrgNodes.length - trackerNodes.length
    const p = Math.min(extra * 3, 12)
    score -= p
    factors.push({ icon: 'target', key: 'score_ad_networks', args: [adOrgNodes.length], penalty: p, bad: true })
  }

  // EN: Beaconing is a strong C2 signal — heavy penalty.
  // FR: Le beaconing est un fort signal de C2 — pénalité lourde.
  if (beaconCount > 0) {
    const p = Math.min(beaconCount * 12, 24)
    score -= p
    factors.push({ icon: 'activity', key: 'score_beacons', args: [beaconCount], penalty: p, bad: true })
  }

  if (suspProcCount > 0) {
    const p = Math.min(suspProcCount * 8, 20)
    score -= p
    factors.push({ icon: 'alert-triangle', key: 'score_susp_proc', args: [suspProcCount], penalty: p, bad: true })
  }

  if (suspPortCount > 0) {
    const p = Math.min(suspPortCount * 7, 18)
    score -= p
    factors.push({ icon: 'unlock', key: 'score_susp_ports', args: [suspPortCount], penalty: p, bad: true })
  }

  if (criticalCount > 0) {
    const p = Math.min(criticalCount * 10, 20)
    score -= p
    factors.push({ icon: 'shield-alert', key: 'score_critical_alerts', args: [criticalCount], penalty: p, bad: true })
  }

  // EN: Only penalize warnings beyond the first few — noise happens.
  // FR: Ne pénaliser les warnings qu'au-delà des premiers — le bruit arrive.
  if (warningCount > 5) {
    const p = Math.min((warningCount - 5) * 2, 10)
    score -= p
    factors.push({ icon: 'bell', key: 'score_warnings', args: [warningCount], penalty: p, bad: true })
  }

  // ── Positive factors / Facteurs positifs ──────────────────────────────────
  const httpsNodes = extNodes.filter(n => n.category === 'safe')
  if (totalPackets > 0 && httpsNodes.length > 0) {
    const ratio = httpsNodes.reduce((a, n) => a + (n.packets || 0), 0) / totalPackets
    if (ratio > 0.7) {
      factors.push({ icon: 'lock', key: 'score_https_ratio', args: [Math.round(ratio * 100)], penalty: 0, bad: false })
    }
  }

  if (extNodes.length > 0 && trackerNodes.length === 0) {
    factors.push({ icon: 'check-circle', key: 'score_no_trackers', args: [], penalty: 0, bad: false })
  }

  score = Math.max(0, Math.min(100, Math.round(score)))

  // EN: Map the numeric score to a letter grade, a color, and an i18n label key.
  // FR: Associer le score numérique à une note lettre, une couleur et une clé i18n.
  const grade    = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 55 ? 'C' : score >= 35 ? 'D' : 'F'
  const color    = score >= 80 ? '#22c55e' : score >= 60 ? '#84cc16' : score >= 40 ? '#f59e0b' : score >= 20 ? '#f97316' : '#ef4444'
  const labelKey = score >= 80 ? 'privacy_label_excellent' : score >= 60 ? 'privacy_label_good' : score >= 40 ? 'privacy_label_average' : score >= 20 ? 'privacy_label_weak' : 'privacy_label_critical'

  return { score, grade, color, labelKey, factors }
}
