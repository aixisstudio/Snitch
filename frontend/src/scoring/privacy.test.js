/**
 * Snitch — privacy score tests (Vitest).
 *
 * EN: Exercises computePrivacyScore's main branches: baseline, tracker
 *     penalties, beacon/critical penalties, grade/color/label mapping and
 *     positive factors.
 * FR: Couvre les branches principales de computePrivacyScore : base,
 *     pénalités trackers, pénalités beacon/critiques, correspondance
 *     note/couleur/libellé et facteurs positifs.
 */
import { describe, it, expect } from 'vitest'
import { computePrivacyScore } from './privacy'

const node = (over = {}) => ({
  id: '1.2.3.4', category: 'unknown', bytes: 1000, packets: 10, org: null, ...over,
})
const alert = (type, severity = 'warning') => ({ type, severity })

describe('computePrivacyScore', () => {
  it('returns a perfect baseline with no external nodes', () => {
    const r = computePrivacyScore({ local: node({ id: 'local' }) }, [])
    expect(r.score).toBe(100)
    expect(r.grade).toBe('A')
    expect(r.color).toBe('#22c55e')
    expect(r.labelKey).toBe('privacy_label_excellent')
  })

  it('penalizes tracker nodes', () => {
    const nodes = {
      local: node({ id: 'local' }),
      '9.9.9.9': node({ id: '9.9.9.9', category: 'tracking', bytes: 5000 }),
    }
    const r = computePrivacyScore(nodes, [])
    expect(r.score).toBeLessThan(100)
    expect(r.factors.some(f => f.key === 'score_trackers')).toBe(true)
  })

  it('penalizes beacon and critical alerts heavily', () => {
    const r = computePrivacyScore(
      { local: node({ id: 'local' }), '1.1.1.1': node() },
      [alert('BEACON'), alert('MEDIA_EXFIL', 'critical')],
    )
    expect(r.score).toBeLessThan(80)
    expect(r.factors.some(f => f.key === 'score_beacons')).toBe(true)
    expect(r.factors.some(f => f.key === 'score_critical_alerts')).toBe(true)
  })

  it('rewards high HTTPS share with a positive factor', () => {
    const nodes = {
      local: node({ id: 'local' }),
      'a': node({ id: 'a', category: 'safe', packets: 100 }),
      'b': node({ id: 'b', category: 'unknown', packets: 10 }),
    }
    const r = computePrivacyScore(nodes, [])
    expect(r.factors.some(f => f.key === 'score_https_ratio' && !f.bad)).toBe(true)
    expect(r.factors.some(f => f.key === 'score_no_trackers' && !f.bad)).toBe(true)
  })

  it('detects ad networks by org name', () => {
    const nodes = {
      local: node({ id: 'local' }),
      'x': node({ id: 'x', org: 'Google LLC' }),
    }
    const r = computePrivacyScore(nodes, [])
    expect(r.factors.some(f => f.key === 'score_ad_networks')).toBe(true)
  })

  it('score is always clamped to [0, 100]', () => {
    const many = Array.from({ length: 50 }, (_, i) => alert('BEACON', 'critical'))
    const r = computePrivacyScore({}, many)
    expect(r.score).toBeGreaterThanOrEqual(0)
    expect(r.score).toBeLessThanOrEqual(100)
  })
})
