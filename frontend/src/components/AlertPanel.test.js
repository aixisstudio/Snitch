/**
 * Snitch — alert timestamp tests (Vitest).
 *
 * EN: Backend alerts carry ISO 8601 timestamps WITH an offset ("+00:00");
 *     the relative time must never render as "NaNh ago".
 * FR: Les alertes du backend portent des horodatages ISO 8601 AVEC décalage
 *     (« +00:00 ») ; le temps relatif ne doit jamais afficher « NaNh ago ».
 */
import { describe, it, expect } from 'vitest'
import { parseTs, timeAgo } from './AlertPanel'

const t = (key, n) => `${key}:${n ?? ''}`
const NOW = Date.parse('2026-10-05T12:00:00Z')

describe('parseTs', () => {
  it('parses offset, Z and naive timestamps as UTC', () => {
    expect(parseTs('2026-10-05T11:00:00+00:00').getTime()).toBe(NOW - 3600e3)
    expect(parseTs('2026-10-05T11:00:00Z').getTime()).toBe(NOW - 3600e3)
    expect(parseTs('2026-10-05T11:00:00').getTime()).toBe(NOW - 3600e3)
  })
})

describe('timeAgo', () => {
  it('formats backend offset timestamps', () => {
    expect(timeAgo('2026-10-05T11:59:30.123456+00:00', t, NOW)).toBe('time_seconds:29')
    expect(timeAgo('2026-10-05T10:00:00+00:00', t, NOW)).toBe('time_hours:2')
  })
  it('never returns NaN', () => {
    expect(timeAgo('garbage', t, NOW)).toBe('')
  })
})
