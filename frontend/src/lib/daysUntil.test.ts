import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { daysUntil } from './datetime'

// KNOWN-7: evidence freshness used new Date('YYYY-MM-DD') (UTC midnight), so west
// of UTC an artifact expiring today showed EXPIRED and "tomorrow" showed 0 days.
const ORIGINAL_TZ = process.env.TZ
beforeAll(() => { process.env.TZ = 'America/Los_Angeles' })
afterAll(() => { process.env.TZ = ORIGINAL_TZ })

describe('daysUntil (TZ=America/Los_Angeles, 20:00 local)', () => {
  const NOW = new Date('2026-10-22T03:00:00Z') // Oct 21 20:00 in LA (PDT)
  beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(NOW) })
  afterEach(() => { vi.useRealTimers() })

  it('the zone really is LA', () => { expect(NOW.getTimezoneOffset()).toBe(420) })
  it('expires today = 0 days left, not expired', () => { expect(daysUntil('2026-10-21')).toBe(0) })
  it('expires tomorrow = 1 day', () => { expect(daysUntil('2026-10-22')).toBe(1) })
  it('expired yesterday = -1', () => { expect(daysUntil('2026-10-20')).toBe(-1) })
  it('across the DST change still counts calendar days', () => { expect(daysUntil('2026-11-30')).toBe(40) })
  it('missing/invalid → null', () => {
    expect(daysUntil(null)).toBeNull()
    expect(daysUntil('not a date')).toBeNull()
  })
})
