import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { daysSince } from './datetime'

// R2USER-6: "Days Open" was computed on the server as server-local today minus the
// UTC creation date, so a brand-new finding read 1 day (east of UTC) or -1 (west).
const ORIGINAL_TZ = process.env.TZ
afterAll(() => { process.env.TZ = ORIGINAL_TZ })

describe('daysSince in Europe/Berlin', () => {
  beforeAll(() => { process.env.TZ = 'Europe/Berlin' })
  it('created a minute ago, just after local midnight, is 0', () => {
    // 23:30 UTC on Oct 21 = 01:30 Oct 22 in Berlin
    expect(daysSince('2026-10-21T23:30:00+00:00', new Date('2026-10-21T23:31:00Z'))).toBe(0)
  })
  it('created yesterday (local) is 1', () => {
    expect(daysSince('2026-10-21T10:00:00+00:00', new Date('2026-10-22T10:00:00Z'))).toBe(1)
  })
})

describe('daysSince in America/Los_Angeles', () => {
  beforeAll(() => { process.env.TZ = 'America/Los_Angeles' })
  it('an evening creation is 0, never -1', () => {
    // 03:00 UTC Oct 22 = 20:00 Oct 21 in LA
    expect(daysSince('2026-10-22T03:00:00Z', new Date('2026-10-22T03:05:00Z'))).toBe(0)
  })
  it('missing → null', () => { expect(daysSince(null)).toBeNull() })
})
