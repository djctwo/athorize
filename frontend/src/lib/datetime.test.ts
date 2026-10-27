import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { formatRelative, parseApiDate } from './datetime'

// Run under a non-UTC zone (CEST = UTC+2 on the pinned date). The suite is
// also run with TZ=Europe/Berlin; setting it here keeps the file meaningful
// when run on a UTC CI box.
const ORIGINAL_TZ = process.env.TZ
beforeAll(() => { process.env.TZ = 'Europe/Berlin' })
afterAll(() => { process.env.TZ = ORIGINAL_TZ })

const NOW = new Date('2026-10-21T12:00:00Z') // 14:00 in Berlin (CEST)

describe('formatRelative (TZ=Europe/Berlin)', () => {
  beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(NOW) })
  afterEach(() => { vi.useRealTimers() })

  it('the zone really is Berlin (guards the rest of the file)', () => {
    expect(NOW.getTimezoneOffset()).toBe(-120)
  })

  it('reads an offset-less API timestamp as UTC, not local time', () => {
    // Older backends emitted naive UTC: 10:00 UTC is two hours before NOW.
    expect(formatRelative('2026-10-21T10:00:00')).toBe('2h ago')
    expect(formatRelative('2026-10-21T09:59:59.500000')).toBe('2h ago')
    expect(formatRelative('2026-10-21 10:00:00')).toBe('2h ago')
  })

  it('a comment posted just now says seconds ago, not 2h ago', () => {
    expect(formatRelative('2026-10-21T11:59:30')).toBe('30s ago')
  })

  it('honours explicit offsets', () => {
    expect(formatRelative('2026-10-21T10:00:00+00:00')).toBe('2h ago')
    expect(formatRelative('2026-10-21T10:00:00Z')).toBe('2h ago')
    expect(formatRelative('2026-10-21T13:00:00+02:00')).toBe('1h ago')
  })

  it('handles empty and garbage input without throwing', () => {
    expect(formatRelative(null)).toBe('')
    expect(formatRelative('')).toBe('')
    expect(formatRelative('not a date')).toBe('')
  })
})

describe('parseApiDate', () => {
  it('treats offset-less datetimes as UTC', () => {
    expect(parseApiDate('2026-10-21T10:00:00')?.toISOString()).toBe('2026-10-21T10:00:00.000Z')
  })

  it('keeps date-only values on the same calendar day in a zone west of UTC', () => {
    process.env.TZ = 'America/New_York'
    try {
      const d = parseApiDate('2026-10-21')
      expect(d?.getFullYear()).toBe(2026)
      expect(d?.getMonth()).toBe(9)
      expect(d?.getDate()).toBe(21)
    } finally {
      process.env.TZ = 'Europe/Berlin'
    }
  })

  it('returns null for empty or invalid input', () => {
    expect(parseApiDate(undefined)).toBeNull()
    expect(parseApiDate('nope')).toBeNull()
  })
})
