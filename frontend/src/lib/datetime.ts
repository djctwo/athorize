// Parsing + display helpers for timestamps returned by the API.
//
// The backend emits timezone-aware UTC ISO strings ("…+00:00"). Older
// backends (and any stray naive value) emitted offset-less UTC, which
// `new Date()` reads as LOCAL time — every "2h ago" was off by the viewer's
// UTC offset. Always go through parseApiDate instead of `new Date(apiValue)`.

const DATE_ONLY = /^(\d{4})-(\d{2})-(\d{2})$/
// Has a time component but no trailing "Z" / "±hh:mm" / "±hhmm" offset.
const NAIVE_DATETIME = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/

/**
 * Parse an API date/datetime string.
 * - offset-less datetimes are UTC (that is what the server stores)
 * - date-only values ("2026-10-21") are calendar dates: local midnight, so
 *   they never shift to the previous day west of UTC
 * Returns null for empty or unparseable input.
 */
export function parseApiDate(value: string | null | undefined): Date | null {
  if (!value) return null
  const s = value.trim()
  const dateOnly = DATE_ONLY.exec(s)
  let d: Date
  if (dateOnly) {
    d = new Date(Number(dateOnly[1]), Number(dateOnly[2]) - 1, Number(dateOnly[3]))
  } else if (NAIVE_DATETIME.test(s)) {
    // JS Date only reliably parses up to milliseconds.
    d = new Date(s.replace(' ', 'T').replace(/(\.\d{3})\d+$/, '$1') + 'Z')
  } else {
    d = new Date(s)
  }
  return Number.isNaN(d.getTime()) ? null : d
}

/** "45s ago" / "3m ago" / "2h ago" / "4d ago", else a local date. */
export function formatRelative(iso: string | null | undefined): string {
  const d = parseApiDate(iso)
  if (!d) return ''
  const diffMs = Date.now() - d.getTime()
  if (diffMs < 0) return d.toLocaleString()
  const s = Math.floor(diffMs / 1000)
  if (s < 60) return `${s}s ago`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  const days = Math.floor(h / 24)
  if (days < 7) return `${days}d ago`
  return d.toLocaleDateString()
}

/** Local date + time for an API timestamp ('' when missing/invalid). */
export function formatDateTime(iso: string | null | undefined): string {
  return parseApiDate(iso)?.toLocaleString() ?? ''
}

/** Local date for an API date or timestamp ('' when missing/invalid). */
export function formatDate(iso: string | null | undefined, options?: Intl.DateTimeFormatOptions, locale?: string): string {
  return parseApiDate(iso)?.toLocaleDateString(locale, options) ?? ''
}

/**
 * Whole calendar days from the viewer's local today to a date-only API value
 * (0 = today, negative = past, null when missing/invalid). Never parse a
 * "YYYY-MM-DD" with new Date(): that is UTC midnight, a day early west of UTC.
 */
export function daysUntil(dateOnly: string | null | undefined, now: Date = new Date()): number | null {
  const d = parseApiDate(dateOnly)
  if (!d) return null
  const target = new Date(d.getFullYear(), d.getMonth(), d.getDate())
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate())
  // round, not floor/ceil: a DST change makes one day 23 or 25 hours long
  return Math.round((target.getTime() - today.getTime()) / 86400000)
}

/**
 * Whole calendar days from a timestamp's LOCAL date to the viewer's local today
 * (0 = earlier today). Used for "Days Open": the server's own date arithmetic
 * mixes its local zone with UTC timestamps, so a finding created a minute ago
 * could read 1 (or -1). Null when missing/invalid; never negative.
 */
export function daysSince(iso: string | null | undefined, now: Date = new Date()): number | null {
  const d = parseApiDate(iso)
  if (!d) return null
  const start = new Date(d.getFullYear(), d.getMonth(), d.getDate())
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate())
  return Math.max(0, Math.round((today.getTime() - start.getTime()) / 86400000))
}
