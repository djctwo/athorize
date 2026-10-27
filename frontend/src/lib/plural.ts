/**
 * "1 item" / "3 items". Pass the plural form for irregular nouns:
 * plural(n, 'entry', 'entries').
 */
export function plural(n: number, singular: string, pluralForm?: string): string {
  return `${n} ${n === 1 ? singular : (pluralForm ?? `${singular}s`)}`
}
