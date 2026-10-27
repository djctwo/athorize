/** RFC 4180 CSV parsing: quoted fields may contain commas, newlines and
 * doubled quotes (""). Returns rows of raw cell strings; blank lines are
 * dropped. A leading UTF-8 BOM (Excel exports) is ignored. */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = []
  let row: string[] = []
  let cell = ''
  let inQuotes = false
  const src = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text
  const endRow = () => {
    row.push(cell)
    if (row.some(c => c.trim() !== '')) rows.push(row)
    row = []
    cell = ''
  }
  for (let i = 0; i < src.length; i++) {
    const ch = src[i]
    if (inQuotes) {
      if (ch === '"') {
        if (src[i + 1] === '"') { cell += '"'; i++ } else inQuotes = false
      } else cell += ch
    } else if (ch === '"') {
      inQuotes = true
    } else if (ch === ',') {
      row.push(cell)
      cell = ''
    } else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && src[i + 1] === '\n') i++
      endRow()
    } else cell += ch
  }
  if (cell !== '' || row.length > 0) endRow()
  return rows
}

export interface CsvControlRow {
  id: string
  family: string
  family_name: string
  title: string
  description: string
}

/** Framework Builder import: columns id,family,family_name,title,description
 * (header row optional). Rows without an id are skipped. */
export function parseControlsCsv(text: string): CsvControlRow[] {
  const out: CsvControlRow[] = []
  for (const raw of parseCsv(text)) {
    const cols = raw.map(c => c.trim())
    if (!cols[0] || cols[0].toLowerCase() === 'id') continue
    out.push({
      id: cols[0], family: cols[1] ?? '', family_name: cols[2] ?? '',
      title: cols[3] || cols[0], description: cols[4] ?? '',
    })
  }
  return out
}
