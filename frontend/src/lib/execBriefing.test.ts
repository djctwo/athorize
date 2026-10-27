import { beforeEach, describe, expect, it, vi } from 'vitest'

// R2USER-17: before any Red Team run the deck had 7 slides, its recommendations
// pointed at an "exposure slide" that was not there, and said "1 critical findings".

type FakeSlide = { texts: string[]; tables: unknown[][][] }
const decks: { slides: FakeSlide[] }[] = []

vi.mock('pptxgenjs', () => {
  class FakePres {
    slides: FakeSlide[] = []
    layout = ''
    constructor() { decks.push(this) }
    defineLayout() {}
    addSlide() {
      const slide = {
        texts: [] as string[],
        tables: [] as unknown[][][],
        background: null as unknown,
        addText(t: unknown) {
          const flat = Array.isArray(t) ? t.map(x => (x as { text: string }).text).join(' ') : String(t)
          slide.texts.push(flat)
        },
        addShape() {},
        addTable(rows: unknown[][]) { slide.tables.push(rows) },
      }
      this.slides.push(slide)
      return slide
    }
    writeFile() { return Promise.resolve() }
  }
  return { default: FakePres }
})

const responses: Record<string, unknown> = {}
vi.mock('./api', () => ({
  api: {
    get: vi.fn((path: string) => (path in responses ? Promise.resolve(responses[path]) : Promise.reject(new Error(`no mock for ${path}`)))),
  },
}))

import { generateExecBriefing, plural } from './execBriefing'
import { api } from './api'

beforeEach(() => {
  decks.length = 0
  for (const k of Object.keys(responses)) delete responses[k]
  Object.assign(responses, {
    '/systems': [{ id: 1, name: 'Portal', acronym: 'POR' }],
    '/frameworks': [{ id: 'cmmc-2.0', name: 'CMMC', short_name: 'CMMC 2.0', is_active: true }],
    '/dashboard/compliance': [],
    '/findings': [{ id: 7, title: 'Zerologon', severity: 'CRITICAL', status: 'OPEN', is_open: true, system_id: 1, framework_id: 'cmmc-2.0', control_id: '' }],
    '/dashboard/snapshot': { organization_name: 'Acme Example Co', overdue_findings: 0, expired_evidence: 0, critical_findings: 1 },
    '/redteam': [],
    '/evidence': [],
    '/risks': [],
    '/calendar?derived=false': [],
    '/crosswalk/findings/7': { impacts: [] },
    '/crosswalk/suggestions?system_id=1': { suggestions: [] },
    '/redteam/risk-context': { methodology: { version: '1', last_reviewed: '2026', breach_costs_source: 'IBM', penalty_sources: 'x', disclaimer: '', stale: false } },
  })
})

describe('executive briefing before any Red Team run', () => {
  it('still has the exposure slide the recommendations point to (8 slides)', async () => {
    await generateExecBriefing()
    const deck = decks[0]
    expect(deck.slides).toHaveLength(8)
    const all = deck.slides.map(s => s.texts.join(' | '))
    expect(all.some(t => t.includes('What the Gaps Cost') && t.includes('Run Red Team'))).toBe(true)
    expect(all.some(t => t.includes('See the exposure slide'))).toBe(true)
  })

  it('never says "1 critical findings" or "1 systems"', async () => {
    await generateExecBriefing()
    const text = decks[0].slides.flatMap(s => s.texts).join('\n')
    expect(text).toContain('1 critical finding.')
    expect(text).not.toMatch(/\b1 (critical findings|systems|active frameworks)\b/)
  })
})

describe('plural', () => {
  it('handles 0, 1 and many', () => {
    expect(plural(0, 'artifact')).toBe('0 artifacts')
    expect(plural(1, 'artifact')).toBe('1 artifact')
    expect(plural(3, 'artifact')).toBe('3 artifacts')
  })
})

// SCA rehearsal: the briefing ignored the Reports page System / Framework filters
// and listed every system x framework pair, most of them 0% with nothing in them.
const cell = (row: unknown[], i: number) => (row[i] as { text: string }).text
const pair = (system_id: number, system_name: string, framework_id: string, score: number, assessed: number, open = 0) => ({
  system_id, system_name, framework_id, score_percentage: score, total_controls: 10,
  implemented: Math.round(score / 10), open_findings: open, critical_findings: 0, assessed_controls: assessed,
})

describe('executive briefing scope', () => {
  it('leaves never-started system x framework pairs out of the posture table, and says so', async () => {
    responses['/dashboard/compliance'] = [pair(1, 'Portal', 'cmmc-2.0', 40, 10), pair(1, 'Portal', 'dora', 0, 0), pair(1, 'Portal', 'gdpr', 0, 0)]
    await generateExecBriefing()
    const posture = decks[0].slides.find(s => s.texts.includes('Where We Stand'))!
    expect(posture.tables[0]).toHaveLength(2) // header + the one pair with data
    expect(posture.texts.join(' ')).toContain('2 system × framework pairs not started yet')
  })

  it('honours the System and Framework filters and drops empty slides', async () => {
    Object.assign(responses, {
      '/systems': [{ id: 1, name: 'Portal', acronym: 'POR' }, { id: 2, name: 'Plant', acronym: 'PLT' }],
      '/frameworks': [
        { id: 'cmmc-2.0', name: 'CMMC', short_name: 'CMMC 2.0', is_active: true },
        { id: 'nist-800-53-r5', name: '800-53', short_name: 'NIST 800-53r5', is_active: true },
      ],
      '/dashboard/compliance?system_id=2': [pair(2, 'Plant', 'nist-800-53-r5', 55, 20), pair(2, 'Plant', 'cmmc-2.0', 30, 9)],
      '/findings?system_id=2&framework_id=nist-800-53-r5': [],
      '/dashboard/snapshot?system_id=2&framework_id=nist-800-53-r5': { organization_name: 'Acme Example Co', overdue_findings: 0, expired_evidence: 0, critical_findings: 0 },
      '/redteam?system_id=2&framework_id=nist-800-53-r5': [],
      '/redteam/exposure-summary?system_id=2&framework_id=nist-800-53-r5': { total_exposure_low: 0, total_exposure_high: 0, top5_reduction_low: 0, top5_reduction_high: 0, quick_win_count: 0, report_ids: [], model: '' },
      '/evidence?system_id=2&framework_id=nist-800-53-r5': [],
      '/risks?system_id=2': [],
      '/calendar?derived=false&system_id=2&framework_id=nist-800-53-r5': [],
      '/crosswalk/suggestions?system_id=2': { suggestions: [] },
    })
    vi.mocked(api.get).mockClear()
    await generateExecBriefing({ systemId: 2, frameworkId: 'nist-800-53-r5' })
    const calls = vi.mocked(api.get).mock.calls.map(c => c[0] as string)
    expect(calls).not.toContain('/findings')
    expect(calls).not.toContain('/crosswalk/suggestions?system_id=1')
    const titles = decks[0].slides.map(s => s.texts[0])
    expect(decks[0].slides[0].texts.join(' ')).toContain('Scope: PLT — Plant · NIST 800-53r5')
    const posture = decks[0].slides.find(s => s.texts.includes('Where We Stand'))!
    expect(posture.tables[0].slice(1).map(r => cell(r, 1))).toEqual(['NIST 800-53r5'])
    // Nothing to say → no slide: no Red Team run, no open findings, no crosswalk claims in scope.
    expect(titles).not.toContain('What the Gaps Cost')
    expect(titles).not.toContain('What Threatens It — Open Findings')
    expect(titles).not.toContain('What We Already Own — Crosswalk Leverage')
    expect(decks[0].slides.flatMap(s => s.texts).join(' ')).not.toContain('See the exposure slide')
    expect(titles).toContain('Program Health')
  })
})
