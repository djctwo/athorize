import { beforeEach, describe, expect, it, vi } from 'vitest'

// R2USER-17: before any Red Team run the deck had 7 slides, its recommendations
// pointed at an "exposure slide" that was not there, and said "1 critical findings".

type FakeSlide = { texts: string[] }
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
        background: null as unknown,
        addText(t: unknown) {
          const flat = Array.isArray(t) ? t.map(x => (x as { text: string }).text).join(' ') : String(t)
          slide.texts.push(flat)
        },
        addShape() {},
        addTable() {},
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

beforeEach(() => {
  decks.length = 0
  for (const k of Object.keys(responses)) delete responses[k]
  Object.assign(responses, {
    '/systems': [{ id: 1, name: 'Portal', acronym: 'POR' }],
    '/frameworks': [{ id: 'cmmc-2.0', name: 'CMMC', short_name: 'CMMC 2.0', is_active: true }],
    '/dashboard/compliance': [],
    '/findings': [{ id: 7, title: 'Zerologon', severity: 'CRITICAL', status: 'OPEN', system_id: 1, framework_id: 'cmmc-2.0', control_id: '' }],
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
