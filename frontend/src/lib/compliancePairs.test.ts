import { describe, expect, it } from 'vitest'
import { pairHasData, splitPairs } from './compliancePairs'

const P = (o: Partial<{ score_percentage: number; implemented: number; open_findings: number; assessed_controls: number }>) =>
  ({ score_percentage: 0, implemented: 0, open_findings: 0, assessed_controls: 0, ...o })

describe('system x framework pairs worth showing', () => {
  it('hides untouched pairs and keeps started, scored or finding-bearing ones', () => {
    expect(pairHasData(P({}))).toBe(false)
    expect(pairHasData(P({ assessed_controls: 3 }))).toBe(true) // assessed Not Implemented: 0% but real
    expect(pairHasData(P({ open_findings: 1 }))).toBe(true)
    expect(pairHasData(P({ score_percentage: 12.5, implemented: 4 }))).toBe(true)
    const { shown, hidden } = splitPairs([P({}), P({}), P({ implemented: 1, score_percentage: 2 })])
    expect(shown).toHaveLength(1)
    expect(hidden).toBe(2)
  })
})
