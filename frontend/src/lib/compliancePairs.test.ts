import { describe, expect, it } from 'vitest'
import { activePairsText, pairHasData, splitPairs } from './compliancePairs'

const P = (o: Partial<{ score_percentage: number; implemented: number; open_findings: number; assessed_controls: number; has_work: boolean }>) =>
  ({ score_percentage: 0, implemented: 0, open_findings: 0, assessed_controls: 0, has_work: false, ...o })

describe('system x framework pairs worth showing', () => {
  it('follows the server\'s has_work flag, the one definition (services/metrics.py)', () => {
    expect(pairHasData(P({}))).toBe(false)
    expect(pairHasData(P({ assessed_controls: 3, has_work: true }))).toBe(true) // assessed Not Implemented: 0% but real
    expect(pairHasData(P({ open_findings: 1, has_work: true }))).toBe(true)
    // The client no longer re-derives the rule from the counts.
    expect(pairHasData(P({ score_percentage: 12.5, implemented: 4, assessed_controls: 4, has_work: false }))).toBe(false)
    const { shown, hidden } = splitPairs([P({}), P({}), P({ implemented: 1, score_percentage: 2, has_work: true })])
    expect(shown).toHaveLength(1)
    expect(hidden).toBe(2)
  })

  it('says what an average is taken over', () => {
    expect(activePairsText(6)).toBe('across 6 active system × framework pairs')
    expect(activePairsText(1)).toBe('across 1 active system × framework pair')
  })
})
