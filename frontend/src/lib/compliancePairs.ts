// Which system x framework pairs are worth a bar, a table row or a place in an
// average. With every framework activated, most pairs have never been touched:
// the demo Dashboard drew 76 bars, most of them 0%, and averaging them pinned
// "Avg compliance %" near 2%. A pair "has work" when someone has assessed at
// least one of its controls or it carries an open finding; a 0% pair whose
// controls were assessed Not Implemented is real information and stays.
// The rule lives in ONE place, the server (services/metrics.py pair_has_work):
// every pair from /dashboard/compliance carries it as `has_work`, and the trend
// and Portfolio averages are computed over the same pairs.
import { plural } from './plural'

export interface PairLike {
  has_work: boolean
}

export function pairHasData(c: PairLike): boolean {
  return c.has_work
}

export function splitPairs<T extends PairLike>(pairs: T[]): { shown: T[]; hidden: number } {
  const shown = pairs.filter(pairHasData)
  return { shown, hidden: pairs.length - shown.length }
}

/** What an average score is taken over: "across 6 active system × framework pairs". */
export function activePairsText(n: number): string {
  return `across ${plural(n, 'active system × framework pair')}`
}
