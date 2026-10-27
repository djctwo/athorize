// Which system x framework pairs are worth a bar or a table row. With every
// framework activated, most pairs have never been touched: the demo Dashboard
// drew 76 bars, most of them 0%. A pair is shown when someone has assessed at
// least one of its controls or it carries an open finding; a 0% pair whose
// controls were assessed Not Implemented is real information and stays.
export interface PairLike {
  score_percentage: number
  implemented: number
  open_findings: number
  assessed_controls?: number
}

export function pairHasData(c: PairLike): boolean {
  if (c.open_findings > 0 || c.implemented > 0 || c.score_percentage > 0) return true
  return (c.assessed_controls ?? 0) > 0
}

export function splitPairs<T extends PairLike>(pairs: T[]): { shown: T[]; hidden: number } {
  const shown = pairs.filter(pairHasData)
  return { shown, hidden: pairs.length - shown.length }
}
