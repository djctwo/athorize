import type { RiskRegisterEntry } from '../types'

/**
 * 3x3 likelihood x impact risk heatmap. Mirrors the backend RISK_LEVEL_MATRIX
 * (routers/risks.py) so cell colors match the risk level the app assigns. Each
 * cell shows the count of active (non-closed) risks that fall in it.
 *
 * Presentational: pass the risks to visualize. Optionally interactive via
 * onCellClick (used on the Risk Register to filter the table).
 */

type Level = 'LOW' | 'MODERATE' | 'HIGH'
type RiskLevelName = 'LOW' | 'MODERATE' | 'HIGH' | 'VERY_HIGH'

// (likelihood, impact) -> risk level. Keep in lockstep with the backend matrix.
const MATRIX: Record<string, RiskLevelName> = {
  'LOW|LOW': 'LOW', 'LOW|MODERATE': 'LOW', 'MODERATE|LOW': 'LOW',
  'LOW|HIGH': 'MODERATE', 'HIGH|LOW': 'MODERATE', 'MODERATE|MODERATE': 'MODERATE',
  'MODERATE|HIGH': 'HIGH', 'HIGH|MODERATE': 'HIGH', 'HIGH|HIGH': 'VERY_HIGH',
}

const LEVEL_COLOR: Record<RiskLevelName, string> = {
  LOW: 'var(--risk-low)', MODERATE: 'var(--risk-med)',
  HIGH: 'var(--risk-high)', VERY_HIGH: 'var(--risk-crit)',
}
const LEVEL_LABEL: Record<RiskLevelName, string> = {
  LOW: 'Low', MODERATE: 'Moderate', HIGH: 'High', VERY_HIGH: 'Very High',
}

// Rows top->bottom = Impact High/Moderate/Low; cols left->right = Likelihood Low/Moderate/High.
const IMPACTS: Level[] = ['HIGH', 'MODERATE', 'LOW']
const LIKELIHOODS: Level[] = ['LOW', 'MODERATE', 'HIGH']
const CLOSED = new Set(['CLOSED'])

interface Props {
  risks: RiskRegisterEntry[]
  onCellClick?: (likelihood: string, impact: string) => void
  activeCell?: { likelihood: string; impact: string } | null
}

export default function RiskMatrix({ risks, onCellClick, activeCell }: Props) {
  const active = risks.filter(r => !CLOSED.has(r.status))
  const counts: Record<string, number> = {}
  let unscored = 0
  for (const r of active) {
    if (LIKELIHOODS.includes(r.likelihood as Level) && IMPACTS.includes(r.impact as Level)) {
      counts[`${r.likelihood}|${r.impact}`] = (counts[`${r.likelihood}|${r.impact}`] ?? 0) + 1
    } else {
      unscored += 1
    }
  }

  return (
    <div>
      <div className="flex">
        {/* Impact axis label */}
        <div className="flex items-center justify-center pr-1">
          <span className="text-[10px] uppercase tracking-wider text-[var(--text-secondary)]"
                style={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)' }}>
            Impact
          </span>
        </div>
        <div className="flex-1">
          <div className="grid grid-cols-[auto_repeat(3,1fr)] gap-1">
            {IMPACTS.map(impact => (
              <RowLabel key={`lbl-${impact}`} label={impact} counts={counts} impact={impact}
                        likelihoods={LIKELIHOODS} onCellClick={onCellClick} activeCell={activeCell} />
            ))}
            {/* bottom-left spacer + likelihood column labels */}
            <div />
            {LIKELIHOODS.map(l => (
              <div key={`col-${l}`} className="text-center text-[10px] text-[var(--text-secondary)] capitalize pt-0.5">
                {l.toLowerCase()}
              </div>
            ))}
          </div>
          <div className="text-center text-[10px] uppercase tracking-wider text-[var(--text-secondary)] mt-1">
            Likelihood
          </div>
        </div>
      </div>

      <div className="flex items-center justify-between mt-2 text-[10px] text-[var(--text-secondary)]">
        <div className="flex items-center gap-2">
          {(['LOW', 'MODERATE', 'HIGH', 'VERY_HIGH'] as RiskLevelName[]).map(lv => (
            <span key={lv} className="flex items-center gap-1">
              <span className="inline-block w-2.5 h-2.5 rounded-sm" style={{ background: LEVEL_COLOR[lv] }} />
              {LEVEL_LABEL[lv]}
            </span>
          ))}
        </div>
        {unscored > 0 && <span>{unscored} unscored</span>}
      </div>
    </div>
  )
}

function RowLabel({ label, impact, likelihoods, counts, onCellClick, activeCell }: {
  label: Level; impact: Level; likelihoods: Level[]
  counts: Record<string, number>
  onCellClick?: (likelihood: string, impact: string) => void
  activeCell?: { likelihood: string; impact: string } | null
}) {
  return (
    <>
      <div className="flex items-center justify-end pr-1 text-[10px] text-[var(--text-secondary)] capitalize">
        {label.toLowerCase()}
      </div>
      {likelihoods.map(likelihood => {
        const level = MATRIX[`${likelihood}|${impact}`]
        const count = counts[`${likelihood}|${impact}`] ?? 0
        const isActive = activeCell?.likelihood === likelihood && activeCell?.impact === impact
        const style = {
          background: LEVEL_COLOR[level],
          opacity: count > 0 ? 1 : 0.28,
        }
        const cls = `aspect-square flex items-center justify-center text-sm font-semibold text-white select-none ${
          onCellClick ? 'cursor-pointer' : ''
        } ${isActive ? 'ring-2 ring-[var(--text-primary)] ring-offset-1 ring-offset-[var(--bg-secondary)]' : ''}`
        const content = <span>{count > 0 ? count : ''}</span>
        return onCellClick ? (
          <button key={likelihood} type="button" style={style} className={cls}
                  title={`${LEVEL_LABEL[level]} — likelihood ${likelihood.toLowerCase()} × impact ${impact.toLowerCase()} (${count})`}
                  onClick={() => onCellClick(likelihood, impact)}>
            {content}
          </button>
        ) : (
          <div key={likelihood} style={style} className={cls}
               title={`${LEVEL_LABEL[level]} — likelihood ${likelihood.toLowerCase()} × impact ${impact.toLowerCase()} (${count})`}>
            {content}
          </div>
        )
      })}
    </>
  )
}
