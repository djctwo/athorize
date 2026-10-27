import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { CheckCircle2, Circle, ChevronDown, ChevronRight, Rocket, X } from 'lucide-react'
import { api } from '../lib/api'

interface OnboardingStep { key: string; label: string; to: string; done: boolean }
interface Onboarding { steps: OnboardingStep[]; complete: boolean; done_count: number; total: number }

/**
 * First-run setup checklist on the Dashboard. Shows the steps a new org needs to
 * complete and deep-links each one. Auto-hides once every step is done (no
 * dismissal state to persist — which keeps us off localStorage). Pass
 * `forceShow` (e.g. from the "Setup guide" button) to surface it even on a
 * populated instance — useful for demos and for re-walking the steps.
 */
export default function OnboardingChecklist({ forceShow = false, onClose }: { forceShow?: boolean; onClose?: () => void }) {
  const [open, setOpen] = useState(true)
  const { data } = useQuery({
    queryKey: ['onboarding'],
    queryFn: () => api.get<Onboarding>('/dashboard/onboarding'),
  })

  if (!data) return null
  if (data.complete && !forceShow) return null
  const pct = Math.round((data.done_count / data.total) * 100)

  return (
    <div className="border border-[var(--accent)] bg-[var(--bg-secondary)] mb-6">
      <div className="w-full flex items-center gap-3 px-4 py-3">
        <button onClick={() => setOpen(o => !o)} className="flex items-center gap-3 flex-1 min-w-0 text-left">
          <Rocket size={16} className="text-[var(--accent)] flex-shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="text-sm font-semibold text-[var(--text-primary)]">
              {data.complete ? 'Setup guide — you\'re all set' : 'Finish setting up Athorize'}
            </div>
            <div className="text-xs text-[var(--text-secondary)]">
              {data.done_count} of {data.total} done{data.complete ? '' : ' — complete these to start getting value from the platform.'}
            </div>
          </div>
          <div className="hidden sm:block w-28 h-1.5 bg-[var(--bg-tertiary)] overflow-hidden flex-shrink-0">
            <div className="h-1.5 bg-[var(--accent)]" style={{ width: `${pct}%` }} />
          </div>
          {open
            ? <ChevronDown size={16} className="text-[var(--text-secondary)]" />
            : <ChevronRight size={16} className="text-[var(--text-secondary)]" />}
        </button>
        {onClose && (
          <button onClick={onClose} aria-label="Close setup guide" className="text-[var(--text-secondary)] hover:text-[var(--text-primary)] flex-shrink-0">
            <X size={15} />
          </button>
        )}
      </div>

      {open && (
        <ul className="px-4 pb-3 space-y-1.5">
          {data.steps.map((s, i) => (
            <li key={s.key}>
              {s.done ? (
                <span className="flex items-center gap-2 text-xs text-[var(--text-secondary)]">
                  <CheckCircle2 size={15} className="text-[var(--success)] flex-shrink-0" />
                  <span className="line-through">{s.label}</span>
                </span>
              ) : (
                <Link
                  to={s.to}
                  className="flex items-center gap-2 text-xs text-[var(--text-primary)] hover:text-[var(--accent)] transition-colors group"
                >
                  <Circle size={15} className="text-[var(--text-tertiary)] flex-shrink-0" />
                  <span className="font-medium">{i + 1}. {s.label}</span>
                  <span className="text-[var(--accent)] opacity-0 group-hover:opacity-100 transition-opacity">→</span>
                </Link>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
