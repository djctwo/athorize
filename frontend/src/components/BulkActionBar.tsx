import { X } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

export type BulkActionTone = 'success' | 'info' | 'danger' | 'warning' | 'accent'

const TONE_CLASSES: Record<BulkActionTone, string> = {
  success: 'border-[var(--success)]/50 text-[var(--success)] hover:bg-[var(--success)]/10',
  info: 'border-[var(--info)]/50 text-[var(--info)] hover:bg-[var(--info)]/10',
  danger: 'border-[var(--danger)]/50 text-[var(--danger)] hover:bg-[var(--danger)]/10',
  warning: 'border-[var(--warning)]/50 text-[var(--warning)] hover:bg-[var(--warning)]/10',
  accent: 'border-[var(--accent)]/60 text-[var(--accent)] hover:bg-[var(--accent)]/10',
}

export interface BulkAction {
  key: string
  label: string
  icon: LucideIcon
  tone: BulkActionTone
  onClick: () => void
  disabled?: boolean
  pending?: boolean
  pendingLabel?: string
  spinIcon?: boolean
}

interface Props {
  count: number
  noun: { singular: string; plural: string }
  onClear: () => void
  actions: BulkAction[]
}

export function BulkActionBar({ count, noun, onClear, actions }: Props) {
  if (count === 0) return null
  const label = count === 1 ? noun.singular : noun.plural
  return (
    <div className="flex items-center justify-between gap-3 px-4 py-2 border-b border-[var(--border)] bg-[var(--accent)]/10">
      <div className="flex items-center gap-2 text-xs text-[var(--text-primary)]">
        <span className="font-medium">{count}</span>
        <span className="text-[var(--text-secondary)]">{label} selected</span>
        <button
          onClick={onClear}
          className="inline-flex items-center gap-1 text-[var(--text-secondary)] hover:text-[var(--text-primary)] ml-2"
        >
          <X size={12} /> Clear
        </button>
      </div>
      <div className="flex items-center gap-2">
        {actions.map((a) => {
          const Icon = a.icon
          const text = a.pending && a.pendingLabel ? a.pendingLabel : a.label
          return (
            <button
              key={a.key}
              onClick={a.onClick}
              disabled={a.disabled || a.pending}
              className={`px-3 py-1.5 text-xs uppercase tracking-wider border inline-flex items-center gap-1.5 disabled:opacity-40 disabled:cursor-not-allowed ${TONE_CLASSES[a.tone]}`}
            >
              <Icon size={12} className={a.pending && a.spinIcon ? 'animate-spin' : ''} /> {text}
            </button>
          )
        })}
      </div>
    </div>
  )
}
