import type { LucideIcon } from 'lucide-react'
import { Inbox } from 'lucide-react'

interface Props {
  icon?: LucideIcon
  title: string
  description?: string
  action?: { label: string; onClick: () => void }
}

export function EmptyState({ icon: Icon = Inbox, title, description, action }: Props) {
  return (
    <div className="border border-dashed border-[var(--border)] px-6 py-12 text-center">
      <Icon size={28} className="mx-auto mb-3 text-[var(--text-secondary)] opacity-50" />
      <div className="text-sm text-[var(--text-primary)]">{title}</div>
      {description && (
        <div className="text-xs text-[var(--text-secondary)] mt-1 max-w-md mx-auto">
          {description}
        </div>
      )}
      {action && (
        <button
          onClick={action.onClick}
          className="mt-4 px-4 py-1.5 text-sm border border-[var(--accent)] text-[var(--accent)] hover:bg-[var(--accent)]/10 transition-colors"
        >
          {action.label}
        </button>
      )}
    </div>
  )
}
