import { useControlPanelStore } from '../store/controlPanelStore'

interface Props {
  controlId: string | null | undefined
  frameworkId?: string
  className?: string
}

export function ControlLink({ controlId, frameworkId, className = '' }: Props) {
  const open = useControlPanelStore((s) => s.open)
  if (!controlId) return <span className="text-[var(--text-secondary)]">—</span>
  return (
    <span
      role="button"
      tabIndex={0}
      onClick={(e) => {
        e.stopPropagation()
        open(controlId, frameworkId)
      }}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          e.stopPropagation()
          open(controlId, frameworkId)
        }
      }}
      title={`Open ${controlId} reference panel`}
      className={`inline-flex items-center px-1.5 py-px text-[var(--accent)] font-mono text-xs cursor-pointer border border-[var(--accent)]/30 bg-[var(--accent)]/5 hover:bg-[var(--accent)]/15 hover:border-[var(--accent)]/60 transition-colors ${className}`}
    >
      {controlId}
    </span>
  )
}
