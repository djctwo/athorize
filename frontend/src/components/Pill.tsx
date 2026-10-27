export type PillTone = 'ok' | 'info' | 'warn' | 'danger' | 'neutral' | 'ot'

const TONE_CLASSES: Record<PillTone, string> = {
  ok: 'bg-[var(--success)]/15 text-[var(--success)] border-[var(--success)]/40',
  info: 'bg-[var(--info)]/15 text-[var(--info)] border-[var(--info)]/40',
  warn: 'bg-[var(--warning)]/15 text-[var(--warning)] border-[var(--warning)]/40',
  danger: 'bg-[var(--danger)]/15 text-[var(--danger)] border-[var(--danger)]/40',
  neutral: 'bg-[var(--bg-tertiary)] text-[var(--text-secondary)] border-[var(--border)]',
  ot: 'bg-[var(--ot-soft)] text-[var(--ot-accent)] border-[var(--ot-accent)]/30',
}

interface PillProps {
  tone?: PillTone
  children: React.ReactNode
  dot?: boolean
}

export function Pill({ tone = 'neutral', children, dot }: PillProps) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 text-[11px] uppercase tracking-wider border rounded-sm font-medium ${TONE_CLASSES[tone]}`}
    >
      {dot && (
        <span
          className="w-1.5 h-1.5 rounded-full shrink-0"
          style={{ background: 'currentColor' }}
        />
      )}
      {children}
    </span>
  )
}
