interface Props {
  label: string
  value: React.ReactNode
}

export function DetailRow({ label, value }: Props) {
  return (
    <div className="grid grid-cols-[140px_1fr] gap-3 py-2 border-b border-[var(--border)]">
      <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] pt-0.5">
        {label}
      </div>
      <div className="text-sm text-[var(--text-primary)] whitespace-pre-wrap">
        {value ?? '—'}
      </div>
    </div>
  )
}
