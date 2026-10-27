import type { LucideIcon } from 'lucide-react'
import { NavLink } from 'react-router-dom'

type Tone = 'default' | 'accent' | 'success' | 'warning' | 'danger' | 'info'

const TONE_COLOR: Record<Tone, string> = {
  default: 'var(--text-primary)',
  accent: 'var(--accent)',
  success: 'var(--success)',
  warning: 'var(--warning)',
  danger: 'var(--danger)',
  info: 'var(--info)',
}

interface KpiCardProps {
  label: string
  value: string | number
  sub?: string
  tone?: Tone
  icon?: LucideIcon
  to?: string
  pulse?: boolean
}

export function KpiCard({
  label,
  value,
  sub,
  tone = 'default',
  icon: Icon,
  to,
  pulse,
}: KpiCardProps) {
  const color = TONE_COLOR[tone]

  const body = (
    <div className="relative flex-1 px-4 py-3 border-r border-[var(--border)] last:border-r-0 hover:bg-[var(--bg-tertiary)] transition-colors">
      {pulse && (
        <span
          className="absolute top-3 right-3 w-1.5 h-1.5 rounded-full"
          style={{
            background: color,
            boxShadow: `0 0 0 3px color-mix(in oklch, ${color} 22%, transparent)`,
          }}
        />
      )}
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-[0.06em] text-[var(--text-tertiary)] font-semibold">
        {Icon && <Icon size={11} />}
        {label}
      </div>
      <div
        className="text-[22px] font-bold mt-1 tabular-nums leading-tight"
        style={{ color }}
      >
        {value}
      </div>
      {sub && (
        <div className="text-[11px] text-[var(--text-secondary)] mt-0.5">
          {sub}
        </div>
      )}
    </div>
  )

  if (to) {
    return (
      <NavLink to={to} className="flex-1 flex">
        {body}
      </NavLink>
    )
  }

  return body
}
