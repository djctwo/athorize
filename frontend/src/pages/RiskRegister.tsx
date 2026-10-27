import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Plus, Pencil, ShieldAlert } from 'lucide-react'
import { api } from '../lib/api'
import { SkeletonTable } from '../components/Skeleton'
import {
  RISK_CATEGORIES, RISK_CATEGORY_LABELS, RISK_STATUSES,
} from '../types'
import type { RiskCategory, RiskRegisterEntry, RiskStatus, System } from '../types'
import { RiskEntryPanel } from '../components/RiskEntryPanel'
import RiskMatrix from '../components/RiskMatrix'
import { useCan } from '../hooks/useRole'

const LEVEL_TONE: Record<string, string> = {
  LOW: 'bg-[var(--risk-low)]/15 text-[var(--risk-low)] border-[var(--risk-low)]/40',
  MODERATE: 'bg-[var(--risk-med)]/15 text-[var(--risk-med)] border-[var(--risk-med)]/40',
  HIGH: 'bg-[var(--risk-high)]/15 text-[var(--risk-high)] border-[var(--risk-high)]/40',
  VERY_HIGH: 'bg-[var(--risk-crit)]/20 text-[var(--risk-crit)] border-[var(--risk-crit)]/50',
}

const STATUS_TONE: Record<string, string> = {
  OPEN: 'text-[var(--risk-crit)]',
  MITIGATING: 'text-[var(--risk-med)]',
  ACCEPTED: 'text-[var(--risk-low)]',
  TRANSFERRED: 'text-[var(--risk-low)]',
  CLOSED: 'text-[var(--text-secondary)]',
}

function RiskLevelBadge({ level }: { level: string | null }) {
  if (!level) return <span className="text-[var(--text-secondary)]">—</span>
  const label = level === 'VERY_HIGH' ? 'Very High' : level.charAt(0) + level.slice(1).toLowerCase()
  return (
    <span className={`inline-block px-2 py-0.5 text-[11px] uppercase tracking-wider border ${LEVEL_TONE[level] ?? ''}`}>
      {label}
    </span>
  )
}

function Metric({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return (
    <div className="px-4 py-2 border-r border-[var(--border)] last:border-r-0">
      <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">{label}</div>
      <div className="text-xl font-semibold mt-0.5" style={{ color: tone ?? 'var(--text-primary)' }}>{value}</div>
    </div>
  )
}

export default function RiskRegister() {
  const [systemFilter, setSystemFilter] = useState<number | 'ALL'>('ALL')
  const [categoryFilter, setCategoryFilter] = useState<RiskCategory | 'ALL'>('ALL')
  const [statusFilter, setStatusFilter] = useState<RiskStatus | 'ALL'>('ALL')
  const [cellFilter, setCellFilter] = useState<{ likelihood: string; impact: string } | null>(null)
  const [panel, setPanel] = useState<{ open: boolean; mode: 'add' | 'edit'; record: RiskRegisterEntry | null }>({ open: false, mode: 'add', record: null })
  const canWrite = useCan('edit:risk')

  const { data: systems = [] } = useQuery({
    queryKey: ['systems'],
    queryFn: () => api.get<System[]>('/systems'),
  })

  const { data: risks = [], isLoading } = useQuery({
    queryKey: ['risks', systemFilter],
    queryFn: () => {
      const qs = systemFilter !== 'ALL' ? `?system_id=${systemFilter}` : ''
      return api.get<RiskRegisterEntry[]>(`/risks${qs}`)
    },
  })

  const filtered = useMemo(() => {
    return risks.filter(r => {
      if (categoryFilter !== 'ALL' && r.category !== categoryFilter) return false
      if (statusFilter !== 'ALL' && r.status !== statusFilter) return false
      if (cellFilter && (r.likelihood !== cellFilter.likelihood || r.impact !== cellFilter.impact)) return false
      return true
    })
  }, [risks, categoryFilter, statusFilter, cellFilter])

  const metrics = useMemo(() => {
    const open = risks.filter(r => r.status === 'OPEN' || r.status === 'MITIGATING').length
    const high = risks.filter(r => r.risk_level === 'HIGH' || r.risk_level === 'VERY_HIGH').length
    const accepted = risks.filter(r => r.status === 'ACCEPTED').length
    const today = new Date().toISOString().slice(0, 10)
    const overdue = risks.filter(r => r.review_date && r.review_date < today && r.status !== 'CLOSED').length
    return { open, high, accepted, overdue }
  }, [risks])

  const activeSystemId = typeof systemFilter === 'number' ? systemFilter : systems[0]?.id

  return (
    <div>
      <div className="flex items-start justify-between mb-4">
        <div>
          <h2 className="text-xl font-bold text-[var(--text-primary)]">Risk Register</h2>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5 max-w-2xl">
            Residual risks tracked with likelihood x impact scoring, treatment, and linked findings.
          </p>
        </div>
        {canWrite && (
          <button onClick={() => setPanel({ open: true, mode: 'add', record: null })}
            className="flex items-center gap-2 px-3 py-1.5 bg-[var(--accent)] hover:opacity-90 text-white text-sm">
            <Plus size={16} /> Add Risk
          </button>
        )}
      </div>

      <div className="flex border border-[var(--border)] bg-[var(--bg-secondary)] mb-4">
        <Metric label="Open" value={metrics.open} tone="var(--risk-crit)" />
        <Metric label="High / Very High" value={metrics.high} tone="var(--risk-crit)" />
        <Metric label="Accepted" value={metrics.accepted} tone="var(--risk-low)" />
        <Metric label="Review Overdue" value={metrics.overdue} tone={metrics.overdue > 0 ? 'var(--risk-med)' : undefined} />
        <Metric label="Total" value={risks.length} />
      </div>

      <div className="border border-[var(--border)] bg-[var(--bg-secondary)] p-4 mb-4 max-w-md">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-xs uppercase tracking-wider text-[var(--text-secondary)]">Risk Matrix</h3>
          {cellFilter && (
            <button onClick={() => setCellFilter(null)}
              className="text-[11px] text-[var(--accent)] hover:underline">Clear cell filter</button>
          )}
        </div>
        <RiskMatrix
          risks={risks}
          activeCell={cellFilter}
          onCellClick={(likelihood, impact) =>
            setCellFilter(prev =>
              prev && prev.likelihood === likelihood && prev.impact === impact
                ? null : { likelihood, impact })}
        />
      </div>

      <div className="flex items-end gap-3 mb-3">
        <div>
          <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">System</div>
          <select value={typeof systemFilter === 'number' ? systemFilter : 'ALL'} onChange={e => setSystemFilter(e.target.value === 'ALL' ? 'ALL' : Number(e.target.value))}
            className="bg-[var(--bg-secondary)] border border-[var(--border)] px-2 py-1 text-xs text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]">
            <option value="ALL">All systems</option>
            {systems.map(s => <option key={s.id} value={s.id}>{s.acronym} — {s.name}</option>)}
          </select>
        </div>
        <div>
          <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Category</div>
          <select value={categoryFilter} onChange={e => setCategoryFilter(e.target.value as RiskCategory | 'ALL')}
            className="bg-[var(--bg-secondary)] border border-[var(--border)] px-2 py-1 text-xs text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]">
            <option value="ALL">All</option>
            {RISK_CATEGORIES.map(c => <option key={c} value={c}>{RISK_CATEGORY_LABELS[c]}</option>)}
          </select>
        </div>
        <div>
          <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Status</div>
          <select value={statusFilter} onChange={e => setStatusFilter(e.target.value as RiskStatus | 'ALL')}
            className="bg-[var(--bg-secondary)] border border-[var(--border)] px-2 py-1 text-xs text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]">
            <option value="ALL">All</option>
            {RISK_STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        <div className="ml-auto text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">
          {filtered.length} of {risks.length} shown
        </div>
      </div>

      {isLoading ? <SkeletonTable rows={8} cols={6} /> : (
        <div className="border border-[var(--border)] bg-[var(--bg-secondary)]">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[var(--border)] text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">
                <th className="px-3 py-2 text-left">ID</th>
                <th className="px-3 py-2 text-left">Title</th>
                <th className="px-3 py-2 text-left">Finding</th>
                <th className="px-3 py-2 text-left">Category</th>
                <th className="px-3 py-2 text-left">Risk</th>
                <th className="px-3 py-2 text-left">Residual</th>
                <th className="px-3 py-2 text-left">Status</th>
                <th className="px-3 py-2 text-left">Treatment</th>
                <th className="px-3 py-2 text-left">Owner</th>
                <th className="px-3 py-2 text-left">Review</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={11} className="px-3 py-8 text-center text-xs text-[var(--text-secondary)]">
                    {risks.length === 0 ? 'No risks logged yet. Click Add Risk to create one.' : 'No risks match current filters.'}
                  </td>
                </tr>
              ) : (
                filtered.map(r => (
                  <tr key={r.id} onClick={() => setPanel({ open: true, mode: 'edit', record: r })}
                    className="border-b border-[var(--border)] last:border-b-0 hover:bg-[var(--bg-tertiary)] cursor-pointer">
                    <td className="px-3 py-2 text-xs text-[var(--text-secondary)] font-mono">R-{r.id.toString().padStart(3, '0')}</td>
                    <td className="px-3 py-2 min-w-[280px]">
                      <div className="text-sm text-[var(--text-primary)]">{r.title}</div>
                      {r.description && <div className="text-[11px] text-[var(--text-secondary)] mt-0.5 line-clamp-1">{r.description}</div>}
                    </td>
                    <td className="px-3 py-2 whitespace-nowrap">
                      {r.linked_finding_id != null ? (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-mono border border-[var(--accent)]/60 text-[var(--accent)] bg-[var(--accent)]/10">
                          <ShieldAlert size={11} /> F-{r.linked_finding_id.toString().padStart(3, '0')}
                        </span>
                      ) : <span className="text-xs text-[var(--text-secondary)]">—</span>}
                    </td>
                    <td className="px-3 py-2 text-xs text-[var(--text-secondary)]">
                      {r.category ? RISK_CATEGORY_LABELS[r.category as RiskCategory] ?? r.category : '—'}
                    </td>
                    <td className="px-3 py-2"><RiskLevelBadge level={r.risk_level} /></td>
                    <td className="px-3 py-2"><RiskLevelBadge level={r.residual_risk} /></td>
                    <td className={`px-3 py-2 text-xs ${STATUS_TONE[r.status] ?? ''}`}>{r.status}</td>
                    <td className="px-3 py-2 text-xs text-[var(--text-secondary)]">{r.treatment ?? '—'}</td>
                    <td className="px-3 py-2 text-xs text-[var(--text-secondary)] max-w-[140px] truncate">{r.owner_name ?? '—'}</td>
                    <td className="px-3 py-2 text-xs text-[var(--text-secondary)] font-mono">{r.review_date ?? '—'}</td>
                    <td className="px-3 py-2 w-10"><Pencil size={12} className="text-[var(--text-secondary)]" /></td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {activeSystemId && (
        <RiskEntryPanel open={panel.open} mode={panel.mode} record={panel.record} systemId={activeSystemId}
          systems={systems} onClose={() => setPanel(p => ({ ...p, open: false }))} />
      )}
    </div>
  )
}
