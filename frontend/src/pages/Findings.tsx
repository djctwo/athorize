import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import type { Finding, System, Framework } from '../types'
import { useCan } from '../hooks/useRole'
import { useUserStore } from '../store/userStore'
import { useBulkSelect } from '../hooks/useBulkSelect'
import { BulkActionBar } from '../components/BulkActionBar'
import SavedViews from '../components/SavedViews'
import { toast } from '../store/toastStore'
import { SeverityBadge, AgingBadge, type SeverityLevel, type AgingBucket } from '../components/AgingBadge'
import { Pill } from '../components/Pill'
import { ControlLink } from '../components/ControlLink'
import { EmptyState } from '../components/EmptyState'
import { KpiCard } from '../components/KpiCard'
import FindingEntryPanel from '../components/FindingEntryPanel'
import FindingDetailPanel from '../components/FindingDetailPanel'
import { SiemImportPanel } from '../components/SiemImportPanel'
import { Plus, AlertTriangle, Upload, PlayCircle, CheckCircle2, UserCheck } from 'lucide-react'

interface BulkResult { updated: number; skipped: { id: number; reason: string }[] }

const STATUS_TONE: Record<string, 'danger' | 'warn' | 'ok' | 'neutral'> = {
  OPEN: 'danger',
  IN_PROGRESS: 'warn',
  CLOSED: 'ok',
  RISK_ACCEPTED: 'neutral',
  FALSE_POSITIVE: 'neutral',
  DELAYED: 'warn',
}

export default function Findings() {
  const [filterFramework, setFilterFramework] = useState('')
  const [filterSeverity, setFilterSeverity] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [filterSource, setFilterSource] = useState('')
  const [entryPanel, setEntryPanel] = useState<{ open: boolean; mode: 'add' | 'edit'; record: Finding | null }>({ open: false, mode: 'add', record: null })
  const [detail, setDetail] = useState<Finding | null>(null)
  const [siemOpen, setSiemOpen] = useState(false)
  const [searchParams] = useSearchParams()
  const [mineOnly, setMineOnly] = useState(searchParams.get('mine') === '1')
  const canWrite = useCan('edit:finding')
  const { user } = useUserStore()
  const queryClient = useQueryClient()

  const { data: findings = [] } = useQuery({
    queryKey: ['findings', filterFramework, filterSeverity, filterStatus, mineOnly, user?.id],
    queryFn: () => {
      const params = new URLSearchParams()
      if (filterFramework) params.set('framework_id', filterFramework)
      if (filterSeverity) params.set('severity', filterSeverity)
      if (filterStatus) params.set('status', filterStatus)
      if (mineOnly && user?.id) params.set('owner_id', String(user.id))
      return api.get<Finding[]>(`/findings?${params}`)
    },
  })

  // ?focus=<id> (from the ⌘K palette): open that finding's detail once loaded.
  const focusId = searchParams.get('focus')
  useEffect(() => {
    if (!focusId || findings.length === 0) return
    const target = findings.find(f => f.id === Number(focusId))
    if (target) setDetail(target)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusId, findings.length])

  const bulk = useBulkSelect<Finding>(`${filterFramework}|${filterSeverity}|${filterStatus}|${filterSource}|${mineOnly}`)
  const bulkUpdate = useMutation({
    mutationFn: (body: { status?: string; owner_id?: number; owner_name?: string }) =>
      api.post<BulkResult>('/findings/bulk', { ...body, ids: [...bulk.selectedIds] }),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['findings'] })
      bulk.clear()
      toast.success(`Updated ${res.updated} finding(s)${res.skipped?.length ? `, ${res.skipped.length} skipped` : ''}`)
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Bulk update failed'),
  })

  const { data: systems = [] } = useQuery({
    queryKey: ['systems'],
    queryFn: () => api.get<System[]>('/systems'),
  })

  const { data: frameworks = [] } = useQuery({
    queryKey: ['frameworks'],
    queryFn: () => api.get<Framework[]>('/frameworks'),
  })

  const activeFrameworks = frameworks.filter(f => f.is_active)
  // Compact label for the table column (full name is in the detail panel).
  const frameworkNames: Record<string, string> = Object.fromEntries(frameworks.map(f => [f.id, f.short_name || f.name]))

  // Source filter: every import format the server supports, plus any source
  // already present in the data (e.g. from an older release).
  const { data: siemFormats = [] } = useQuery({
    queryKey: ['siem-formats'],
    queryFn: () => api.get<{ key: string; source_type?: string; source_label?: string; label: string }[]>('/siem/formats'),
  })
  const sourceOptions = new Map<string, string>()
  for (const f of siemFormats) {
    if (f.source_type && !sourceOptions.has(f.source_type)) sourceOptions.set(f.source_type, f.source_label || f.label)
  }
  for (const f of findings) {
    const src = (f.extra_data as Record<string, unknown>)?.source_type
    if (typeof src === 'string' && src && !sourceOptions.has(src)) sourceOptions.set(src, src)
  }

  const filtered = filterSource
    ? findings.filter(f => {
        const src = (f.extra_data as Record<string, unknown>)?.source_type as string | undefined
        if (filterSource === 'manual') return !src
        return src === filterSource
      })
    : findings

  const open = filtered.filter(f => f.status === 'OPEN' || f.status === 'IN_PROGRESS')
  const overdue = filtered.filter(f => f.aging_bucket === 'OVERDUE')
  const critical = filtered.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH')
  const siemCount = findings.filter(f => !!(f.extra_data as Record<string, unknown>)?.source_type).length

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-[var(--text-primary)]">Findings</h2>
        {canWrite && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => setSiemOpen(true)}
              className="flex items-center gap-2 px-3 py-1.5 border border-[var(--accent)] text-[var(--accent)] hover:bg-[var(--accent)]/10 text-sm"
            >
              <Upload size={16} /> Import
            </button>
            <button
              onClick={() => setEntryPanel({ open: true, mode: 'add', record: null })}
              className="flex items-center gap-2 px-3 py-1.5 bg-[var(--accent)] hover:opacity-90 text-white text-sm"
            >
              <Plus size={16} /> New Finding
            </button>
          </div>
        )}
      </div>

      <div className="flex border border-[var(--border)] bg-[var(--bg-secondary)] mb-4">
        <KpiCard label="Total" value={filtered.length} />
        <KpiCard label="Open" value={open.length} tone={open.length > 0 ? 'warning' : 'default'} />
        <KpiCard label="Overdue" value={overdue.length} tone={overdue.length > 0 ? 'danger' : 'default'} />
        <KpiCard label="Critical/High" value={critical.length} tone={critical.length > 0 ? 'danger' : 'default'} />
        <KpiCard label="SIEM/Scanner" value={siemCount} />
      </div>

      <div className="flex gap-3 mb-4">
        <select className="text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1" value={filterFramework} onChange={(e) => setFilterFramework(e.target.value)}>
          <option value="">All Frameworks</option>
          {activeFrameworks.map(f => <option key={f.id} value={f.id}>{f.short_name}</option>)}
        </select>
        <select className="text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1" value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}>
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <select className="text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1" value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)}>
          <option value="">All Statuses</option>
          <option value="OPEN">Open</option>
          <option value="IN_PROGRESS">In Progress</option>
          <option value="CLOSED">Closed</option>
          <option value="RISK_ACCEPTED">Risk Accepted</option>
          <option value="DELAYED">Delayed</option>
          <option value="FALSE_POSITIVE">False Positive</option>
        </select>
        <select className="text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1" value={filterSource} onChange={(e) => setFilterSource(e.target.value)}>
          <option value="">All Sources</option>
          <option value="manual">Manual</option>
          {[...sourceOptions].map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
        <button
          onClick={() => setMineOnly(m => !m)}
          className={`text-sm px-3 py-1 border inline-flex items-center gap-1.5 ${mineOnly ? 'border-[var(--accent)] text-[var(--accent)] bg-[var(--accent)]/10' : 'border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'}`}
        >
          <UserCheck size={14} /> Assigned to me
        </button>
        <div className="ml-auto">
          <SavedViews
            page="findings"
            current={{ filterFramework, filterSeverity, filterStatus, filterSource, mineOnly }}
            onApply={(p) => {
              setFilterFramework(typeof p.filterFramework === 'string' ? p.filterFramework : '')
              setFilterSeverity(typeof p.filterSeverity === 'string' ? p.filterSeverity : '')
              setFilterStatus(typeof p.filterStatus === 'string' ? p.filterStatus : '')
              setFilterSource(typeof p.filterSource === 'string' ? p.filterSource : '')
              setMineOnly(!!p.mineOnly)
            }}
          />
        </div>
      </div>

      {filtered.length === 0 ? (
        <EmptyState
          icon={AlertTriangle}
          title="No findings"
          description="Findings track compliance gaps, vulnerabilities, and issues across your systems."
        />
      ) : (
        <div className="bg-[var(--bg-secondary)] border border-[var(--border)]">
          {canWrite && (
            <BulkActionBar
              count={bulk.selectedCount}
              noun={{ singular: 'finding', plural: 'findings' }}
              onClear={bulk.clear}
              actions={[
                { key: 'progress', label: 'Mark In Progress', icon: PlayCircle, tone: 'warning', pending: bulkUpdate.isPending, spinIcon: true, onClick: () => bulkUpdate.mutate({ status: 'IN_PROGRESS' }) },
                { key: 'close', label: 'Close', icon: CheckCircle2, tone: 'success', pending: bulkUpdate.isPending, spinIcon: true, onClick: () => bulkUpdate.mutate({ status: 'CLOSED' }) },
                { key: 'mine', label: 'Assign to me', icon: UserCheck, tone: 'accent', pending: bulkUpdate.isPending, spinIcon: true, onClick: () => bulkUpdate.mutate({ owner_id: user?.id, owner_name: user?.display_name || user?.username }) },
              ]}
            />
          )}
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--border)] text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">
                {canWrite && (
                  <th className="px-3 py-2 w-8">
                    <input
                      type="checkbox"
                      aria-label="Select all"
                      checked={bulk.allSelected(filtered.map(f => f.id))}
                      ref={el => { if (el) el.indeterminate = bulk.someSelected(filtered.map(f => f.id)) }}
                      onChange={e => bulk.toggleAll(filtered.map(f => f.id), e.target.checked)}
                    />
                  </th>
                )}
                <th className="text-left px-3 py-2">Title</th>
                <th className="text-left px-3 py-2">Framework</th>
                <th className="text-left px-3 py-2">Control</th>
                <th className="text-left px-3 py-2">Severity</th>
                <th className="text-left px-3 py-2">Status</th>
                <th className="text-left px-3 py-2">Source</th>
                <th className="text-left px-3 py-2">Aging</th>
                <th className="text-left px-3 py-2">Due</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((f) => (
                <tr
                  key={f.id}
                  onClick={() => setDetail(f)}
                  className={`border-b border-[var(--border)] hover:bg-[var(--bg-tertiary)] cursor-pointer ${bulk.isSelected(f.id) ? 'bg-[var(--accent)]/5' : ''}`}
                >
                  {canWrite && (
                    <td className="px-3 py-2" onClick={e => e.stopPropagation()}>
                      <input type="checkbox" aria-label={`Select ${f.title}`} checked={bulk.isSelected(f.id)} onChange={() => bulk.toggleOne(f.id)} />
                    </td>
                  )}
                  <td className="px-3 py-2 font-medium max-w-[280px] truncate text-[var(--text-primary)]">{f.title}</td>
                  <td className="px-3 py-2 text-[var(--text-secondary)] text-xs">{frameworkNames[f.framework_id] ?? f.framework_id}</td>
                  <td className="px-3 py-2">
                    <ControlLink controlId={f.control_id} frameworkId={f.framework_id} />
                  </td>
                  <td className="px-3 py-2">
                    <SeverityBadge severity={f.severity as SeverityLevel} />
                  </td>
                  <td className="px-3 py-2">
                    <Pill tone={STATUS_TONE[f.status] ?? 'neutral'}>{f.status.replace(/_/g, ' ')}</Pill>
                  </td>
                  <td className="px-3 py-2 text-xs text-[var(--text-secondary)]">
                    {((f.extra_data as Record<string, unknown>)?.source_type as string) || 'manual'}
                  </td>
                  <td className="px-3 py-2">
                    <AgingBadge bucket={(f.aging_bucket ?? 'ON_TRACK') as AgingBucket} />
                  </td>
                  <td className="px-3 py-2 text-[var(--text-secondary)] text-xs">{f.due_date || f.scheduled_completion || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <FindingEntryPanel
        open={entryPanel.open}
        mode={entryPanel.mode}
        record={entryPanel.record}
        systems={systems}
        frameworks={frameworks}
        onClose={() => setEntryPanel({ open: false, mode: 'add', record: null })}
      />

      <FindingDetailPanel
        finding={detail ? findings.find(f => f.id === detail.id) ?? detail : null}
        onClose={() => setDetail(null)}
        onEdit={(f) => {
          setDetail(null)
          setEntryPanel({ open: true, mode: 'edit', record: f })
        }}
      />

      <SiemImportPanel open={siemOpen} onClose={() => setSiemOpen(false)} />
    </div>
  )
}
