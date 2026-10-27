import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { parseApiDate } from '../lib/datetime'
import type { ConMonEntry, Framework } from '../types'
import { useCan } from '../hooks/useRole'
import { Pill } from '../components/Pill'
import { KpiCard } from '../components/KpiCard'
import { EmptyState } from '../components/EmptyState'
import ConMonEntryPanel from '../components/ConMonEntryPanel'
import { Plus, AlertTriangle, ClipboardList, CalendarClock, Pencil, Check, X } from 'lucide-react'
import { toast } from '../store/toastStore'

interface Cadence {
  framework_id: string
  activity_type: string
  interval_days: number
  source: string
  last_done: string | null
  next_due: string | null
  status: 'OK' | 'DUE_SOON' | 'OVERDUE' | 'NEVER'
  days_overdue: number | null
}

const STATUS_TONE: Record<string, 'ok' | 'warn' | 'danger' | 'neutral'> = {
  OK: 'ok', DUE_SOON: 'warn', OVERDUE: 'danger', NEVER: 'neutral',
}

export default function ConMon() {
  const [entryOpen, setEntryOpen] = useState(false)
  const [showCadence, setShowCadence] = useState(false)
  const [editing, setEditing] = useState<string | null>(null)
  const [editVal, setEditVal] = useState(30)
  const canWrite = useCan('edit:conmon')
  const queryClient = useQueryClient()

  const { data: entries = [] } = useQuery({
    queryKey: ['conmon'],
    queryFn: () => api.get<ConMonEntry[]>('/conmon'),
  })

  const { data: cadences = [] } = useQuery({
    queryKey: ['conmon-cadences'],
    queryFn: () => api.get<Cadence[]>('/conmon/cadences'),
  })

  const { data: frameworks = [] } = useQuery({
    queryKey: ['frameworks'],
    queryFn: () => api.get<Framework[]>('/frameworks'),
  })
  const fwName = (id: string) => id ? (frameworks.find(f => f.id === id)?.short_name || id) : 'Org-wide'

  const saveCadence = useMutation({
    mutationFn: (c: { framework_id: string; activity_type: string; interval_days: number }) =>
      api.put('/conmon/cadences', { ...c, enabled: true }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['conmon-cadences'] })
      setEditing(null)
      toast.success('Cadence updated')
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const overdueCadences = useMemo(
    // Never-logged requirements are due one interval after the first system was
    // registered and only count as overdue after that (server-side, R2USER-18).
    () => cadences.filter(c => c.status === 'OVERDUE'),
    [cadences],
  )

  const stats = useMemo(() => {
    const now = Date.now()
    const thirtyDaysAgo = now - 30 * 86400000
    const last30 = entries.filter(e => (parseApiDate(e.entry_date)?.getTime() ?? 0) >= thirtyDaysAgo)
    const openFollowUps = entries.filter(e => e.follow_up_required && !e.actions_taken)
    return { total: entries.length, last30: last30.length, followUps: openFollowUps.length }
  }, [entries])

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-[var(--text-primary)]">Continuous Monitoring</h2>
        {canWrite && (
          <button
            onClick={() => setEntryOpen(true)}
            className="flex items-center gap-2 px-3 py-1.5 bg-[var(--accent)] hover:opacity-90 text-white text-sm"
          >
            <Plus size={16} /> Log Activity
          </button>
        )}
      </div>

      <div className="flex border border-[var(--border)] bg-[var(--bg-secondary)] mb-4">
        <KpiCard label="Total Entries" value={stats.total} />
        <KpiCard label="Last 30 Days" value={stats.last30} />
        <KpiCard label="Open Follow-ups" value={stats.followUps} tone={stats.followUps > 0 ? 'warning' : 'default'} />
      </div>

      {overdueCadences.length > 0 && (
        <div className="mb-4 p-3 border border-[var(--warning)]/30 bg-[var(--warning)]/5">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle size={14} className="text-[var(--warning)]" />
            <span className="text-xs font-semibold text-[var(--warning)] uppercase tracking-wider">
              Cadence Overdue ({overdueCadences.length})
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            {overdueCadences.map(c => (
              <Pill key={`${c.framework_id}:${c.activity_type}`} tone="warn">
                {fwName(c.framework_id)} · {c.activity_type.replace(/_/g, ' ')} — {c.last_done ? `${c.days_overdue}d overdue` : `never logged, ${c.days_overdue}d overdue`} (every {c.interval_days}d)
              </Pill>
            ))}
          </div>
        </div>
      )}

      <div className="mb-4 border border-[var(--border)] bg-[var(--bg-secondary)]">
        <button onClick={() => setShowCadence(v => !v)}
          className="w-full flex items-center justify-between px-3 py-2 text-left hover:bg-[var(--bg-tertiary)]">
          <span className="flex items-center gap-2 text-sm font-medium">
            <CalendarClock size={14} className="text-[var(--accent)]" /> Cadence Requirements ({cadences.length})
          </span>
          <span className="text-xs text-[var(--text-secondary)]">{showCadence ? 'Hide' : 'Show'}</span>
        </button>
        {showCadence && (
          <table className="w-full text-sm border-t border-[var(--border)]">
            <thead>
              <tr className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] border-b border-[var(--border)]">
                <th className="text-left px-3 py-2">Framework</th>
                <th className="text-left px-3 py-2">Activity</th>
                <th className="text-left px-3 py-2">Every</th>
                <th className="text-left px-3 py-2">Last done</th>
                <th className="text-left px-3 py-2">Next due</th>
                <th className="text-left px-3 py-2">Status</th>
                {canWrite && <th className="px-3 py-2"></th>}
              </tr>
            </thead>
            <tbody>
              {cadences.map(c => {
                const id = `${c.framework_id}:${c.activity_type}`
                return (
                  <tr key={id} className="border-b border-[var(--border)] last:border-b-0">
                    <td className="px-3 py-2 text-xs text-[var(--text-secondary)]">{fwName(c.framework_id)}</td>
                    <td className="px-3 py-2">{c.activity_type.replace(/_/g, ' ')}</td>
                    <td className="px-3 py-2">
                      {editing === id ? (
                        <input type="number" min={1} value={editVal}
                          onChange={e => setEditVal(Number(e.target.value))}
                          className="w-20 bg-[var(--bg-tertiary)] border border-[var(--border)] px-1.5 py-0.5 text-xs" />
                      ) : (
                        <span>{c.interval_days}d <span className="text-[10px] text-[var(--text-secondary)]">({c.source})</span></span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-xs text-[var(--text-secondary)]">{c.last_done ?? '—'}</td>
                    <td className="px-3 py-2 text-xs text-[var(--text-secondary)]">{c.next_due ?? '—'}</td>
                    <td className="px-3 py-2"><Pill tone={STATUS_TONE[c.status]}>{c.status.replace('_', ' ')}</Pill></td>
                    {canWrite && (
                      <td className="px-3 py-2 text-right">
                        {editing === id ? (
                          <span className="inline-flex gap-1">
                            <button onClick={() => saveCadence.mutate({ framework_id: c.framework_id, activity_type: c.activity_type, interval_days: editVal })}
                              className="text-[var(--success)] hover:opacity-80"><Check size={14} /></button>
                            <button onClick={() => setEditing(null)} className="text-[var(--text-secondary)] hover:opacity-80"><X size={14} /></button>
                          </span>
                        ) : (
                          <button onClick={() => { setEditing(id); setEditVal(c.interval_days) }}
                            className="text-[var(--text-secondary)] hover:text-[var(--accent)]"><Pencil size={13} /></button>
                        )}
                      </td>
                    )}
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      {entries.length === 0 ? (
        <EmptyState
          icon={ClipboardList}
          title="No ConMon entries"
          description="Log continuous monitoring activities to maintain compliance cadence."
        />
      ) : (
        <div className="bg-[var(--bg-secondary)] border border-[var(--border)]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--border)] text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">
                <th className="text-left px-3 py-2">Date</th>
                <th className="text-left px-3 py-2">Activity</th>
                <th className="text-left px-3 py-2">Description</th>
                <th className="text-left px-3 py-2">Performed By</th>
                <th className="text-left px-3 py-2">Follow-up</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.id} className="border-b border-[var(--border)] hover:bg-[var(--bg-tertiary)]">
                  <td className="px-3 py-2 text-[var(--text-secondary)] text-xs whitespace-nowrap">{e.entry_date}</td>
                  <td className="px-3 py-2">
                    <Pill tone="neutral">{e.activity_type.replace(/_/g, ' ')}</Pill>
                  </td>
                  <td className="px-3 py-2 text-[var(--text-primary)] max-w-[300px] truncate">{e.description}</td>
                  <td className="px-3 py-2 text-[var(--text-secondary)] text-xs">{e.performed_by || '—'}</td>
                  <td className="px-3 py-2">
                    {e.follow_up_required ? (
                      <Pill tone="warn">Yes{e.follow_up_date ? ` · ${e.follow_up_date}` : ''}</Pill>
                    ) : (
                      <span className="text-[var(--text-secondary)] text-xs">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ConMonEntryPanel open={entryOpen} onClose={() => setEntryOpen(false)} />
    </div>
  )
}
