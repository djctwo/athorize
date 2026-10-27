import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ClipboardCheck, Download, Printer } from 'lucide-react'
import { api } from '../lib/api'
import { daysUntil } from '../lib/datetime'
import type { Framework, System } from '../types'
import { Pill } from '../components/Pill'
import { plural } from '../lib/plural'

interface FamilyRow {
  family: string
  family_name: string
  total: number
  ready: number
  readiness_pct: number
  implemented: number
  narrative_gaps: number
  evidence_gaps: number
  stale_evidence: number
  /** Controls in the family with an open finding (Open / In Progress / Delayed): never ready. */
  open_findings?: number
}

interface PunchItem {
  priority: number
  /** What to do: implement | remediate | evidence | refresh | narrative (absent on older servers). */
  action?: string
  system_acronym: string
  control_id: string
  control_title: string
  family: string
  status: string
  issues: string[]
  owner: string | null
}

interface TimelineItem {
  window: string
  focus: string
  items: number
  detail: string
}

interface PrepPackage {
  framework_id: string
  inspection_date?: string | null
  control_count: number
  assessed_items?: number
  not_applicable?: number
  readiness_score: number
  families: FamilyRow[]
  punch_list: PunchItem[]
  timeline: TimelineItem[]
}

const PRIORITY_LABEL: Record<number, string> = {
  1: 'Implement', 2: 'Evidence', 3: 'Refresh', 4: 'Narrative',
}
const ACTION_LABEL: Record<string, string> = {
  implement: 'Implement', remediate: 'Remediate', evidence: 'Evidence', refresh: 'Refresh', narrative: 'Narrative',
}
const PRIORITY_TONE: Record<number, 'danger' | 'warn' | 'info' | 'neutral'> = {
  1: 'danger', 2: 'warn', 3: 'warn', 4: 'info',
}
const actionLabel = (p: PunchItem) => (p.action && ACTION_LABEL[p.action]) || PRIORITY_LABEL[p.priority]

function scoreColor(pct: number): string {
  return pct >= 80 ? 'var(--success)' : pct >= 50 ? 'var(--warning)' : 'var(--danger)'
}

// The server words the countdown with ITS date; recount it in the viewer's own
// calendar (R2USER-6: an LA user on 21 Oct saw "85 days" to 15 Jan instead of 86).
function statusFocus(t: TimelineItem, inspectionDate: string | null | undefined): string {
  if (t.window !== 'status') return t.focus
  const n = daysUntil(inspectionDate)
  if (n === null) return t.focus
  if (n >= 0) return `${n} ${n === 1 ? 'day' : 'days'} to inspection`
  return `${-n} ${n === -1 ? 'day' : 'days'} past inspection date`
}

export default function InspectionPrep() {
  const [frameworkId, setFrameworkId] = useState('')
  const [systemId, setSystemId] = useState<number | ''>('')
  const [inspectionDate, setInspectionDate] = useState('')

  const { data: frameworks = [] } = useQuery({
    queryKey: ['frameworks'],
    queryFn: () => api.get<Framework[]>('/frameworks'),
  })
  const activeFrameworks = frameworks.filter(f => f.is_active)
  const { data: systems = [] } = useQuery({
    queryKey: ['systems'],
    queryFn: () => api.get<System[]>('/systems'),
  })

  const ready = frameworkId !== '' && systemId !== ''
  const qs = ready
    ? `?framework_id=${frameworkId}&system_ids=${systemId}${inspectionDate ? `&inspection_date=${inspectionDate}` : ''}`
    : ''

  const { data: pkg, isLoading } = useQuery({
    queryKey: ['inspection-prep', frameworkId, systemId, inspectionDate],
    queryFn: () => api.get<PrepPackage>(`/inspection/prep${qs}`),
    enabled: ready,
  })

  const fwName = (id: string) => frameworks.find(f => f.id === id)?.short_name || id

  return (
    <div className="print:p-0">
      <div className="flex items-start justify-between mb-4 print:hidden">
        <div>
          <h2 className="text-xl font-bold text-[var(--text-primary)] flex items-center gap-2">
            <ClipboardCheck size={20} className="text-[var(--accent)]" />
            Inspection Prep
          </h2>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5 max-w-2xl">
            Audit-readiness package generated from live data: per-control-family readiness, a prioritized punch list with owners, and a 90/60/30-day timeline to your inspection date.
          </p>
        </div>
        {pkg && (
          <div className="flex gap-2">
            <button onClick={() => window.print()}
              className="flex items-center gap-2 px-3 py-1.5 border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] text-sm">
              <Printer size={14} /> Print
            </button>
            <a href={`/api/inspection/prep/punch-list.csv${qs}`}
              className="flex items-center gap-2 px-3 py-1.5 bg-[var(--accent)] hover:opacity-90 text-white text-sm">
              <Download size={14} /> Punch list CSV
            </a>
          </div>
        )}
      </div>

      <div className="flex items-end gap-3 mb-4 print:hidden">
        <div>
          <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Framework</div>
          <select value={frameworkId} onChange={e => setFrameworkId(e.target.value)}
            className="text-sm bg-[var(--bg-secondary)] border border-[var(--border)] px-2 py-1.5 text-[var(--text-primary)]">
            <option value="">Select…</option>
            {activeFrameworks.map(f => <option key={f.id} value={f.id}>{f.short_name}</option>)}
          </select>
        </div>
        <div>
          <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">System</div>
          <select value={systemId} onChange={e => setSystemId(e.target.value === '' ? '' : Number(e.target.value))}
            className="text-sm bg-[var(--bg-secondary)] border border-[var(--border)] px-2 py-1.5 text-[var(--text-primary)]">
            <option value="">Select…</option>
            {systems.map(s => <option key={s.id} value={s.id}>{s.acronym} — {s.name}</option>)}
          </select>
        </div>
        <div>
          <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Inspection date</div>
          <input type="date" value={inspectionDate} onChange={e => setInspectionDate(e.target.value)}
            className="text-sm bg-[var(--bg-secondary)] border border-[var(--border)] px-2 py-1.5 text-[var(--text-primary)]" />
        </div>
      </div>

      {!ready && (
        <div className="text-center py-16 text-[var(--text-secondary)]">
          <ClipboardCheck size={32} className="mx-auto mb-2" />
          <p>Pick a framework and system to generate the readiness package.</p>
        </div>
      )}

      {ready && isLoading && <p className="text-sm text-[var(--text-secondary)]">Generating…</p>}

      {pkg && (
        <div className="space-y-6">
          {/* Header / score */}
          <div className="flex items-center gap-6 border border-[var(--border)] bg-[var(--bg-secondary)] p-4">
            <div className="text-center">
              <div className="text-4xl font-bold" style={{ color: scoreColor(pkg.readiness_score) }}>
                {pkg.readiness_score}%
              </div>
              <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">Readiness</div>
            </div>
            <div className="text-sm text-[var(--text-secondary)]">
              <div>
                <strong className="text-[var(--text-primary)]">{fwName(pkg.framework_id)}</strong> · {plural(pkg.control_count, 'control')}
                {(pkg.not_applicable ?? 0) > 0 && (
                  <> · {pkg.not_applicable} not applicable (excluded from readiness)</>
                )}
              </div>
              <div>{plural(pkg.punch_list.length, 'punch-list item')} · {plural(pkg.families.length, 'control family', 'control families')}</div>
              <div className="text-xs mt-1">
                A control is ready when it is Implemented or Inherited, has a real narrative, has evidence still fresh on the inspection date, and has no open finding (Open, In Progress or Delayed) against it.
              </div>
            </div>
          </div>

          {/* Timeline */}
          {pkg.timeline.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-2">Way Forward</h3>
              <div className="grid grid-cols-4 gap-3">
                {pkg.timeline.map(t => (
                  <div key={t.window} className="border border-[var(--border)] bg-[var(--bg-secondary)] p-3">
                    <div className="text-[11px] uppercase tracking-wider text-[var(--accent)]">{t.window}</div>
                    <div className="text-sm font-medium mt-1">{statusFocus(t, pkg.inspection_date)}</div>
                    <div className="text-xs text-[var(--text-secondary)] mt-1">{plural(t.items, 'item')}</div>
                    <div className="text-[11px] text-[var(--text-secondary)] mt-1">{t.detail}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Family readiness */}
          <div>
            <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-2">Readiness by Control Family</h3>
            <div className="border border-[var(--border)] bg-[var(--bg-secondary)]">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] border-b border-[var(--border)]">
                    <th className="text-left px-3 py-2">Family</th>
                    <th className="text-left px-3 py-2">Ready</th>
                    <th className="text-left px-3 py-2">Readiness</th>
                    <th className="text-left px-3 py-2">Narrative gaps</th>
                    <th className="text-left px-3 py-2">Evidence gaps</th>
                    <th className="text-left px-3 py-2">Stale evidence</th>
                    <th className="text-left px-3 py-2">Open findings</th>
                  </tr>
                </thead>
                <tbody>
                  {pkg.families.map(f => (
                    <tr key={f.family} className="border-b border-[var(--border)] last:border-b-0">
                      <td className="px-3 py-2">{f.family} <span className="text-[var(--text-secondary)] text-xs">{f.family_name}</span></td>
                      <td className="px-3 py-2 text-xs">{f.ready}/{f.total}</td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-2">
                          <div className="w-24 h-1.5 bg-[var(--bg-tertiary)]">
                            <div className="h-full" style={{ width: `${f.readiness_pct}%`, backgroundColor: scoreColor(f.readiness_pct) }} />
                          </div>
                          <span className="text-xs" style={{ color: scoreColor(f.readiness_pct) }}>{f.readiness_pct}%</span>
                        </div>
                      </td>
                      <td className="px-3 py-2 text-xs">{f.narrative_gaps || '—'}</td>
                      <td className="px-3 py-2 text-xs">{f.evidence_gaps || '—'}</td>
                      <td className="px-3 py-2 text-xs">{f.stale_evidence || '—'}</td>
                      <td className="px-3 py-2 text-xs">{f.open_findings
                        ? <span className="text-[var(--danger)]">{f.open_findings}</span>
                        : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Punch list */}
          <div>
            <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-2">Punch List ({pkg.punch_list.length})</h3>
            {pkg.punch_list.length === 0 ? (
              <div className="text-sm text-[var(--success)] border border-[var(--success)]/30 bg-[var(--success)]/5 p-3">
                No gaps — every control is implemented with a narrative and fresh evidence, and none has an open finding. Inspection-ready.
              </div>
            ) : (
              <div className="border border-[var(--border)] bg-[var(--bg-secondary)]">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] border-b border-[var(--border)]">
                      <th className="text-left px-3 py-2">Action</th>
                      <th className="text-left px-3 py-2">Control</th>
                      <th className="text-left px-3 py-2">System</th>
                      <th className="text-left px-3 py-2">Issues</th>
                      <th className="text-left px-3 py-2">Owner</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pkg.punch_list.map((p, i) => (
                      <tr key={i} className="border-b border-[var(--border)] last:border-b-0">
                        <td className="px-3 py-2"><Pill tone={PRIORITY_TONE[p.priority]}>{actionLabel(p)}</Pill></td>
                        <td className="px-3 py-2"><span className="font-mono text-[var(--accent)]">{p.control_id}</span> <span className="text-[var(--text-secondary)] text-xs">{p.control_title}</span></td>
                        <td className="px-3 py-2 text-xs">{p.system_acronym}</td>
                        <td className="px-3 py-2 text-xs text-[var(--text-secondary)]">{p.issues.join(' · ')}</td>
                        <td className="px-3 py-2 text-xs">{p.owner ?? <span className="text-[var(--danger)]">unassigned</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
