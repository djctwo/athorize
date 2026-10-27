import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  ChevronsUpDown,
  ExternalLink,
  Radar,
  RefreshCw,
  Rss,
  ShieldAlert,
  Undo2,
  X,
} from 'lucide-react'
import { api } from '../lib/api'
import { formatDateTime } from '../lib/datetime'
import { toast } from '../store/toastStore'
import { ControlLink } from '../components/ControlLink'
import { SlideInPanel } from '../components/SlideInPanel'
import { SkeletonTable } from '../components/Skeleton'
import { EmptyState } from '../components/EmptyState'
import CustomFeedsPanel from '../components/CustomFeedsPanel'
import { useCan } from '../hooks/useRole'
import type { CustomFeed, IcsAdvisory, IcsAdvisoryMatch, System } from '../types'
import { plural } from '../lib/plural'

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const
const STATUSES = ['NEW', 'TRIAGED', 'DISMISSED', 'REMEDIATED'] as const
const CONFIDENCE_LABELS: Record<string, string> = {
  EXACT: 'Exact', FIRMWARE_RANGE: 'Firmware Range',
  VENDOR_PRODUCT: 'Vendor+Product', VENDOR_ONLY: 'Vendor Only',
}

const SEVERITY_TONE: Record<string, string> = {
  CRITICAL: 'bg-[var(--risk-crit)]/20 text-[var(--risk-crit)] border-[var(--risk-crit)]/50',
  HIGH: 'bg-[var(--risk-high)]/15 text-[var(--risk-high)] border-[var(--risk-high)]/30',
  MEDIUM: 'bg-[var(--risk-med)]/15 text-[var(--risk-med)] border-[var(--risk-med)]/40',
  LOW: 'bg-[var(--risk-low)]/15 text-[var(--risk-low)] border-[var(--risk-low)]/40',
}

const STATUS_TONE: Record<string, string> = {
  NEW: 'bg-[var(--accent)]/15 text-[var(--accent)] border-[var(--accent)]/40',
  TRIAGED: 'bg-[var(--risk-low)]/15 text-[var(--risk-low)] border-[var(--risk-low)]/40',
  REMEDIATED: 'bg-[var(--risk-low)]/20 text-[var(--risk-low)] border-[var(--risk-low)]/40',
  DISMISSED: 'bg-[var(--bg-tertiary)] text-[var(--text-secondary)] border-[var(--border)]',
}

const SAMPLE_TONE = 'bg-[var(--bg-tertiary)] text-[var(--text-secondary)] border-[var(--border)]'

const CONFIDENCE_TONE: Record<string, string> = {
  EXACT: 'bg-[var(--risk-crit)]/20 text-[var(--risk-crit)] border-[var(--risk-crit)]/50',
  FIRMWARE_RANGE: 'bg-[var(--risk-high)]/15 text-[var(--risk-high)] border-[var(--risk-high)]/30',
  VENDOR_PRODUCT: 'bg-[var(--risk-med)]/15 text-[var(--risk-med)] border-[var(--risk-med)]/40',
  VENDOR_ONLY: 'bg-[var(--bg-tertiary)] text-[var(--text-secondary)] border-[var(--border)]',
}

function Stat({ label, value, tone = 'default' }: { label: string; value: number | string; tone?: string }) {
  const cls = tone === 'danger' ? 'text-[var(--risk-crit)]'
    : tone === 'warning' ? 'text-[var(--risk-med)]'
    : tone === 'success' ? 'text-[var(--risk-low)]'
    : tone === 'accent' ? 'text-[var(--accent)]'
    : 'text-[var(--text-primary)]'
  return (
    <div className="bg-[var(--bg-secondary)] border border-[var(--border)] px-4 py-3">
      <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">{label}</div>
      <div className={`text-2xl mt-1 font-semibold ${cls}`}>{value}</div>
    </div>
  )
}

function Badge({ label, tone }: { label: string; tone: string }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 text-[11px] uppercase tracking-wider border ${tone}`}>
      {label}
    </span>
  )
}

type SortKey = 'advisory_id' | 'severity' | 'title' | 'affected_vendor' | 'match_count' | 'status'

function sortAdvisories(items: IcsAdvisory[], key: SortKey, dir: 'asc' | 'desc'): IcsAdvisory[] {
  const sevOrder: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }
  return [...items].sort((a, b) => {
    let cmp = 0
    if (key === 'severity') {
      cmp = (sevOrder[a.severity] ?? 0) - (sevOrder[b.severity] ?? 0)
    } else if (key === 'match_count') {
      cmp = a.match_count - b.match_count
    } else {
      const av = String(a[key] ?? '')
      const bv = String(b[key] ?? '')
      cmp = av.localeCompare(bv)
    }
    return dir === 'desc' ? -cmp : cmp
  })
}

function GridSortCol({ label, field, activeKey, dir, onSort }: {
  label: string; field: SortKey; activeKey: SortKey; dir: 'asc' | 'desc'; onSort: () => void
}) {
  const active = field === activeKey
  const Icon = active ? (dir === 'asc' ? ChevronUp : ChevronDown) : ChevronsUpDown
  return (
    <button onClick={onSort} className="flex items-center gap-1 hover:text-[var(--accent)] transition-colors cursor-pointer">
      {label}
      <Icon size={10} className={active ? 'text-[var(--accent)]' : 'opacity-40'} />
    </button>
  )
}

function FilterSelect({ label, value, onChange, options }: {
  label: string; value: string; onChange: (v: string) => void; options: { value: string; label: string }[]
}) {
  return (
    <label className="flex items-center gap-2 text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">
      {label}
      <select value={value} onChange={e => onChange(e.target.value)}
        className="bg-[var(--bg-primary)] border border-[var(--border)] text-[var(--text-primary)] text-sm px-2 py-1 focus:outline-none focus:border-[var(--accent)]">
        {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </label>
  )
}

export default function Advisories() {
  const queryClient = useQueryClient()
  const canManageFeeds = useCan('manage:settings')
  const canTriage = useCan('edit:conmon')
  const [severityFilter, setSeverityFilter] = useState('ALL')
  const [statusFilter, setStatusFilter] = useState('ALL')
  const [sourceFilter, setSourceFilter] = useState('ALL')
  const [detail, setDetail] = useState<IcsAdvisory | null>(null)
  const [showCustomFeeds, setShowCustomFeeds] = useState(false)
  const [sortKey, setSortKey] = useState<SortKey>('severity')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')

  const { data: advisories = [], isLoading } = useQuery({
    queryKey: ['advisories'],
    queryFn: () => api.get<IcsAdvisory[]>('/advisories'),
  })

  const { data: systems = [] } = useQuery({
    queryKey: ['systems'],
    queryFn: () => api.get<System[]>('/systems'),
  })

  const { data: feedStatus } = useQuery({
    queryKey: ['feed-status'],
    queryFn: () => api.get<{
      last_refreshed: string | null
      last_refreshed_by: string | null
      live: boolean
      auto_refresh_hours: number | null
      custom_feeds: CustomFeed[]
    }>('/advisories/feed-status'),
    refetchInterval: 60_000,
  })

  const refresh = useMutation({
    mutationFn: () => api.post<{ advisories_refreshed: number; advisories_new_or_updated: number; matches_new: number; matches_dropped: number; feed_errors: string[] }>('/advisories/refresh'),
    onSuccess: (summary) => {
      queryClient.invalidateQueries({ queryKey: ['advisories'] })
      queryClient.invalidateQueries({ queryKey: ['feed-status'] })
      toast.success(
        `Refreshed ${plural(summary.advisories_refreshed, 'advisory', 'advisories')} · ` +
        `${summary.advisories_new_or_updated} new/updated · ` +
        `+${plural(summary.matches_new, 'match', 'matches')} · -${summary.matches_dropped} stale`
      )
      if ((summary.feed_errors ?? []).length > 0) {
        toast.error(`Feed errors (refresh still completed): ${summary.feed_errors.join(' · ')}`)
      }
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const toggle = (key: SortKey) => {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortKey(key); setSortDir('desc') }
  }

  const sources = useMemo(() => [...new Set(advisories.map(a => a.source))].sort(), [advisories])

  const filtered = useMemo(() => {
    return advisories.filter(a => {
      if (severityFilter !== 'ALL' && a.severity !== severityFilter) return false
      if (statusFilter !== 'ALL' && a.status !== statusFilter) return false
      if (sourceFilter !== 'ALL' && a.source !== sourceFilter) return false
      return true
    })
  }, [advisories, severityFilter, statusFilter, sourceFilter])

  const sorted = useMemo(() => sortAdvisories(filtered, sortKey, sortDir), [filtered, sortKey, sortDir])

  const metrics = useMemo(() => {
    const affecting = advisories.filter(a => a.match_count > 0)
    return {
      total: advisories.length,
      affecting: affecting.length,
      critical: advisories.filter(a => a.severity === 'CRITICAL' && a.match_count > 0).length,
      newAffecting: affecting.filter(a => a.status === 'NEW').length,
      totalMatches: advisories.reduce((acc, a) => acc + a.match_count, 0),
    }
  }, [advisories])

  return (
    <div>
      <div className="flex items-start justify-between mb-4">
        <div>
          <h2 className="text-xl font-bold text-[var(--text-primary)] flex items-center gap-2">
            <Radar size={20} className="text-[var(--accent)]" />
            Threat Advisories
          </h2>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            CISA ICS, KEV, NVD, AA-series, and vendor PSIRT feeds — cross-referenced with your IT and OT asset inventory and mapped to controls.
          </p>
        </div>
        <div className="flex flex-col items-end gap-1">
          <div className="flex items-center gap-1.5">
            {canManageFeeds && (
              <button onClick={() => setShowCustomFeeds(true)}
                className="px-3 py-1.5 text-xs uppercase tracking-wider border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)] inline-flex items-center gap-1.5">
                <Rss size={12} />
                Custom feeds
              </button>
            )}
            {canTriage && (
              <button onClick={() => refresh.mutate()} disabled={refresh.isPending}
                className="px-3 py-1.5 text-xs uppercase tracking-wider border border-[var(--accent)] text-[var(--accent)] hover:bg-[var(--accent)]/10 inline-flex items-center gap-1.5 disabled:opacity-40">
                <RefreshCw size={12} className={refresh.isPending ? 'animate-spin' : ''} />
                {refresh.isPending ? 'Refreshing...' : 'Refresh feeds'}
              </button>
            )}
          </div>
          {feedStatus && (
            <span className="text-[10px] text-[var(--text-secondary)]">
              {feedStatus.last_refreshed
                ? `Last refreshed ${formatDateTime(feedStatus.last_refreshed)} by ${feedStatus.last_refreshed_by}`
                : 'Never refreshed'}
              {feedStatus.auto_refresh_hours
                ? ` · auto every ${feedStatus.auto_refresh_hours}h`
                : ' · manual only'}
              {feedStatus.live ? ' · LIVE feeds' : ' · demo fixtures (sample data, fictional vendors)'}
              {(feedStatus.custom_feeds ?? []).length > 0
                ? ` · ${feedStatus.custom_feeds.length} custom feed${feedStatus.custom_feeds.length === 1 ? '' : 's'}`
                : ''}
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-5 gap-3 mb-4">
        <Stat label="Advisories" value={metrics.total} />
        <Stat label="Affecting inventory" value={metrics.affecting} tone={metrics.affecting > 0 ? 'warning' : 'default'} />
        <Stat label="Critical affecting" value={metrics.critical} tone={metrics.critical > 0 ? 'danger' : 'success'} />
        <Stat label="New affecting" value={metrics.newAffecting} tone={metrics.newAffecting > 0 ? 'accent' : 'default'} />
        <Stat label="Total matches" value={metrics.totalMatches} />
      </div>

      <div className="bg-[var(--bg-secondary)] border border-[var(--border)] px-3 py-2 mb-4 flex items-center gap-3 flex-wrap">
        <FilterSelect label="Severity" value={severityFilter} onChange={setSeverityFilter}
          options={[{ value: 'ALL', label: 'All' }, ...SEVERITIES.map(s => ({ value: s, label: s }))]} />
        <FilterSelect label="Status" value={statusFilter} onChange={setStatusFilter}
          options={[{ value: 'ALL', label: 'All' }, ...STATUSES.map(s => ({ value: s, label: s }))]} />
        <FilterSelect label="Source" value={sourceFilter} onChange={setSourceFilter}
          options={[{ value: 'ALL', label: 'All' }, ...sources.map(s => ({ value: s, label: s === 'MOCK' ? 'MOCK (sample ICS feed)' : s }))]} />
        <div className="ml-auto text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">
          {filtered.length} of {advisories.length} shown
        </div>
      </div>

      <div className="bg-[var(--bg-secondary)] border border-[var(--border)]">
        <div className="grid grid-cols-[130px_90px_1fr_180px_90px_120px] px-3 py-2 text-[11px] uppercase tracking-wider text-[var(--text-secondary)] border-b border-[var(--border)]">
          <GridSortCol label="Advisory" field="advisory_id" activeKey={sortKey} dir={sortDir} onSort={() => toggle('advisory_id')} />
          <GridSortCol label="Severity" field="severity" activeKey={sortKey} dir={sortDir} onSort={() => toggle('severity')} />
          <GridSortCol label="Title" field="title" activeKey={sortKey} dir={sortDir} onSort={() => toggle('title')} />
          <GridSortCol label="Affected" field="affected_vendor" activeKey={sortKey} dir={sortDir} onSort={() => toggle('affected_vendor')} />
          <GridSortCol label="Matches" field="match_count" activeKey={sortKey} dir={sortDir} onSort={() => toggle('match_count')} />
          <GridSortCol label="Status" field="status" activeKey={sortKey} dir={sortDir} onSort={() => toggle('status')} />
        </div>
        {isLoading && <SkeletonTable rows={6} cols={6} />}
        {!isLoading && sorted.length === 0 && (
          <EmptyState icon={Radar} title="No advisories match the current filters."
            description="Adjust severity or status filters, or click Refresh Feed to load advisories." />
        )}
        {sorted.map(a => (
          <button key={a.id} type="button" onClick={() => setDetail(a)}
            className="w-full grid grid-cols-[130px_90px_1fr_180px_90px_120px] px-3 py-2 text-sm border-b border-[var(--border)] last:border-b-0 text-left hover:bg-[var(--bg-tertiary)]">
            <div className="font-mono text-[var(--text-primary)] truncate pr-2" title={a.is_sample ? 'Sample data: fictional vendor and product' : undefined}>
              {a.advisory_id}
              {a.is_sample && <span className="ml-1.5 font-sans text-[10px] uppercase tracking-wider text-[var(--text-secondary)]">Sample</span>}
            </div>
            <div><Badge label={a.severity} tone={SEVERITY_TONE[a.severity] ?? ''} /></div>
            <div className="text-[var(--text-primary)] truncate pr-2">{a.title}</div>
            <div className="text-[var(--text-secondary)] truncate pr-2">{a.affected_vendor} · {a.affected_product}</div>
            <div className="text-[var(--text-primary)]">
              {a.match_count > 0 ? (
                <span className="inline-flex items-center gap-1.5">
                  <ShieldAlert size={12} className="text-[var(--risk-crit)]" />
                  {a.match_count}
                  {a.system_acronyms.length > 0 && (
                    <span className="text-[11px] text-[var(--text-secondary)]">· {a.system_acronyms.join(', ')}</span>
                  )}
                </span>
              ) : <span className="text-[var(--text-secondary)]">—</span>}
            </div>
            <div><Badge label={a.status} tone={STATUS_TONE[a.status] ?? ''} /></div>
          </button>
        ))}
      </div>

      {detail && (
        <AdvisoryDetailPanel advisory={advisories.find(a => a.id === detail.id) ?? detail} onClose={() => setDetail(null)} systems={systems} />
      )}

      <CustomFeedsPanel open={showCustomFeeds} onClose={() => setShowCustomFeeds(false)} />
    </div>
  )
}

function AdvisoryDetailPanel({ advisory, onClose, systems }: {
  advisory: IcsAdvisory; onClose: () => void; systems: System[]
}) {
  const queryClient = useQueryClient()
  // Spawning creates a Finding: same permission as POST /api/findings.
  const canCreateFinding = useCan('edit:finding')
  const canTriage = useCan('edit:conmon')
  const [notes, setNotes] = useState(advisory.notes ?? '')
  const [targetSystem, setTargetSystem] = useState<number | ''>(systems[0]?.id ?? '')

  useEffect(() => {
    setNotes(advisory.notes ?? '')
    setTargetSystem(systems[0]?.id ?? '')
  }, [advisory.id, advisory.notes, systems])

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['advisories'] })
    queryClient.invalidateQueries({ queryKey: ['findings'] })
    queryClient.invalidateQueries({ queryKey: ['conmon'] })
    queryClient.invalidateQueries({ queryKey: ['audit'] })
  }

  const updateStatus = useMutation({
    mutationFn: (patch: { status?: string; notes?: string }) => api.patch(`/advisories/${advisory.id}`, patch),
    onSuccess: () => invalidate(),
  })

  const spawnFinding = useMutation({
    mutationFn: (systemId: number) => api.post<{ finding_id: number }>(`/advisories/${advisory.id}/spawn-finding`, { system_id: systemId }),
    onSuccess: (res) => { invalidate(); toast.success(`Finding ${res.finding_id} created.`) },
    onError: (e: Error) => toast.error(e.message),
  })

  const spawnConMon = useMutation({
    mutationFn: (systemId: number) => api.post<{ conmon_id: number }>(`/advisories/${advisory.id}/spawn-conmon`, { system_id: systemId }),
    onSuccess: (res) => { invalidate(); toast.success(`ConMon entry ${res.conmon_id} logged.`) },
    onError: (e: Error) => toast.error(e.message),
  })

  const dismissMatch = useMutation({
    mutationFn: (matchId: number) => api.post(`/advisories/matches/${matchId}/dismiss`),
    onSuccess: () => invalidate(),
  })

  const restoreMatch = useMutation({
    mutationFn: (matchId: number) => api.post(`/advisories/matches/${matchId}/restore`),
    onSuccess: () => invalidate(),
  })

  const defaultTarget = typeof targetSystem === 'number' ? targetSystem : null

  return (
    <SlideInPanel open onClose={onClose} width={640}
      eyebrow={<span className="inline-flex items-center gap-2">
        {advisory.advisory_id}
        <Badge label={advisory.severity} tone={SEVERITY_TONE[advisory.severity] ?? ''} />
        <Badge label={advisory.status} tone={STATUS_TONE[advisory.status] ?? ''} />
        {advisory.is_sample && <Badge label="Sample data" tone={SAMPLE_TONE} />}
        {advisory.cvss_score && <span className="text-[var(--text-secondary)]">CVSS {advisory.cvss_score}</span>}
      </span>}
      title={advisory.title}
      subtitle={<span>{advisory.affected_vendor} · {advisory.affected_product}{advisory.affected_firmware_range ? ` · ${advisory.affected_firmware_range}` : ''}</span>}
      headerAccessory={advisory.source_url ? (
        <a href={advisory.source_url} target="_blank" rel="noreferrer"
          className="inline-flex items-center gap-1 text-xs text-[var(--accent)] hover:underline">
          <ExternalLink size={12} /> Source advisory
        </a>
      ) : undefined}
      footer={canTriage ? <>
        <select value={typeof targetSystem === 'number' ? targetSystem : ''} onChange={e => setTargetSystem(e.target.value ? Number(e.target.value) : '')}
          className="bg-[var(--bg-primary)] border border-[var(--border)] text-[var(--text-primary)] text-sm px-2 py-1 focus:outline-none focus:border-[var(--accent)]">
          <option value="">Select system...</option>
          {systems.map(s => <option key={s.id} value={s.id}>{s.acronym} — {s.name}</option>)}
        </select>
        {canCreateFinding && (
        <button type="button" disabled={!defaultTarget || spawnFinding.isPending} onClick={() => defaultTarget && spawnFinding.mutate(defaultTarget)}
          className="px-3 py-1.5 text-xs uppercase tracking-wider border border-[var(--risk-crit)] text-[var(--risk-crit)] hover:bg-[var(--risk-crit)]/10 disabled:opacity-40">
          {spawnFinding.isPending ? 'Spawning...' : 'Spawn Finding'}
        </button>
        )}
        <button type="button" disabled={!defaultTarget || spawnConMon.isPending} onClick={() => defaultTarget && spawnConMon.mutate(defaultTarget)}
          className="px-3 py-1.5 text-xs uppercase tracking-wider border border-[var(--accent)] text-[var(--accent)] hover:bg-[var(--accent)]/10 disabled:opacity-40">
          {spawnConMon.isPending ? 'Logging...' : 'Log ConMon review'}
        </button>
        <div className="ml-auto flex gap-1.5">
          {advisory.status !== 'REMEDIATED' && (
            <button type="button" onClick={() => updateStatus.mutate({ status: 'REMEDIATED' })}
              className="px-3 py-1.5 text-xs uppercase tracking-wider border border-[var(--risk-low)] text-[var(--risk-low)] hover:bg-[var(--risk-low)]/10">
              Mark remediated
            </button>
          )}
          {advisory.status !== 'DISMISSED' && (
            <button type="button" onClick={() => updateStatus.mutate({ status: 'DISMISSED' })}
              className="px-3 py-1.5 text-xs uppercase tracking-wider border border-[var(--border)] text-[var(--text-secondary)] hover:bg-[var(--bg-tertiary)]">
              Dismiss
            </button>
          )}
        </div>
      </> : undefined}
    >
      <div className="space-y-5">
        {advisory.is_sample && (
          <div role="note" className="border border-[var(--border)] bg-[var(--bg-tertiary)] px-3 py-2 text-xs text-[var(--text-secondary)]">
            Sample data: a fictional vendor, product and vulnerability bundled for demos and offline installs.
            It is not a real advisory. Set THREAT_FEEDS=live (and ICS_FEED=live) for real feeds.
          </div>
        )}
        <Section title="Summary">
          <div className="text-sm text-[var(--text-primary)] whitespace-pre-wrap leading-relaxed">{advisory.summary}</div>
          {advisory.cve_ids && advisory.cve_ids.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-1.5">
              {advisory.cve_ids.map(cve => (
                <span key={cve} className="inline-flex items-center text-[11px] font-mono px-1.5 py-0.5 border border-[var(--border)] text-[var(--text-secondary)]">
                  {cve}
                </span>
              ))}
            </div>
          )}
        </Section>

        {advisory.recommended_mitigations && (
          <Section title="Recommended mitigations">
            <div className="text-sm text-[var(--text-primary)] whitespace-pre-wrap leading-relaxed">{advisory.recommended_mitigations}</div>
          </Section>
        )}

        {(advisory.related_controls ?? []).length > 0 && (
          <Section title="Mapped controls (SP 800-53 — crosswalk shows obligations in every active framework)">
            <div className="flex flex-wrap gap-1.5">
              {advisory.related_controls.map(c => (
                <ControlLink key={c} controlId={c} frameworkId="nist-800-53-r5" />
              ))}
            </div>
            <p className="mt-1.5 text-[11px] text-[var(--text-secondary)]">
              Inferred from the advisory content. Open a control on the Controls page to see its crosswalk into the other frameworks.
            </p>
          </Section>
        )}

        <Section title={`Matched assets (${advisory.matches.filter(m => !m.dismissed).length} active, ${advisory.matches.filter(m => m.dismissed).length} dismissed)`}>
          {advisory.matches.length === 0 ? (
            <div className="text-sm text-[var(--text-secondary)] italic">
              No matching assets in inventory. Refresh the feed after adding OT assets.
            </div>
          ) : (
            <div className="border border-[var(--border)]">
              <div className="grid grid-cols-[1fr_160px_110px_110px_70px] px-2 py-1.5 text-[11px] uppercase tracking-wider text-[var(--text-secondary)] border-b border-[var(--border)]">
                <div>Asset</div><div>Model / firmware</div><div>Zone</div><div>Confidence</div><div className="text-right">Action</div>
              </div>
              {advisory.matches.map(m => (
                <MatchRow key={m.id} match={m}
                  systemAcronym={systems.find(s => s.id === m.system_id)?.acronym ?? '—'}
                  onDismiss={canTriage ? () => dismissMatch.mutate(m.id) : undefined}
                  onRestore={canTriage ? () => restoreMatch.mutate(m.id) : undefined}
                  pending={dismissMatch.isPending || restoreMatch.isPending} />
              ))}
            </div>
          )}
        </Section>

        <Section title="Triage notes">
          <textarea value={notes} onChange={e => setNotes(e.target.value)} readOnly={!canTriage}
            onBlur={() => { if (canTriage && notes !== (advisory.notes ?? '')) updateStatus.mutate({ notes }) }}
            rows={3} placeholder="Why you triaged, dismissed, or accepted this advisory..."
            className="w-full bg-[var(--bg-primary)] border border-[var(--border)] text-[var(--text-primary)] text-sm px-2 py-1.5 focus:outline-none focus:border-[var(--accent)]" />
          <div className="mt-1 text-[11px] text-[var(--text-secondary)]">
            {advisory.triaged_by && advisory.triaged_at
              ? `Last triaged by ${advisory.triaged_by} · ${formatDateTime(advisory.triaged_at)}`
              : 'Not yet triaged'}
          </div>
        </Section>

        {advisory.published_date && (
          <div className="text-[11px] text-[var(--text-secondary)] uppercase tracking-wider">
            Published {advisory.published_date} · Source {advisory.source}
          </div>
        )}
      </div>
    </SlideInPanel>
  )
}

function MatchRow({ match, systemAcronym, onDismiss, onRestore, pending }: {
  match: IcsAdvisoryMatch; systemAcronym: string; onDismiss?: () => void; onRestore?: () => void; pending: boolean
}) {
  return (
    <div className={`grid grid-cols-[1fr_160px_110px_110px_70px] px-2 py-1.5 text-sm border-b border-[var(--border)] last:border-b-0 items-center ${match.dismissed ? 'opacity-50' : ''}`}>
      <div className="min-w-0">
        <div className="text-[var(--text-primary)] truncate">{match.asset_name}</div>
        <div className="text-[11px] text-[var(--text-secondary)]">{systemAcronym} · {match.asset_vendor}{match.asset_kind ? ` · ${match.asset_kind}` : ''}</div>
      </div>
      <div className="text-[var(--text-secondary)] text-xs truncate pr-2">
        {match.asset_model}{match.asset_firmware ? ` · ${match.asset_firmware}` : ''}
      </div>
      <div className="text-[var(--text-secondary)] text-xs">{match.asset_purdue_level ?? '—'}</div>
      <div><Badge label={CONFIDENCE_LABELS[match.confidence] ?? match.confidence} tone={CONFIDENCE_TONE[match.confidence] ?? ''} /></div>
      <div className="text-right">
        {match.dismissed ? (onRestore &&
          <button type="button" disabled={pending} onClick={onRestore} title="Restore"
            className="inline-flex items-center justify-center p-1 text-[var(--text-secondary)] hover:text-[var(--accent)]">
            <Undo2 size={13} />
          </button>
        ) : (onDismiss &&
          <button type="button" disabled={pending} onClick={onDismiss} title="Dismiss false positive"
            className="inline-flex items-center justify-center p-1 text-[var(--text-secondary)] hover:text-[var(--risk-crit)]">
            <X size={13} />
          </button>
        )}
      </div>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-2 inline-flex items-center gap-1.5">
        <AlertTriangle size={12} className="text-[var(--accent)]" /> {title}
      </div>
      {children}
    </div>
  )
}
