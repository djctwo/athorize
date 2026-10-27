import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Crosshair, Play, ChevronDown, ChevronRight,
  Link2, Clock, FileText, Plus, DollarSign,
  ArrowUpDown, Zap, AlertTriangle, Settings,
} from 'lucide-react'
import { api } from '../lib/api'
import { formatDate, formatDateTime } from '../lib/datetime'
import { useCan } from '../hooks/useRole'
import type { System, Framework } from '../types'
import { plural } from '../lib/plural'

interface CostBreakdownItem {
  factor: string
  detail: string
  source: string
}

interface RTFinding {
  id: string
  title: string
  description: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  category: string
  control_ids: string[]
  affected_entities: { type: string; id: number; name: string }[]
  remediation: string
  finding_language: {
    title: string
    description: string
    remediation_plan: string
    severity: string
    scheduled_completion_days: number
  }
  estimated_exposure_low: number
  estimated_exposure_high: number
  remediation_effort: 'LOW' | 'MEDIUM' | 'HIGH'
  effort_hours_low: number
  effort_hours_high: number
  priority_score: number
  cost_breakdown: CostBreakdownItem[]
}

interface AttackChain {
  id: string
  title: string
  severity: string
  description: string
  finding_ids: string[]
  impact: string
  // Combined estimate computed server-side with the report's probable-loss
  // model + revenue cap. Absent on reports created before it existed.
  estimated_exposure_low?: number
  estimated_exposure_high?: number
}

interface RTReport {
  id: number
  system_id: number
  framework_id: string
  run_by: string
  summary: string
  total_findings: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  total_exposure_low: number
  total_exposure_high: number
  top5_reduction_low: number
  top5_reduction_high: number
  quick_win_count: number
  has_org_context: number
  findings: RTFinding[]
  attack_chains: AttackChain[]
  created_at: string
}

interface RiskContext {
  industry?: string
  annual_revenue?: number
  largest_contract_value?: number
  record_count?: number
  employee_count?: number
}

interface IndustryOption {
  id: string
  label: string
  source: string
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: 'var(--risk-crit)',
  HIGH: 'var(--risk-high)',
  MEDIUM: 'var(--risk-med)',
  LOW: 'var(--risk-low)',
}

const EFFORT_COLORS: Record<string, string> = {
  LOW: 'var(--risk-low)',
  MEDIUM: 'var(--risk-med)',
  HIGH: 'var(--risk-high)',
}

type SortMode = 'severity' | 'exposure' | 'effort' | 'priority'

function fmt$(n: number): string {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`
  return `$${n.toLocaleString()}`
}

function SevBadge({ severity }: { severity: string }) {
  return (
    <span
      className="inline-block px-2 py-0.5 text-[11px] uppercase tracking-wider font-medium border rounded-sm"
      style={{
        color: SEV_COLORS[severity] || 'var(--text-secondary)',
        borderColor: `color-mix(in oklch, ${SEV_COLORS[severity] || '#888'} 40%, transparent)`,
        backgroundColor: `color-mix(in oklch, ${SEV_COLORS[severity] || '#888'} 10%, transparent)`,
      }}
    >
      {severity}
    </span>
  )
}

function EffortBadge({ effort }: { effort: string }) {
  return (
    <span
      className="inline-block px-2 py-0.5 text-[11px] uppercase tracking-wider font-medium border rounded-sm"
      style={{
        color: EFFORT_COLORS[effort] || 'var(--text-secondary)',
        borderColor: `color-mix(in oklch, ${EFFORT_COLORS[effort] || '#888'} 40%, transparent)`,
        backgroundColor: `color-mix(in oklch, ${EFFORT_COLORS[effort] || '#888'} 10%, transparent)`,
      }}
    >
      {effort} effort
    </span>
  )
}

function KpiBox({ label, value, color, sub }: { label: string; value: string | number; color?: string; sub?: string }) {
  return (
    <div className="flex-1 px-4 py-3 border-r border-border last:border-r-0">
      <div className="text-[10px] uppercase tracking-wider text-text-muted font-semibold">{label}</div>
      <div className="text-xl font-bold mt-1" style={{ color: color || 'var(--text-primary)' }}>
        {value}
      </div>
      {sub && <div className="text-[10px] text-text-muted mt-0.5">{sub}</div>}
    </div>
  )
}

interface Methodology {
  version: string
  last_reviewed: string
  breach_costs_source: string
  penalty_sources: string
  disclaimer: string
  aggregation_model?: string
  stale: boolean
}

function MethodologyNote() {
  const { data } = useQuery({
    queryKey: ['risk-context'],
    queryFn: () => api.get<{ methodology?: Methodology }>('/redteam/risk-context'),
    staleTime: 10 * 60 * 1000,
  })
  const m = data?.methodology
  if (!m) return null
  return (
    <div className="border border-border border-t-0 bg-bg-secondary px-4 py-2 text-[11px] text-text-muted leading-relaxed">
      <strong className="text-text-secondary">Estimates, not actuals.</strong>{' '}
      Breach costs: {m.breach_costs_source}. Penalties: {m.penalty_sources}. {m.aggregation_model ? `${m.aggregation_model} ` : ''}{m.disclaimer}{' '}
      <span className="italic">Benchmarks v{m.version}, reviewed {m.last_reviewed}.</span>
      {m.stale && (
        <span className="ml-1 text-[var(--warning)] font-medium">
          Benchmark data is over 18 months old — refresh against the latest published reports.
        </span>
      )}
    </div>
  )
}

function CostBreakdown({ items }: { items: CostBreakdownItem[] }) {
  return (
    <div className="space-y-1.5">
      {items.map((item, i) => (
        <div key={i} className="flex items-start gap-3 text-[12px]">
          <span className="text-text-muted w-32 shrink-0 font-medium">{item.factor}</span>
          <span className="text-text-secondary flex-1">{item.detail}</span>
          <span className="text-text-muted text-[11px] shrink-0 italic">{item.source}</span>
        </div>
      ))}
    </div>
  )
}

export function FindingCard({ finding, reportId, rank, total }: { finding: RTFinding; reportId: number; rank: number; total: number }) {
  const [expanded, setExpanded] = useState(false)
  const [showLang, setShowLang] = useState(false)
  const [showCost, setShowCost] = useState(false)
  const queryClient = useQueryClient()
  // "Create Finding" files a real Finding: same permission as POST /api/findings.
  const canCreateFinding = useCan('edit:finding')
  const isQuickWin = finding.remediation_effort === 'LOW' && finding.priority_score > 0

  const createFinding = useMutation({
    mutationFn: () => api.post(`/redteam/${reportId}/findings/${finding.id}/create-finding`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['findings'] }),
  })

  return (
    <div className="border border-border bg-bg-secondary">
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-bg-tertiary transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        {rank <= 5 && (
          <span className="flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider rounded-sm shrink-0"
            style={{ color: 'var(--success)', backgroundColor: 'color-mix(in srgb, var(--success) 10%, transparent)', border: '1px solid color-mix(in srgb, var(--success) 30%, transparent)' }}>
            <Zap size={9} /> #{rank}
          </span>
        )}
        {isQuickWin && rank > 5 && (
          <span className="px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider rounded-sm shrink-0"
            style={{ color: 'var(--success)', backgroundColor: 'color-mix(in srgb, var(--success) 8%, transparent)', border: '1px solid color-mix(in srgb, var(--success) 20%, transparent)' }}>
            quick win
          </span>
        )}
        <span className="text-[11px] font-mono text-text-muted w-14 shrink-0">{finding.id}</span>
        <SevBadge severity={finding.severity} />
        <EffortBadge effort={finding.remediation_effort} />
        <span className="text-sm font-medium text-text-primary flex-1 truncate">{finding.title}</span>
        <span className="text-[12px] font-mono text-text-secondary shrink-0 tabular-nums">
          {fmt$(finding.estimated_exposure_low)}–{fmt$(finding.estimated_exposure_high)}
        </span>
      </button>

      {expanded && (
        <div className="px-4 pb-4 border-t border-border space-y-4 pt-3">
          <div className="flex gap-6 text-sm">
            <div>
              <span className="text-[10px] uppercase tracking-wider text-text-muted font-semibold">Exposure</span>
              <div className="font-mono font-bold text-text-primary">{fmt$(finding.estimated_exposure_low)} – {fmt$(finding.estimated_exposure_high)}</div>
            </div>
            <div>
              <span className="text-[10px] uppercase tracking-wider text-text-muted font-semibold">Effort</span>
              <div className="text-text-secondary">{finding.effort_hours_low}–{finding.effort_hours_high} hours</div>
            </div>
            <div>
              <span className="text-[10px] uppercase tracking-wider text-text-muted font-semibold">Priority</span>
              {/* The raw score (exposure midpoint ÷ effort hours, e.g. 4,108,750) means nothing to a
                  reader; its rank in this report does. */}
              <div className="font-mono font-bold text-accent">#{rank} of {total}</div>
              <div className="text-[11px] text-text-muted">ranked by estimated exposure avoided per hour of effort</div>
            </div>
          </div>

          <div>
            <h4 className="text-[10px] uppercase tracking-wider text-text-muted font-semibold mb-1">Description</h4>
            <p className="text-sm text-text-secondary leading-relaxed">{finding.description}</p>
          </div>

          {finding.control_ids.length > 0 && (
            <div>
              <h4 className="text-[10px] uppercase tracking-wider text-text-muted font-semibold mb-1">Affected Controls</h4>
              <div className="flex flex-wrap gap-1.5">
                {finding.control_ids.map(cid => (
                  <span key={cid} className="px-2 py-0.5 text-[11px] font-mono bg-bg-tertiary border border-border text-accent">
                    {cid}
                  </span>
                ))}
              </div>
            </div>
          )}

          {finding.affected_entities.length > 0 && (
            <div>
              <h4 className="text-[10px] uppercase tracking-wider text-text-muted font-semibold mb-1">Affected Entities</h4>
              <div className="flex flex-wrap gap-1.5">
                {finding.affected_entities.map((e, i) => (
                  <span key={i} className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] bg-bg-tertiary text-text-secondary border border-border">
                    <Link2 size={10} />
                    {e.type}: {e.name}
                  </span>
                ))}
              </div>
            </div>
          )}

          <div>
            <h4 className="text-[10px] uppercase tracking-wider text-text-muted font-semibold mb-1">Remediation</h4>
            <p className="text-sm text-text-primary leading-relaxed bg-bg-tertiary px-3 py-2 border-l-2 border-accent">
              {finding.remediation}
            </p>
          </div>

          <div className="flex gap-4">
            <button
              className="text-[11px] text-accent hover:underline flex items-center gap-1"
              onClick={() => setShowCost(!showCost)}
            >
              <DollarSign size={12} />
              {showCost ? 'Hide' : 'Show'} Cost Breakdown
            </button>

            <button
              className="text-[11px] text-accent hover:underline flex items-center gap-1"
              onClick={() => setShowLang(!showLang)}
            >
              <FileText size={12} />
              {showLang ? 'Hide' : 'Show'} Finding Language
            </button>
          </div>

          {showCost && finding.cost_breakdown && (
            <div className="p-3 bg-bg-tertiary border border-border">
              <h4 className="text-[10px] uppercase tracking-wider text-text-muted font-semibold mb-2">How this estimate was calculated</h4>
              <CostBreakdown items={finding.cost_breakdown} />
            </div>
          )}

          {showLang && (
            <div className="p-3 bg-bg-tertiary border border-border space-y-2 text-sm">
              <div><span className="text-text-muted text-[10px] uppercase">Title:</span> <span className="text-text-primary">{finding.finding_language.title}</span></div>
              <div><span className="text-text-muted text-[10px] uppercase">Description:</span> <span className="text-text-secondary">{finding.finding_language.description}</span></div>
              <div><span className="text-text-muted text-[10px] uppercase">Remediation:</span> <span className="text-text-secondary">{finding.finding_language.remediation_plan}</span></div>
              <div className="flex gap-4">
                <span><span className="text-text-muted text-[10px] uppercase">Severity:</span> <SevBadge severity={finding.finding_language.severity} /></span>
                <span><span className="text-text-muted text-[10px] uppercase">Due:</span> <span className="text-text-primary">{plural(finding.finding_language.scheduled_completion_days, 'day')}</span></span>
              </div>
              {canCreateFinding && (
                <button
                  className="mt-2 flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-accent text-white hover:opacity-90 transition-opacity disabled:opacity-50"
                  onClick={() => createFinding.mutate()}
                  disabled={createFinding.isPending}
                >
                  <Plus size={12} />
                  {createFinding.isPending ? 'Creating...' : 'Create Finding'}
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function ChainCard({ chain, findings }: { chain: AttackChain; findings: RTFinding[] }) {
  const [expanded, setExpanded] = useState(false)
  const linked = findings.filter(f => chain.finding_ids.includes(f.id))
  const hasEstimate = chain.estimated_exposure_high != null

  return (
    <div className="border border-border bg-bg-secondary">
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-bg-tertiary transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        <span className="text-[11px] font-mono text-text-muted w-14 shrink-0">{chain.id}</span>
        <SevBadge severity={chain.severity} />
        <span className="text-sm font-medium text-text-primary flex-1">{chain.title}</span>
        {hasEstimate ? (
          <span className="text-[12px] font-mono text-text-secondary shrink-0" title="Estimate — probable-loss model, not a straight sum">
            est. {fmt$(chain.estimated_exposure_low ?? 0)}–{fmt$(chain.estimated_exposure_high ?? 0)} combined
          </span>
        ) : (
          <span className="text-[11px] text-text-muted shrink-0" title="This report predates combined chain estimates">
            re-run for combined estimate
          </span>
        )}
        <span className="text-[11px] text-text-muted">{plural(chain.finding_ids.length, 'finding')}</span>
      </button>

      {expanded && (
        <div className="px-4 pb-4 border-t border-border space-y-3 pt-3">
          <p className="text-sm text-text-secondary leading-relaxed">{chain.description}</p>
          <div>
            <h4 className="text-[10px] uppercase tracking-wider text-text-muted font-semibold mb-1">Impact</h4>
            <p className="text-sm leading-relaxed" style={{ color: SEV_COLORS.HIGH }}>{chain.impact}</p>
          </div>
          <div>
            <h4 className="text-[10px] uppercase tracking-wider text-text-muted font-semibold mb-1">Constituent Findings</h4>
            <div className="space-y-1">
              {linked.map(f => (
                <div key={f.id} className="flex items-center gap-2 text-sm">
                  <span className="font-mono text-[11px] text-text-muted">{f.id}</span>
                  <SevBadge severity={f.severity} />
                  <span className="text-text-secondary flex-1">{f.title}</span>
                  <span className="text-[11px] font-mono text-text-muted">{fmt$(f.estimated_exposure_low)}-{fmt$(f.estimated_exposure_high)}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function sortFindings(findings: RTFinding[], mode: SortMode): RTFinding[] {
  const sevRank: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }
  const sorted = [...findings]
  switch (mode) {
    case 'severity':
      return sorted.sort((a, b) => (sevRank[b.severity] || 0) - (sevRank[a.severity] || 0))
    case 'exposure':
      return sorted.sort((a, b) => b.estimated_exposure_high - a.estimated_exposure_high)
    case 'effort':
      return sorted.sort((a, b) => a.effort_hours_low - b.effort_hours_low)
    case 'priority':
      return sorted.sort((a, b) => b.priority_score - a.priority_score)
  }
}

function ReportView({ report }: { report: RTReport }) {
  const [tab, setTab] = useState<'findings' | 'chains' | 'start-here'>('findings')
  const [sortMode, setSortMode] = useState<SortMode>('priority')

  const sorted = sortFindings(report.findings, sortMode)
  const priorityRanked = sortFindings(report.findings, 'priority')
  const rankMap = new Map(priorityRanked.map((f, i) => [f.id, i + 1]))

  const quickWins = report.findings
    .filter(f => f.remediation_effort === 'LOW')
    .sort((a, b) => b.priority_score - a.priority_score)

  return (
    <div className="space-y-4">
      {!report.has_org_context && (
        <div className="flex items-center gap-2 px-4 py-2.5 border border-border bg-bg-secondary">
          <AlertTriangle size={14} style={{ color: SEV_COLORS.MEDIUM }} />
          <span className="text-sm text-text-secondary">
            Cost estimates use industry averages. Configure your organization's revenue, contract value, and record count in
            <strong className="text-accent"> Risk Context</strong> for more accurate estimates.
          </span>
        </div>
      )}

      <div className="flex items-center gap-0 border border-border bg-bg-secondary">
        <KpiBox label="Total Findings" value={report.total_findings} />
        <KpiBox
          label="Estimated Exposure"
          value={`${fmt$(report.total_exposure_low)}-${fmt$(report.total_exposure_high)}`}
          color={report.total_exposure_high > 0 ? SEV_COLORS.HIGH : undefined}
        />
        <KpiBox
          label="Fix Top 5, Save (est.)"
          value={`${fmt$(report.top5_reduction_low)}-${fmt$(report.top5_reduction_high)}`}
          color="var(--success)"
          sub={`${Math.round((report.top5_reduction_high / Math.max(report.total_exposure_high, 1)) * 100)}% of total exposure`}
        />
        <KpiBox label="Quick Wins" value={report.quick_win_count} color="var(--success)" sub="Low effort, high ROI" />
        <KpiBox label="Attack Chains" value={report.attack_chains.length} color={report.attack_chains.length > 0 ? SEV_COLORS.HIGH : undefined} />
      </div>
      <MethodologyNote />

      <div className="bg-bg-secondary border border-border px-4 py-3">
        <p className="text-sm text-text-secondary leading-relaxed">{report.summary}</p>
        <div className="flex gap-4 mt-2 text-[11px] text-text-muted">
          <span className="flex items-center gap-1"><Clock size={11} />{formatDateTime(report.created_at)}</span>
          <span>Run by: {report.run_by}</span>
          <span>Framework: <span className="text-accent">{report.framework_id}</span></span>
        </div>
      </div>

      <div className="flex items-center gap-0 border-b border-border">
        {(['start-here', 'findings', 'chains'] as const).map(t => (
          <button
            key={t}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
              tab === t
                ? 'border-accent text-accent'
                : 'border-transparent text-text-secondary hover:text-text-primary'
            }`}
            onClick={() => setTab(t)}
          >
            {t === 'start-here' && <span className="inline-flex items-center gap-1"><Zap size={12} />Start Here ({quickWins.length})</span>}
            {t === 'findings' && `All Findings (${report.total_findings})`}
            {t === 'chains' && `Attack Chains (${report.attack_chains.length})`}
          </button>
        ))}

        {tab === 'findings' && (
          <div className="ml-auto flex items-center gap-1.5 pr-2">
            <ArrowUpDown size={12} className="text-text-muted" />
            <select
              className="text-[11px] bg-bg-secondary border border-border px-2 py-1 text-text-secondary"
              value={sortMode}
              onChange={e => setSortMode(e.target.value as SortMode)}
            >
              <option value="priority">Priority (ROI)</option>
              <option value="exposure">Exposure (highest)</option>
              <option value="severity">Severity</option>
              <option value="effort">Effort (easiest)</option>
            </select>
          </div>
        )}
      </div>

      {tab === 'start-here' && (
        <div className="space-y-1">
          {quickWins.length === 0 ? (
            <p className="text-sm text-text-muted py-8 text-center">No quick wins identified. All findings require moderate to high effort.</p>
          ) : (
            <>
              <p className="text-[11px] text-text-muted px-1 pb-2">
                Low-effort findings sorted by return on investment. Fix these first.
              </p>
              {quickWins.map(f => <FindingCard key={f.id} finding={f} reportId={report.id} rank={rankMap.get(f.id) || 99} total={report.findings.length} />)}
            </>
          )}
        </div>
      )}

      {tab === 'findings' && (
        <div className="space-y-1">
          {sorted.map(f => <FindingCard key={f.id} finding={f} reportId={report.id} rank={rankMap.get(f.id) || 99} total={report.findings.length} />)}
        </div>
      )}

      {tab === 'chains' && (
        <div className="space-y-1">
          {report.attack_chains.length === 0 ? (
            <p className="text-sm text-text-muted py-8 text-center">No attack chains identified.</p>
          ) : (
            report.attack_chains.map(c => <ChainCard key={c.id} chain={c} findings={report.findings} />)
          )}
        </div>
      )}
    </div>
  )
}

function RiskContextPanel({
  onClose,
}: {
  onClose: () => void
}) {
  const queryClient = useQueryClient()
  const canEdit = useCan('manage:redteam')
  const { data } = useQuery({
    queryKey: ['risk-context'],
    queryFn: () => api.get<{ risk_context: RiskContext; industries: IndustryOption[] }>('/redteam/risk-context'),
  })

  const industries = data?.industries || []

  const [form, setForm] = useState<RiskContext>({
    industry: '',
    annual_revenue: undefined,
    largest_contract_value: undefined,
    record_count: undefined,
    employee_count: undefined,
  })

  // The query resolves after mount; populate the form when the saved
  // context arrives or a quick save would overwrite it with blanks.
  useEffect(() => {
    const ctx = data?.risk_context
    if (!ctx) return
    setForm({
      industry: ctx.industry || '',
      annual_revenue: ctx.annual_revenue || undefined,
      largest_contract_value: ctx.largest_contract_value || undefined,
      record_count: ctx.record_count || undefined,
      employee_count: ctx.employee_count || undefined,
    })
  }, [data?.risk_context])

  const save = useMutation({
    mutationFn: () => api.put('/redteam/risk-context', form),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['risk-context'] })
      onClose()
    },
  })

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div className="absolute inset-0 bg-black/40" />
      <div
        className="relative w-[480px] max-w-full bg-bg-primary border-l border-border h-full overflow-y-auto p-6 space-y-6"
        onClick={e => e.stopPropagation()}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold text-text-primary">Risk Context</h2>
          <button className="text-text-muted hover:text-text-primary text-sm" onClick={onClose}>Close</button>
        </div>

        <p className="text-sm text-text-secondary">
          These values calibrate cost estimates to your organization. Without them, estimates use global industry averages.
        </p>

        <div className="space-y-4">
          <div>
            <label className="block text-[11px] uppercase tracking-wider text-text-muted font-semibold mb-1">Industry</label>
            <select
              className="w-full text-sm bg-bg-secondary border border-border px-3 py-2 text-text-primary"
              value={form.industry || ''}
              onChange={e => setForm({ ...form, industry: e.target.value || undefined })}
            >
              <option value="">Select industry...</option>
              {industries.map(i => <option key={i.id} value={i.id}>{i.label}</option>)}
            </select>
          </div>

          <div>
            <label className="block text-[11px] uppercase tracking-wider text-text-muted font-semibold mb-1">Annual Revenue (USD)</label>
            <input
              type="number"
              className="w-full text-sm bg-bg-secondary border border-border px-3 py-2 text-text-primary"
              placeholder="e.g. 5000000"
              value={form.annual_revenue || ''}
              onChange={e => setForm({ ...form, annual_revenue: Number(e.target.value) || undefined })}
            />
            <span className="text-[10px] text-text-muted">Used for regulatory penalty calculations (GDPR, DORA)</span>
          </div>

          <div>
            <label className="block text-[11px] uppercase tracking-wider text-text-muted font-semibold mb-1">Largest Contract Value (USD)</label>
            <input
              type="number"
              className="w-full text-sm bg-bg-secondary border border-border px-3 py-2 text-text-primary"
              placeholder="e.g. 2000000"
              value={form.largest_contract_value || ''}
              onChange={e => setForm({ ...form, largest_contract_value: Number(e.target.value) || undefined })}
            />
            <span className="text-[10px] text-text-muted">Used for contract-loss frameworks (CMMC, FedRAMP)</span>
          </div>

          <div>
            <label className="block text-[11px] uppercase tracking-wider text-text-muted font-semibold mb-1">Records / Users at Risk</label>
            <input
              type="number"
              className="w-full text-sm bg-bg-secondary border border-border px-3 py-2 text-text-primary"
              placeholder="e.g. 50000"
              value={form.record_count || ''}
              onChange={e => setForm({ ...form, record_count: Number(e.target.value) || undefined })}
            />
            <span className="text-[10px] text-text-muted">Per-record breach cost from IBM/Ponemon by industry</span>
          </div>

          <div>
            <label className="block text-[11px] uppercase tracking-wider text-text-muted font-semibold mb-1">Employee Count</label>
            <input
              type="number"
              className="w-full text-sm bg-bg-secondary border border-border px-3 py-2 text-text-primary"
              placeholder="e.g. 500"
              value={form.employee_count || ''}
              onChange={e => setForm({ ...form, employee_count: Number(e.target.value) || undefined })}
            />
          </div>
        </div>

        {canEdit && (
          <button
            className="w-full flex items-center justify-center gap-2 px-4 py-2 text-sm font-medium bg-accent text-white hover:opacity-90 transition-opacity disabled:opacity-50"
            onClick={() => save.mutate()}
            disabled={save.isPending}
          >
            {save.isPending ? 'Saving...' : 'Save Risk Context'}
          </button>
        )}
      </div>
    </div>
  )
}

export default function RedTeam() {
  const queryClient = useQueryClient()
  const [selectedSystem, setSelectedSystem] = useState<number | null>(null)
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null)
  const [activeReport, setActiveReport] = useState<number | null>(null)
  const [showRiskContext, setShowRiskContext] = useState(false)
  const canRun = useCan('run:redteam')

  const systemsQ = useQuery({ queryKey: ['systems'], queryFn: () => api.get<System[]>('/systems') })
  const frameworksQ = useQuery({ queryKey: ['frameworks'], queryFn: () => api.get<Framework[]>('/frameworks') })

  const activeFrameworks = (frameworksQ.data || []).filter(f => f.is_active)
  const systems = systemsQ.data || []

  const reportsQ = useQuery({
    queryKey: ['redteam-reports', selectedSystem, selectedFramework],
    queryFn: () => {
      const params = new URLSearchParams()
      if (selectedSystem) params.set('system_id', String(selectedSystem))
      if (selectedFramework) params.set('framework_id', selectedFramework)
      const qs = params.toString()
      return api.get<RTReport[]>(`/redteam${qs ? `?${qs}` : ''}`)
    },
  })

  const runAnalysis = useMutation({
    mutationFn: () => {
      if (!selectedSystem || !selectedFramework) throw new Error('Select system and framework')
      return api.post<RTReport>(`/redteam/analyze/${selectedSystem}/${selectedFramework}`)
    },
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['redteam-reports'] })
      setActiveReport(data.id)
    },
  })

  const reports = reportsQ.data || []
  const currentReport = reports.find(r => r.id === activeReport) || reports[0]

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Crosshair size={18} className="text-accent" />
          <h1 className="text-lg font-bold text-text-primary">Compliance Red Team</h1>
        </div>
        <button
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-text-secondary hover:text-text-primary border border-border hover:border-accent transition-colors"
          onClick={() => setShowRiskContext(true)}
        >
          <Settings size={12} />
          Risk Context
        </button>
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <select
          className="text-sm bg-bg-secondary border border-border px-3 py-1.5 text-text-secondary"
          value={selectedSystem ?? ''}
          onChange={e => { setSelectedSystem(Number(e.target.value) || null); setActiveReport(null) }}
        >
          <option value="">Select system...</option>
          {systems.map(s => <option key={s.id} value={s.id}>{s.name} ({s.acronym})</option>)}
        </select>

        <select
          className="text-sm bg-bg-secondary border border-border px-3 py-1.5 text-text-secondary"
          value={selectedFramework ?? ''}
          onChange={e => { setSelectedFramework(e.target.value || null); setActiveReport(null) }}
        >
          <option value="">Select framework...</option>
          {activeFrameworks.map(f => <option key={f.id} value={f.id}>{f.short_name || f.name}</option>)}
        </select>

        {reports.length > 1 && (
          <select
            className="text-sm bg-bg-secondary border border-border px-2 py-1.5 text-text-secondary"
            value={activeReport ?? currentReport?.id ?? ''}
            onChange={e => setActiveReport(Number(e.target.value))}
          >
            {reports.map(r => (
              <option key={r.id} value={r.id}>
                {formatDate(r.created_at)} — {plural(r.total_findings, 'finding')} — est. {fmt$(r.total_exposure_high)} exposure
              </option>
            ))}
          </select>
        )}

        {canRun && (
          <button
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-accent text-white hover:opacity-90 transition-opacity disabled:opacity-50"
            onClick={() => runAnalysis.mutate()}
            disabled={runAnalysis.isPending || !selectedSystem || !selectedFramework}
          >
            <Play size={12} />
            {runAnalysis.isPending ? 'Analyzing...' : 'Run Analysis'}
          </button>
        )}
      </div>

      {(!selectedSystem || !selectedFramework) && (
        <div className="py-12 text-center text-text-muted">
          <Crosshair size={32} className="mx-auto mb-3 opacity-30" />
          <p className="text-sm">Select a system and framework to run compliance red team analysis.</p>
        </div>
      )}

      {selectedSystem && selectedFramework && !reportsQ.isLoading && !currentReport && (
        <div className="py-12 text-center text-text-muted">
          <Crosshair size={32} className="mx-auto mb-3 opacity-30" />
          <p className="text-sm mb-1">No reports yet.</p>
          <p className="text-[11px]">Click <strong>Run Analysis</strong> to scan compliance data for gaps and weaknesses.</p>
        </div>
      )}

      {runAnalysis.isError && (
        <div className="px-4 py-2 bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
          {runAnalysis.error.message}
        </div>
      )}

      {currentReport && <ReportView report={currentReport} />}
      {showRiskContext && <RiskContextPanel onClose={() => setShowRiskContext(false)} />}
    </div>
  )
}
