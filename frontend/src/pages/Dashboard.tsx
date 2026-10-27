import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useFrameworkShortNames } from '../hooks/useFrameworkNames'
import { api } from '../lib/api'
import { formatDateTime } from '../lib/datetime'
import OnboardingChecklist from '../components/OnboardingChecklist'
import MyWorkCard from '../components/MyWorkCard'
import type {
  DashboardSnapshot, FindingAging, EvidenceFreshness, ActivityEntry, ComplianceScore, System,
} from '../types'
import { KpiCard } from '../components/KpiCard'
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, LabelList,
  ResponsiveContainer, Legend, LineChart, Line,
} from 'recharts'
import {
  AlertTriangle, Server, Shield, FileCheck, Clock, Flame, ShieldAlert, Activity, Rocket,
} from 'lucide-react'

const SEV_COLORS: Record<string, string> = {
  CRITICAL: 'var(--risk-crit)',
  HIGH: 'var(--risk-high)',
  MEDIUM: 'var(--risk-med)',
  LOW: 'var(--risk-low)',
}

const EVIDENCE_COLORS = ['var(--risk-low)', 'var(--risk-med)', 'var(--risk-crit)']
const AGING_COLORS = ['var(--risk-crit)', 'var(--risk-high)', 'var(--risk-med)', 'var(--risk-low)']

export default function Dashboard() {
  const [systemId, setSystemId] = useState<number | ''>('')
  const [showGuide, setShowGuide] = useState(false)
  const qs = systemId ? `?system_id=${systemId}` : ''
  const key = systemId || 'all'

  const fwShort = useFrameworkShortNames()
  const { data: systems = [] } = useQuery({
    queryKey: ['systems'],
    queryFn: () => api.get<System[]>('/systems'),
  })

  const { data: snapshot } = useQuery({
    queryKey: ['dashboard-snapshot', key],
    queryFn: () => api.get<DashboardSnapshot>(`/dashboard/snapshot${qs}`),
  })

  const { data: aging } = useQuery({
    queryKey: ['dashboard-aging', key],
    queryFn: () => api.get<FindingAging>(`/dashboard/finding-aging${qs}`),
  })

  const { data: sevBreakdown } = useQuery({
    queryKey: ['dashboard-severity', key],
    queryFn: () => api.get<Record<string, number>>(`/dashboard/finding-severity${qs}`),
  })

  const { data: freshness } = useQuery({
    queryKey: ['dashboard-freshness', key],
    queryFn: () => api.get<EvidenceFreshness>(`/dashboard/evidence-freshness${qs}`),
  })

  const { data: activity = [] } = useQuery({
    queryKey: ['dashboard-activity', key],
    queryFn: () => api.get<ActivityEntry[]>(`/dashboard/activity${qs}`),
  })

  const { data: compliance = [] } = useQuery({
    queryKey: ['dashboard-compliance', key],
    queryFn: () => api.get<ComplianceScore[]>(`/dashboard/compliance${qs}`),
  })

  const { data: history = [] } = useQuery({
    queryKey: ['dashboard-history', key],
    queryFn: () => api.get<{ date: string; avg_score: number; open_findings: number; overdue_findings: number }[]>(`/dashboard/history${qs}`),
  })

  const cards: { label: string; value: number; icon: typeof Server; tone: 'default' | 'warning' | 'danger' }[] = [
    { label: 'Systems', value: snapshot?.total_systems ?? 0, icon: Server, tone: 'default' },
    { label: 'Open Findings', value: snapshot?.open_findings ?? 0, icon: AlertTriangle, tone: (snapshot?.open_findings ?? 0) > 0 ? 'warning' : 'default' },
    { label: 'Critical', value: snapshot?.critical_findings ?? 0, icon: Flame, tone: (snapshot?.critical_findings ?? 0) > 0 ? 'danger' : 'default' },
    { label: 'Overdue', value: snapshot?.overdue_findings ?? 0, icon: Clock, tone: (snapshot?.overdue_findings ?? 0) > 0 ? 'danger' : 'default' },
    { label: 'Frameworks', value: snapshot?.active_frameworks ?? 0, icon: Shield, tone: 'default' },
    { label: 'Evidence', value: snapshot?.total_evidence ?? 0, icon: FileCheck, tone: 'default' },
    { label: 'Expiring', value: snapshot?.expiring_evidence ?? 0, icon: Clock, tone: (snapshot?.expiring_evidence ?? 0) > 0 ? 'warning' : 'default' },
    { label: 'Open Risks', value: snapshot?.open_risks ?? 0, icon: ShieldAlert, tone: (snapshot?.open_risks ?? 0) > 0 ? 'warning' : 'default' },
    { label: 'Cadence Overdue', value: snapshot?.cadence_overdue ?? 0, icon: Clock, tone: (snapshot?.cadence_overdue ?? 0) > 0 ? 'danger' : 'default' },
  ]

  const sevData = sevBreakdown
    ? Object.entries(sevBreakdown).map(([name, value]) => ({ name, value })).filter(d => d.value > 0)
    : []

  const agingData = aging
    ? [
        { name: 'Overdue', value: aging.overdue },
        { name: 'Due 7d', value: aging.due_7 },
        { name: 'Due 30d', value: aging.due_30 },
        { name: 'On Track', value: aging.on_track },
      ].filter(d => d.value > 0)
    : []

  const evidenceData = freshness
    ? [
        { name: 'Fresh', value: freshness.fresh },
        { name: 'Expiring', value: freshness.expiring },
        { name: 'Expired', value: freshness.expired },
      ].filter(d => d.value > 0)
    : []

  const complianceBars = compliance.map(c => {
    const sys = c.system_name.length > 22 ? `${c.system_name.slice(0, 21)}…` : c.system_name
    return {
      label: `${sys} · ${fwShort[c.framework_id] ?? c.framework_id}`,
      score: c.score_percentage,
      findings: c.open_findings,
    }
  })

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-[var(--text-primary)]">Compliance Dashboard</h2>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowGuide(true)}
            className="inline-flex items-center gap-1.5 text-sm px-2.5 py-1.5 border border-[var(--border)] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--accent)] transition-colors"
            title="Walk through the setup steps"
          >
            <Rocket size={14} /> Setup guide
          </button>
          <span className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">System</span>
          <select
            value={systemId}
            onChange={e => setSystemId(e.target.value === '' ? '' : Number(e.target.value))}
            className="text-sm bg-[var(--bg-secondary)] border border-[var(--border)] px-2 py-1.5 text-[var(--text-primary)]"
          >
            <option value="">All systems</option>
            {systems.map(s => <option key={s.id} value={s.id}>{s.acronym} — {s.name}</option>)}
          </select>
        </div>
      </div>

      <OnboardingChecklist forceShow={showGuide} onClose={showGuide ? () => setShowGuide(false) : undefined} />
      <MyWorkCard />

      {/* KPI strip */}
      <div className="flex border border-[var(--border)] bg-[var(--bg-secondary)] mb-6">
        {cards.map(({ label, value, icon, tone }) => (
          <KpiCard key={label} label={label} value={value} tone={tone} icon={icon} />
        ))}
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        {/* Severity donut */}
        <div className="bg-[var(--bg-secondary)] border border-[var(--border)] p-4">
          <h3 className="text-xs uppercase tracking-wider text-[var(--text-secondary)] mb-3">Open by Severity</h3>
          {sevData.length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={sevData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={40} outerRadius={70} paddingAngle={2}>
                  {sevData.map(d => <Cell key={d.name} fill={SEV_COLORS[d.name] ?? '#888'} />)}
                </Pie>
                <Tooltip contentStyle={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border)', fontSize: 12 }} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[180px] flex items-center justify-center text-xs text-[var(--text-secondary)]">No open findings</div>
          )}
        </div>

        {/* Finding aging donut */}
        <div className="bg-[var(--bg-secondary)] border border-[var(--border)] p-4">
          <h3 className="text-xs uppercase tracking-wider text-[var(--text-secondary)] mb-3">Finding Aging</h3>
          {agingData.length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={agingData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={40} outerRadius={70} paddingAngle={2}>
                  {agingData.map((d, i) => <Cell key={d.name} fill={AGING_COLORS[i] ?? '#888'} />)}
                </Pie>
                <Tooltip contentStyle={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border)', fontSize: 12 }} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[180px] flex items-center justify-center text-xs text-[var(--text-secondary)]">No aging data</div>
          )}
        </div>

        {/* Evidence freshness donut */}
        <div className="bg-[var(--bg-secondary)] border border-[var(--border)] p-4">
          <h3 className="text-xs uppercase tracking-wider text-[var(--text-secondary)] mb-3">Evidence Freshness</h3>
          {evidenceData.length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie data={evidenceData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={40} outerRadius={70} paddingAngle={2}>
                  {evidenceData.map((d, i) => <Cell key={d.name} fill={EVIDENCE_COLORS[i] ?? '#888'} />)}
                </Pie>
                <Tooltip contentStyle={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border)', fontSize: 12 }} />
                <Legend wrapperStyle={{ fontSize: 11 }} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[180px] flex items-center justify-center text-xs text-[var(--text-secondary)]">No evidence data</div>
          )}
        </div>
      </div>

      {/* Compliance trend + findings burndown (daily snapshots) */}
      <div className="bg-[var(--bg-secondary)] border border-[var(--border)] p-4 mb-6">
        <h3 className="text-xs uppercase tracking-wider text-[var(--text-secondary)] mb-3">Compliance Trend</h3>
        {history.length >= 2 ? (
          <ResponsiveContainer width="100%" height={200}>
            <LineChart data={history} margin={{ top: 4, right: 8, bottom: 0, left: -18 }}>
              <XAxis dataKey="date" tick={{ fontSize: 10, fill: 'var(--text-secondary)' }}
                     tickFormatter={(d: string) => d.slice(5)} />
              <YAxis yAxisId="score" domain={[0, 100]} tick={{ fontSize: 10, fill: 'var(--text-secondary)' }} />
              <YAxis yAxisId="count" orientation="right" allowDecimals={false}
                     tick={{ fontSize: 10, fill: 'var(--text-secondary)' }} />
              <Tooltip contentStyle={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border)', fontSize: 12 }} />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Line yAxisId="score" type="monotone" dataKey="avg_score" name="Avg compliance %"
                    stroke="var(--accent)" strokeWidth={2} dot={false} />
              <Line yAxisId="count" type="monotone" dataKey="open_findings" name="Open findings"
                    stroke="var(--risk-med)" strokeWidth={2} dot={false} />
              <Line yAxisId="count" type="monotone" dataKey="overdue_findings" name="Overdue"
                    stroke="var(--risk-crit)" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        ) : (
          <div className="h-[80px] flex items-center justify-center text-xs text-[var(--text-secondary)]">
            Trend appears after a few days of snapshots (recorded daily, automatically).
          </div>
        )}
      </div>

      {/* Compliance scores bar chart */}
      {complianceBars.length > 0 && (
        <div className="bg-[var(--bg-secondary)] border border-[var(--border)] p-4 mb-6">
          <h3 className="text-xs uppercase tracking-wider text-[var(--text-secondary)] mb-3">Compliance Scores by System × Framework</h3>
          <ResponsiveContainer width="100%" height={Math.max(200, complianceBars.length * 36)}>
            <BarChart data={complianceBars} layout="vertical" margin={{ left: 110, right: 45, top: 5, bottom: 5 }}>
              <XAxis type="number" domain={[0, 100]} tick={{ fontSize: 11 }} />
              <YAxis type="category" dataKey="label" tick={{ fontSize: 10 }} width={210} interval={0} />
              <Tooltip contentStyle={{ background: 'var(--bg-tertiary)', border: '1px solid var(--border)', fontSize: 12 }} />
              <Bar dataKey="score" fill="var(--accent)" barSize={16} radius={[0, 4, 4, 0]} minPointSize={3}>
                <LabelList dataKey="score" position="right" formatter={(v: number) => `${v}%`} style={{ fontSize: 10, fill: 'var(--text-secondary)' }} />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Activity feed */}
      <div className="bg-[var(--bg-secondary)] border border-[var(--border)] p-4">
        <h3 className="text-xs uppercase tracking-wider text-[var(--text-secondary)] mb-3 flex items-center gap-2">
          <Activity size={14} /> Recent Activity
        </h3>
        {activity.length === 0 ? (
          <div className="text-xs text-[var(--text-secondary)] py-4 text-center">No recent activity</div>
        ) : (
          <div className="space-y-1">
            {activity.map(a => (
              <div key={a.id} className="flex items-start justify-between text-xs border-b border-[var(--border)] py-2 last:border-b-0">
                <div className="flex-1 min-w-0">
                  <span className="text-[var(--text-primary)]">{a.summary}</span>
                  <span className="text-[var(--text-secondary)] ml-2">— {a.actor}</span>
                </div>
                <div className="text-[var(--text-secondary)] whitespace-nowrap ml-3 text-[11px]">
                  {a.created_at ? formatDateTime(a.created_at) : '—'}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
