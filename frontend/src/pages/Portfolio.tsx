import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Building2, ArrowRight } from 'lucide-react'
import { api } from '../lib/api'
import { useUserStore } from '../store/userStore'
import type { User } from '../types'

interface Company {
  id: number
  name: string
  slug: string
  systems: number
  open_findings: number
  overdue_findings: number
  critical_findings: number
  evidence_stale: number
  avg_score: number | null
}

/** Operator cockpit: every client company's compliance posture on one screen.
 * Clicking a company switches the active context and opens its dashboard. */
export default function Portfolio() {
  const { user, setUser } = useUserStore()
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const { data } = useQuery({
    queryKey: ['portfolio'],
    queryFn: () => api.get<{ companies: Company[]; active_organization_id: number }>('/orgs/portfolio'),
    enabled: !!user?.is_operator,
  })

  if (!user?.is_operator) {
    return <div className="text-sm text-[var(--text-secondary)]">The portfolio view is available to operators only.</div>
  }

  const companies = data?.companies ?? []
  const activeId = data?.active_organization_id

  const openCompany = async (id: number) => {
    if (id !== activeId) {
      await api.post('/orgs/switch', { org_id: id })
      setUser(await api.get<User>('/auth/me'))
      queryClient.invalidateQueries()
    }
    navigate('/')
  }

  const scoreColor = (s: number | null) =>
    s === null ? 'var(--text-secondary)' : s >= 80 ? 'var(--risk-low)' : s >= 50 ? 'var(--risk-med)' : 'var(--risk-crit)'

  return (
    <div>
      <div className="mb-4">
        <h2 className="text-xl font-bold text-[var(--text-primary)]">Portfolio</h2>
        <p className="text-xs text-[var(--text-secondary)] mt-0.5">
          Every company you manage, on one screen. Click a company to switch into it.
        </p>
      </div>

      <div className="bg-[var(--bg-secondary)] border border-[var(--border)]">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] border-b border-[var(--border)]">
              <th className="text-left px-3 py-2">Company</th>
              <th className="text-right px-3 py-2">Systems</th>
              <th className="text-right px-3 py-2">Avg Score</th>
              <th className="text-right px-3 py-2">Open Findings</th>
              <th className="text-right px-3 py-2">Overdue</th>
              <th className="text-right px-3 py-2">Critical</th>
              <th className="text-right px-3 py-2">Stale Evidence</th>
              <th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border)]">
            {companies.map(c => (
              <tr
                key={c.id}
                onClick={() => openCompany(c.id)}
                className="cursor-pointer hover:bg-[var(--bg-tertiary)] transition-colors"
              >
                <td className="px-3 py-2.5">
                  <div className="flex items-center gap-2">
                    <Building2 size={14} className="text-[var(--accent)]" />
                    <span className="font-medium text-[var(--text-primary)]">{c.name}</span>
                    {c.id === activeId && (
                      <span className="text-[10px] uppercase tracking-wider text-[var(--accent)] border border-[var(--accent)]/50 px-1.5 py-0.5">Current</span>
                    )}
                  </div>
                </td>
                <td className="px-3 py-2.5 text-right text-[var(--text-secondary)]">{c.systems}</td>
                <td className="px-3 py-2.5 text-right font-semibold" style={{ color: scoreColor(c.avg_score) }}>
                  {c.avg_score !== null ? `${c.avg_score}%` : '—'}
                </td>
                <td className="px-3 py-2.5 text-right">{c.open_findings}</td>
                <td className="px-3 py-2.5 text-right" style={{ color: c.overdue_findings > 0 ? 'var(--risk-crit)' : undefined }}>
                  {c.overdue_findings}
                </td>
                <td className="px-3 py-2.5 text-right" style={{ color: c.critical_findings > 0 ? 'var(--risk-crit)' : undefined }}>
                  {c.critical_findings}
                </td>
                <td className="px-3 py-2.5 text-right" style={{ color: c.evidence_stale > 0 ? 'var(--risk-med)' : undefined }}>
                  {c.evidence_stale}
                </td>
                <td className="px-3 py-2.5 text-right">
                  <ArrowRight size={14} className="text-[var(--text-secondary)]" />
                </td>
              </tr>
            ))}
            {companies.length === 0 && (
              <tr><td colSpan={8} className="px-3 py-6 text-center text-xs text-[var(--text-secondary)]">No companies yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
