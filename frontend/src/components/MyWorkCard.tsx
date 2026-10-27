import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { ClipboardList, Shield, FileCheck } from 'lucide-react'
import { api } from '../lib/api'
import { useUserStore } from '../store/userStore'

interface MyWork {
  findings: { id: number; title: string; overdue: boolean }[]
  controls: { system_id: number; system: string; framework_id: string; control_id: string }[]
  evidence: { id: number; filename: string; days: number; expired: boolean }[]
}

/**
 * Personal "what do I need to do" entry point on the Dashboard: open findings,
 * unimplemented controls, and evidence nearing expiry — all assigned to the
 * current user. Hidden when nothing is assigned, to avoid clutter.
 */
export default function MyWorkCard() {
  const { user } = useUserStore()
  const { data } = useQuery({
    queryKey: ['my-work', user?.id],
    queryFn: () => api.get<MyWork>('/dashboard/my-work'),
    enabled: !!user?.id,
  })

  if (!data) return null
  const { findings, controls, evidence } = data
  if (findings.length + controls.length + evidence.length === 0) return null

  const overdueFindings = findings.filter(f => f.overdue).length
  const expiredEvidence = evidence.filter(e => e.expired).length
  const firstControl = controls[0]

  return (
    <div className="border border-[var(--border)] bg-[var(--bg-secondary)] px-4 py-3 mb-6">
      <div className="text-sm font-semibold text-[var(--text-primary)] mb-2">Your work</div>
      <div className="flex flex-wrap gap-x-8 gap-y-1.5">
        {findings.length > 0 && (
          <Link to="/findings?mine=1" className="flex items-center gap-2 text-xs text-[var(--text-secondary)] hover:text-[var(--accent)]">
            <ClipboardList size={14} className="text-[var(--accent)]" />
            {findings.length} finding{findings.length === 1 ? '' : 's'}
            {overdueFindings > 0 && <span className="text-[var(--danger)]">· {overdueFindings} overdue</span>}
            <span className="text-[var(--accent)]">→</span>
          </Link>
        )}
        {controls.length > 0 && firstControl && (
          <Link
            to={`/controls?framework=${encodeURIComponent(firstControl.framework_id)}&system=${firstControl.system_id}`}
            className="flex items-center gap-2 text-xs text-[var(--text-secondary)] hover:text-[var(--accent)]"
          >
            <Shield size={14} className="text-[var(--accent)]" />
            {controls.length} control{controls.length === 1 ? '' : 's'} to implement
            <span className="text-[var(--accent)]">→</span>
          </Link>
        )}
        {evidence.length > 0 && (
          <Link to="/evidence" className="flex items-center gap-2 text-xs text-[var(--text-secondary)] hover:text-[var(--accent)]">
            <FileCheck size={14} className="text-[var(--accent)]" />
            {evidence.length} evidence item{evidence.length === 1 ? '' : 's'} to refresh
            {expiredEvidence > 0 && <span className="text-[var(--danger)]">· {expiredEvidence} expired</span>}
            <span className="text-[var(--accent)]">→</span>
          </Link>
        )}
      </div>
    </div>
  )
}
