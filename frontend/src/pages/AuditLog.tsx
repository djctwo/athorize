import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import { formatDateTime } from '../lib/datetime'
import type { AuditEntry } from '../types'
import { AlertTriangle, CheckCircle, XCircle } from 'lucide-react'
import { plural } from '../lib/plural'

export interface AuditVerifyResult {
  valid: boolean
  entries_checked: number
  broken_at_id: number | null
  reason?: string | null
  legacy_entries?: number
  unauthenticated_legacy_entries?: number
}

export default function AuditLog() {
  const { data: entries = [] } = useQuery({
    queryKey: ['audit'],
    queryFn: () => api.get<AuditEntry[]>('/audit'),
  })

  const { data: integrity } = useQuery({
    queryKey: ['audit-verify'],
    queryFn: () => api.get<AuditVerifyResult>('/audit/verify'),
  })

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold">Audit Log</h2>
        {integrity && (() => {
          const unauth = integrity.unauthenticated_legacy_entries ?? 0
          const tone = !integrity.valid ? 'text-danger' : unauth > 0 ? 'text-warning' : 'text-success'
          const label = !integrity.valid
            ? (integrity.broken_at_id != null ? `Chain broken at #${integrity.broken_at_id}` : 'Chain broken')
            : unauth > 0
              ? `Chain verified — ${unauth} older ${unauth === 1 ? 'entry is' : 'entries are'} unauthenticated`
              : 'Chain verified'
          return (
            <div className={`flex items-center gap-2 text-sm ${tone}`} title={integrity.reason ?? undefined}
                 data-testid="audit-integrity">
              {!integrity.valid ? <XCircle size={16} /> : unauth > 0 ? <AlertTriangle size={16} /> : <CheckCircle size={16} />}
              {label}
              <span className="text-text-muted ml-1">({plural(integrity.entries_checked, 'entry', 'entries')})</span>
            </div>
          )
        })()}
      </div>
      {integrity?.reason && (
        <p className="-mt-4 mb-4 text-xs text-text-muted" data-testid="audit-integrity-reason">{integrity.reason}</p>
      )}

      <div className="bg-bg-secondary border border-border">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Entity</th>
              <th>Summary</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.id}>
                <td className="text-xs text-text-muted whitespace-nowrap">{formatDateTime(e.timestamp)}</td>
                <td className="text-sm">{e.actor_username}</td>
                <td><ActionBadge action={e.action} /></td>
                <td className="text-xs text-text-muted">{e.entity_type}{e.entity_id != null ? ` #${e.entity_id}` : ''}</td>
                <td className="text-sm text-text-secondary max-w-[300px] truncate">{e.summary}</td>
              </tr>
            ))}
            {entries.length === 0 && (
              <tr><td colSpan={5} className="text-center text-text-muted py-8">No audit entries yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function ActionBadge({ action }: { action: string }) {
  const colors: Record<string, string> = {
    CREATE: 'bg-success/20 text-success',
    UPDATE: 'bg-accent/20 text-accent',
    DELETE: 'bg-danger/20 text-danger',
    UPLOAD: 'bg-warning/20 text-warning',
  }
  return <span className={`px-2 py-0.5 text-xs ${colors[action] || 'bg-bg-tertiary text-text-muted'}`}>{action}</span>
}
