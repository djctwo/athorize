import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { api } from '../lib/api'
import type { Finding } from '../types'
import { useCan } from '../hooks/useRole'
import { useUserStore } from '../store/userStore'
import { toast } from '../store/toastStore'
import { SlideInPanel } from './SlideInPanel'
import ConfirmDialog from './ConfirmDialog'
import { ControlLink } from './ControlLink'
import { SeverityBadge, AgingBadge, type SeverityLevel, type AgingBucket } from './AgingBadge'
import { DetailRow } from './DetailRow'
import { daysSince } from '../lib/datetime'
import EntityAuditTrail from './EntityAuditTrail'
import FindingImpactSection from './FindingImpactSection'
import { useFrameworkNames } from '../hooks/useFrameworkNames'
import CommentsSection from './CommentsSection'
import { plural } from '../lib/plural'

interface Props {
  finding: Finding | null
  onClose: () => void
  onEdit?: (finding: Finding) => void
}

const STATUS_COLORS: Record<string, string> = {
  OPEN: 'var(--danger)',
  IN_PROGRESS: 'var(--warning)',
  CLOSED: 'var(--success)',
  RISK_ACCEPTED: 'var(--text-secondary)',
  FALSE_POSITIVE: 'var(--text-secondary)',
  DELAYED: 'var(--warning)',
}

type Milestone = { title: string; due: string; complete: boolean }

// Working-status moves the owner may make (mirrors the server's transition
// table restricted to non-terminal statuses).
const OWNER_TRANSITIONS: Record<string, string[]> = {
  OPEN: ['IN_PROGRESS'],
  IN_PROGRESS: ['OPEN', 'DELAYED'],
  DELAYED: ['OPEN', 'IN_PROGRESS'],
}

/** POA&M milestones: view, check off, add, and remove remediation steps.
 * The whole array PATCHes back to the finding (JSON column). */
function MilestonesSection({ finding, canWrite }: { finding: Finding; canWrite: boolean }) {
  const qc = useQueryClient()
  const [newTitle, setNewTitle] = useState('')
  const [newDue, setNewDue] = useState('')
  const milestones: Milestone[] = (finding.milestones ?? []).map(m => ({
    title: m.title ?? '', due: m.due ?? '', complete: !!m.complete,
  }))

  const saveMut = useMutation({
    mutationFn: (next: Milestone[]) => api.patch(`/findings/${finding.id}`, { milestones: next }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['findings'] }),
  })

  const doneCount = milestones.filter(m => m.complete).length
  if (milestones.length === 0 && !canWrite) return null

  const addMilestone = () => {
    const title = newTitle.trim()
    if (!title) return
    saveMut.mutate([...milestones, { title, due: newDue, complete: false }])
    setNewTitle('')
    setNewDue('')
  }

  return (
    <div className="pt-3 border-t border-[var(--border)]">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">Milestones</span>
        {milestones.length > 0 && (
          <span className="text-xs text-[var(--text-secondary)]">{doneCount}/{milestones.length} complete</span>
        )}
      </div>
      <div className="space-y-1.5">
        {milestones.map((m, i) => (
          <div key={i} className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={m.complete}
              disabled={!canWrite || saveMut.isPending}
              onChange={e => saveMut.mutate(milestones.map((x, j) => j === i ? { ...x, complete: e.target.checked } : x))}
            />
            <span className={`flex-1 min-w-0 truncate ${m.complete ? 'line-through text-[var(--text-secondary)]' : 'text-[var(--text-primary)]'}`}>
              {m.title}
            </span>
            {m.due && <span className="text-xs text-[var(--text-secondary)] shrink-0">{m.due}</span>}
            {canWrite && (
              <button
                onClick={() => saveMut.mutate(milestones.filter((_x, j) => j !== i))}
                disabled={saveMut.isPending}
                className="text-[var(--text-secondary)] hover:text-[var(--danger)] text-xs shrink-0"
                title="Remove milestone"
              >
                ✕
              </button>
            )}
          </div>
        ))}
        {milestones.length === 0 && (
          <p className="text-xs text-[var(--text-secondary)]">No milestones yet — break the remediation into steps.</p>
        )}
      </div>
      {canWrite && (
        <div className="flex gap-2 mt-2">
          <input
            value={newTitle}
            onChange={e => setNewTitle(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') addMilestone() }}
            placeholder="New milestone…"
            className="flex-1 min-w-0 text-xs bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1"
          />
          <input
            type="date"
            value={newDue}
            onChange={e => setNewDue(e.target.value)}
            className="text-xs bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1"
          />
          <button
            onClick={addMilestone}
            disabled={!newTitle.trim() || saveMut.isPending}
            className="px-2 py-1 text-xs bg-[var(--accent)] text-white disabled:opacity-50"
          >
            Add
          </button>
        </div>
      )}
    </div>
  )
}

export default function FindingDetailPanel({ finding, onClose, onEdit }: Props) {
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [confirmClose, setConfirmClose] = useState(false)
  const canWrite = useCan('edit:finding')
  const canWorkOwn = useCan('work:own_finding')
  const me = useUserStore(s => s.user)
  const frameworkNames = useFrameworkNames()
  const qc = useQueryClient()

  const deleteMut = useMutation({
    mutationFn: () => api.delete(`/findings/${finding!.id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['dashboard'] })
      onClose()
    },
  })

  const closeMut = useMutation({
    mutationFn: () => api.patch(`/findings/${finding!.id}`, {
      status: 'CLOSED',
      actual_completion: new Date().toISOString().slice(0, 10),
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['dashboard'] })
      onClose()
    },
  })

  const statusMut = useMutation({
    mutationFn: (status: string) => api.patch(`/findings/${finding!.id}`, {
      status, expected_updated_at: finding!.updated_at || undefined,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['dashboard'] })
      toast.success('Status updated')
    },
    onError: (e) => {
      if ((e as { status?: number }).status === 409) qc.invalidateQueries({ queryKey: ['findings'] })
      toast.error(e instanceof Error ? e.message : 'Could not update the status')
    },
  })

  const pending = deleteMut.isPending || closeMut.isPending || statusMut.isPending

  if (!finding) return null

  // R2USER-12: the assigned owner works their own finding even without
  // edit:finding — status between Open / In Progress / Delayed, and milestones.
  const isOwnerWorker = !canWrite && canWorkOwn && !!me && finding.owner_id === me.id
  const canMilestones = canWrite || isOwnerWorker
  const ownerNext = OWNER_TRANSITIONS[finding.status] ?? []

  const daysUntil = finding.days_until_due
  const overdue = daysUntil !== null && daysUntil < 0

  return (
    <SlideInPanel open={!!finding} onClose={onClose} title={finding.title} width={580}>
      <div className="space-y-4">
        <div className="flex items-center gap-2 flex-wrap">
          <SeverityBadge severity={finding.severity as SeverityLevel} />
          <AgingBadge bucket={(finding.aging_bucket ?? 'ON_TRACK') as AgingBucket} />
          <span
            className="text-xs font-medium"
            style={{ color: STATUS_COLORS[finding.status] ?? 'var(--text-secondary)' }}
          >
            {finding.status.replace(/_/g, ' ')}
          </span>
        </div>

        <div className="space-y-0">
          <DetailRow label="Framework" value={frameworkNames[finding.framework_id] ?? finding.framework_id} />
          <DetailRow label="Control" value={<ControlLink controlId={finding.control_id} frameworkId={finding.framework_id} />} />
          {finding.weakness_description && (
            <DetailRow label="Weakness" value={finding.weakness_description} />
          )}
          {finding.remediation_plan && (
            <DetailRow label="Remediation" value={finding.remediation_plan} />
          )}
          <DetailRow label="Due Date" value={finding.due_date || finding.scheduled_completion || '—'} />
          {daysUntil !== null && (
            <DetailRow label="Days Until Due" value={
              <span className={overdue ? 'text-[var(--danger)] font-medium' : ''}>
                {overdue ? `${plural(Math.abs(daysUntil), 'day')} overdue` : plural(daysUntil, 'day')}
              </span>
            } />
          )}
          {(daysSince(finding.created_at) ?? finding.days_open) !== null && (
            <DetailRow label="Days Open" value={`${daysSince(finding.created_at) ?? finding.days_open}`} />
          )}
          {finding.owner_name && (
            <DetailRow label="Owner" value={
              <span>
                {finding.owner_name}
                {finding.owner_email && (
                  <a href={`mailto:${finding.owner_email}`} className="ml-2 text-[var(--accent)] text-xs">
                    {finding.owner_email}
                  </a>
                )}
              </span>
            } />
          )}
          {finding.risk_rationale && (
            <DetailRow label="Risk Rationale" value={finding.risk_rationale} />
          )}
          {finding.reopen_reason && (
            <DetailRow label="Reopen Reason" value={finding.reopen_reason} />
          )}
        </div>

        {isOwnerWorker && ownerNext.length > 0 && (
          <div className="flex items-center gap-2 pt-3 border-t border-[var(--border)] text-sm">
            <label htmlFor={`finding-${finding.id}-owner-status`} className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">
              Your finding — status
            </label>
            <select
              id={`finding-${finding.id}-owner-status`}
              value={finding.status}
              disabled={pending}
              onChange={e => statusMut.mutate(e.target.value)}
              className="text-xs bg-[var(--bg-tertiary)] border border-[var(--border)] px-1.5 py-1"
            >
              <option value={finding.status}>{finding.status.replace(/_/g, ' ')}</option>
              {ownerNext.map(s => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
            </select>
            <span className="text-xs text-[var(--text-secondary)]">Closing needs a compliance manager or admin.</span>
          </div>
        )}

        <MilestonesSection finding={finding} canWrite={canMilestones} />

        <FindingImpactSection findingId={finding.id} frameworkNames={frameworkNames} />

        {canWrite && (
          <div className="flex items-center gap-2 pt-3 border-t border-[var(--border)]">
            {onEdit && (
              <button
                onClick={() => onEdit(finding)}
                disabled={pending}
                className="px-3 py-1.5 text-sm border border-[var(--border)] text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)]"
              >
                Edit
              </button>
            )}
            {finding.status !== 'CLOSED' && (
              <button
                onClick={() => setConfirmClose(true)}
                disabled={pending}
                className="px-3 py-1.5 text-sm border border-[var(--success)]/40 text-[var(--success)] hover:bg-[var(--success)]/10"
              >
                Mark Closed
              </button>
            )}
            <button
              onClick={() => setConfirmDelete(true)}
              disabled={pending}
              className="ml-auto px-3 py-1.5 text-sm text-[var(--danger)] hover:bg-[var(--danger)]/10"
            >
              Delete
            </button>
          </div>
        )}

        <CommentsSection entityType="finding" entityId={finding.id} />

        <EntityAuditTrail entityType="finding" entityId={finding.id} />
      </div>

      <ConfirmDialog
        open={confirmDelete}
        title="Delete Finding"
        message={`Delete "${finding.title}"? This cannot be undone.`}
        onConfirm={() => { setConfirmDelete(false); deleteMut.mutate() }}
        onCancel={() => setConfirmDelete(false)}
      />
      <ConfirmDialog
        open={confirmClose}
        title="Close Finding"
        message={`Mark "${finding.title}" as closed? This sets actual_completion to today.`}
        onConfirm={() => { setConfirmClose(false); closeMut.mutate() }}
        onCancel={() => setConfirmClose(false)}
      />
    </SlideInPanel>
  )
}
