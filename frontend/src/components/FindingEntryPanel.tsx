import { useState, useEffect, useId, useRef } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import type { Finding, System, Framework } from '../types'
import { useCan } from '../hooks/useRole'
import { SlideInPanel } from './SlideInPanel'
import ConfirmDialog from './ConfirmDialog'
import EntityAuditTrail from './EntityAuditTrail'

const EMPTY: Record<string, unknown> = {
  system_id: 0, framework_id: '', control_id: '', title: '', description: '',
  weakness_description: '', severity: 'MEDIUM', owner_id: '',
  due_date: '', scheduled_completion: '', remediation_plan: '',
}

// Fields the edit form never PATCHes (immutable after create).
const CREATE_ONLY = new Set(['system_id', 'framework_id'])

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const
const STATUSES = ['OPEN', 'IN_PROGRESS', 'CLOSED', 'RISK_ACCEPTED', 'DELAYED', 'FALSE_POSITIVE'] as const

interface Props {
  open: boolean
  mode: 'add' | 'edit'
  record: Finding | null
  systems: System[]
  frameworks: Framework[]
  onClose: () => void
}

export default function FindingEntryPanel({ open, mode, record, systems, frameworks, onClose }: Props) {
  const [form, setForm] = useState<Record<string, unknown>>({ ...EMPTY })
  const [confirmDelete, setConfirmDelete] = useState(false)
  // What the form held when it opened — the edit PATCH sends only fields that
  // differ from it, so it can't revert someone else's change (INTEGRITY-20).
  const initial = useRef<Record<string, unknown>>({})
  const canWrite = useCan('edit:finding')
  const qc = useQueryClient()
  const uid = useId()
  const fid = (name: string) => `${uid}-${name}`

  // Owner = a real user (owner_id), so the finding lands in their My Work and
  // "Assigned to me" (E2E-16). The server fills owner_name/email from it.
  // Only people who can actually work a finding on the chosen system are offered
  // (R2USER-12): not the read-only auditor, not someone scoped to other systems.
  const ownerSystemId = Number(form.system_id) || 0
  const { data: assignable = [] } = useQuery({
    queryKey: ['assignable-users', 'finding', ownerSystemId],
    queryFn: () => api.get<{ id: number; display_name: string; username: string }[]>(
      `/users/assignable?finding_system_id=${ownerSystemId}`),
    enabled: open && ownerSystemId > 0,
  })

  // The chosen framework's catalog ids: a picker for Control ID (the server
  // refuses ids that aren't in the catalog — R2USER-7).
  const frameworkId = form.framework_id as string
  const { data: catalogIds = [] } = useQuery({
    queryKey: ['catalog-ids', frameworkId],
    queryFn: async () => (await api.get<{ control_id: string }[]>(
      `/controls?framework_id=${encodeURIComponent(frameworkId)}`)).map(c => c.control_id),
    enabled: open && !!frameworkId,
    staleTime: 5 * 60 * 1000,
  })

  useEffect(() => {
    if (!open) return
    if (mode === 'edit' && record) {
      const snapshot = {
        system_id: record.system_id,
        framework_id: record.framework_id,
        control_id: record.control_id || '',
        title: record.title,
        description: record.description || '',
        weakness_description: record.weakness_description || '',
        severity: record.severity,
        status: record.status,
        owner_id: record.owner_id ?? '',
        due_date: record.due_date || '',
        scheduled_completion: record.scheduled_completion || '',
        actual_completion: record.actual_completion || '',
        remediation_plan: record.remediation_plan || '',
        risk_rationale: record.risk_rationale || '',
        reopen_reason: record.reopen_reason || '',
      }
      initial.current = snapshot
      setForm(snapshot)
    } else {
      initial.current = { ...EMPTY }
      setForm({ ...EMPTY })
    }
  }, [open, mode, record])

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['findings'] })
    qc.invalidateQueries({ queryKey: ['dashboard'] })
  }

  const createMut = useMutation({
    mutationFn: () => {
      const payload = { ...form }
      for (const k of ['due_date', 'scheduled_completion', 'owner_id']) {
        if (!payload[k]) payload[k] = null
      }
      return api.post('/findings', payload)
    },
    onSuccess: () => { invalidate(); onClose() },
  })

  const updateMut = useMutation({
    mutationFn: () => {
      const payload: Record<string, unknown> = {}
      for (const [k, v] of Object.entries(form)) {
        if (CREATE_ONLY.has(k) || v === initial.current[k]) continue
        payload[k] = v === '' ? null : v
      }
      // Optimistic concurrency: the server answers 409 if the finding changed
      // since this panel opened, instead of last-write-wins.
      if (Object.keys(payload).length === 0) return Promise.resolve(record)  // nothing changed
      payload.expected_updated_at = record!.updated_at
      return api.patch(`/findings/${record!.id}`, payload)
    },
    onSuccess: () => { invalidate(); onClose() },
    // 409 = someone else saved first: refresh the list so reopening shows their version.
    onError: (e) => { if ((e as { status?: number }).status === 409) invalidate() },
  })

  const deleteMut = useMutation({
    mutationFn: () => api.delete(`/findings/${record!.id}`),
    onSuccess: () => { invalidate(); onClose() },
  })

  const pending = createMut.isPending || updateMut.isPending || deleteMut.isPending
  const canSubmit = canWrite && !pending && !!(form.title as string)?.trim() && (form.system_id as number) > 0 && !!(form.framework_id as string)

  const set = (k: string, v: unknown) => setForm(f => ({ ...f, [k]: v }))
  const activeFrameworks = frameworks.filter(f => f.is_active)

  return (
    <SlideInPanel
      open={open}
      onClose={onClose}
      title={mode === 'add' ? 'New Finding' : `Edit: ${record?.title ?? ''}`}
      width={580}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault()
          if (mode === 'add') createMut.mutate()
          else updateMut.mutate()
        }}
        className="flex flex-col gap-4"
      >
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1" htmlFor={fid('system')}>System</label>
            <select
              id={fid('system')}
              className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
              value={form.system_id as number}
              onChange={(e) => set('system_id', Number(e.target.value))}
              disabled={mode === 'edit' || !canWrite}
              required
            >
              <option value={0}>Select system…</option>
              {systems.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1" htmlFor={fid('framework')}>Framework</label>
            <select
              id={fid('framework')}
              className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
              value={form.framework_id as string}
              onChange={(e) => set('framework_id', e.target.value)}
              disabled={mode === 'edit' || !canWrite}
              required
            >
              <option value="">Select framework…</option>
              {activeFrameworks.map(f => <option key={f.id} value={f.id}>{f.short_name}</option>)}
            </select>
          </div>
        </div>

        <div>
          <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1" htmlFor={fid('title')}>Title</label>
          <input
            id={fid('title')}
            className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
            value={form.title as string}
            onChange={(e) => set('title', e.target.value)}
            disabled={!canWrite}
            required
          />
        </div>

        <div>
          <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1" htmlFor={fid('description')}>Description</label>
          <textarea
            id={fid('description')}
            className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5 min-h-[60px]"
            value={form.description as string}
            onChange={(e) => set('description', e.target.value)}
            disabled={!canWrite}
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1" htmlFor={fid('severity')}>Severity</label>
            <select
              id={fid('severity')}
              className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
              value={form.severity as string}
              onChange={(e) => set('severity', e.target.value)}
              disabled={!canWrite}
            >
              {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div>
            <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1" htmlFor={fid('control-id')}>Control ID</label>
            <input
              id={fid('control-id')}
              className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
              value={form.control_id as string}
              onChange={(e) => set('control_id', e.target.value)}
              disabled={!canWrite}
              list={fid('control-ids')}
              placeholder={catalogIds.length ? `e.g. ${catalogIds[0]}` : 'Choose a framework first'}
            />
            <datalist id={fid('control-ids')}>
              {catalogIds.map(c => <option key={c} value={c} />)}
            </datalist>
          </div>
        </div>

        {mode === 'edit' && (
          <div>
            <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1" htmlFor={fid('status')}>Status</label>
            <select
              id={fid('status')}
              className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
              value={form.status as string}
              onChange={(e) => set('status', e.target.value)}
              disabled={!canWrite}
            >
              {STATUSES.map(s => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
            </select>
          </div>
        )}

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1" htmlFor={fid('due-date')}>Due Date</label>
            <input
              id={fid('due-date')}
              type="date"
              className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
              value={form.due_date as string}
              onChange={(e) => set('due_date', e.target.value)}
              disabled={!canWrite}
            />
          </div>
          <div>
            <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1" htmlFor={fid('scheduled-completion')}>Scheduled Completion</label>
            <input
              id={fid('scheduled-completion')}
              type="date"
              className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
              value={form.scheduled_completion as string}
              onChange={(e) => set('scheduled_completion', e.target.value)}
              disabled={!canWrite}
            />
          </div>
        </div>

        <div>
          <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1" htmlFor={fid('owner')}>Owner</label>
          <select
            id={fid('owner')}
            className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
            value={form.owner_id === '' || form.owner_id == null ? '' : String(form.owner_id)}
            onChange={(e) => set('owner_id', e.target.value === '' ? '' : Number(e.target.value))}
            disabled={!canWrite}
          >
            <option value="">Unassigned</option>
            {assignable.map(u => <option key={u.id} value={u.id}>{u.display_name}</option>)}
            {mode === 'edit' && record?.owner_id && form.owner_id === record.owner_id && !assignable.some(u => u.id === record.owner_id) && (
              <option value={record.owner_id}>{record.owner_name || `User #${record.owner_id}`} (can't work this finding)</option>
            )}
          </select>
          <p className="text-[11px] text-[var(--text-secondary)] mt-1">
            {ownerSystemId > 0
              ? 'Lists people who can work findings on this system. The owner can move it between Open, In Progress and Delayed and manage its milestones; closing needs a compliance manager or admin.'
              : 'Choose a system first to see who can own this finding.'}
          </p>
          {mode === 'edit' && !record?.owner_id && record?.owner_name && (
            <p className="text-[11px] text-[var(--text-secondary)] mt-1">
              Imported owner: {record.owner_name}{record.owner_email ? ` <${record.owner_email}>` : ''} — not a user here; pick one to put it in their My Work.
            </p>
          )}
        </div>

        <div>
          <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1" htmlFor={fid('remediation-plan')}>Remediation Plan</label>
          <textarea
            id={fid('remediation-plan')}
            className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5 min-h-[60px]"
            value={form.remediation_plan as string}
            onChange={(e) => set('remediation_plan', e.target.value)}
            disabled={!canWrite}
          />
        </div>

        {mode === 'edit' && (form.status === 'RISK_ACCEPTED' || form.status === 'FALSE_POSITIVE') && (
          <div>
            <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1" htmlFor={fid('risk-rationale')}>Risk Rationale</label>
            <textarea
              id={fid('risk-rationale')}
              className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5 min-h-[40px]"
              value={(form.risk_rationale as string) ?? ''}
              onChange={(e) => set('risk_rationale', e.target.value)}
              disabled={!canWrite}
            />
          </div>
        )}

        {(createMut.isError || updateMut.isError) && (
          <div role="alert" className="text-[var(--danger)] text-xs">
            {(createMut.error || updateMut.error)?.message}
          </div>
        )}

        {canWrite && (
          <div className="flex items-center gap-2 pt-2 border-t border-[var(--border)]">
            <button type="submit" disabled={!canSubmit} className="px-4 py-1.5 bg-[var(--accent)] text-white text-sm disabled:opacity-40">
              {mode === 'add' ? 'Create' : 'Save'}
            </button>
            <button type="button" onClick={onClose} className="px-4 py-1.5 border border-[var(--border)] text-[var(--text-secondary)] text-sm hover:bg-[var(--bg-tertiary)]">
              Cancel
            </button>
            {mode === 'edit' && (
              <button type="button" onClick={() => setConfirmDelete(true)} className="ml-auto px-3 py-1.5 text-[var(--danger)] text-sm hover:bg-[var(--danger)]/10">
                Delete
              </button>
            )}
          </div>
        )}
      </form>

      {mode === 'edit' && record && (
        <div className="pt-4">
          <EntityAuditTrail entityType="finding" entityId={record.id} />
        </div>
      )}

      <ConfirmDialog
        open={confirmDelete}
        title="Delete Finding"
        message={`Delete "${record?.title}"? This cannot be undone.`}
        onConfirm={() => { setConfirmDelete(false); deleteMut.mutate() }}
        onCancel={() => setConfirmDelete(false)}
      />
    </SlideInPanel>
  )
}
