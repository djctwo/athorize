import { useEffect, useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Save, Trash2, ShieldAlert } from 'lucide-react'
import { api } from '../lib/api'
import { useCan } from '../hooks/useRole'
import { toast } from '../store/toastStore'
import {
  RISK_CATEGORIES, RISK_CATEGORY_LABELS, RISK_LEVELS, RISK_STATUSES, RISK_TREATMENTS,
} from '../types'
import type { RiskCategory, RiskLevel, RiskRegisterEntry, RiskStatus, RiskTreatment } from '../types'
import { SlideInPanel } from './SlideInPanel'
import ConfirmDialog from './ConfirmDialog'

type Mode = 'add' | 'edit'

interface Props {
  open: boolean
  mode: Mode
  record: RiskRegisterEntry | null
  systemId: number
  systems: { id: number; acronym: string; name: string }[]
  onClose: () => void
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block py-2">
      <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">{label}</div>
      {children}
    </label>
  )
}

const inputCls =
  'w-full bg-[var(--bg-primary)] border border-[var(--border)] px-2 py-1.5 text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]'

const EMPTY_FORM = {
  title: '',
  description: '',
  category: 'TECH' as RiskCategory,
  control_id: '',
  likelihood: 'MODERATE' as RiskLevel,
  impact: 'MODERATE' as RiskLevel,
  status: 'OPEN' as RiskStatus,
  treatment: 'MITIGATE' as RiskTreatment,
  mitigation: '',
  residual_risk: 'LOW' as RiskLevel,
  owner_name: '',
  owner_email: '',
  review_date: '',
}

function fromRecord(r: RiskRegisterEntry): typeof EMPTY_FORM {
  return {
    title: r.title ?? '',
    description: r.description ?? '',
    category: (r.category ?? 'TECH') as RiskCategory,
    control_id: r.control_id ?? '',
    likelihood: (r.likelihood ?? 'MODERATE') as RiskLevel,
    impact: (r.impact ?? 'MODERATE') as RiskLevel,
    status: (r.status ?? 'OPEN') as RiskStatus,
    treatment: (r.treatment ?? 'MITIGATE') as RiskTreatment,
    mitigation: r.mitigation ?? '',
    residual_risk: (r.residual_risk ?? 'LOW') as RiskLevel,
    owner_name: r.owner_name ?? '',
    owner_email: r.owner_email ?? '',
    review_date: r.review_date ?? '',
  }
}

export function RiskEntryPanel({ open, mode, record, systemId, systems, onClose }: Props) {
  const qc = useQueryClient()
  const [form, setForm] = useState(EMPTY_FORM)
  const [targetSystemId, setTargetSystemId] = useState(systemId)
  const [error, setError] = useState<string | null>(null)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [confirmSpawn, setConfirmSpawn] = useState(false)

  useEffect(() => {
    if (!open) return
    setError(null)
    setForm(mode === 'edit' && record ? fromRecord(record) : EMPTY_FORM)
    setTargetSystemId(mode === 'edit' && record ? record.system_id : systemId)
  }, [open, mode, record, systemId])

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['risks'] })
    qc.invalidateQueries({ queryKey: ['findings'] })
  }

  const createMut = useMutation({
    mutationFn: (payload: Record<string, unknown>) => api.post('/risks', payload),
    onSuccess: () => { invalidate(); onClose(); toast.success('Risk created') },
    onError: (e: Error) => { setError(e.message); toast.error('Failed to create risk') },
  })

  const updateMut = useMutation({
    mutationFn: (payload: Record<string, unknown>) => api.patch(`/risks/${record!.id}`, payload),
    onSuccess: () => { invalidate(); onClose(); toast.success('Risk updated') },
    onError: (e: Error) => { setError(e.message); toast.error('Failed to update risk') },
  })

  const deleteMut = useMutation({
    mutationFn: () => api.delete(`/risks/${record!.id}`),
    onSuccess: () => { invalidate(); onClose(); toast.success('Risk deleted') },
    onError: (e: Error) => { setError(e.message); toast.error('Failed to delete risk') },
  })

  const spawnMut = useMutation({
    mutationFn: () => api.post<{ finding_id: number }>(`/risks/${record!.id}/spawn-finding`),
    onSuccess: (res) => { invalidate(); onClose(); toast.success(`Finding ${res.finding_id} spawned from risk`) },
    onError: (e: Error) => { setError(e.message); toast.error('Failed to spawn finding') },
  })

  const busy = createMut.isPending || updateMut.isPending || deleteMut.isPending || spawnMut.isPending
  // Rows open this panel for every role; only edit:risk may save/spawn/delete.
  const canEdit = useCan('edit:risk')
  const canSubmit = form.title.trim().length > 0 && !busy
  const linkedFindingId = record?.linked_finding_id ?? null
  // Spawning creates a Finding, so it also needs edit:finding (server checks both).
  const canCreateFinding = useCan('edit:finding')
  const canSpawn = canEdit && canCreateFinding && mode === 'edit' && record != null && !linkedFindingId && !busy

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!canEdit || !canSubmit) return
    const payload: Record<string, unknown> = {
      system_id: targetSystemId,
      title: form.title.trim(),
      description: form.description.trim() || '',
      category: form.category,
      control_id: form.control_id.trim() || '',
      likelihood: form.likelihood,
      impact: form.impact,
      status: form.status,
      treatment: form.treatment,
      mitigation: form.mitigation.trim() || '',
      residual_risk: form.residual_risk,
      owner_name: form.owner_name.trim() || '',
      owner_email: form.owner_email.trim() || '',
      review_date: form.review_date || null,
    }
    if (mode === 'edit') updateMut.mutate(payload)
    else createMut.mutate(payload)
  }

  return (
    <SlideInPanel open={open} onClose={onClose} width={560}
      eyebrow={mode === 'edit' ? `Risk #${record?.id}` : 'New Risk'}
      title={mode === 'edit' ? 'Edit Risk Entry' : 'Add Risk Entry'}
      footer={<>
        {canEdit && <button type="submit" onClick={handleSubmit} disabled={!canSubmit}
          className="px-3 py-1.5 text-xs uppercase tracking-wider border border-[var(--accent)] text-[var(--accent)] hover:bg-[var(--accent)]/10 inline-flex items-center gap-1.5 disabled:opacity-40 disabled:cursor-not-allowed">
          <Save size={12} />
          {busy ? 'Saving...' : mode === 'edit' ? 'Save Changes' : 'Create Risk'}
        </button>}
        <button type="button" onClick={onClose}
          className="px-3 py-1.5 text-xs uppercase tracking-wider border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]">
          Cancel
        </button>
        {canSpawn && (
          <button type="button" onClick={() => setConfirmSpawn(true)} disabled={busy}
            className="ml-auto px-3 py-1.5 text-xs uppercase tracking-wider border border-[var(--accent)] text-[var(--accent)] hover:bg-[var(--accent)]/10 inline-flex items-center gap-1.5 disabled:opacity-40"
            title="Create a Finding pre-filled from this risk">
            <ShieldAlert size={12} />
            {spawnMut.isPending ? 'Spawning...' : 'Spawn Finding'}
          </button>
        )}
        {canEdit && mode === 'edit' && record && (
          <button type="button" onClick={() => setConfirmDelete(true)}
            className={`${canSpawn ? '' : 'ml-auto'} px-3 py-1.5 text-xs uppercase tracking-wider border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--risk-crit)] hover:border-[var(--risk-crit)] inline-flex items-center gap-1.5`}>
            <Trash2 size={12} /> Delete
          </button>
        )}
      </>}
    >
      <form onSubmit={handleSubmit}>
        {linkedFindingId && (
          <div className="w-full mb-3 px-3 py-2 text-xs border border-[var(--accent)]/40 bg-[var(--accent)]/10 text-[var(--accent)] inline-flex items-center gap-2">
            <ShieldAlert size={12} />
            Linked to Finding #{linkedFindingId}
          </div>
        )}

        <Field label="System *">
          <select value={targetSystemId} onChange={e => setTargetSystemId(Number(e.target.value))} className={inputCls} disabled={mode === 'edit'}>
            {systems.map(s => <option key={s.id} value={s.id}>{s.acronym} — {s.name}</option>)}
          </select>
        </Field>

        <Field label="Title *">
          <input type="text" value={form.title} onChange={e => setForm(f => ({ ...f, title: e.target.value }))} className={inputCls} required />
        </Field>

        <Field label="Description / Narrative">
          <textarea value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} rows={4} className={inputCls} placeholder="Threat source, vulnerability, exposure." />
        </Field>

        <div className="grid grid-cols-2 gap-3">
          <Field label="Category">
            <select value={form.category} onChange={e => setForm(f => ({ ...f, category: e.target.value as RiskCategory }))} className={inputCls}>
              {RISK_CATEGORIES.map(c => <option key={c} value={c}>{RISK_CATEGORY_LABELS[c]}</option>)}
            </select>
          </Field>
          <Field label="Linked Control">
            <input type="text" value={form.control_id} onChange={e => setForm(f => ({ ...f, control_id: e.target.value }))} className={inputCls} placeholder="e.g. SI-2" />
          </Field>
        </div>

        <div className="grid grid-cols-3 gap-3">
          <Field label="Likelihood">
            <select value={form.likelihood} onChange={e => setForm(f => ({ ...f, likelihood: e.target.value as RiskLevel }))} className={inputCls}>
              {RISK_LEVELS.map(l => <option key={l} value={l}>{l}</option>)}
            </select>
          </Field>
          <Field label="Impact">
            <select value={form.impact} onChange={e => setForm(f => ({ ...f, impact: e.target.value as RiskLevel }))} className={inputCls}>
              {RISK_LEVELS.map(l => <option key={l} value={l}>{l}</option>)}
            </select>
          </Field>
          <Field label="Residual">
            <select value={form.residual_risk} onChange={e => setForm(f => ({ ...f, residual_risk: e.target.value as RiskLevel }))} className={inputCls}>
              {RISK_LEVELS.map(l => <option key={l} value={l}>{l}</option>)}
            </select>
          </Field>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <Field label="Status">
            <select value={form.status} onChange={e => setForm(f => ({ ...f, status: e.target.value as RiskStatus }))} className={inputCls}>
              {RISK_STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
          </Field>
          <Field label="Treatment">
            <select value={form.treatment} onChange={e => setForm(f => ({ ...f, treatment: e.target.value as RiskTreatment }))} className={inputCls}>
              {RISK_TREATMENTS.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
          </Field>
        </div>

        <Field label="Mitigation Plan">
          <textarea value={form.mitigation} onChange={e => setForm(f => ({ ...f, mitigation: e.target.value }))} rows={4} className={inputCls} placeholder="Compensating controls, treatment path, review cadence." />
        </Field>

        <div className="grid grid-cols-2 gap-3">
          <Field label="Owner Name">
            <input type="text" value={form.owner_name} onChange={e => setForm(f => ({ ...f, owner_name: e.target.value }))} className={inputCls} />
          </Field>
          <Field label="Owner Email">
            <input type="email" value={form.owner_email} onChange={e => setForm(f => ({ ...f, owner_email: e.target.value }))} className={inputCls} />
          </Field>
        </div>

        <Field label="Next Review Date">
          <input type="date" value={form.review_date} onChange={e => setForm(f => ({ ...f, review_date: e.target.value }))} className={inputCls} />
        </Field>

        {error && (
          <div className="mt-3 text-xs text-[var(--risk-crit)] border border-[var(--risk-crit)]/40 bg-[var(--risk-crit)]/10 px-3 py-2">{error}</div>
        )}
        <button type="submit" className="hidden" aria-hidden tabIndex={-1} />
      </form>

      {record && (
        <>
          <ConfirmDialog open={confirmDelete} title="Delete Risk" message={`Delete "${record.title}"? This cannot be undone.`}
            confirmLabel="Delete" onConfirm={() => { setConfirmDelete(false); deleteMut.mutate() }} onCancel={() => setConfirmDelete(false)} />
          <ConfirmDialog open={confirmSpawn} title="Spawn Finding"
            message={`Create a remediation Finding from "${record.title}"? It will be linked back to this risk.`}
            confirmLabel="Spawn Finding" danger={false}
            onConfirm={() => { setConfirmSpawn(false); spawnMut.mutate() }} onCancel={() => setConfirmSpawn(false)} />
        </>
      )}
    </SlideInPanel>
  )
}
