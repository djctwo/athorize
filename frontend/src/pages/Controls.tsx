import { useState, useMemo, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import type { Control, Framework, System } from '../types'
import { Shield, ListChecks, UserCheck, Users, Crop } from 'lucide-react'
import CrosswalkSection from '../components/CrosswalkSection'
import CommentsSection from '../components/CommentsSection'
import { BulkActionBar } from '../components/BulkActionBar'
import { BulkSelectCheckbox } from '../components/BulkSelectCheckbox'
import SavedViews from '../components/SavedViews'
import { SlideInPanel } from '../components/SlideInPanel'
import { useBulkSelect } from '../hooks/useBulkSelect'
import { useCan } from '../hooks/useRole'
import { useUserStore } from '../store/userStore'
import { toast } from '../store/toastStore'
import { plural } from '../lib/plural'

interface Impl {
  id: number
  control_id: string
  implementation_status: string
  narrative?: string
  responsible_party?: string
  owner_id?: number | null
  updated_at?: string | null
}

interface Assignable {
  id: number
  display_name: string
  username: string
}

interface BulkResult {
  updated: number
  skipped: { system_id: number; framework_id: string; control_id: string; reason: string }[]
}

const STATUSES = ['NOT_ASSESSED', 'IMPLEMENTED', 'PARTIALLY', 'NOT_IMPLEMENTED', 'NOT_APPLICABLE', 'INHERITED', 'PLANNED'] as const
const STATUS_LABEL: Record<string, string> = {
  NOT_ASSESSED: 'Not Assessed', IMPLEMENTED: 'Implemented', PARTIALLY: 'Partially',
  NOT_IMPLEMENTED: 'Not Implemented', NOT_APPLICABLE: 'Not Applicable', INHERITED: 'Inherited', PLANNED: 'Planned',
}
const STATUS_COLOR: Record<string, string> = {
  IMPLEMENTED: 'var(--success)', INHERITED: 'var(--success)', PARTIALLY: 'var(--warning)',
  PLANNED: 'var(--info)', NOT_IMPLEMENTED: 'var(--danger)', NOT_APPLICABLE: 'var(--text-tertiary)',
  NOT_ASSESSED: 'var(--text-tertiary)',
}

export default function Controls() {
  const [searchParams] = useSearchParams()
  const [selectedFramework, setSelectedFramework] = useState(searchParams.get('framework') || '')
  const [selectedSystem, setSelectedSystem] = useState(searchParams.get('system') || '')
  const [selectedFamily, setSelectedFamily] = useState('')
  const [expandedControl, setExpandedControl] = useState<string | null>(null)
  const [scopeOpen, setScopeOpen] = useState(false)
  const [scopeBaseline, setScopeBaseline] = useState('')
  const [bulkPanel, setBulkPanel] = useState<'status' | 'owner' | null>(null)
  const [panelStatus, setPanelStatus] = useState<string>('IMPLEMENTED')
  const [panelOwner, setPanelOwner] = useState<number | ''>('')
  const canAssess = useCan('assess:control')
  const { user } = useUserStore()
  const queryClient = useQueryClient()

  const { data: frameworks = [] } = useQuery({ queryKey: ['frameworks'], queryFn: () => api.get<Framework[]>('/frameworks') })
  const { data: systems = [] } = useQuery({ queryKey: ['systems'], queryFn: () => api.get<System[]>('/systems') })
  const { data: assignable = [] } = useQuery({
    queryKey: ['assignable-users'],
    queryFn: () => api.get<Assignable[]>('/users/assignable'),
    enabled: canAssess,
  })
  const { data: baselines = [] } = useQuery({
    queryKey: ['baselines', selectedFramework],
    queryFn: () => api.get<string[]>(`/controls/baselines?framework_id=${encodeURIComponent(selectedFramework)}`),
    enabled: !!selectedFramework,
  })
  const frameworkNames = Object.fromEntries(frameworks.map(f => [f.id, f.name]))
  const activeFrameworks = frameworks.filter(f => f.is_active)

  const { data: controls = [] } = useQuery({
    queryKey: ['controls', selectedFramework, selectedFamily],
    queryFn: () => {
      const params = new URLSearchParams()
      if (selectedFramework) params.set('framework_id', selectedFramework)
      if (selectedFamily) params.set('family', selectedFamily)
      return api.get<Control[]>(`/controls?${params}`)
    },
    enabled: !!selectedFramework,
  })

  const assessing = !!selectedSystem && !!selectedFramework
  const { data: impls = [] } = useQuery({
    queryKey: ['system-impls', selectedSystem, selectedFramework],
    queryFn: () => api.get<Impl[]>(`/controls/systems/${selectedSystem}?framework_id=${selectedFramework}`),
    enabled: assessing,
  })
  const implByControl = useMemo(() => Object.fromEntries(impls.map(i => [i.control_id, i])), [impls])

  const families = [...new Set(controls.map(c => c.family))].sort()
  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['system-impls', selectedSystem, selectedFramework] })

  // Selection is keyed by control_id; changing system/framework/family resets it.
  const bulk = useBulkSelect<{ id: string }>(`${selectedSystem}|${selectedFramework}|${selectedFamily}`)

  const setStatus = useMutation({
    mutationFn: (v: { controlId: string; status: string }) =>
      api.put(`/controls/systems/${selectedSystem}/${selectedFramework}/${v.controlId}`, { implementation_status: v.status }),
    onSuccess: invalidate,
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Could not update status'),
  })
  const bulkUpdate = useMutation({
    mutationFn: (body: { implementation_status?: string; owner_id?: number }) =>
      api.post<BulkResult>('/controls/bulk', {
        targets: [...bulk.selectedIds].map(control_id => ({
          system_id: Number(selectedSystem), framework_id: selectedFramework, control_id,
        })),
        ...body,
      }),
    onSuccess: (res) => {
      invalidate()
      bulk.clear()
      setBulkPanel(null)
      toast.success(`Updated ${res.updated} control(s)${res.skipped?.length ? `, ${res.skipped.length} skipped` : ''}`)
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Bulk update failed'),
  })
  const scopeMut = useMutation({
    mutationFn: () =>
      api.post<{ in_scope: number; marked_na: number; skipped_assessed: number }>(
        `/controls/systems/${selectedSystem}/scope`,
        { framework_id: selectedFramework, baseline: scopeBaseline },
      ),
    onSuccess: (res) => {
      invalidate()
      setScopeOpen(false)
      toast.success(`Scoped: ${res.in_scope} in scope, ${res.marked_na} marked N/A${res.skipped_assessed ? `, ${res.skipped_assessed} left as assessed` : ''}`)
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Scoping failed'),
  })

  const visibleIds = controls.map(c => c.control_id)
  const counts = useMemo(() => {
    const c: Record<string, number> = {}
    for (const ctrl of controls) {
      const st = implByControl[ctrl.control_id]?.implementation_status || 'NOT_ASSESSED'
      c[st] = (c[st] || 0) + 1
    }
    return c
  }, [controls, implByControl])

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold">{assessing ? 'Assess Controls' : 'Control Catalog'}</h2>
      </div>

      <div className="flex flex-wrap gap-3 mb-4 items-center">
        <select className="text-sm" value={selectedFramework} onChange={(e) => { setSelectedFramework(e.target.value); setSelectedFamily('') }}>
          <option value="">Select Framework...</option>
          {activeFrameworks.map(f => <option key={f.id} value={f.id}>{f.name}</option>)}
        </select>
        <select className="text-sm" value={selectedSystem} onChange={(e) => setSelectedSystem(e.target.value)} title="Pick a system to record implementation status">
          <option value="">No system — browse catalog</option>
          {systems.map(s => <option key={s.id} value={s.id}>{s.acronym} — {s.name}</option>)}
        </select>
        {families.length > 0 && (
          <select className="text-sm" value={selectedFamily} onChange={(e) => setSelectedFamily(e.target.value)}>
            <option value="">All Families</option>
            {families.map(f => <option key={f} value={f}>{f}</option>)}
          </select>
        )}
        <span className="text-sm text-text-muted self-center">{plural(controls.length, 'control')}</span>
        {assessing && canAssess && baselines.length > 0 && (
          <button
            onClick={() => { setScopeBaseline(baselines[0]); setScopeOpen(true) }}
            className="flex items-center gap-1.5 px-2.5 py-1 text-xs border border-border text-text-secondary hover:text-accent hover:border-accent"
            title="Mark everything outside a baseline as Not Applicable"
          >
            <Crop size={12} /> Scope to baseline…
          </button>
        )}
        <div className="ml-auto">
          <SavedViews
            page="controls"
            current={{ selectedFramework, selectedSystem, selectedFamily }}
            onApply={(p) => {
              setSelectedFramework(typeof p.selectedFramework === 'string' ? p.selectedFramework : '')
              setSelectedSystem(typeof p.selectedSystem === 'string' ? p.selectedSystem : '')
              setSelectedFamily(typeof p.selectedFamily === 'string' ? p.selectedFamily : '')
            }}
          />
        </div>
      </div>

      <SlideInPanel
        open={scopeOpen}
        onClose={() => setScopeOpen(false)}
        width={420}
        eyebrow="Scoping wizard"
        title="Scope to a baseline"
        subtitle="Cut the catalog down to what actually applies to this system."
        footer={
          <>
            <button
              onClick={() => scopeMut.mutate()}
              disabled={scopeMut.isPending || !scopeBaseline}
              className="px-4 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm disabled:opacity-50"
            >
              {scopeMut.isPending ? 'Scoping…' : 'Apply scope'}
            </button>
            <button onClick={() => setScopeOpen(false)} className="px-3 py-1.5 text-text-secondary text-sm">
              Cancel
            </button>
          </>
        }
      >
        <p className="text-xs text-[var(--text-secondary)] mb-3">
          Every control <b>not</b> tagged with the chosen baseline is marked <b>Not Applicable</b> for
          this system. Controls you have already assessed are never overwritten — they are skipped and
          reported. You can undo any control individually afterwards.
        </p>
        <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Baseline</label>
        <select
          value={scopeBaseline}
          onChange={e => setScopeBaseline(e.target.value)}
          className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
        >
          {baselines.map(b => <option key={b} value={b}>{b}</option>)}
        </select>
      </SlideInPanel>

      <SlideInPanel
        open={bulkPanel === 'status'}
        onClose={() => setBulkPanel(null)}
        width={420}
        eyebrow="Bulk edit"
        title="Set implementation status"
        subtitle={`Applies to ${bulk.selectedCount} selected control(s).`}
        footer={
          <>
            <button
              onClick={() => bulkUpdate.mutate({ implementation_status: panelStatus })}
              disabled={bulkUpdate.isPending}
              className="px-4 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm disabled:opacity-50"
            >
              {bulkUpdate.isPending ? 'Applying…' : `Apply to ${bulk.selectedCount}`}
            </button>
            <button onClick={() => setBulkPanel(null)} className="px-3 py-1.5 text-text-secondary text-sm">
              Cancel
            </button>
          </>
        }
      >
        <p className="text-xs text-[var(--text-secondary)] mb-3">
          Sets the implementation status on every selected control for this system. Narratives,
          responsible parties, and owners are left untouched.
        </p>
        <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Status</label>
        <select
          value={panelStatus}
          onChange={e => setPanelStatus(e.target.value)}
          className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
        >
          {STATUSES.map(s => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
        </select>
      </SlideInPanel>

      <SlideInPanel
        open={bulkPanel === 'owner'}
        onClose={() => setBulkPanel(null)}
        width={420}
        eyebrow="Bulk edit"
        title="Assign owner"
        subtitle={`Applies to ${bulk.selectedCount} selected control(s).`}
        footer={
          <>
            <button
              onClick={() => panelOwner !== '' && bulkUpdate.mutate({ owner_id: panelOwner })}
              disabled={bulkUpdate.isPending || panelOwner === ''}
              className="px-4 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm disabled:opacity-50"
            >
              {bulkUpdate.isPending ? 'Assigning…' : `Assign to ${bulk.selectedCount}`}
            </button>
            <button onClick={() => setBulkPanel(null)} className="px-3 py-1.5 text-text-secondary text-sm">
              Cancel
            </button>
          </>
        }
      >
        <p className="text-xs text-[var(--text-secondary)] mb-3">
          The owner sees these controls in My Work and in their reminder emails.
        </p>
        <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Owner</label>
        <select
          value={panelOwner}
          onChange={e => setPanelOwner(e.target.value === '' ? '' : Number(e.target.value))}
          className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
        >
          <option value="">Choose a teammate…</option>
          {assignable.map(u => <option key={u.id} value={u.id}>{u.display_name || u.username}</option>)}
        </select>
      </SlideInPanel>

      {assessing && controls.length > 0 && (
        <div className="flex flex-wrap gap-3 mb-3 text-xs">
          {STATUSES.filter(s => counts[s]).map(s => (
            <span key={s} className="inline-flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full" style={{ background: STATUS_COLOR[s] }} />
              <span className="text-text-secondary">{STATUS_LABEL[s]}: <b className="text-text-primary">{counts[s]}</b></span>
            </span>
          ))}
        </div>
      )}

      {!selectedFramework && (
        <div className="bg-bg-secondary border border-border p-8 text-center">
          <Shield size={48} className="mx-auto mb-4 text-text-muted" />
          <p className="text-text-muted">Select an active framework to browse its control catalog — and a system to record implementation status.</p>
          {activeFrameworks.length === 0 && (
            <p className="text-text-muted text-sm mt-2">No frameworks activated yet. Go to <span className="text-accent">Frameworks</span> to activate one.</p>
          )}
        </div>
      )}

      {selectedFramework && (
        <div className="bg-bg-secondary border border-border">
          {assessing && canAssess && (
            <BulkActionBar
              count={bulk.selectedCount}
              noun={{ singular: 'control', plural: 'controls' }}
              onClear={bulk.clear}
              actions={[
                { key: 'status', label: 'Set status…', icon: ListChecks, tone: 'accent', disabled: bulkUpdate.isPending, onClick: () => { setPanelStatus('IMPLEMENTED'); setBulkPanel('status') } },
                { key: 'mine', label: 'Assign to me', icon: UserCheck, tone: 'info', pending: bulkUpdate.isPending, spinIcon: true, onClick: () => user?.id && bulkUpdate.mutate({ owner_id: user.id }) },
                { key: 'owner', label: 'Assign owner…', icon: Users, tone: 'accent', disabled: bulkUpdate.isPending, onClick: () => { setPanelOwner(''); setBulkPanel('owner') } },
              ]}
            />
          )}

          {assessing && canAssess && controls.length > 0 && (
            <label className="flex items-center gap-2 px-3 py-2 border-b border-border text-xs text-text-secondary">
              <BulkSelectCheckbox
                checked={bulk.allSelected(visibleIds)}
                indeterminate={bulk.someSelected(visibleIds)}
                onChange={checked => bulk.toggleAll(visibleIds, checked)}
                ariaLabel="Select all controls"
              />
              Select all {controls.length}
            </label>
          )}

          <div className="divide-y divide-border">
            {controls.map((c) => {
              const impl = implByControl[c.control_id]
              const status = impl?.implementation_status || 'NOT_ASSESSED'
              const key = `${c.framework_id}:${c.control_id}`
              return (
                <div key={key}>
                  <div className="w-full text-left p-3 flex items-center gap-3 hover:bg-bg-tertiary transition-colors">
                    {assessing && canAssess && (
                      <BulkSelectCheckbox
                        checked={bulk.isSelected(c.control_id)}
                        onChange={() => bulk.toggleOne(c.control_id)}
                        ariaLabel={`Select ${c.control_id}`}
                      />
                    )}
                    <button className="flex items-center gap-3 flex-1 min-w-0 text-left"
                      onClick={() => setExpandedControl(expandedControl === key ? null : key)}>
                      <span className="text-xs font-mono text-accent min-w-[80px]">{c.control_id}</span>
                      <span className="text-sm font-medium flex-1 truncate">{c.title}</span>
                    </button>
                    {assessing ? (
                      canAssess ? (
                        <select
                          value={status}
                          onClick={e => e.stopPropagation()}
                          onChange={e => setStatus.mutate({ controlId: c.control_id, status: e.target.value })}
                          className="text-xs border border-border bg-bg-tertiary px-1.5 py-1"
                          style={{ color: STATUS_COLOR[status] }}
                        >
                          {STATUSES.map(s => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
                        </select>
                      ) : (
                        <span className="text-xs" style={{ color: STATUS_COLOR[status] }}>{STATUS_LABEL[status]}</span>
                      )
                    ) : (
                      <span className="text-xs text-text-muted">{c.family_name}</span>
                    )}
                  </div>

                  {expandedControl === key && (
                    <div className="px-3 pb-3 pt-0 border-t border-border">
                      <p className="text-sm text-text-secondary mt-2">{c.description}</p>
                      {c.supplemental_guidance && <p className="text-xs text-text-muted mt-2 italic">{c.supplemental_guidance}</p>}
                      {c.baselines.length > 0 && (
                        <div className="mt-2 flex gap-1">
                          {c.baselines.map(b => <span key={b} className="px-2 py-0.5 text-xs bg-bg-tertiary text-text-muted">{b}</span>)}
                        </div>
                      )}
                      {assessing && canAssess && (
                        <ImplementationEditor
                          control={c}
                          impl={impl}
                          assignable={assignable}
                          onSave={(body) => api.put<Impl>(`/controls/systems/${selectedSystem}/${selectedFramework}/${c.control_id}`, body)
                            .then(saved => { invalidate(); return saved })}
                          onConflict={invalidate}
                        />
                      )}
                      {assessing && impl?.id && (
                        <div className="mt-3">
                          {/* Comments attach to the saved implementation row — any role can discuss it */}
                          <CommentsSection entityType="control_implementation" entityId={impl.id} />
                        </div>
                      )}
                      <CrosswalkSection frameworkId={c.framework_id} controlId={c.control_id} frameworkNames={frameworkNames} />
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}

type Draft = { status: string; narrative: string; party: string; ownerId: number | '' }
const DRAFT_FIELDS: (keyof Draft)[] = ['status', 'narrative', 'party', 'ownerId']

function draftOf(impl?: Impl): Draft {
  return {
    status: impl?.implementation_status || 'NOT_ASSESSED',
    narrative: impl?.narrative || '',
    party: impl?.responsible_party || '',
    ownerId: impl?.owner_id ?? '',
  }
}

type SaveBody = {
  implementation_status: string; narrative: string; responsible_party: string; owner_id: number | null
  expected_updated_at: string | null
}

function ImplementationEditor({ control, impl, assignable, onSave, onConflict }: {
  control: Control
  impl?: Impl
  assignable: Assignable[]
  onSave: (body: SaveBody) => Promise<Impl>
  onConflict: () => void
}) {
  // `base` is the saved version the draft started from. A refetch (the row's
  // status dropdown, a bulk change, a colleague's save) only replaces fields the
  // user has NOT touched — a typed narrative is never wiped (R2USER-2) — and the
  // save sends base's updated_at so the server refuses it (409) if someone else
  // changed the control in between (R2DATA-12).
  const [base, setBase] = useState<{ draft: Draft; version: string | null }>(() => ({ draft: draftOf(impl), version: impl?.updated_at ?? null }))
  const [draft, setDraft] = useState<Draft>(() => draftOf(impl))
  const [saving, setSaving] = useState(false)
  const [conflict, setConflict] = useState<string | null>(null)
  const set = <K extends keyof Draft>(k: K, v: Draft[K]) => setDraft(d => ({ ...d, [k]: v }))

  const incomingVersion = impl?.updated_at ?? null
  useEffect(() => {
    if (incomingVersion === base.version) return
    const next = draftOf(impl)
    const dirty = DRAFT_FIELDS.filter(f => draft[f] !== base.draft[f])
    // Someone else changed a field the user is editing: keep the draft and the
    // old version, so saving reports the conflict instead of overwriting them.
    if (dirty.some(f => next[f] !== base.draft[f] && next[f] !== draft[f])) return
    setDraft(d => {
      const merged = { ...d }
      for (const f of DRAFT_FIELDS) if (!dirty.includes(f)) (merged as Record<string, unknown>)[f] = next[f]
      return merged
    })
    setBase({ draft: next, version: incomingVersion })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [control.control_id, incomingVersion])

  const loadLatest = () => {
    const next = draftOf(impl)
    setDraft(next)
    setBase({ draft: next, version: incomingVersion })
    setConflict(null)
  }

  const save = async () => {
    setSaving(true)
    try {
      const saved = await onSave({
        implementation_status: draft.status, narrative: draft.narrative, responsible_party: draft.party,
        owner_id: draft.ownerId === '' ? null : draft.ownerId,
        // null = "this control had no saved implementation when I opened it"
        expected_updated_at: base.version,
      })
      const next = draftOf(saved)
      setDraft(next)
      setBase({ draft: next, version: saved?.updated_at ?? null })
      setConflict(null)
      toast.success('Saved')
    } catch (e) {
      if ((e as { status?: number }).status === 409) {
        setConflict(e instanceof Error ? e.message : 'This control was changed by someone else.')
        onConflict()
      } else {
        toast.error(e instanceof Error ? e.message : 'Save failed')
      }
    } finally { setSaving(false) }
  }

  return (
    <div className="mt-3 p-3 border border-border bg-bg-tertiary/40 space-y-2">
      <div className="text-xs uppercase tracking-wider text-text-secondary">Implementation</div>
      {conflict && (
        <div role="alert" className="flex flex-wrap items-center gap-2 border border-[var(--warning)] bg-bg-secondary px-2 py-1.5 text-xs">
          <span className="flex-1 min-w-0">{conflict} Your draft is still here — copy anything you need first.</span>
          <button type="button" onClick={loadLatest} className="px-2 py-1 border border-border hover:bg-bg-tertiary">
            Load latest version
          </button>
        </div>
      )}
      <div className="flex flex-wrap gap-2">
        <select aria-label="Implementation status" value={draft.status} onChange={e => set('status', e.target.value)} className="text-xs border border-border bg-bg-secondary px-2 py-1">
          {STATUSES.map(s => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
        </select>
        <select aria-label="Assigned owner" value={draft.ownerId} onChange={e => set('ownerId', e.target.value === '' ? '' : Number(e.target.value))}
          className="text-xs border border-border bg-bg-secondary px-2 py-1" title="Assigned owner (appears in their My Work)">
          <option value="">No owner</option>
          {assignable.map(u => <option key={u.id} value={u.id}>{u.display_name}</option>)}
        </select>
        <input aria-label="Responsible party" value={draft.party} onChange={e => set('party', e.target.value)} placeholder="Responsible party (team)"
          className="text-xs border border-border bg-bg-secondary px-2 py-1 flex-1 min-w-[10rem]" />
      </div>
      <textarea aria-label="Implementation narrative" value={draft.narrative} onChange={e => set('narrative', e.target.value)} rows={3}
        placeholder="Implementation narrative — how this control is met, by whom, with what tooling."
        className="w-full text-xs border border-border bg-bg-secondary px-2 py-1.5" />
      <div className="flex justify-end">
        <button onClick={save} disabled={saving} className="px-3 py-1.5 text-xs bg-accent hover:opacity-90 text-white disabled:opacity-50">
          {saving ? 'Saving…' : 'Save implementation'}
        </button>
      </div>
    </div>
  )
}
