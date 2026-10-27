import { useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Upload, Wrench, Pencil, ArrowLeft } from 'lucide-react'
import { api } from '../lib/api'
import { SlideInPanel } from '../components/SlideInPanel'
import ConfirmDialog from '../components/ConfirmDialog'
import { toast } from '../store/toastStore'
import { useCan } from '../hooks/useRole'
import { parseControlsCsv } from '../lib/csv'

interface CustomFramework {
  id: string
  name: string
  short_name: string
  description: string
  publisher: string
  category: string
  version: string
  control_count: number
  active_in_orgs: number
}

interface CustomControl {
  id: string
  family: string
  family_name: string
  title: string
  description: string
  supplemental_guidance: string
  baselines: string[]
}

const EMPTY_CONTROL: CustomControl = {
  id: '', family: '', family_name: '', title: '', description: '',
  supplemental_guidance: '', baselines: [],
}

/** Author an in-house framework (company policy, contractual requirements) on
 * the same plugin format as the shipped catalogs. Custom frameworks appear in
 * the Marketplace, activate like any framework, and are never license-gated. */
export default function FrameworkBuilder() {
  const isAdmin = useCan('manage:frameworks')
  const qc = useQueryClient()
  const [editingId, setEditingId] = useState<string | null>(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [form, setForm] = useState({ name: '', description: '', publisher: '', category: 'general' })
  const [controls, setControls] = useState<CustomControl[]>([])
  const [dirty, setDirty] = useState(false)
  const [controlPanel, setControlPanel] = useState<{ open: boolean; index: number | null; draft: CustomControl }>({ open: false, index: null, draft: EMPTY_CONTROL })
  const [confirmDeleteFw, setConfirmDeleteFw] = useState<string | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const { data: customs = [] } = useQuery({
    queryKey: ['custom-frameworks'],
    queryFn: () => api.get<CustomFramework[]>('/custom-frameworks'),
    enabled: isAdmin,
  })

  const openFramework = async (id: string) => {
    const rows = await api.get<CustomControl[]>(`/custom-frameworks/${id}/controls`)
    setControls(rows)
    setEditingId(id)
    setDirty(false)
  }

  const createMut = useMutation({
    mutationFn: () => api.post<{ id: string }>('/custom-frameworks', form),
    onSuccess: async (res) => {
      qc.invalidateQueries({ queryKey: ['custom-frameworks'] })
      qc.invalidateQueries({ queryKey: ['frameworks'] })
      setCreateOpen(false)
      setForm({ name: '', description: '', publisher: '', category: 'general' })
      toast.success('Framework created — now add its controls')
      await openFramework(res.id)
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Create failed'),
  })

  const saveMut = useMutation({
    mutationFn: () => api.put<{ controls: number }>(`/custom-frameworks/${editingId}/controls`, { controls }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['custom-frameworks'] })
      qc.invalidateQueries({ queryKey: ['frameworks'] })
      qc.invalidateQueries({ queryKey: ['controls'] })
      setDirty(false)
      toast.success(`Saved ${res.controls} control(s)`)
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Save failed'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => api.delete(`/custom-frameworks/${id}`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['custom-frameworks'] })
      qc.invalidateQueries({ queryKey: ['frameworks'] })
      setEditingId(null)
      toast.success('Framework deleted')
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Delete failed'),
  })

  const importCsv = (text: string) => {
    // Expected columns: id,family,family_name,title,description (header optional).
    // Real CSV parsing: quoted fields may hold commas and line breaks.
    const parsed: CustomControl[] = parseControlsCsv(text).map(r => ({ ...EMPTY_CONTROL, ...r }))
    if (parsed.length === 0) {
      toast.error('No rows recognized (expected: id,family,family_name,title,description)')
      return
    }
    const existing = new Set(controls.map(c => c.id))
    const fresh = parsed.filter(c => !existing.has(c.id))
    setControls([...controls, ...fresh])
    setDirty(true)
    toast.success(`Imported ${fresh.length} control(s)${fresh.length < parsed.length ? ` (${parsed.length - fresh.length} duplicates skipped)` : ''}`)
  }

  if (!isAdmin) {
    return <div className="text-sm text-[var(--text-secondary)]">The framework builder is available to admins only.</div>
  }

  const editing = customs.find(c => c.id === editingId)

  return (
    <div>
      <div className="flex items-start justify-between mb-4">
        <div>
          <h2 className="text-xl font-bold text-[var(--text-primary)]">Framework Builder</h2>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5 max-w-2xl">
            Author your own framework — internal policy, contractual clauses, anything you must track —
            on the same engine as the shipped catalogs. It appears in the <Link to="/marketplace" className="text-[var(--accent)]">Marketplace</Link> and works with findings, evidence, assessments, and the Audit Binder.
          </p>
        </div>
        <button
          onClick={() => setCreateOpen(true)}
          className="flex items-center gap-2 px-3 py-1.5 bg-[var(--accent)] hover:opacity-90 text-white text-sm"
        >
          <Plus size={16} /> New framework
        </button>
      </div>

      {!editingId ? (
        <div className="grid grid-cols-2 gap-3">
          {customs.map(c => (
            <div key={c.id} className="bg-[var(--bg-secondary)] border border-[var(--border)] p-4">
              <div className="flex items-center gap-2 mb-1">
                <Wrench size={16} className="text-[var(--accent)]" />
                <span className="text-sm font-semibold text-[var(--text-primary)]">{c.name}</span>
              </div>
              <div className="text-[11px] text-[var(--text-secondary)] mb-2">
                {c.control_count} control(s) · {c.publisher}
                {c.active_in_orgs > 0 && <span className="text-[var(--success)]"> · active in {c.active_in_orgs} company(ies)</span>}
              </div>
              <p className="text-xs text-[var(--text-secondary)] mb-3 line-clamp-2">{c.description || 'No description.'}</p>
              <div className="flex gap-2">
                <button onClick={() => openFramework(c.id)}
                  className="flex items-center gap-1 px-2 py-1 text-xs border border-[var(--accent)] text-[var(--accent)] hover:bg-[var(--accent)]/10">
                  <Pencil size={12} /> Edit controls
                </button>
                <button
                  onClick={() => setConfirmDeleteFw(c.id)}
                  disabled={c.active_in_orgs > 0}
                  title={c.active_in_orgs > 0 ? 'Deactivate it everywhere first' : 'Delete framework'}
                  className="flex items-center gap-1 px-2 py-1 text-xs text-[var(--danger)] hover:bg-[var(--danger)]/10 disabled:opacity-40">
                  <Trash2 size={12} /> Delete
                </button>
              </div>
            </div>
          ))}
          {customs.length === 0 && (
            <div className="col-span-2 bg-[var(--bg-secondary)] border border-[var(--border)] p-8 text-center">
              <Wrench size={40} className="mx-auto mb-3 text-[var(--text-secondary)]" />
              <p className="text-sm text-[var(--text-secondary)]">
                No custom frameworks yet. Create one and add controls by hand or CSV import.
              </p>
            </div>
          )}
        </div>
      ) : (
        <div className="bg-[var(--bg-secondary)] border border-[var(--border)]">
          <div className="flex items-center gap-3 px-3 py-2 border-b border-[var(--border)]">
            <button onClick={() => setEditingId(null)} className="text-[var(--text-secondary)] hover:text-[var(--text-primary)]">
              <ArrowLeft size={16} />
            </button>
            <span className="text-sm font-semibold text-[var(--text-primary)]">{editing?.name ?? editingId}</span>
            <span className="text-xs text-[var(--text-secondary)]">{controls.length} control(s){dirty ? ' · unsaved changes' : ''}</span>
            <div className="ml-auto flex gap-2">
              <input ref={fileRef} type="file" accept=".csv,text/csv" className="hidden"
                onChange={async e => {
                  const f = e.target.files?.[0]
                  if (f) importCsv(await f.text())
                  e.target.value = ''
                }} />
              <button onClick={() => fileRef.current?.click()}
                className="flex items-center gap-1 px-2 py-1 text-xs border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--accent)] hover:border-[var(--accent)]">
                <Upload size={12} /> Import CSV
              </button>
              <button onClick={() => setControlPanel({ open: true, index: null, draft: EMPTY_CONTROL })}
                className="flex items-center gap-1 px-2 py-1 text-xs border border-[var(--accent)] text-[var(--accent)] hover:bg-[var(--accent)]/10">
                <Plus size={12} /> Add control
              </button>
              <button onClick={() => saveMut.mutate()} disabled={!dirty || saveMut.isPending}
                className="px-3 py-1 text-xs bg-[var(--accent)] text-white disabled:opacity-40">
                {saveMut.isPending ? 'Saving…' : 'Save'}
              </button>
            </div>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] border-b border-[var(--border)]">
                <th className="text-left px-3 py-2 w-28">ID</th>
                <th className="text-left px-3 py-2 w-28">Family</th>
                <th className="text-left px-3 py-2">Title</th>
                <th className="px-3 py-2 w-20" />
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border)]">
              {controls.map((c, i) => (
                <tr key={c.id} className="hover:bg-[var(--bg-tertiary)]">
                  <td className="px-3 py-2 font-mono text-xs text-[var(--accent)]">{c.id}</td>
                  <td className="px-3 py-2 text-xs text-[var(--text-secondary)]">{c.family}</td>
                  <td className="px-3 py-2">{c.title}</td>
                  <td className="px-3 py-2 text-right">
                    <button onClick={() => setControlPanel({ open: true, index: i, draft: { ...c } })}
                      className="text-[var(--text-secondary)] hover:text-[var(--accent)] mr-2"><Pencil size={13} /></button>
                    <button onClick={() => { setControls(controls.filter((_x, j) => j !== i)); setDirty(true) }}
                      className="text-[var(--text-secondary)] hover:text-[var(--danger)]"><Trash2 size={13} /></button>
                  </td>
                </tr>
              ))}
              {controls.length === 0 && (
                <tr><td colSpan={4} className="px-3 py-6 text-center text-xs text-[var(--text-secondary)]">
                  No controls yet — add one or import a CSV (id,family,family_name,title,description).
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* New framework panel */}
      <SlideInPanel
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        width={440}
        eyebrow="Framework Builder"
        title="New custom framework"
        footer={
          <>
            <button onClick={() => createMut.mutate()} disabled={createMut.isPending || form.name.trim().length < 2}
              className="px-4 py-1.5 bg-[var(--accent)] hover:opacity-90 text-white text-sm disabled:opacity-50">
              {createMut.isPending ? 'Creating…' : 'Create'}
            </button>
            <button onClick={() => setCreateOpen(false)} className="px-3 py-1.5 text-[var(--text-secondary)] text-sm">Cancel</button>
          </>
        }
      >
        <div className="space-y-3">
          <div>
            <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Name</label>
            <input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              placeholder="e.g. Acme Security Policy" className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5" />
          </div>
          <div>
            <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Description</label>
            <textarea value={form.description} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} rows={3}
              className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5" />
          </div>
          <div>
            <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Publisher</label>
            <input value={form.publisher} onChange={e => setForm(f => ({ ...f, publisher: e.target.value }))}
              placeholder="Your organization" className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5" />
          </div>
        </div>
      </SlideInPanel>

      {/* Control editor panel */}
      <SlideInPanel
        open={controlPanel.open}
        onClose={() => setControlPanel(p => ({ ...p, open: false }))}
        width={480}
        eyebrow={editing?.name ?? 'Custom framework'}
        title={controlPanel.index === null ? 'Add control' : `Edit ${controlPanel.draft.id}`}
        footer={
          <>
            <button
              onClick={() => {
                const d = controlPanel.draft
                if (!d.id.trim() || !d.title.trim()) { toast.error('ID and title are required'); return }
                const dup = controls.some((c, j) => c.id === d.id.trim() && j !== controlPanel.index)
                if (dup) { toast.error(`Control id ${d.id} already exists`); return }
                const clean = { ...d, id: d.id.trim(), title: d.title.trim() }
                setControls(controlPanel.index === null
                  ? [...controls, clean]
                  : controls.map((c, j) => j === controlPanel.index ? clean : c))
                setDirty(true)
                setControlPanel(p => ({ ...p, open: false }))
              }}
              className="px-4 py-1.5 bg-[var(--accent)] hover:opacity-90 text-white text-sm"
            >
              {controlPanel.index === null ? 'Add' : 'Apply'}
            </button>
            <button onClick={() => setControlPanel(p => ({ ...p, open: false }))}
              className="px-3 py-1.5 text-[var(--text-secondary)] text-sm">Cancel</button>
          </>
        }
      >
        <div className="space-y-3">
          <div className="flex gap-2">
            <div className="w-32">
              <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">ID</label>
              <input value={controlPanel.draft.id}
                onChange={e => setControlPanel(p => ({ ...p, draft: { ...p.draft, id: e.target.value } }))}
                placeholder="POL-1" className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5 font-mono" />
            </div>
            <div className="flex-1">
              <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Family</label>
              <input value={controlPanel.draft.family}
                onChange={e => setControlPanel(p => ({ ...p, draft: { ...p.draft, family: e.target.value } }))}
                placeholder="e.g. ACCESS" className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5" />
            </div>
          </div>
          <div>
            <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Title</label>
            <input value={controlPanel.draft.title}
              onChange={e => setControlPanel(p => ({ ...p, draft: { ...p.draft, title: e.target.value } }))}
              className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5" />
          </div>
          <div>
            <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Requirement text</label>
            <textarea value={controlPanel.draft.description} rows={4}
              onChange={e => setControlPanel(p => ({ ...p, draft: { ...p.draft, description: e.target.value } }))}
              className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5" />
          </div>
          <div>
            <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Guidance (optional)</label>
            <textarea value={controlPanel.draft.supplemental_guidance} rows={2}
              onChange={e => setControlPanel(p => ({ ...p, draft: { ...p.draft, supplemental_guidance: e.target.value } }))}
              className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5" />
          </div>
        </div>
      </SlideInPanel>

      <ConfirmDialog
        open={!!confirmDeleteFw}
        title="Delete Custom Framework"
        message={`Delete "${customs.find(c => c.id === confirmDeleteFw)?.name ?? confirmDeleteFw}" and its controls? This cannot be undone.`}
        onConfirm={() => { if (confirmDeleteFw) deleteMut.mutate(confirmDeleteFw); setConfirmDeleteFw(null) }}
        onCancel={() => setConfirmDeleteFw(null)}
      />
    </div>
  )
}
