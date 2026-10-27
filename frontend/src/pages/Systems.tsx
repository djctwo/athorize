import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { formatDate } from '../lib/datetime'
import type { System } from '../types'
import { Plus, Pencil, Trash2, Wand2 } from 'lucide-react'
import { useCan } from '../hooks/useRole'
import { toast } from '../store/toastStore'
import ConfirmDialog from '../components/ConfirmDialog'
import NewSystemWizard from '../components/NewSystemWizard'

export default function Systems() {
  const [showForm, setShowForm] = useState(false)
  const [wizardOpen, setWizardOpen] = useState(false)
  const [editing, setEditing] = useState<System | null>(null)
  const [pendingDelete, setPendingDelete] = useState<System | null>(null)
  const [form, setForm] = useState({ name: '', acronym: '', description: '', system_type: '', environment: 'production', criticality: 'moderate', is_ot_enabled: false })
  const queryClient = useQueryClient()
  const canWrite = useCan('edit:system')
  const canDelete = useCan('delete:system')

  const { data: systems = [] } = useQuery({
    queryKey: ['systems'],
    queryFn: () => api.get<System[]>('/systems'),
  })

  const create = useMutation({
    mutationFn: () => api.post('/systems', form),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['systems'] }); resetForm() },
    onError: (e: Error) => toast.error(`Failed to create system: ${e.message}`),
  })

  const update = useMutation({
    mutationFn: () => api.patch(`/systems/${editing!.id}`, form),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['systems'] }); resetForm() },
    onError: (e: Error) => toast.error(`Failed to update system: ${e.message}`),
  })

  const remove = useMutation({
    mutationFn: (id: number) => api.delete(`/systems/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['systems'] }),
    onError: (e: Error) => toast.error(`Failed to delete system: ${e.message}`),
  })

  function resetForm() {
    setShowForm(false)
    setEditing(null)
    setForm({ name: '', acronym: '', description: '', system_type: '', environment: 'production', criticality: 'moderate', is_ot_enabled: false })
  }

  function startEdit(s: System) {
    setEditing(s)
    setForm({ name: s.name, acronym: s.acronym, description: s.description, system_type: s.system_type, environment: s.environment, criticality: s.criticality, is_ot_enabled: !!s.is_ot_enabled })
    setShowForm(true)
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold">Systems</h2>
        {canWrite && (
          <div className="flex items-center gap-2">
            <button onClick={() => setWizardOpen(true)} className="flex items-center gap-2 px-3 py-1.5 border border-accent text-accent hover:bg-accent/10 text-sm">
              <Wand2 size={16} /> Guided setup
            </button>
            <button onClick={() => { resetForm(); setShowForm(true) }} className="flex items-center gap-2 px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm">
              <Plus size={16} /> Add System
            </button>
          </div>
        )}
      </div>

      <NewSystemWizard open={wizardOpen} onClose={() => setWizardOpen(false)} />

      {showForm && (
        <div className="bg-bg-secondary border border-border p-4 mb-6">
          <h3 className="text-sm font-semibold mb-3">{editing ? 'Edit System' : 'New System'}</h3>
          <form onSubmit={(e) => { e.preventDefault(); editing ? update.mutate() : create.mutate() }} className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-text-muted mb-1" htmlFor="system-name">Name</label>
              <input id="system-name" className="w-full" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            </div>
            <div>
              <label className="block text-xs text-text-muted mb-1" htmlFor="system-acronym">Acronym</label>
              <input id="system-acronym" className="w-full" value={form.acronym} onChange={(e) => setForm({ ...form, acronym: e.target.value })} />
            </div>
            <div className="col-span-2">
              <label className="block text-xs text-text-muted mb-1" htmlFor="system-description">Description</label>
              <textarea id="system-description" className="w-full" rows={2} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            </div>
            <div>
              <label className="block text-xs text-text-muted mb-1" htmlFor="system-environment">Environment</label>
              <select id="system-environment" className="w-full" value={form.environment} onChange={(e) => setForm({ ...form, environment: e.target.value })}>
                <option value="production">Production</option>
                <option value="staging">Staging</option>
                <option value="development">Development</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-text-muted mb-1" htmlFor="system-criticality">Criticality</label>
              <select id="system-criticality" className="w-full" value={form.criticality} onChange={(e) => setForm({ ...form, criticality: e.target.value })}>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="moderate">Moderate</option>
                <option value="low">Low</option>
              </select>
            </div>
            <label className="col-span-2 flex items-center gap-2 text-sm text-text-secondary">
              {/* R2USER-19: OT could be set only in the guided wizard and never changed afterwards. */}
              <input type="checkbox" checked={form.is_ot_enabled} onChange={(e) => setForm({ ...form, is_ot_enabled: e.target.checked })} />
              OT / industrial system (includes industrial control assets)
            </label>
            <div className="col-span-2 flex gap-2">
              <button type="submit" className="px-4 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm">
                {editing ? 'Update' : 'Create'}
              </button>
              <button type="button" onClick={resetForm} className="px-4 py-1.5 border border-border text-text-secondary text-sm hover:bg-bg-tertiary">
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      <div className="bg-bg-secondary border border-border">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Acronym</th>
              <th>Environment</th>
              <th>Criticality</th>
              <th>Created</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {systems.map((s) => (
              <tr key={s.id}>
                <td className="font-medium">{s.name}</td>
                <td className="text-text-muted">{s.acronym}</td>
                <td><span className="px-2 py-0.5 text-xs bg-bg-tertiary">{s.environment}</span></td>
                <td><CriticalityBadge level={s.criticality} /></td>
                <td className="text-text-muted text-xs">{formatDate(s.created_at)}</td>
                <td className="text-right">
                  {canWrite && (
                    <button onClick={() => startEdit(s)} className="text-text-muted hover:text-accent mr-2" aria-label={`Edit ${s.name}`} title="Edit"><Pencil size={14} /></button>
                  )}
                  {canDelete && (
                    <button onClick={() => setPendingDelete(s)} className="text-text-muted hover:text-danger" aria-label={`Delete ${s.name}`} title="Delete"><Trash2 size={14} /></button>
                  )}
                </td>
              </tr>
            ))}
            {systems.length === 0 && (
              <tr><td colSpan={6} className="text-center text-text-muted py-8">No systems yet — register the system you're authorizing to begin. Everything else (controls, evidence, findings) attaches to a system. See Help → Getting Started for the setup order.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <ConfirmDialog
        open={pendingDelete !== null}
        title="Delete System"
        message={`Delete "${pendingDelete?.name}"? Its assets, findings, and implementations will be removed. This cannot be undone.`}
        confirmLabel="Delete"
        onConfirm={() => { if (pendingDelete) remove.mutate(pendingDelete.id); setPendingDelete(null) }}
        onCancel={() => setPendingDelete(null)}
      />
    </div>
  )
}

function CriticalityBadge({ level }: { level: string }) {
  const colors: Record<string, string> = {
    critical: 'text-danger',
    high: 'text-warning',
    moderate: 'text-accent',
    low: 'text-text-muted',
  }
  return <span className={`text-xs font-medium uppercase ${colors[level] || ''}`}>{level}</span>
}
