import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { formatDate } from '../lib/datetime'
import type { Assessment, System, Framework } from '../types'
import { Plus, ClipboardCheck, FileText } from 'lucide-react'
import { useCan } from '../hooks/useRole'
import { toast } from '../store/toastStore'

export default function Assessments() {
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ system_id: 0, framework_id: '', assessment_type: 'Annual Review', notes: '' })
  const queryClient = useQueryClient()
  // Backend gates create/update with require_min_role("assessor")
  const canAssess = useCan('edit:assessment')

  const { data: assessments = [] } = useQuery({
    queryKey: ['assessments'],
    queryFn: () => api.get<Assessment[]>('/assessments'),
  })

  const { data: systems = [] } = useQuery({
    queryKey: ['systems'],
    queryFn: () => api.get<System[]>('/systems'),
  })

  const { data: frameworks = [] } = useQuery({
    queryKey: ['frameworks'],
    queryFn: () => api.get<Framework[]>('/frameworks'),
  })

  const activeFrameworks = frameworks.filter(f => f.is_active)

  const create = useMutation({
    mutationFn: () => api.post('/assessments', form),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['assessments'] }); setShowForm(false) },
    onError: (e: Error) => toast.error(`Failed to create assessment: ${e.message}`),
  })

  const updateStatus = useMutation({
    mutationFn: ({ id, status }: { id: number; status: string }) => api.put(`/assessments/${id}`, { status }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['assessments'] }),
    onError: (e: Error) => toast.error(`Failed to update status: ${e.message}`),
  })

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold">Assessments</h2>
        {canAssess && (
          <button onClick={() => setShowForm(true)} className="flex items-center gap-2 px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm">
            <Plus size={16} /> New Assessment
          </button>
        )}
      </div>

      {showForm && (
        <div className="bg-bg-secondary border border-border p-4 mb-6">
          <form onSubmit={(e) => { e.preventDefault(); create.mutate() }} className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-text-muted mb-1">System</label>
              <select className="w-full" value={form.system_id} onChange={(e) => setForm({ ...form, system_id: Number(e.target.value) })} required>
                <option value={0}>Select system...</option>
                {systems.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-text-muted mb-1">Framework</label>
              <select className="w-full" value={form.framework_id} onChange={(e) => setForm({ ...form, framework_id: e.target.value })} required>
                <option value="">Select framework...</option>
                {activeFrameworks.map(f => <option key={f.id} value={f.id}>{f.name}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-text-muted mb-1">Type</label>
              <input className="w-full" value={form.assessment_type} onChange={(e) => setForm({ ...form, assessment_type: e.target.value })} />
            </div>
            <div>
              <label className="block text-xs text-text-muted mb-1">Notes</label>
              <input className="w-full" value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} />
            </div>
            <div className="col-span-2 flex gap-2">
              <button type="submit" className="px-4 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm">Create</button>
              <button type="button" onClick={() => setShowForm(false)} className="px-4 py-1.5 border border-border text-text-secondary text-sm hover:bg-bg-tertiary">Cancel</button>
            </div>
          </form>
        </div>
      )}

      <div className="bg-bg-secondary border border-border">
        <table>
          <thead>
            <tr>
              <th>System</th>
              <th>Framework</th>
              <th>Type</th>
              <th>Status</th>
              <th>Started</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {assessments.map((a) => (
              <tr key={a.id}>
                <td className="font-medium">{systems.find(s => s.id === a.system_id)?.name || a.system_id}</td>
                <td className="text-xs text-text-muted">{frameworks.find(f => f.id === a.framework_id)?.short_name || frameworks.find(f => f.id === a.framework_id)?.name || a.framework_id}</td>
                <td className="text-sm">{a.assessment_type}</td>
                <td><AssessmentStatus status={a.status} /></td>
                <td className="text-xs text-text-muted">{a.started_at ? formatDate(a.started_at) : '—'}</td>
                <td>
                  <div className="flex items-center gap-2">
                    {canAssess ? (
                      <select
                        className="text-xs bg-bg-tertiary border-0 py-0.5"
                        value={a.status}
                        onChange={(e) => updateStatus.mutate({ id: a.id, status: e.target.value })}
                      >
                        <option value="PLANNED">Planned</option>
                        <option value="IN_PROGRESS">In Progress</option>
                        <option value="COMPLETE">Complete</option>
                      </select>
                    ) : (
                      <span className="text-xs text-text-muted">—</span>
                    )}
                    <button
                      onClick={() => window.open(`/api/reports/assessment/${a.id}`, '_blank', 'noopener')}
                      title="Generate report (opens print-ready HTML in a new tab)"
                      className="flex items-center gap-1 px-2 py-0.5 text-xs border border-border text-text-secondary hover:bg-bg-tertiary"
                    >
                      <FileText size={12} /> Report
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {assessments.length === 0 && (
              <tr><td colSpan={6} className="text-center text-text-muted py-8">
                <ClipboardCheck size={32} className="mx-auto mb-2" />
                No assessments scheduled.
              </td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function AssessmentStatus({ status }: { status: string }) {
  const colors: Record<string, string> = { PLANNED: 'text-text-muted', IN_PROGRESS: 'text-warning', COMPLETE: 'text-success' }
  return <span className={`text-xs font-medium ${colors[status] || ''}`}>{status}</span>
}
