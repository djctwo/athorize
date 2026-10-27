import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate, Link } from 'react-router-dom'
import { api } from '../lib/api'
import type { Framework, System } from '../types'
import { toast } from '../store/toastStore'
import { X, ArrowRight, ArrowLeft, Server, Check } from 'lucide-react'

const EMPTY = { name: '', acronym: '', description: '', environment: 'production', criticality: 'moderate', is_ot_enabled: false }

/**
 * Guided "add a system" flow: collect the basics, pick a framework to assess
 * against, then drop the user straight into the implementation grid for the new
 * system — instead of creating a system and leaving them at a list with no next
 * step. UX-first: the goal is to end in productive work, not on a form.
 */
export default function NewSystemWizard({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [step, setStep] = useState(1)
  const [form, setForm] = useState({ ...EMPTY })
  const [framework, setFramework] = useState('')
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const { data: frameworks = [] } = useQuery({ queryKey: ['frameworks'], queryFn: () => api.get<Framework[]>('/frameworks') })
  const active = frameworks.filter(f => f.is_active)

  const reset = () => { setStep(1); setForm({ ...EMPTY }); setFramework('') }
  const close = () => { reset(); onClose() }

  const create = useMutation({
    mutationFn: () => api.post<System>('/systems', form),
    onSuccess: (sys) => {
      queryClient.invalidateQueries({ queryKey: ['systems'] })
      queryClient.invalidateQueries({ queryKey: ['onboarding'] })
      toast.success(`System "${sys.acronym || sys.name}" created`)
      close()
      if (framework) navigate(`/controls?system=${sys.id}&framework=${framework}`)
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Could not create system'),
  })

  if (!open) return null

  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <div className="absolute inset-0 bg-black/30" onClick={close} />
      <div className="relative w-[460px] max-w-full bg-[var(--bg-secondary)] border-l border-[var(--border)] h-full overflow-y-auto">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[var(--border)]">
          <div className="flex items-center gap-2">
            <Server size={16} className="text-[var(--accent)]" />
            <h3 className="text-sm font-semibold text-[var(--text-primary)]">New system — step {step} of 2</h3>
          </div>
          <button onClick={close} aria-label="Close"><X size={16} className="text-[var(--text-secondary)] hover:text-[var(--text-primary)]" /></button>
        </div>

        {step === 1 && (
          <div className="p-5 space-y-3">
            <p className="text-xs text-[var(--text-secondary)]">The system is the thing you're authorizing — controls, evidence, and findings all attach to it.</p>
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1" htmlFor="wizard-name">Name *</label>
              <input id="wizard-name" autoFocus value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1" htmlFor="wizard-acronym">Acronym</label>
                <input id="wizard-acronym" value={form.acronym} onChange={e => setForm({ ...form, acronym: e.target.value })} className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5" />
              </div>
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1" htmlFor="wizard-environment">Environment</label>
                <select id="wizard-environment" value={form.environment} onChange={e => setForm({ ...form, environment: e.target.value })} className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5">
                  <option value="production">Production</option>
                  <option value="staging">Staging</option>
                  <option value="development">Development</option>
                </select>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3 items-end">
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1" htmlFor="wizard-criticality">Criticality</label>
                <select id="wizard-criticality" value={form.criticality} onChange={e => setForm({ ...form, criticality: e.target.value })} className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5">
                  <option value="low">Low</option>
                  <option value="moderate">Moderate</option>
                  <option value="high">High</option>
                </select>
              </div>
              <label className="flex items-center gap-2 text-xs text-[var(--text-secondary)] pb-1.5">
                <input type="checkbox" checked={form.is_ot_enabled} onChange={e => setForm({ ...form, is_ot_enabled: e.target.checked })} />
                OT / industrial system
              </label>
            </div>
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1" htmlFor="wizard-description">Description</label>
              <textarea id="wizard-description" rows={2} value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5" />
            </div>
            <div className="flex justify-end pt-2">
              <button onClick={() => setStep(2)} disabled={!form.name.trim()}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm bg-[var(--accent)] hover:opacity-90 text-white disabled:opacity-50">
                Next <ArrowRight size={14} />
              </button>
            </div>
          </div>
        )}

        {step === 2 && (
          <div className="p-5 space-y-3">
            <p className="text-xs text-[var(--text-secondary)]">Pick the framework you'll start assessing <b>{form.acronym || form.name}</b> against. You'll land right in the control grid for it.</p>
            {active.length === 0 ? (
              <div className="border border-[var(--warning)]/50 bg-[var(--warning)]/5 p-3 text-xs text-[var(--text-secondary)]">
                No frameworks are active yet. <Link to="/marketplace" onClick={close} className="text-[var(--accent)]">Activate one in the Marketplace</Link>, or create the system now and assess it later.
              </div>
            ) : (
              <div className="space-y-1.5 max-h-64 overflow-y-auto">
                {active.map(f => (
                  <label key={f.id} className={`flex items-center gap-2 px-3 py-2 border cursor-pointer ${framework === f.id ? 'border-[var(--accent)] bg-[var(--accent)]/10' : 'border-[var(--border)]'}`}>
                    <input type="radio" name="fw" checked={framework === f.id} onChange={() => setFramework(f.id)} />
                    <span className="text-sm text-[var(--text-primary)]">{f.name}</span>
                    {framework === f.id && <Check size={14} className="text-[var(--accent)] ml-auto" />}
                  </label>
                ))}
              </div>
            )}
            <div className="flex items-center justify-between pt-2">
              <button onClick={() => setStep(1)} className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]">
                <ArrowLeft size={14} /> Back
              </button>
              <button onClick={() => create.mutate()} disabled={create.isPending}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm bg-[var(--accent)] hover:opacity-90 text-white disabled:opacity-50">
                {create.isPending ? 'Creating…' : framework ? 'Create & start assessing' : 'Create system'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
