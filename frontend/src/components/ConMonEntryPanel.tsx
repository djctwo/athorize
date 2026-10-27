import { useEffect, useId, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import type { Framework, System } from '../types'
import { SlideInPanel } from './SlideInPanel'

const ACTIVITY_TYPES = [
  'VULNERABILITY_SCAN',
  'PATCH_REVIEW',
  'ACCOUNT_REVIEW',
  'CONFIG_REVIEW',
  'POLICY_REVIEW',
  'LOG_REVIEW',
  'INCIDENT_RESPONSE',
  'ACCESS_REVIEW',
  'USER_TRAINING',
  'RISK_ASSESSMENT',
  'BACKUP_VERIFICATION',
  'CONTINUITY_TEST',
  'OTHER',
] as const

interface Props {
  open: boolean
  onClose: () => void
}

// The user's LOCAL calendar date (toISOString() is the UTC date, which is
// "tomorrow" or "yesterday" for part of the day away from UTC).
const localToday = () => new Date().toLocaleDateString('en-CA')

export default function ConMonEntryPanel({ open, onClose }: Props) {
  const uid = useId()
  const fid = (name: string) => `${uid}-${name}`
  const [systemId, setSystemId] = useState<number | ''>('')
  const [frameworkId, setFrameworkId] = useState('')
  const [entryDate, setEntryDate] = useState(localToday())
  const [activityType, setActivityType] = useState('')
  const [description, setDescription] = useState('')
  const [performedBy, setPerformedBy] = useState('')
  const [findingsText, setFindingsText] = useState('')
  const [actionsTaken, setActionsTaken] = useState('')
  const [followUp, setFollowUp] = useState(false)
  const [followUpDate, setFollowUpDate] = useState('')
  const qc = useQueryClient()

  const { data: systems = [] } = useQuery<System[]>({
    queryKey: ['systems'],
    queryFn: () => api.get('/systems'),
  })
  const { data: frameworks = [] } = useQuery<Framework[]>({
    queryKey: ['frameworks'],
    queryFn: () => api.get('/frameworks'),
  })
  const activeFrameworks = frameworks.filter(f => f.is_active)

  const reset = () => {
    setSystemId('')
    setFrameworkId('')
    setEntryDate(localToday())
    setActivityType('')
    setDescription('')
    setPerformedBy('')
    setFindingsText('')
    setActionsTaken('')
    setFollowUp(false)
    setFollowUpDate('')
  }

  useEffect(() => {
    if (open) reset()
  }, [open])

  const createMut = useMutation({
    mutationFn: () => api.post('/conmon', {
      system_id: systemId,
      // '' = org-wide; a framework id satisfies that framework's cadence too.
      framework_id: frameworkId,
      entry_date: entryDate,
      activity_type: activityType,
      description,
      // Optional text fields: blank is "", never null (the API rejected null — E2E-4).
      performed_by: performedBy,
      findings: findingsText,
      actions_taken: actionsTaken,
      follow_up_required: followUp,
      follow_up_date: followUp && followUpDate ? followUpDate : null,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['conmon'] })
      // The overdue banner and the dashboard KPI read these (E2E-21).
      qc.invalidateQueries({ queryKey: ['conmon-cadences'] })
      qc.invalidateQueries({ queryKey: ['dashboard'] })
      reset()
      onClose()
    },
  })

  const canSubmit = !createMut.isPending && systemId !== '' && !!entryDate && !!activityType && !!description.trim()

  return (
    <SlideInPanel open={open} onClose={onClose} title="Log ConMon Activity" width={520}>
      <form
        onSubmit={(e) => { e.preventDefault(); createMut.mutate() }}
        className="flex flex-col gap-4"
      >
        <div>
          <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1" htmlFor={fid('system')}>System</label>
          <select
            id={fid('system')}
            className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
            value={systemId}
            onChange={(e) => setSystemId(e.target.value === '' ? '' : Number(e.target.value))}
            required
          >
            <option value="">Select…</option>
            {systems.map(s => (
              <option key={s.id} value={s.id}>{s.acronym} — {s.name}</option>
            ))}
          </select>
        </div>

        <div>
          <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1" htmlFor={fid('framework')}>Framework</label>
          <select
            id={fid('framework')}
            className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
            value={frameworkId}
            onChange={(e) => setFrameworkId(e.target.value)}
          >
            <option value="">Org-wide (all frameworks)</option>
            {activeFrameworks.map(f => (
              <option key={f.id} value={f.id}>{f.short_name || f.name}</option>
            ))}
          </select>
          <p className="text-[11px] text-[var(--text-secondary)] mt-1">
            Org-wide entries count toward every framework's cadence for this activity. Pick a framework when the activity was done only for it (e.g. a PCI DSS ASV scan); framework entries also count org-wide.
          </p>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1" htmlFor={fid('date')}>Date</label>
            <input
              id={fid('date')}
              type="date"
              className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
              value={entryDate}
              onChange={(e) => setEntryDate(e.target.value)}
              required
            />
          </div>
          <div>
            <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1" htmlFor={fid('type')}>Activity Type</label>
            <select
              id={fid('type')}
              className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
              value={activityType}
              onChange={(e) => setActivityType(e.target.value)}
              required
            >
              <option value="">Select…</option>
              {ACTIVITY_TYPES.map(t => (
                <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>
              ))}
            </select>
          </div>
        </div>

        <div>
          <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1" htmlFor={fid('description')}>Description</label>
          <textarea
              id={fid('description')}
            className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5 min-h-[80px]"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            required
          />
        </div>

        <div>
          <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1" htmlFor={fid('performed-by')}>Performed By</label>
          <input
              id={fid('performed-by')}
            className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
            value={performedBy}
            onChange={(e) => setPerformedBy(e.target.value)}
          />
        </div>

        <div>
          <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1" htmlFor={fid('findings')}>Findings</label>
          <textarea
              id={fid('findings')}
            className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5 min-h-[40px]"
            value={findingsText}
            onChange={(e) => setFindingsText(e.target.value)}
          />
        </div>

        <div>
          <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1" htmlFor={fid('actions')}>Actions Taken</label>
          <textarea
              id={fid('actions')}
            className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5 min-h-[40px]"
            value={actionsTaken}
            onChange={(e) => setActionsTaken(e.target.value)}
          />
        </div>

        <div className="flex items-center gap-4">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={followUp}
              onChange={(e) => setFollowUp(e.target.checked)}
              className="accent-[var(--accent)]"
            />
            <span className="text-[var(--text-secondary)]">Follow-up required</span>
          </label>
          {followUp && (
            <input
              type="date"
              aria-label="Follow-up date"
              className="text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1"
              value={followUpDate}
              onChange={(e) => setFollowUpDate(e.target.value)}
            />
          )}
        </div>

        {createMut.isError && (
          <div role="alert" className="text-[var(--danger)] text-xs">{createMut.error?.message}</div>
        )}

        <div className="flex items-center gap-2 pt-2 border-t border-[var(--border)]">
          <button type="submit" disabled={!canSubmit} className="px-4 py-1.5 bg-[var(--accent)] text-white text-sm disabled:opacity-40">
            Log Activity
          </button>
          <button type="button" onClick={onClose} className="px-4 py-1.5 border border-[var(--border)] text-[var(--text-secondary)] text-sm hover:bg-[var(--bg-tertiary)]">
            Cancel
          </button>
        </div>
      </form>
    </SlideInPanel>
  )
}
