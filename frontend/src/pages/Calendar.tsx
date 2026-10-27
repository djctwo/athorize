import { useId, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { formatDate, parseApiDate } from '../lib/datetime'
import { useCan } from '../hooks/useRole'
import type { CalendarEvent } from '../types'
import { Link } from 'react-router-dom'
import { Plus, CalendarDays, Trash2 } from 'lucide-react'
import { Pill } from '../components/Pill'
import { toast } from '../store/toastStore'

export default function Calendar() {
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ title: '', event_date: '', event_type: 'CUSTOM', description: '' })
  const queryClient = useQueryClient()
  const uid = useId()
  const canAdd = useCan('edit:calendar')
  const canDelete = useCan('delete:calendar')
  const [showDerived, setShowDerived] = useState(true)
  const [upcomingLimit, setUpcomingLimit] = useState(40)

  const { data: events = [] } = useQuery({
    queryKey: ['calendar'],
    queryFn: () => api.get<CalendarEvent[]>('/calendar'),
  })

  const create = useMutation({
    mutationFn: () => api.post('/calendar', form),
    onSuccess: () => { queryClient.invalidateQueries({ queryKey: ['calendar'] }); setShowForm(false) },
    onError: (e) => toast.error(`Could not add event: ${e instanceof Error ? e.message : 'unknown error'}`),
  })

  const remove = useMutation({
    mutationFn: (id: number) => api.delete(`/calendar/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['calendar'] }),
    onError: (e) => toast.error(`Could not delete event: ${e instanceof Error ? e.message : 'unknown error'}`),
  })

  // event_date is a YYYY-MM-DD string; comparing parsed Dates against now()
  // puts today's events in "past" for any timezone east of UTC
  const today = new Date().toLocaleDateString('en-CA')
  const shown = showDerived ? events : events.filter(e => e.source !== 'derived')
  const allUpcoming = shown.filter(e => e.event_date >= today)
  const upcoming = allUpcoming.slice(0, upcomingLimit)
  // newest first: an overdue deadline from yesterday matters more than one from last quarter
  const past = shown.filter(e => e.event_date < today).reverse().slice(0, 15)
  const derivedCount = events.filter(e => e.source === 'derived').length

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold">Calendar</h2>
        {canAdd && (
          <button onClick={() => setShowForm(true)} className="flex items-center gap-2 px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm">
            <Plus size={16} /> Add Event
          </button>
        )}
      </div>

      {showForm && (
        <div className="bg-bg-secondary border border-border p-4 mb-6">
          <form onSubmit={(e) => { e.preventDefault(); create.mutate() }} className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="sm:col-span-2">
              <label className="block text-xs text-text-muted mb-1" htmlFor={`${uid}-title`}>Title</label>
              <input id={`${uid}-title`} className="w-full" value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} required />
            </div>
            <div>
              <label className="block text-xs text-text-muted mb-1" htmlFor={`${uid}-date`}>Date</label>
              <input id={`${uid}-date`} type="date" className="w-full" value={form.event_date} onChange={(e) => setForm({ ...form, event_date: e.target.value })} required />
            </div>
            <div>
              <label className="block text-xs text-text-muted mb-1" htmlFor={`${uid}-type`}>Type</label>
              <select id={`${uid}-type`} className="w-full" value={form.event_type} onChange={(e) => setForm({ ...form, event_type: e.target.value })}>
                <option value="DEADLINE">Deadline</option>
                <option value="REVIEW">Review</option>
                <option value="EXPIRATION">Expiration</option>
                <option value="ASSESSMENT">Assessment</option>
                <option value="CUSTOM">Custom</option>
              </select>
            </div>
            <div className="sm:col-span-2 flex gap-2">
              <button type="submit" className="px-4 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm">Create</button>
              <button type="button" onClick={() => setShowForm(false)} className="px-4 py-1.5 border border-border text-text-secondary text-sm hover:bg-bg-tertiary">Cancel</button>
            </div>
          </form>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3 mb-4 text-xs text-text-secondary">
        <label className="inline-flex items-center gap-2 cursor-pointer">
          <input type="checkbox" checked={showDerived} onChange={e => setShowDerived(e.target.checked)} />
          Show deadlines from findings, milestones, evidence, assessments and ConMon ({derivedCount})
        </label>
        <span className="text-text-muted">These are read-only — change them on their own page. Events you add here can be deleted.</span>
      </div>

      <div className="mb-6">
        <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-3">Upcoming</h3>
        {upcoming.length === 0 ? (
          <div className="bg-bg-secondary border border-border p-8 text-center text-text-muted">
            <CalendarDays size={32} className="mx-auto mb-2" />
            No upcoming events.
          </div>
        ) : (
          <div className="space-y-1">
            {upcoming.map(e => <EventRow key={eventKey(e)} e={e} canDelete={canDelete} onDelete={id => remove.mutate(id)} />)}
            {allUpcoming.length > upcoming.length && (
              <button type="button" onClick={() => setUpcomingLimit(n => n + 40)}
                className="w-full text-xs text-text-secondary border border-border py-2 hover:bg-bg-tertiary">
                Show {Math.min(40, allUpcoming.length - upcoming.length)} more of {allUpcoming.length - upcoming.length} remaining
              </button>
            )}
          </div>
        )}
      </div>

      {past.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-3">Past</h3>
          <div className="space-y-1 opacity-60">
            {past.map(e => <EventRow key={eventKey(e)} e={e} canDelete={false} onDelete={() => undefined} />)}
          </div>
        </div>
      )}
    </div>
  )
}

const DERIVED_LABEL: Record<string, string> = {
  FINDING_DUE: 'Finding due', MILESTONE: 'Milestone', EVIDENCE_EXPIRY: 'Evidence expiry',
  ASSESSMENT: 'Assessment', CONMON_DUE: 'ConMon',
}

function eventKey(e: CalendarEvent): string {
  return e.source === 'derived' ? `d:${e.derived_key}` : `m:${e.id}`
}

/** One calendar row. Derived deadlines (R2USER-4) are marked "Auto", link to
 * their source record and can't be deleted here. */
function EventRow({ e, canDelete, onDelete }: { e: CalendarEvent; canDelete: boolean; onDelete: (id: number) => void }) {
  const derived = e.source === 'derived'
  const title = derived && e.link
    ? <Link to={e.link} className="hover:text-accent">{e.title}</Link>
    : e.title
  return (
    <div className="bg-bg-secondary border border-border p-3 flex items-center gap-4" data-source={derived ? 'derived' : 'manual'}>
      <div className="text-center min-w-[50px]">
        <div className="text-xs text-text-muted">{formatDate(e.event_date, { month: 'short' }, 'en')}</div>
        <div className="text-lg font-bold">{parseApiDate(e.event_date)?.getDate()}</div>
      </div>
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium break-words">{title}</div>
        <div className="text-xs text-text-muted">
          {derived ? (DERIVED_LABEL[e.event_type] ?? e.event_type) : e.event_type}
          {e.description ? ` · ${e.description}` : ''}
        </div>
      </div>
      {derived && <Pill tone="info">Auto</Pill>}
      {!derived && canDelete && e.id !== null && (
        <button onClick={() => onDelete(e.id as number)} className="text-text-muted hover:text-danger" aria-label={`Delete ${e.title}`} title="Delete"><Trash2 size={14} /></button>
      )}
    </div>
  )
}
