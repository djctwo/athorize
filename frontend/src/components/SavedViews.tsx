import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bookmark, X } from 'lucide-react'
import { api } from '../lib/api'
import { toast } from '../store/toastStore'

interface View {
  id: number
  page: string
  name: string
  params: Record<string, unknown>
}

interface Props {
  page: string
  /** Current filter state of the host page — saved verbatim. */
  current: Record<string, unknown>
  /** Apply a saved view's params back onto the host page. */
  onApply: (params: Record<string, unknown>) => void
}

/** Named filter sets ("views") for a list page. Server-stored per user. */
export default function SavedViews({ page, current, onApply }: Props) {
  const [naming, setNaming] = useState(false)
  const [name, setName] = useState('')
  const qc = useQueryClient()

  const { data: views = [] } = useQuery({
    queryKey: ['views', page],
    queryFn: () => api.get<View[]>(`/views?page=${encodeURIComponent(page)}`),
  })

  const saveMut = useMutation({
    mutationFn: () => api.post<View>('/views', { page, name: name.trim(), params: current }),
    onSuccess: (v) => {
      qc.invalidateQueries({ queryKey: ['views', page] })
      setNaming(false)
      setName('')
      toast.success(`View "${v.name}" saved`)
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Could not save view'),
  })
  const deleteMut = useMutation({
    mutationFn: (id: number) => api.delete(`/views/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['views', page] }),
  })

  return (
    <div className="flex items-end gap-2">
      {views.length > 0 && (
        <div>
          <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Views</div>
          <div className="flex items-center gap-1">
            <select
              value=""
              onChange={e => {
                const v = views.find(x => x.id === Number(e.target.value))
                if (v) onApply(v.params)
              }}
              className="bg-[var(--bg-secondary)] border border-[var(--border)] px-2 py-1 text-xs text-[var(--text-primary)]"
            >
              <option value="">Apply a view…</option>
              {views.map(v => <option key={v.id} value={v.id}>{v.name}</option>)}
            </select>
            {views.length > 0 && (
              <select
                value=""
                onChange={e => { if (e.target.value) deleteMut.mutate(Number(e.target.value)) }}
                className="bg-[var(--bg-secondary)] border border-[var(--border)] px-1 py-1 text-xs text-[var(--text-secondary)]"
                title="Delete a saved view"
              >
                <option value="">🗑</option>
                {views.map(v => <option key={v.id} value={v.id}>{v.name}</option>)}
              </select>
            )}
          </div>
        </div>
      )}
      {naming ? (
        <div className="flex items-center gap-1">
          <input
            autoFocus
            value={name}
            onChange={e => setName(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && name.trim()) saveMut.mutate()
              if (e.key === 'Escape') { setNaming(false); setName('') }
            }}
            placeholder="View name…"
            className="text-xs bg-[var(--bg-secondary)] border border-[var(--border)] px-2 py-1 text-[var(--text-primary)] w-32"
          />
          <button
            onClick={() => name.trim() && saveMut.mutate()}
            disabled={!name.trim() || saveMut.isPending}
            className="text-xs px-2 py-1 bg-[var(--accent)] text-white disabled:opacity-50"
          >
            Save
          </button>
          <button onClick={() => { setNaming(false); setName('') }} className="text-[var(--text-secondary)]">
            <X size={12} />
          </button>
        </div>
      ) : (
        <button
          onClick={() => setNaming(true)}
          className="flex items-center gap-1 text-xs px-2 py-1 border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--accent)] hover:border-[var(--accent)]"
          title="Save the current filters as a named view"
        >
          <Bookmark size={12} /> Save view
        </button>
      )}
    </div>
  )
}
