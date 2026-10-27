import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Rss, Trash2 } from 'lucide-react'
import { api } from '../lib/api'
import { toast } from '../store/toastStore'
import { SlideInPanel } from './SlideInPanel'
import type { CustomFeed } from '../types'

interface Props {
  open: boolean
  onClose: () => void
}

const EMPTY_ROW: CustomFeed = { name: '', url: '', format: 'rss' }

export default function CustomFeedsPanel({ open, onClose }: Props) {
  const qc = useQueryClient()
  const [rows, setRows] = useState<CustomFeed[]>([])
  const [dirty, setDirty] = useState(false)

  const { data, isLoading } = useQuery({
    queryKey: ['custom-feeds'],
    queryFn: () => api.get<{ feeds: CustomFeed[] }>('/advisories/custom-feeds'),
    enabled: open,
  })

  useEffect(() => {
    if (open) {
      setRows(data?.feeds ?? [])
      setDirty(false)
    }
  }, [open, data])

  const save = useMutation({
    mutationFn: (feeds: CustomFeed[]) =>
      api.put<{ feeds: CustomFeed[] }>('/advisories/custom-feeds', { feeds }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['custom-feeds'] })
      qc.invalidateQueries({ queryKey: ['feed-status'] })
      qc.invalidateQueries({ queryKey: ['audit'] })
      setDirty(false)
      toast.success(
        res.feeds.length === 0
          ? 'Custom feeds cleared.'
          : `Saved ${res.feeds.length} custom feed${res.feeds.length === 1 ? '' : 's'}. They will be pulled on the next refresh.`
      )
      onClose()
    },
    onError: (e: Error) => toast.error(e.message),
  })

  const update = (idx: number, patch: Partial<CustomFeed>) => {
    setRows(rs => rs.map((r, i) => (i === idx ? { ...r, ...patch } : r)))
    setDirty(true)
  }

  const remove = (idx: number) => {
    setRows(rs => rs.filter((_, i) => i !== idx))
    setDirty(true)
  }

  const addRow = () => {
    setRows(rs => [...rs, { ...EMPTY_ROW }])
    setDirty(true)
  }

  const canSave = !save.isPending && rows.every(r => r.name.trim() && r.url.trim())

  return (
    <SlideInPanel
      open={open}
      onClose={onClose}
      width={640}
      eyebrow={<span className="inline-flex items-center gap-1.5"><Rss size={12} /> Threat advisories</span>}
      title="Custom feeds"
      subtitle="Additional advisory sources pulled on every feed refresh. Each source is labeled with the name you give it."
      footer={<>
        <button type="button" onClick={addRow}
          className="px-3 py-1.5 text-xs uppercase tracking-wider border border-[var(--border)] text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)] inline-flex items-center gap-1.5">
          <Plus size={12} /> Add feed
        </button>
        <div className="ml-auto flex gap-1.5 items-center">
          {dirty && <span className="text-[11px] text-[var(--text-secondary)]">Unsaved changes</span>}
          <button type="button" disabled={!canSave} onClick={() => save.mutate(rows)}
            className="px-3 py-1.5 text-xs uppercase tracking-wider border border-[var(--accent)] text-[var(--accent)] hover:bg-[var(--accent)]/10 disabled:opacity-40">
            {save.isPending ? 'Saving…' : 'Save feeds'}
          </button>
        </div>
      </>}
    >
      <div className="space-y-4">
        <div className="text-xs text-[var(--text-secondary)] leading-relaxed border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2">
          <span className="text-[var(--text-primary)]">RSS</span> — an advisory list feed (items become advisories).{' '}
          <span className="text-[var(--text-primary)]">CSAF</span> — a provider-metadata.json URL; the public ROLIE
          feed is walked and CSAF documents are parsed.
          <div className="mt-1">
            HTTPS only. Requests never leave the configured host, redirects are refused, and hosts that resolve
            to private or internal addresses are rejected. A broken feed is reported on refresh but never blocks
            the other feeds.
          </div>
        </div>

        {isLoading && <div className="text-sm text-[var(--text-secondary)]">Loading…</div>}

        {!isLoading && rows.length === 0 && (
          <div className="text-sm text-[var(--text-secondary)] italic">
            No custom feeds configured. Click "Add feed" to add an RSS or CSAF source.
          </div>
        )}

        {rows.map((row, idx) => (
          <div key={idx} className="border border-[var(--border)] p-3 space-y-3">
            <div className="grid grid-cols-[1fr_130px_32px] gap-3 items-end">
              <div>
                <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">
                  Name (source label)
                </label>
                <input
                  type="text"
                  value={row.name}
                  maxLength={100}
                  placeholder="e.g. Siemens PSIRT"
                  onChange={e => update(idx, { name: e.target.value })}
                  className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5 text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
                />
              </div>
              <div>
                <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">
                  Format
                </label>
                <select
                  value={row.format}
                  onChange={e => update(idx, { format: e.target.value as CustomFeed['format'] })}
                  className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5 text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
                >
                  <option value="rss">RSS</option>
                  <option value="csaf">CSAF</option>
                </select>
              </div>
              <button type="button" onClick={() => remove(idx)} title="Remove feed"
                className="inline-flex items-center justify-center h-[30px] text-[var(--text-secondary)] hover:text-[var(--risk-crit)]">
                <Trash2 size={14} />
              </button>
            </div>
            <div>
              <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">
                {row.format === 'csaf' ? 'Provider metadata URL (https)' : 'Feed URL (https)'}
              </label>
              <input
                type="url"
                value={row.url}
                maxLength={500}
                placeholder={row.format === 'csaf'
                  ? 'https://vendor.example.com/.well-known/csaf/provider-metadata.json'
                  : 'https://vendor.example.com/security/advisories.xml'}
                onChange={e => update(idx, { url: e.target.value })}
                className="w-full text-sm font-mono bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5 text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
              />
            </div>
          </div>
        ))}
      </div>
    </SlideInPanel>
  )
}
