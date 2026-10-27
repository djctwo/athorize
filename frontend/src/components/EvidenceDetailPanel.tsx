import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, downloadFile } from '../lib/api'
import type { EvidenceArtifact, Framework, System } from '../types'
import { SlideInPanel } from './SlideInPanel'
import { DetailRow } from './DetailRow'
import { Pill } from './Pill'
import { toast } from '../store/toastStore'
import { useCan } from '../hooks/useRole'
import { ArrowLeftRight, Download, Pencil, Plus } from 'lucide-react'

interface CrosswalkSuggestion {
  framework_id: string
  control_id: string
  title: string
  relationship: string
  confidence: string
  path: string
  source_framework_id: string
  source_control_id: string
}

interface Props {
  open: boolean
  onClose: () => void
  artifact: EvidenceArtifact | null
  systems: System[]
}

export default function EvidenceDetailPanel({ open, onClose, artifact, systems }: Props) {
  const [editing, setEditing] = useState(false)
  const [controlsInput, setControlsInput] = useState('')
  const [frameworkIds, setFrameworkIds] = useState<string[]>([])
  const [description, setDescription] = useState('')
  const [expiresOn, setExpiresOn] = useState('')
  const [downloading, setDownloading] = useState(false)
  const queryClient = useQueryClient()

  // PATCH /evidence (linkage, owner) needs upload:evidence — read-only roles
  // get a read-only panel instead of buttons that 403 (E2E-13).
  const canUpload = useCan('upload:evidence')

  const download = async () => {
    if (!artifact) return
    setDownloading(true)
    try {
      await downloadFile(`/evidence/${artifact.id}/download`, artifact.filename)
    } catch (e) {
      toast.error(`Download failed: ${e instanceof Error ? e.message : 'unknown error'}`)
    } finally {
      setDownloading(false)
    }
  }

  const { data: frameworks = [] } = useQuery({
    queryKey: ['frameworks'],
    queryFn: () => api.get<Framework[]>('/frameworks'),
  })
  const activeFrameworks = frameworks.filter(f => f.is_active)

  const { data: assignable = [] } = useQuery({
    queryKey: ['assignable-users'],
    queryFn: () => api.get<{ id: number; display_name: string }[]>('/users/assignable'),
    enabled: canUpload,
  })

  const setOwner = useMutation({
    mutationFn: (ownerId: number | null) =>
      api.patch(`/evidence/${artifact!.id}`, { owner_id: ownerId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['evidence'] })
      queryClient.invalidateQueries({ queryKey: ['my-work'] })
      toast.success('Refresh owner updated')
    },
    onError: (e) => toast.error(`Failed to set owner: ${e instanceof Error ? e.message : 'unknown error'}`),
  })

  const { data: suggestionData } = useQuery({
    queryKey: ['evidence-suggestions', artifact?.id],
    queryFn: () => api.get<{ suggestions: CrosswalkSuggestion[] }>(`/crosswalk/evidence/${artifact!.id}/suggestions`),
    enabled: !!artifact,
    staleTime: 60 * 1000,
  })
  const suggestions = suggestionData?.suggestions ?? []

  const acceptSuggestion = useMutation({
    mutationFn: (s: CrosswalkSuggestion) => {
      const controls = new Set(artifact!.control_ids || [])
      controls.add(s.control_id)
      const fws = new Set(artifact!.framework_ids || [])
      fws.add(s.framework_id)
      return api.patch(`/evidence/${artifact!.id}`, {
        control_ids: [...controls],
        framework_ids: [...fws],
      })
    },
    onSuccess: (_d, s) => {
      queryClient.invalidateQueries({ queryKey: ['evidence'] })
      queryClient.invalidateQueries({ queryKey: ['evidence-suggestions', artifact?.id] })
      toast.success(`Linked ${s.control_id} (${s.framework_id})`)
    },
    onError: (e) => toast.error(`Failed to add linkage: ${e instanceof Error ? e.message : 'unknown error'}`),
  })

  // Keyed on the id, not the object: query invalidation produces a fresh
  // artifact reference, and resetting on that would wipe in-progress edits.
  useEffect(() => {
    if (artifact) {
      setControlsInput((artifact.control_ids || []).join(', '))
      setFrameworkIds(artifact.framework_ids || [])
      setDescription(artifact.description || '')
      setExpiresOn(artifact.expiration_date || '')
      setEditing(false)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [artifact?.id])

  const save = useMutation({
    mutationFn: () =>
      api.patch(`/evidence/${artifact!.id}`, {
        description,
        control_ids: controlsInput.split(',').map(c => c.trim()).filter(Boolean),
        framework_ids: frameworkIds,
        // R2USER-11: the expiry is editable (a scan is stale long before a year).
        ...(expiresOn && expiresOn !== artifact!.expiration_date ? { expiration_date: expiresOn } : {}),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['evidence'] })
      // New linkage => new crosswalk suggestions; don't wait out the staleTime.
      queryClient.invalidateQueries({ queryKey: ['evidence-suggestions', artifact?.id] })
      toast.success('Evidence linkage updated')
      setEditing(false)
    },
    onError: (e) => toast.error(`Failed to update evidence: ${e instanceof Error ? e.message : 'unknown error'}`),
  })

  if (!artifact) return null

  const systemName = systems.find(s => s.id === artifact.system_id)?.name ?? `System #${artifact.system_id}`
  const fwName = (id: string) => frameworks.find(f => f.id === id)?.short_name || id

  return (
    <SlideInPanel
      open={open}
      onClose={onClose}
      eyebrow="Evidence Artifact"
      title={artifact.filename}
      subtitle={systemName}
      headerAccessory={
        !editing ? (
          <div className="flex items-center gap-2">
            <button
              onClick={download}
              disabled={downloading}
              className="flex items-center gap-1.5 px-2.5 py-1 text-xs border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--accent)] disabled:opacity-50"
              title="Download the stored file (its SHA-256 is re-checked first)"
            >
              <Download size={12} /> {downloading ? 'Downloading…' : 'Download'}
            </button>
            {canUpload && (
              <button
                onClick={() => { setExpiresOn(artifact.expiration_date || ''); setEditing(true) }}
                className="flex items-center gap-1.5 px-2.5 py-1 text-xs border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:border-[var(--accent)]"
              >
                <Pencil size={12} /> Edit Linkage
              </button>
            )}
          </div>
        ) : undefined
      }
      footer={
        editing ? (
          <div className="flex gap-2 px-5 py-3 border-t border-[var(--border)]">
            <button
              onClick={() => save.mutate()}
              disabled={save.isPending}
              className="px-4 py-1.5 bg-[var(--accent)] hover:opacity-90 text-white text-sm disabled:opacity-50"
            >
              {save.isPending ? 'Saving...' : 'Save'}
            </button>
            <button
              onClick={() => setEditing(false)}
              className="px-4 py-1.5 border border-[var(--border)] text-[var(--text-secondary)] text-sm hover:bg-[var(--bg-tertiary)]"
            >
              Cancel
            </button>
          </div>
        ) : undefined
      }
    >
      <DetailRow label="Type" value={<Pill tone="neutral">{artifact.artifact_type}</Pill>} />
      <DetailRow label="Collected" value={artifact.date_collected ?? '—'} />
      <DetailRow label="Expires" value={artifact.expiration_date ?? 'No expiry'} />
      <DetailRow
        label="Refresh Owner"
        value={
          canUpload ? (
            <select
              value={artifact.owner_id ?? ''}
              onChange={e => setOwner.mutate(e.target.value === '' ? null : Number(e.target.value))}
              disabled={setOwner.isPending}
              className="text-xs bg-[var(--bg-tertiary)] border border-[var(--border)] px-1.5 py-1"
              title="Who keeps this artifact fresh — appears in their My Work and expiry reminders"
            >
              <option value="">Unassigned</option>
              {assignable.map(u => <option key={u.id} value={u.id}>{u.display_name}</option>)}
            </select>
          ) : (
            <span className="text-[var(--text-secondary)]">
              {assignable.find(u => u.id === artifact.owner_id)?.display_name ?? (artifact.owner_id ? `User #${artifact.owner_id}` : 'Unassigned')}
            </span>
          )
        }
      />
      <DetailRow label="SHA-256" value={<span className="font-mono text-xs">{artifact.file_hash}</span>} />

      {editing ? (
        <>
          <div className="py-3 border-b border-[var(--border)]">
            <label htmlFor={`ev-${artifact.id}-description`} className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1.5">
              Description
            </label>
            <input
              id={`ev-${artifact.id}-description`}
              className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
              value={description}
              onChange={e => setDescription(e.target.value)}
            />
          </div>
          <div className="py-3 border-b border-[var(--border)]">
            <label htmlFor={`ev-${artifact.id}-expires`} className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1.5">
              Expires on
            </label>
            <input
              id={`ev-${artifact.id}-expires`}
              type="date"
              className="text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
              value={expiresOn}
              onChange={e => setExpiresOn(e.target.value)}
            />
            <p className="text-xs text-[var(--text-secondary)] mt-1">After this date the artifact counts as stale in freshness and readiness.</p>
          </div>
          <div className="py-3 border-b border-[var(--border)]">
            <label htmlFor={`ev-${artifact.id}-controls`} className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1.5">
              Linked Controls (comma-separated)
            </label>
            <input
              id={`ev-${artifact.id}-controls`}
              className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
              placeholder="e.g. AC-2, 8.3.6, A.5.16"
              value={controlsInput}
              onChange={e => setControlsInput(e.target.value)}
            />
          </div>
          <div className="py-3 border-b border-[var(--border)]">
            <label className="block text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1.5">
              Satisfies Frameworks
            </label>
            <div className="space-y-1.5">
              {activeFrameworks.map(f => (
                <label key={f.id} className="flex items-center gap-2 text-sm text-[var(--text-primary)] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={frameworkIds.includes(f.id)}
                    onChange={e =>
                      setFrameworkIds(prev =>
                        e.target.checked ? [...prev, f.id] : prev.filter(id => id !== f.id)
                      )
                    }
                  />
                  {f.short_name || f.name}
                </label>
              ))}
              {activeFrameworks.length === 0 && (
                <p className="text-xs text-[var(--text-secondary)]">No active frameworks.</p>
              )}
            </div>
          </div>
        </>
      ) : (
        <>
          <DetailRow label="Description" value={artifact.description || '—'} />
          <DetailRow
            label="Linked Controls"
            value={
              (artifact.control_ids || []).length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {artifact.control_ids.map(c => (
                    <Pill key={c} tone="info">{c}</Pill>
                  ))}
                </div>
              ) : (
                <span className="text-[var(--text-secondary)]">No controls linked</span>
              )
            }
          />
          <DetailRow
            label="Satisfies"
            value={
              (artifact.framework_ids || []).length > 0 ? (
                <div className="flex flex-wrap gap-1.5">
                  {artifact.framework_ids.map(id => (
                    <Pill key={id} tone="ok">{fwName(id)}</Pill>
                  ))}
                </div>
              ) : (
                <span className="text-[var(--text-secondary)]">No frameworks tagged</span>
              )
            }
          />
          {(artifact.framework_ids || []).length > 1 && (
            <p className="mt-3 text-xs text-[var(--text-secondary)]">
              This artifact satisfies controls across {artifact.framework_ids.length} frameworks — collected once, reused everywhere.
            </p>
          )}

          {suggestions.length > 0 && (
            <div className="mt-4 pt-3 border-t border-[var(--border)]">
              <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-2">
                <ArrowLeftRight size={12} />
                Suggested by Crosswalk
              </div>
              <p className="text-xs text-[var(--text-secondary)] mb-2">
                Based on its current linkage, this evidence likely also satisfies:
              </p>
              <div className="space-y-1.5">
                {suggestions.map(s => (
                  <div
                    key={`${s.framework_id}:${s.control_id}`}
                    className="flex items-center gap-2 text-xs border border-[var(--border)] px-2 py-1.5"
                  >
                    <span className="font-mono text-[var(--text-primary)]">{s.control_id}</span>
                    {s.title && <span className="text-[var(--text-secondary)] truncate max-w-[160px]">{s.title}</span>}
                    <Pill tone="neutral">{fwName(s.framework_id)}</Pill>
                    <span
                      className="text-[10px] uppercase tracking-wider text-[var(--text-secondary)]"
                      title={`${s.relationship} · ${s.confidence}${s.path !== 'direct' ? ` · ${s.path}` : ''} · from ${s.source_control_id}`}
                    >
                      {s.relationship}{s.confidence === 'derived' ? ' · via hub' : ''}
                    </span>
                    {canUpload && (
                      <button
                        onClick={() => acceptSuggestion.mutate(s)}
                        disabled={acceptSuggestion.isPending}
                        className="ml-auto inline-flex items-center gap-1 px-2 py-0.5 border border-[var(--accent)] text-[var(--accent)] hover:bg-[var(--accent)]/10 disabled:opacity-40"
                      >
                        <Plus size={10} /> Link
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </SlideInPanel>
  )
}
