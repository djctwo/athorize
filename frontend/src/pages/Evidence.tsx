import { useId, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, getCsrfToken, responseError } from '../lib/api'
import { useCan } from '../hooks/useRole'
import { useUserStore } from '../store/userStore'
import type { EvidenceArtifact, System } from '../types'
import { Upload, Trash2, FileCheck, UserCheck } from 'lucide-react'
import EvidenceDetailPanel from '../components/EvidenceDetailPanel'
import ConfirmDialog from '../components/ConfirmDialog'
import { toast } from '../store/toastStore'
import SavedViews from '../components/SavedViews'
import SortHeader from '../components/SortHeader'
import { useSorted } from '../lib/useSort'
import { daysUntil } from '../lib/datetime'

type EvidenceSortKey = 'created_at' | 'owner_name'

// R2USER-11: every artifact used to get 365 days, so a quarterly scan counted as
// fresh for a year. Defaults follow the type; the user can change them.
const DEFAULT_EXPIRY_DAYS: Record<string, number> = {
  POLICY: 365, SCAN_RESULT: 90, SCREENSHOT: 90, LOG: 90, DIAGRAM: 365, ATTESTATION: 365, OTHER: 365,
}

function expiryHint(days: string): string {
  const n = Number(days)
  if (!Number.isInteger(n) || n < 1 || n > 3650) return 'Enter 1–3650 days.'
  const d = new Date()
  d.setDate(d.getDate() + n)
  return `Expires ${d.toLocaleDateString()}.`
}

export default function Evidence() {
  const [showUpload, setShowUpload] = useState(false)
  const canUpload = useCan('upload:evidence')
  const canDelete = useCan('delete:evidence')
  const [detail, setDetail] = useState<EvidenceArtifact | null>(null)
  const [systemId, setSystemId] = useState(0)
  const [description, setDescription] = useState('')
  const [artifactType, setArtifactType] = useState('OTHER')
  const [expiryDays, setExpiryDays] = useState(String(DEFAULT_EXPIRY_DAYS.OTHER))
  const [file, setFile] = useState<File | null>(null)
  const [mineOnly, setMineOnly] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState<EvidenceArtifact | null>(null)
  const uid = useId()
  const { user } = useUserStore()
  const queryClient = useQueryClient()

  const { data: evidence = [] } = useQuery({
    queryKey: ['evidence', mineOnly, user?.id],
    queryFn: () => {
      const params = new URLSearchParams()
      if (mineOnly && user?.id) params.set('owner_id', String(user.id))
      return api.get<EvidenceArtifact[]>(`/evidence?${params}`)
    },
  })

  // Server order is created_at desc; the Owner header re-sorts client-side.
  const { data: rows, sort, toggle } = useSorted<EvidenceArtifact, EvidenceSortKey>(evidence, 'created_at', 'desc')

  const { data: systems = [] } = useQuery({
    queryKey: ['systems'],
    queryFn: () => api.get<System[]>('/systems'),
  })

  const upload = useMutation({
    mutationFn: async () => {
      if (!file) return
      // R2USER-21: the placeholder used to be a valid-looking 0, so the browser's
      // `required` check passed and the server answered "System not found".
      if (!systemId) throw new Error('Choose the system this evidence belongs to.')
      const formData = new FormData()
      formData.append('file', file)
      formData.append('system_id', String(systemId))
      formData.append('description', description)
      formData.append('artifact_type', artifactType)
      formData.append('expiration_days', expiryDays)
      const res = await fetch('/api/evidence/upload', {
        method: 'POST',
        body: formData,
        credentials: 'include',
        headers: { 'X-CSRF-Token': getCsrfToken() },
      })
      if (!res.ok) throw await responseError(res)
      return res.json()
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['evidence'] })
      setShowUpload(false)
      setFile(null)
      setDescription('')
      toast.success('Evidence uploaded')
    },
    // 415 wrong type / 413 too large / 404 out of scope — say so (E2E-18).
    onError: (e) => toast.error(`Upload failed: ${e instanceof Error ? e.message : 'unknown error'}`),
  })

  const remove = useMutation({
    mutationFn: (id: number) => api.delete(`/evidence/${id}`),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['evidence'] })
      toast.success('Evidence deleted')
    },
    onError: (e) => toast.error(`Delete failed: ${e instanceof Error ? e.message : 'unknown error'}`),
  })

  function freshness(item: EvidenceArtifact): { label: string; color: string } {
    if (!item.expiration_date) return { label: 'No expiry', color: 'text-text-muted' }
    const days = daysUntil(item.expiration_date)
    if (days === null) return { label: 'No expiry', color: 'text-text-muted' }
    if (days < 0) return { label: 'EXPIRED', color: 'text-danger' }
    if (days < 30) return { label: `${days}d left`, color: 'text-warning' }
    return { label: 'Fresh', color: 'text-success' }
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold">Evidence Vault</h2>
        {canUpload && (
          <button onClick={() => { upload.reset(); setShowUpload(true) }} className="flex items-center gap-2 px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm">
            <Upload size={16} /> Upload
          </button>
        )}
      </div>

      {showUpload && (
        <div className="bg-bg-secondary border border-border p-4 mb-6">
          <h3 className="text-sm font-semibold mb-3">Upload Evidence</h3>
          <form onSubmit={(e) => { e.preventDefault(); upload.mutate() }} className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-text-muted mb-1" htmlFor={`${uid}-system`}>System</label>
              <select id={`${uid}-system`} className="w-full" value={systemId || ''} onChange={(e) => setSystemId(Number(e.target.value) || 0)} required>
                <option value="" disabled>Select system...</option>
                {systems.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-text-muted mb-1" htmlFor={`${uid}-type`}>Type</label>
              <select id={`${uid}-type`} className="w-full" value={artifactType} onChange={(e) => {
                setArtifactType(e.target.value)
                setExpiryDays(String(DEFAULT_EXPIRY_DAYS[e.target.value] ?? 365))
              }}>
                <option value="POLICY">Policy</option>
                <option value="SCAN_RESULT">Scan Result</option>
                <option value="SCREENSHOT">Screenshot</option>
                <option value="LOG">Log</option>
                <option value="DIAGRAM">Diagram</option>
                <option value="ATTESTATION">Attestation</option>
                <option value="OTHER">Other</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-text-muted mb-1" htmlFor={`${uid}-expiry`}>Expires in (days)</label>
              <input id={`${uid}-expiry`} type="number" min={1} max={3650} className="w-full" value={expiryDays}
                onChange={(e) => setExpiryDays(e.target.value)} required aria-describedby={`${uid}-expiry-hint`} />
              <p id={`${uid}-expiry-hint`} className="text-xs text-text-muted mt-1">
                {expiryHint(expiryDays)} Scans and logs default to 90 days, policies and other documents to a year.
              </p>
            </div>
            <div className="sm:col-span-2">
              <label className="block text-xs text-text-muted mb-1" htmlFor={`${uid}-description`}>Description</label>
              <input id={`${uid}-description`} className="w-full" value={description} onChange={(e) => setDescription(e.target.value)} />
            </div>
            <div className="sm:col-span-2">
              <label className="block text-xs text-text-muted mb-1" htmlFor={`${uid}-file`}>File</label>
              <input id={`${uid}-file`} type="file" onChange={(e) => setFile(e.target.files?.[0] || null)} className="text-sm text-text-secondary" required />
            </div>
            {upload.isError && (
              <div role="alert" className="sm:col-span-2 text-sm text-danger p-2 bg-danger/10 border border-danger/20">
                {upload.error instanceof Error ? upload.error.message : 'Upload failed'}
              </div>
            )}
            <div className="sm:col-span-2 flex gap-2">
              <button type="submit" disabled={upload.isPending} className="px-4 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm disabled:opacity-50">
                {upload.isPending ? 'Uploading...' : 'Upload'}
              </button>
              <button type="button" onClick={() => setShowUpload(false)} className="px-4 py-1.5 border border-border text-text-secondary text-sm hover:bg-bg-tertiary">Cancel</button>
            </div>
          </form>
        </div>
      )}

      <div className="flex gap-3 mb-4 items-end">
        <button
          onClick={() => setMineOnly(m => !m)}
          className={`text-sm px-3 py-1 border inline-flex items-center gap-1.5 ${mineOnly ? 'border-[var(--accent)] text-[var(--accent)] bg-[var(--accent)]/10' : 'border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'}`}
        >
          <UserCheck size={14} /> Assigned to me
        </button>
        <div className="ml-auto">
          <SavedViews
            page="evidence"
            current={{ mineOnly }}
            onApply={(p) => setMineOnly(!!p.mineOnly)}
          />
        </div>
      </div>

      <div className="bg-bg-secondary border border-border overflow-x-auto">
        <table>
          <thead>
            <tr>
              <th>Filename</th>
              <th>Type</th>
              <th>System</th>
              <SortHeader
                label="Owner"
                field="owner_name"
                active={sort.key === 'owner_name'}
                dir={sort.dir}
                onSort={() => toggle('owner_name')}
              />
              <th>Controls</th>
              <th>Frameworks</th>
              <th>Collected</th>
              <th>Freshness</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => {
              const f = freshness(e)
              const controls = e.control_ids || []
              const fws = e.framework_ids || []
              return (
                <tr key={e.id} onClick={() => setDetail(e)} className="cursor-pointer hover:bg-bg-tertiary">
                  <td className="font-medium flex items-center gap-2">
                    <FileCheck size={14} className="text-text-muted" />
                    {e.filename}
                  </td>
                  <td className="text-xs text-text-muted">{e.artifact_type}</td>
                  <td className="text-xs text-text-muted">{systems.find(s => s.id === e.system_id)?.name || e.system_id}</td>
                  <td className="text-xs text-text-muted">{e.owner_name || '—'}</td>
                  <td className="text-xs text-text-muted">
                    {controls.length > 0
                      ? controls.slice(0, 2).join(', ') + (controls.length > 2 ? ` +${controls.length - 2}` : '')
                      : '—'}
                  </td>
                  <td className="text-xs text-text-muted">{fws.length > 0 ? fws.length : '—'}</td>
                  <td className="text-xs text-text-muted">{e.date_collected || '—'}</td>
                  <td><span className={`text-xs font-medium ${f.color}`}>{f.label}</span></td>
                  <td className="text-right">
                    {canDelete && (
                      <button
                        onClick={(ev) => { ev.stopPropagation(); setConfirmDelete(e) }}
                        className="text-text-muted hover:text-danger"
                        aria-label={`Delete ${e.filename}`}
                        title="Delete"
                      >
                        <Trash2 size={14} />
                      </button>
                    )}
                  </td>
                </tr>
              )
            })}
            {rows.length === 0 && (
              <tr><td colSpan={9} className="text-center text-text-muted py-8">{mineOnly
                ? 'Nothing assigned to you — clear the "Assigned to me" filter to see all evidence.'
                : 'No evidence yet — upload artifacts and link them to the controls they satisfy. The platform tracks freshness and warns before they expire; the crosswalk then suggests where the same evidence applies in other frameworks.'}</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <ConfirmDialog
        open={confirmDelete !== null}
        title="Delete Evidence"
        message={`Delete "${confirmDelete?.filename ?? ''}" and its stored file? This cannot be undone, and the artifact will drop out of every control and audit binder it supports.`}
        confirmLabel="Delete"
        onConfirm={() => { if (confirmDelete) remove.mutate(confirmDelete.id); setConfirmDelete(null) }}
        onCancel={() => setConfirmDelete(null)}
      />

      <EvidenceDetailPanel
        open={detail !== null}
        onClose={() => setDetail(null)}
        artifact={detail ? evidence.find(e => e.id === detail.id) ?? detail : null}
        systems={systems}
      />
    </div>
  )
}
