import { useCallback, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Upload, FileText, Check, Loader2 } from 'lucide-react'
import { SlideInPanel } from './SlideInPanel'
import { toast } from '../store/toastStore'
import type { System } from '../types'
import { api, getCsrfToken, responseError } from '../lib/api'
import { formatDate } from '../lib/datetime'
import { plural } from '../lib/plural'

interface SiemFormat {
  key: string
  label: string
  extensions: string[]
  description: string
  source_type?: string
  source_label?: string
}

/** Counts every import response carries (server: services/import_common.RowReport). */
export interface ImportAccounting {
  merged_duplicates?: number
  skipped_rows?: number
  skip_reasons?: Record<string, number>
  truncated?: boolean
  truncated_count?: number
  max_rows?: number
  warnings?: string[]
}

// Used until /siem/formats loads; the server list is the source of truth.
const FALLBACK_EXTENSIONS = ['.csv', '.json', '.ndjson', '.log', '.txt', '.xml']

export function acceptFromFormats(formats: { extensions: string[] }[]): string {
  const exts = formats.flatMap(f => f.extensions)
  return [...new Set(exts.length ? exts : FALLBACK_EXTENSIONS)].join(',')
}

interface PreviewItem {
  title: string
  severity: string
  description: string
  is_duplicate: boolean
  extra_data: Record<string, unknown>
}

interface PreviewResult extends ImportAccounting {
  format: string
  total_parsed: number
  new_count: number
  duplicate_count: number
  preview: PreviewItem[]
  system_id: number
  framework_id: string
}

interface ConfirmResult extends ImportAccounting {
  format: string
  created: number
  skipped: number
  total_parsed: number
}

interface ImportHistory {
  id: number
  actor: string
  summary: string
  system_id: number | null
  created_at: string | null
}

const SEV_TONE: Record<string, string> = {
  CRITICAL: 'text-[var(--risk-crit)]',
  HIGH: 'text-[var(--risk-high)]',
  MEDIUM: 'text-[var(--risk-med)]',
  LOW: 'text-[var(--risk-low)]',
}

interface Props {
  open: boolean
  onClose: () => void
}

export function SiemImportPanel({ open, onClose }: Props) {
  const qc = useQueryClient()

  const [file, setFile] = useState<File | null>(null)
  const [systemId, setSystemId] = useState<number | ''>('')
  const [frameworkId, setFrameworkId] = useState('')
  const [formatOverride, setFormatOverride] = useState('')
  const [preview, setPreview] = useState<PreviewResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [result, setResult] = useState<ConfirmResult | null>(null)
  const [dragOver, setDragOver] = useState(false)

  const { data: systems = [] } = useQuery({
    queryKey: ['systems'],
    queryFn: () => api.get<System[]>('/systems'),
  })

  const { data: formats = [] } = useQuery({
    queryKey: ['siem-formats'],
    queryFn: () => api.get<SiemFormat[]>('/siem/formats'),
  })

  const { data: history = [] } = useQuery({
    queryKey: ['siem-history'],
    queryFn: () => api.get<ImportHistory[]>('/siem/import/history'),
    enabled: open,
  })

  const { data: frameworks = [] } = useQuery<{ id: string; name: string }[]>({
    queryKey: ['active-frameworks'],
    queryFn: () => api.get('/frameworks'),
  })

  const reset = useCallback(() => {
    setFile(null)
    setPreview(null)
    setResult(null)
    setLoading(false)
    setConfirming(false)
  }, [])

  const handleClose = useCallback(() => {
    reset()
    onClose()
  }, [reset, onClose])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const f = e.dataTransfer.files[0]
    if (f) {
      setFile(f)
      setPreview(null)
      setResult(null)
    }
  }, [])

  const handleFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (f) {
      setFile(f)
      setPreview(null)
      setResult(null)
    }
  }, [])

  const handlePreview = async () => {
    if (!file || !systemId || !frameworkId) return
    setLoading(true)
    try {
      const form = new FormData()
      form.append('file', file)
      form.append('system_id', String(systemId))
      form.append('framework_id', frameworkId)
      if (formatOverride) form.append('format_override', formatOverride)

      const headers: Record<string, string> = {}
      const token = getCsrfToken()
      if (token) headers['X-CSRF-Token'] = token

      const res = await fetch('/api/siem/import', {
        method: 'POST',
        credentials: 'include',
        headers,
        body: form,
      })
      if (!res.ok) throw await responseError(res)
      const data: PreviewResult = await res.json()
      setPreview(data)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Import preview failed')
    } finally {
      setLoading(false)
    }
  }

  const handleConfirm = async () => {
    if (!file || !systemId || !frameworkId) return
    setConfirming(true)
    try {
      const form = new FormData()
      form.append('file', file)
      form.append('system_id', String(systemId))
      form.append('framework_id', frameworkId)
      if (formatOverride) form.append('format_override', formatOverride)

      const headers: Record<string, string> = {}
      const token = getCsrfToken()
      if (token) headers['X-CSRF-Token'] = token

      const res = await fetch('/api/siem/import/confirm', {
        method: 'POST',
        credentials: 'include',
        headers,
        body: form,
      })
      if (!res.ok) throw await responseError(res)
      const data: ConfirmResult = await res.json()
      setResult(data)
      setPreview(null)
      const notes = [`${plural(data.skipped, 'duplicate')} skipped`]
      if (data.skipped_rows) notes.push(`${plural(data.skipped_rows, 'row')} skipped`)
      if (data.truncated_count) notes.push(`${data.truncated_count} not imported (row limit)`)
      const msg = `Imported ${plural(data.created, 'finding')} (${notes.join(', ')})`
      if (data.truncated) toast.info(msg)
      else toast.success(msg)
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['siem-history'] })
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Import failed')
    } finally {
      setConfirming(false)
    }
  }

  const accept = acceptFromFormats(formats)

  const activeFrameworks = (frameworks ?? []).filter((f: { id: string; name: string } & Record<string, unknown>) => (f as Record<string, unknown>).is_active !== false)

  return (
    <SlideInPanel
      open={open}
      onClose={handleClose}
      width={600}
      eyebrow="Security Evidence"
      title="Import SIEM / Scanner Output"
      subtitle="Parse security tool output into findings with network metadata"
    >
      <div className="space-y-4">
        {/* File upload */}
        <div
          onDragOver={e => { e.preventDefault(); setDragOver(true) }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          className={`border-2 border-dashed rounded p-6 text-center transition-colors ${
            dragOver ? 'border-[var(--accent)] bg-[var(--accent)]/5' : 'border-[var(--border)]'
          }`}
        >
          {file ? (
            <div className="flex items-center justify-center gap-2">
              <FileText size={16} className="text-[var(--accent)]" />
              <span className="text-sm text-[var(--text-primary)]">{file.name}</span>
              <span className="text-[11px] text-[var(--text-secondary)]">({(file.size / 1024).toFixed(1)} KB)</span>
              <button onClick={() => { setFile(null); setPreview(null); setResult(null) }}
                className="ml-2 text-[11px] text-[var(--text-secondary)] hover:text-[var(--risk-crit)]">Remove</button>
            </div>
          ) : (
            <label className="cursor-pointer">
              <Upload size={24} className="mx-auto mb-2 text-[var(--text-secondary)]" />
              <div className="text-sm text-[var(--text-secondary)]">
                Drop file here or <span className="text-[var(--accent)] underline">browse</span>
              </div>
              <div className="text-[11px] text-[var(--text-secondary)] mt-1">
                {accept.split(',').map(e => e.replace('.', '').toUpperCase()).join(', ')} — max 16 MiB
              </div>
              <input type="file" className="hidden" accept={accept} onChange={handleFileChange} />
            </label>
          )}
        </div>

        {/* System + Framework + Format selects */}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] block mb-1">System *</label>
            <select value={systemId} onChange={e => setSystemId(e.target.value ? Number(e.target.value) : '')}
              className="w-full bg-[var(--bg-primary)] border border-[var(--border)] px-2 py-1.5 text-xs text-[var(--text-primary)]">
              <option value="">Select system...</option>
              {systems.map(s => <option key={s.id} value={s.id}>{s.acronym} — {s.name}</option>)}
            </select>
          </div>
          <div>
            <label className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] block mb-1">Framework *</label>
            <select value={frameworkId} onChange={e => setFrameworkId(e.target.value)}
              className="w-full bg-[var(--bg-primary)] border border-[var(--border)] px-2 py-1.5 text-xs text-[var(--text-primary)]">
              <option value="">Select framework...</option>
              {activeFrameworks.map((f: { id: string; name: string }) => <option key={f.id} value={f.id}>{f.name}</option>)}
            </select>
          </div>
        </div>

        <div>
          <label className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] block mb-1">Format Override</label>
          <select value={formatOverride} onChange={e => setFormatOverride(e.target.value)}
            className="w-full bg-[var(--bg-primary)] border border-[var(--border)] px-2 py-1.5 text-xs text-[var(--text-primary)]">
            <option value="">Auto-detect</option>
            {formats.map(f => <option key={f.key} value={f.key}>{f.label} — {f.description}</option>)}
          </select>
        </div>

        {/* Preview button */}
        {!preview && !result && (
          <button onClick={handlePreview}
            disabled={!file || !systemId || !frameworkId || loading}
            className="w-full px-3 py-2 text-xs uppercase tracking-wider border border-[var(--accent)] text-[var(--accent)] hover:bg-[var(--accent)]/10 disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2">
            {loading ? <Loader2 size={14} className="animate-spin" /> : <Upload size={14} />}
            {loading ? 'Parsing...' : 'Preview Import'}
          </button>
        )}

        {/* Preview results */}
        {preview && (
          <div className="space-y-3">
            <div className="flex gap-3 text-xs">
              <div className="px-3 py-2 border border-[var(--border)] flex-1 text-center">
                <div className="text-[var(--text-secondary)]">Parsed</div>
                <div className="text-lg font-semibold text-[var(--text-primary)]">{preview.total_parsed}</div>
              </div>
              <div className="px-3 py-2 border border-[var(--border)] flex-1 text-center">
                <div className="text-[var(--text-secondary)]">New</div>
                <div className="text-lg font-semibold text-[var(--risk-low)]">{preview.new_count}</div>
              </div>
              <div className="px-3 py-2 border border-[var(--border)] flex-1 text-center">
                <div className="text-[var(--text-secondary)]">Duplicate</div>
                <div className="text-lg font-semibold text-[var(--text-secondary)]">{preview.duplicate_count}</div>
              </div>
            </div>

            <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">
              Detected format: <span className="text-[var(--accent)]">{preview.format}</span>
            </div>

            <ImportWarnings warnings={preview.warnings} />

            <div className="border border-[var(--border)] max-h-60 overflow-y-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-[var(--border)] text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">
                    <th className="px-2 py-1 text-left">Title</th>
                    <th className="px-2 py-1 text-left">Severity</th>
                    <th className="px-2 py-1 text-left">Source</th>
                    <th className="px-2 py-1 text-left">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.preview.map((item, i) => (
                    <tr key={i} className={`border-b border-[var(--border)] last:border-b-0 ${item.is_duplicate ? 'opacity-40' : ''}`}>
                      <td className="px-2 py-1 text-[var(--text-primary)] max-w-[200px] truncate">{item.title}</td>
                      <td className={`px-2 py-1 ${SEV_TONE[item.severity] ?? ''}`}>{item.severity}</td>
                      <td className="px-2 py-1 text-[var(--text-secondary)]">
                        {item.extra_data?.src_ip ? <span>{String(item.extra_data.src_ip)}</span> : null}
                        {item.extra_data?.src_ip && item.extra_data?.dst_ip ? <span> → </span> : null}
                        {item.extra_data?.dst_ip ? <span>{String(item.extra_data.dst_ip)}</span> : null}
                      </td>
                      <td className="px-2 py-1">
                        {item.is_duplicate ? (
                          <span className="text-[var(--text-secondary)]">DUP</span>
                        ) : (
                          <span className="text-[var(--risk-low)]">NEW</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flex gap-2">
              <button onClick={handleConfirm}
                disabled={preview.new_count === 0 || confirming}
                className="flex-1 px-3 py-2 text-xs uppercase tracking-wider bg-[var(--accent)] text-white hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2">
                {confirming ? <Loader2 size={14} className="animate-spin" /> : <Check size={14} />}
                {confirming ? 'Importing...' : `Import ${plural(preview.new_count, 'Finding')}`}
              </button>
              <button onClick={reset}
                className="px-3 py-2 text-xs uppercase tracking-wider border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]">
                Cancel
              </button>
            </div>
          </div>
        )}

        {/* Confirmed result */}
        {result && (
          <div className="border border-[var(--risk-low)]/40 bg-[var(--risk-low)]/5 p-4">
            <div className="flex items-center gap-2 mb-2">
              <Check size={16} className="text-[var(--risk-low)]" />
              <span className="text-sm font-semibold text-[var(--risk-low)]">Import Complete</span>
            </div>
            <div className="text-xs text-[var(--text-secondary)] space-y-1">
              <div>{plural(result.created, 'finding')} created</div>
              <div>{plural(result.skipped, 'duplicate')} skipped</div>
              {!!result.merged_duplicates && <div>{plural(result.merged_duplicates, 'repeated row')} merged</div>}
              {!!result.skipped_rows && <div>{plural(result.skipped_rows, 'row')} skipped</div>}
              {!!result.truncated_count && <div>{result.truncated_count} not imported (row limit)</div>}
              <div>Format: {result.format}</div>
            </div>
            <ImportWarnings warnings={result.warnings} />
            <button onClick={reset}
              className="mt-3 px-3 py-1.5 text-xs uppercase tracking-wider border border-[var(--accent)] text-[var(--accent)] hover:bg-[var(--accent)]/10">
              Import Another
            </button>
          </div>
        )}

        {/* Import history */}
        {history.length > 0 && !preview && !result && (
          <div>
            <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-2">Recent Imports</div>
            <div className="space-y-1">
              {history.slice(0, 10).map(h => (
                <div key={h.id} className="flex items-start justify-between text-xs border-b border-[var(--border)] py-1.5">
                  <div className="text-[var(--text-primary)]">{h.summary}</div>
                  <div className="text-[var(--text-secondary)] whitespace-nowrap ml-3">
                    {h.created_at ? formatDate(h.created_at) : '—'}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </SlideInPanel>
  )
}

/** Server-written import warnings (truncation, skipped rows + reasons, merges). */
export function ImportWarnings({ warnings }: { warnings?: string[] }) {
  if (!warnings || warnings.length === 0) return null
  return (
    <div role="status" className="border border-[var(--warning)]/40 bg-[var(--warning)]/5 px-3 py-2 text-xs text-[var(--warning)] space-y-1">
      {warnings.map((w, i) => <div key={i}>⚠ {w}</div>)}
    </div>
  )
}
