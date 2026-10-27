import { useCallback, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Upload, FileText, Check, Loader2, Plug, Download } from 'lucide-react'
import { SlideInPanel } from './SlideInPanel'
import { toast } from '../store/toastStore'
import type { System } from '../types'
import { api, getCsrfToken, responseError } from '../lib/api'
import { formatDate, formatDateTime } from '../lib/datetime'
import { ImportWarnings, type ImportAccounting } from './SiemImportPanel'
import { plural } from '../lib/plural'

interface AssetSource {
  key: string
  label: string
  extensions: string[]
  description: string
}

interface Connector {
  key: string
  label: string
  configured: boolean
  env: string[]
  note?: string // e.g. configured for another company on a multi-company install
}

interface ConnectorSync {
  enabled: boolean
  interval_hours: number | null
  org_slug: string | null
  last_synced: string | null
}

interface ConnectorsStatus {
  connectors: Connector[]
  sync: ConnectorSync
}

interface PreviewItem {
  asset_name: string
  hostname?: string
  ip_address?: string
  os_family?: string
  asset_role?: string
  is_duplicate: boolean
}

interface RowError { row: number; field: string; message: string; asset_name?: string }

interface PreviewResult extends ImportAccounting {
  source: string
  total_parsed: number
  new_count: number
  duplicate_count: number
  valid_count: number
  error_count: number
  errors: RowError[]
  preview: PreviewItem[]
  system_id: number
}

interface ConfirmResult extends ImportAccounting {
  source: string
  created: number
  skipped: number
  error_count: number
  errors?: RowError[]
  total_parsed: number
}

function RowErrors({ errors, count }: { errors?: RowError[]; count: number }) {
  if (!count) return null
  return (
    <div className="border border-[var(--risk-high)]/40 bg-[var(--risk-high)]/5 px-3 py-2 text-xs text-[var(--risk-high)] space-y-0.5">
      <div className="font-semibold">{count} row error(s) — these rows are not imported</div>
      {(errors ?? []).slice(0, 10).map((e, i) => (
        <div key={i}>{e.asset_name || `Asset ${e.row + 1}`}{e.field && e.field !== '*' ? ` · ${e.field}` : ''}: {e.message}</div>
      ))}
      {(errors?.length ?? 0) > 10 && <div>…and {count - 10} more</div>}
    </div>
  )
}

interface ImportHistory {
  id: number
  actor: string
  summary: string
  system_id: number | null
  created_at: string | null
}

interface Props {
  open: boolean
  onClose: () => void
}

export function AssetImportPanel({ open, onClose }: Props) {
  const qc = useQueryClient()

  const [file, setFile] = useState<File | null>(null)
  const [systemId, setSystemId] = useState<number | ''>('')
  const [sourceOverride, setSourceOverride] = useState('')
  const [preview, setPreview] = useState<PreviewResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [result, setResult] = useState<ConfirmResult | null>(null)
  const [dragOver, setDragOver] = useState(false)
  // null = file-upload flow; otherwise the active live-connector key
  const [connectorKey, setConnectorKey] = useState<string | null>(null)

  const { data: systems = [] } = useQuery({
    queryKey: ['systems'],
    queryFn: () => api.get<System[]>('/systems'),
  })

  const { data: sources = [] } = useQuery({
    queryKey: ['asset-sources'],
    queryFn: () => api.get<AssetSource[]>('/asset-import/sources'),
  })

  const { data: connectorsStatus } = useQuery({
    queryKey: ['asset-connectors'],
    queryFn: () => api.get<ConnectorsStatus>('/asset-import/connectors'),
    enabled: open,
  })
  const connectors = connectorsStatus?.connectors ?? []
  const connectorSync = connectorsStatus?.sync

  const { data: history = [] } = useQuery({
    queryKey: ['asset-import-history'],
    queryFn: () => api.get<ImportHistory[]>('/asset-import/history'),
    enabled: open,
  })

  const reset = useCallback(() => {
    setFile(null)
    setPreview(null)
    setResult(null)
    setLoading(false)
    setConfirming(false)
    setConnectorKey(null)
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

  const post = async (path: string, withFile: boolean) => {
    const form = new FormData()
    if (withFile) form.append('file', file as File)
    form.append('system_id', String(systemId))
    if (withFile && sourceOverride) form.append('source_override', sourceOverride)

    const headers: Record<string, string> = {}
    const token = getCsrfToken()
    if (token) headers['X-CSRF-Token'] = token

    const res = await fetch(path, { method: 'POST', credentials: 'include', headers, body: form })
    if (!res.ok) throw await responseError(res)
    return res.json()
  }

  const handlePreview = async () => {
    if (!file || !systemId) return
    setLoading(true)
    setConnectorKey(null)
    try {
      setPreview(await post('/api/asset-import/import', true))
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Import preview failed')
    } finally {
      setLoading(false)
    }
  }

  const handleConnectorPreview = async (key: string) => {
    if (!systemId) { toast.error('Select a system first'); return }
    setLoading(true)
    setConnectorKey(key)
    try {
      setPreview(await post(`/api/asset-import/connectors/${key}/import`, false))
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Connector pull failed')
      setConnectorKey(null)
    } finally {
      setLoading(false)
    }
  }

  const handleConfirm = async () => {
    if (!systemId || (!file && !connectorKey)) return
    setConfirming(true)
    try {
      const path = connectorKey
        ? `/api/asset-import/connectors/${connectorKey}/import/confirm`
        : '/api/asset-import/import/confirm'
      const data: ConfirmResult = await post(path, !connectorKey)
      setResult(data)
      setPreview(null)
      const notes = [`${plural(data.skipped, 'duplicate')} skipped`]
      if (data.error_count) notes.push(`${data.error_count} row errors`)
      if (data.skipped_rows) notes.push(`${plural(data.skipped_rows, 'row')} skipped`)
      if (data.truncated_count) notes.push(`${data.truncated_count} not imported (row limit)`)
      const msg = `Imported ${plural(data.created, 'asset')} (${notes.join(', ')})`
      if (data.error_count || data.truncated) toast.info(msg)
      else toast.success(msg)
      qc.invalidateQueries({ queryKey: ['it-assets'] })
      qc.invalidateQueries({ queryKey: ['asset-import-history'] })
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Import failed')
    } finally {
      setConfirming(false)
    }
  }

  return (
    <SlideInPanel
      open={open}
      onClose={handleClose}
      width={600}
      eyebrow="Asset Inventory"
      title="Import Assets"
      subtitle="Pull asset inventory from Tanium or Cisco ISE exports"
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
                Drop a CSV export here or <span className="text-[var(--accent)] underline">browse</span>
              </div>
              <div className="text-[11px] text-[var(--text-secondary)] mt-1">
                Tanium or Cisco ISE CSV — max 16 MiB
              </div>
              <input type="file" className="hidden" accept=".csv" onChange={handleFileChange} />
            </label>
          )}
        </div>

        {/* System + Source selects */}
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
            <label className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] block mb-1">Source</label>
            <select value={sourceOverride} onChange={e => setSourceOverride(e.target.value)}
              className="w-full bg-[var(--bg-primary)] border border-[var(--border)] px-2 py-1.5 text-xs text-[var(--text-primary)]">
              <option value="">Auto-detect</option>
              {sources.map(s => <option key={s.key} value={s.key}>{s.label}</option>)}
            </select>
          </div>
        </div>

        {/* Preview button (file flow) */}
        {!preview && !result && (
          <button onClick={handlePreview}
            disabled={!file || !systemId || loading}
            className="w-full px-3 py-2 text-xs uppercase tracking-wider border border-[var(--accent)] text-[var(--accent)] hover:bg-[var(--accent)]/10 disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center gap-2">
            {loading ? <Loader2 size={14} className="animate-spin" /> : <Upload size={14} />}
            {loading ? 'Parsing...' : 'Preview Import'}
          </button>
        )}

        {/* Live connectors (Tanium / Cisco ISE) */}
        {!preview && !result && connectors.length > 0 && (
          <div>
            <div className="flex items-center justify-between gap-2 mb-2">
              <div className="flex items-center gap-2 text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">
                <Plug size={12} /> Or pull from a connected source
              </div>
              {/* Sync mode — mirrors the Advisories feed-status readout */}
              {connectorSync && (
                <span className="text-[10px] text-[var(--text-secondary)]">
                  {connectorSync.enabled
                    ? `Auto-sync every ${connectorSync.interval_hours}h`
                    : 'Manual pull only'}
                  {connectorSync.last_synced
                    ? ` · last sync ${formatDateTime(connectorSync.last_synced)}`
                    : ''}
                </span>
              )}
            </div>
            <div className="space-y-2">
              {connectors.map(c => (
                <div key={c.key} className="flex items-center justify-between border border-[var(--border)] px-3 py-2">
                  <div>
                    <div className="text-sm text-[var(--text-primary)]">{c.label}</div>
                    <div className="text-[11px] text-[var(--text-secondary)]">
                      {c.configured ? 'Connected' : c.note ?? `Set ${c.env.join(', ')}`}
                    </div>
                  </div>
                  <button
                    onClick={() => handleConnectorPreview(c.key)}
                    disabled={!c.configured || !systemId || loading}
                    title={!c.configured ? 'Connector not configured' : !systemId ? 'Select a system first' : ''}
                    className="flex items-center gap-1.5 px-2.5 py-1 text-xs border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] disabled:opacity-40 disabled:cursor-not-allowed">
                    <Download size={13} /> Pull
                  </button>
                </div>
              ))}
            </div>
          </div>
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
              Detected source: <span className="text-[var(--accent)]">{preview.source}</span>
              {preview.error_count > 0 && (
                <span className="ml-2 text-[var(--risk-high)]">{preview.error_count} row error(s)</span>
              )}
            </div>

            <ImportWarnings warnings={preview.warnings} />
            <RowErrors errors={preview.errors} count={preview.error_count} />

            <div className="border border-[var(--border)] max-h-60 overflow-y-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-[var(--border)] text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">
                    <th className="px-2 py-1 text-left">Name</th>
                    <th className="px-2 py-1 text-left">Role</th>
                    <th className="px-2 py-1 text-left">OS</th>
                    <th className="px-2 py-1 text-left">IP</th>
                    <th className="px-2 py-1 text-left">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.preview.map((item, i) => (
                    <tr key={i} className={`border-b border-[var(--border)] last:border-b-0 ${item.is_duplicate ? 'opacity-40' : ''}`}>
                      <td className="px-2 py-1 text-[var(--text-primary)] max-w-[160px] truncate">{item.asset_name}</td>
                      <td className="px-2 py-1 text-[var(--text-secondary)]">{item.asset_role || '—'}</td>
                      <td className="px-2 py-1 text-[var(--text-secondary)]">{item.os_family || '—'}</td>
                      <td className="px-2 py-1 text-[var(--text-secondary)] font-mono">{item.ip_address || '—'}</td>
                      <td className="px-2 py-1">
                        {item.is_duplicate
                          ? <span className="text-[var(--text-secondary)]">DUP</span>
                          : <span className="text-[var(--risk-low)]">NEW</span>}
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
                {confirming ? 'Importing...' : `Import ${plural(preview.new_count, 'Asset')}`}
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
              <div>{plural(result.created, 'asset')} created</div>
              <div>{plural(result.skipped, 'duplicate')} skipped</div>
              {!!result.skipped_rows && <div>{plural(result.skipped_rows, 'row')} skipped</div>}
              {!!result.truncated_count && <div>{result.truncated_count} not imported (row limit)</div>}
              <div>Source: {result.source}</div>
            </div>
            <div className="mt-2 space-y-2">
              <ImportWarnings warnings={result.warnings} />
              <RowErrors errors={result.errors} count={result.error_count} />
            </div>
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
