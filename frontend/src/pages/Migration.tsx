import { useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { FileUp, Database, CheckCircle2 } from 'lucide-react'
import { api, getCsrfToken, responseError } from '../lib/api'
import type { Framework, System } from '../types'
import { toast } from '../store/toastStore'
import { useCan } from '../hooks/useRole'

interface PreviewResult {
  kind: string
  total?: number
  new?: number
  matched?: number
  duplicates?: number
  merged_in_file?: number
  adopted?: number
  unknown_controls?: number
  already_assessed?: number
  created?: number
  written?: number
  issues: string[]
  mapped_columns?: Record<string, string>
  preview?: Record<string, unknown>[]
}

/** Data Migration — get existing POA&M / SSP spreadsheets into Athorize.
 * Preview first (nothing written), then import. Never overwrites assessed work. */
export default function Migration() {
  // POA&M import creates findings (edit:finding); SSP import writes control
  // implementations (assess:control) — different roles on the server.
  const canImportPoam = useCan('edit:finding')
  const canImportSsp = useCan('assess:control')
  const [systemId, setSystemId] = useState<number | ''>('')
  const [frameworkId, setFrameworkId] = useState('')

  const { data: systems = [] } = useQuery({ queryKey: ['systems'], queryFn: () => api.get<System[]>('/systems') })
  const { data: frameworks = [] } = useQuery({ queryKey: ['frameworks'], queryFn: () => api.get<Framework[]>('/frameworks') })
  const activeFrameworks = frameworks.filter(f => f.is_active)
  const ready = !!systemId && !!frameworkId

  if (!canImportPoam && !canImportSsp) {
    return <div className="text-sm text-[var(--text-secondary)]">Data migration requires a role that can edit findings or assess controls.</div>
  }

  return (
    <div>
      <div className="mb-4">
        <h2 className="text-xl font-bold text-[var(--text-primary)]">Data Migration</h2>
        <p className="text-xs text-[var(--text-secondary)] mt-0.5 max-w-2xl">
          Moving from spreadsheets or another tool? Import your existing POA&amp;M and SSP data in minutes.
          CSV format (in Excel: File → Save As → CSV). Column names are matched flexibly — Weakness/Finding/Title,
          Risk/Severity, POC/Owner, etc. all work. Preview shows exactly what will happen before anything is written.
        </p>
      </div>

      <div className="flex gap-3 mb-5">
        <div>
          <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Target system</div>
          <select value={systemId} onChange={e => setSystemId(e.target.value ? Number(e.target.value) : '')}
            className="bg-[var(--bg-secondary)] border border-[var(--border)] px-2 py-1 text-xs text-[var(--text-primary)]">
            <option value="">Select…</option>
            {systems.map(s => <option key={s.id} value={s.id}>{s.acronym} — {s.name}</option>)}
          </select>
        </div>
        <div>
          <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Framework</div>
          <select value={frameworkId} onChange={e => setFrameworkId(e.target.value)}
            className="bg-[var(--bg-secondary)] border border-[var(--border)] px-2 py-1 text-xs text-[var(--text-primary)]">
            <option value="">Select…</option>
            {activeFrameworks.map(f => <option key={f.id} value={f.id}>{f.short_name}</option>)}
          </select>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-4">
        {canImportPoam && <ImportCard
          kind="poam"
          title="POA&M → Findings"
          blurb="Each row becomes a finding: title/weakness, severity, status, due date, owner, and the remediation plan as a first milestone. Rows whose title already exists are skipped."
          disabled={!ready}
          systemId={systemId as number}
          frameworkId={frameworkId}
        />}
        {canImportSsp && <ImportCard
          kind="ssp"
          title="SSP → Control Implementations"
          blurb="Each row sets a control's implementation status and narrative. Control ids are validated against the framework catalog; anything a human already assessed is never overwritten."
          disabled={!ready}
          systemId={systemId as number}
          frameworkId={frameworkId}
        />}
      </div>
    </div>
  )
}

function ImportCard({ kind, title, blurb, disabled, systemId, frameworkId }: {
  kind: 'poam' | 'ssp'
  title: string
  blurb: string
  disabled: boolean
  systemId: number
  frameworkId: string
}) {
  const fileRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [preview, setPreview] = useState<PreviewResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState<PreviewResult | null>(null)

  const send = async (commit: boolean): Promise<PreviewResult> => {
    const fd = new FormData()
    fd.set('system_id', String(systemId))
    fd.set('framework_id', frameworkId)
    fd.set('commit', String(commit))
    fd.set('file', file!)
    const headers: Record<string, string> = {}
    const token = getCsrfToken()
    if (token) headers['X-CSRF-Token'] = token
    const res = await fetch(`/api/migration/${kind}`, {
      method: 'POST', credentials: 'include', headers, body: fd,
    })
    if (!res.ok) throw await responseError(res)
    return res.json()
  }

  const doPreview = async () => {
    if (!file) return
    setBusy(true)
    setDone(null)
    try {
      setPreview(await send(false))
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Preview failed')
    } finally {
      setBusy(false)
    }
  }

  const doImport = async () => {
    setBusy(true)
    try {
      const res = await send(true)
      setDone(res)
      setPreview(null)
      setFile(null)
      toast.success(kind === 'poam'
        ? `Imported ${res.created} finding(s)`
        : `Wrote ${res.written} implementation(s)`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Import failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="bg-[var(--bg-secondary)] border border-[var(--border)] p-4">
      <div className="flex items-center gap-2 mb-1">
        <Database size={16} className="text-[var(--accent)]" />
        <span className="text-sm font-semibold text-[var(--text-primary)]">{title}</span>
      </div>
      <p className="text-[11px] text-[var(--text-secondary)] mb-3">{blurb}</p>

      <input ref={fileRef} type="file" accept=".csv,text/csv" className="hidden"
        onChange={e => { setFile(e.target.files?.[0] ?? null); setPreview(null); setDone(null) }} />
      <div className="flex items-center gap-2">
        <button onClick={() => fileRef.current?.click()} disabled={disabled}
          className="flex items-center gap-1.5 px-2.5 py-1 text-xs border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--accent)] hover:border-[var(--accent)] disabled:opacity-40">
          <FileUp size={12} /> {file ? file.name : 'Choose CSV…'}
        </button>
        <button onClick={doPreview} disabled={disabled || !file || busy}
          className="px-2.5 py-1 text-xs border border-[var(--accent)] text-[var(--accent)] hover:bg-[var(--accent)]/10 disabled:opacity-40">
          {busy && !preview ? 'Parsing…' : 'Preview'}
        </button>
        {preview && (
          <button onClick={doImport} disabled={busy}
            className="px-3 py-1 text-xs bg-[var(--accent)] text-white disabled:opacity-40">
            {busy ? 'Importing…' : 'Import'}
          </button>
        )}
      </div>
      {disabled && <p className="text-[10px] text-[var(--warning)] mt-2">Select a system and framework first.</p>}

      {preview && (
        <div className="mt-3 text-xs text-[var(--text-secondary)] space-y-1">
          <div className="text-[var(--text-primary)]">
            {kind === 'poam'
              ? <>{preview.total} row(s) parsed → <b>{preview.new} new finding(s)</b>, {preview.duplicates} already imported (skipped){preview.adopted ? <>, {preview.adopted} existing finding(s) linked to their POA&amp;M ID</> : null}{preview.merged_in_file ? <>, {preview.merged_in_file} repeated row(s) merged</> : null}</>
              : <>{preview.total} row(s) parsed → <b>{preview.matched} matched control(s)</b>, {preview.unknown_controls} unknown, {preview.already_assessed} already assessed (kept)</>}
          </div>
          <IssueList issues={preview.issues} />
          {preview.mapped_columns && Object.keys(preview.mapped_columns).length > 0 && (
            <div className="text-[10px]">
              Columns recognized: {Object.entries(preview.mapped_columns).map(([a, c]) => `${a}→${c}`).join(', ')}
            </div>
          )}
        </div>
      )}
      {done && (
        <div className="mt-3 flex items-center gap-1.5 text-xs text-[var(--success)]">
          <CheckCircle2 size={13} />
          {kind === 'poam'
            ? `${done.created} finding(s) imported · ${done.duplicates ?? 0} already imported (skipped)${done.adopted ? ` · ${done.adopted} existing finding(s) linked to their POA&M ID` : ''}${done.merged_in_file ? ` · ${done.merged_in_file} repeated row(s) merged` : ''}`
            : `${done.written} implementation(s) written · ${done.already_assessed ?? 0} already assessed (kept) · ${done.unknown_controls ?? 0} unknown control(s)`}
        </div>
      )}
      {done && <div className="mt-1 text-xs"><IssueList issues={done.issues} /></div>}
    </div>
  )
}

const ISSUE_PREVIEW = 8

/** Every issue the server reported — the first few inline, the rest behind a toggle (never silently dropped). */
function IssueList({ issues }: { issues?: string[] }) {
  const [all, setAll] = useState(false)
  const list = issues ?? []
  if (list.length === 0) return null
  const shown = all ? list : list.slice(0, ISSUE_PREVIEW)
  return (
    <div className="space-y-0.5">
      {shown.map((iss, i) => <div key={i} className="text-[var(--warning)]">⚠ {iss}</div>)}
      {list.length > ISSUE_PREVIEW && (
        <button onClick={() => setAll(a => !a)} className="text-[10px] underline text-[var(--text-secondary)]">
          {all ? 'Show fewer' : `Show all ${list.length} issues`}
        </button>
      )}
    </div>
  )
}
