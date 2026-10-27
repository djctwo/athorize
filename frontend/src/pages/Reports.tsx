import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api, getCsrfToken, responseError } from '../lib/api'
import type { Assessment, System, Framework } from '../types'
import { Download, ExternalLink, FileSpreadsheet, FileText, Presentation, FolderArchive } from 'lucide-react'
import { generateExecBriefing } from '../lib/execBriefing'
import { toast } from '../store/toastStore'

interface ReportDef {
  key: string
  label: string
  description: string
  filters: ('system' | 'framework')[]
  endpoint: string
}

const REPORTS: ReportDef[] = [
  {
    key: 'findings', label: 'Findings Export',
    description: 'All findings with severity, status, ownership, and dates.',
    filters: ['system', 'framework'], endpoint: '/reports/findings',
  },
  {
    key: 'evidence', label: 'Evidence Export',
    description: 'Evidence artifacts with freshness and control mapping.',
    filters: ['system'], endpoint: '/reports/evidence',
  },
  {
    key: 'risks', label: 'Risk Register Export',
    description: 'Risk entries with likelihood, impact, treatment, and review dates.',
    filters: ['system'], endpoint: '/reports/risks',
  },
  {
    key: 'compliance', label: 'Compliance Summary',
    description: 'Compliance scores per system × framework matrix.',
    filters: [], endpoint: '/reports/compliance-summary',
  },
  {
    key: 'conmon', label: 'ConMon Activity Export',
    description: 'Continuous monitoring log entries.',
    filters: ['system'], endpoint: '/reports/conmon',
  },
]

export default function Reports() {
  const [downloading, setDownloading] = useState<string | null>(null)
  const [generatingPptx, setGeneratingPptx] = useState(false)
  const [systemFilter, setSystemFilter] = useState<number | ''>('')
  const [frameworkFilter, setFrameworkFilter] = useState('')
  const [binderBusy, setBinderBusy] = useState(false)
  const [rsawStyle, setRsawStyle] = useState(false)
  const [assessmentId, setAssessmentId] = useState<number | ''>('')

  const { data: systems = [] } = useQuery({
    queryKey: ['systems'],
    queryFn: () => api.get<System[]>('/systems'),
  })

  const { data: frameworks = [] } = useQuery({
    queryKey: ['frameworks'],
    queryFn: () => api.get<Framework[]>('/frameworks'),
  })

  const { data: assessments = [] } = useQuery({
    queryKey: ['assessments'],
    queryFn: () => api.get<Assessment[]>('/assessments'),
  })

  const activeFrameworks = frameworks.filter(f => f.is_active)

  const handleDownload = async (report: ReportDef) => {
    setDownloading(report.key)
    try {
      const params = new URLSearchParams()
      if (report.filters.includes('system') && systemFilter) params.set('system_id', String(systemFilter))
      if (report.filters.includes('framework') && frameworkFilter) params.set('framework_id', frameworkFilter)

      const qs = params.toString() ? `?${params}` : ''
      const headers: Record<string, string> = {}
      const token = getCsrfToken()
      if (token) headers['X-CSRF-Token'] = token

      const res = await fetch(`/api${report.endpoint}${qs}`, {
        credentials: 'include',
        headers,
      })
      if (!res.ok) throw await responseError(res)

      const blob = await res.blob()
      const disposition = res.headers.get('Content-Disposition') ?? ''
      const filenameMatch = disposition.match(/filename="?(.+?)"?$/)
      const filename = filenameMatch?.[1] ?? `${report.key}.csv`

      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      a.click()
      URL.revokeObjectURL(url)
      toast.success(`Downloaded ${filename}`)
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Download failed')
    } finally {
      setDownloading(null)
    }
  }

  return (
    <div>
      <div className="flex items-start justify-between mb-4">
        <div>
          <h2 className="text-xl font-bold text-[var(--text-primary)]">Reports</h2>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">
            Export compliance data as CSV files for offline analysis or audit evidence.
          </p>
        </div>
        <button
          onClick={async () => {
            setGeneratingPptx(true)
            try {
              await generateExecBriefing()
              toast.success('Executive briefing downloaded')
            } catch (e) {
              toast.error(e instanceof Error ? e.message : 'Failed to generate briefing')
            } finally {
              setGeneratingPptx(false)
            }
          }}
          disabled={generatingPptx}
          className="flex items-center gap-2 px-3 py-1.5 bg-[var(--accent)] hover:opacity-90 text-white text-sm disabled:opacity-50"
        >
          <Presentation size={16} />
          {generatingPptx ? 'Generating…' : 'Executive Briefing (PPTX)'}
        </button>
      </div>

      <div className="flex gap-3 mb-6">
        <div>
          <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">System</div>
          <select value={systemFilter} onChange={e => setSystemFilter(e.target.value ? Number(e.target.value) : '')}
            className="bg-[var(--bg-secondary)] border border-[var(--border)] px-2 py-1 text-xs text-[var(--text-primary)]">
            <option value="">All systems</option>
            {systems.map(s => <option key={s.id} value={s.id}>{s.acronym} — {s.name}</option>)}
          </select>
        </div>
        <div>
          <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-1">Framework</div>
          <select value={frameworkFilter} onChange={e => setFrameworkFilter(e.target.value)}
            className="bg-[var(--bg-secondary)] border border-[var(--border)] px-2 py-1 text-xs text-[var(--text-primary)]">
            <option value="">All frameworks</option>
            {activeFrameworks.map(f => <option key={f.id} value={f.id}>{f.short_name}</option>)}
          </select>
        </div>
      </div>

      {/* Audit Binder — the evidence-backed package you hand the auditor */}
      <div className="bg-[var(--bg-secondary)] border border-[var(--accent)]/50 p-4 mb-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <FolderArchive size={22} className="text-[var(--accent)]" />
          <div>
            <div className="text-sm font-semibold text-[var(--text-primary)]">Audit Binder</div>
            <div className="text-[11px] text-[var(--text-secondary)]">
              Print-ready package for one system × framework: control-by-control status with narratives,
              findings &amp; milestones (POA&amp;M), compliance progress over time, and the evidence files — zipped.
            </div>
            {(!systemFilter || !frameworkFilter) && (
              <div className="text-[10px] text-[var(--warning)] mt-0.5">Select a system AND a framework above.</div>
            )}
            {frameworkFilter.startsWith('nerc') && (
              <label className="flex items-center gap-1.5 text-[11px] text-[var(--text-secondary)] mt-1.5 cursor-pointer">
                <input type="checkbox" checked={rsawStyle} onChange={e => setRsawStyle(e.target.checked)} />
                RSAW-style worksheets (NERC audit format: assessment approach / entity response / evidence per requirement)
              </label>
            )}
          </div>
        </div>
        <button
          onClick={async () => {
            if (!systemFilter || !frameworkFilter) return
            setBinderBusy(true)
            try {
              const style = rsawStyle && frameworkFilter.startsWith('nerc') ? 'rsaw' : 'standard'
              const res = await fetch(`/api/reports/audit-binder?system_id=${systemFilter}&framework_id=${encodeURIComponent(frameworkFilter)}&style=${style}`, {
                credentials: 'include',
              })
              if (!res.ok) throw await responseError(res)
              const blob = await res.blob()
              const disposition = res.headers.get('Content-Disposition') ?? ''
              const filename = disposition.match(/filename="?(.+?)"?$/)?.[1] ?? 'audit-binder.zip'
              const url = URL.createObjectURL(blob)
              const a = document.createElement('a')
              a.href = url
              a.download = filename
              a.click()
              URL.revokeObjectURL(url)
              toast.success(`Downloaded ${filename}`)
            } catch (e) {
              toast.error(e instanceof Error ? e.message : 'Binder export failed')
            } finally {
              setBinderBusy(false)
            }
          }}
          disabled={binderBusy || !systemFilter || !frameworkFilter}
          className="px-3 py-1.5 text-xs uppercase tracking-wider bg-[var(--accent)] text-white hover:opacity-90 disabled:opacity-40 flex items-center gap-1.5"
        >
          <Download size={12} />
          {binderBusy ? 'Building…' : 'ZIP'}
        </button>
      </div>

      {/* Assessment Report — the per-assessment deliverable */}
      <div className="bg-[var(--bg-secondary)] border border-[var(--border)] p-4 mb-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <FileText size={22} className="text-[var(--accent)]" />
          <div>
            <div className="text-sm font-semibold text-[var(--text-primary)]">Assessment Report</div>
            <div className="text-[11px] text-[var(--text-secondary)]">
              Print-ready deliverable for one assessment: cover, control-by-control results with
              narratives and linked evidence, findings from the assessment window, and a sign-off block.
              Opens in a new tab — use your browser&apos;s Print to save as PDF. Also available per row on
              the Assessments page.
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <select
            value={assessmentId}
            onChange={e => setAssessmentId(e.target.value ? Number(e.target.value) : '')}
            className="bg-[var(--bg-secondary)] border border-[var(--border)] px-2 py-1 text-xs text-[var(--text-primary)] max-w-[260px]"
          >
            <option value="">Select assessment…</option>
            {assessments.map(a => (
              <option key={a.id} value={a.id}>
                {(systems.find(s => s.id === a.system_id)?.acronym ?? `#${a.system_id}`)} × {a.framework_id} — {a.assessment_type}
              </option>
            ))}
          </select>
          <button
            onClick={() => { if (assessmentId) window.open(`/api/reports/assessment/${assessmentId}`, '_blank', 'noopener') }}
            disabled={!assessmentId}
            className="px-3 py-1.5 text-xs uppercase tracking-wider bg-[var(--accent)] text-white hover:opacity-90 disabled:opacity-40 flex items-center gap-1.5"
          >
            <ExternalLink size={12} /> Open
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3">
        {REPORTS.map(report => (
          <div key={report.key}
            className="bg-[var(--bg-secondary)] border border-[var(--border)] p-4 flex items-center justify-between">
            <div className="flex items-center gap-3">
              <FileSpreadsheet size={20} className="text-[var(--accent)]" />
              <div>
                <div className="text-sm font-medium text-[var(--text-primary)]">{report.label}</div>
                <div className="text-[11px] text-[var(--text-secondary)]">{report.description}</div>
                <div className="text-[10px] text-[var(--text-secondary)] mt-0.5">
                  {report.filters.length > 0
                    ? `Filters: ${report.filters.join(', ')}`
                    : 'No filters — exports all data'}
                </div>
              </div>
            </div>
            <button
              onClick={() => handleDownload(report)}
              disabled={downloading === report.key}
              className="px-3 py-1.5 text-xs uppercase tracking-wider border border-[var(--accent)] text-[var(--accent)] hover:bg-[var(--accent)]/10 disabled:opacity-40 flex items-center gap-1.5"
            >
              <Download size={12} />
              {downloading === report.key ? 'Downloading...' : 'CSV'}
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}
