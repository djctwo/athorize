import { useQuery } from '@tanstack/react-query'
import { ArrowLeftRight } from 'lucide-react'
import { api } from '../lib/api'

export interface CrosswalkMapping {
  framework_id: string
  control_id: string
  title: string
  relationship: string
  confidence: string
  path: string
  rationale: string
  open_findings: number
}

interface CrosswalkResponse {
  framework_id: string
  control_id: string
  mappings: CrosswalkMapping[]
}

const REL_LABELS: Record<string, string> = {
  equivalent: 'Equivalent',
  subset: 'Subset of',
  superset: 'Superset of',
  intersects: 'Intersects',
  related: 'Related',
}

const REL_TONE: Record<string, string> = {
  equivalent: 'border-[var(--success)]/50 text-[var(--success)]',
  subset: 'border-[var(--info)]/50 text-[var(--info)]',
  superset: 'border-[var(--info)]/50 text-[var(--info)]',
  intersects: 'border-[var(--warning)]/50 text-[var(--warning)]',
  related: 'border-[var(--border)] text-[var(--text-secondary)]',
}

interface Props {
  frameworkId: string
  controlId: string
  frameworkNames: Record<string, string>
}

export default function CrosswalkSection({ frameworkId, controlId, frameworkNames }: Props) {
  const { data, isLoading } = useQuery({
    queryKey: ['crosswalk', frameworkId, controlId],
    queryFn: () => api.get<CrosswalkResponse>(`/crosswalk/${frameworkId}/${encodeURIComponent(controlId)}`),
    staleTime: 5 * 60 * 1000, // catalog data — changes only on framework (de)activation
  })

  if (isLoading) {
    return <div className="mt-3 text-xs text-text-muted">Loading crosswalk…</div>
  }
  const mappings = data?.mappings ?? []
  if (mappings.length === 0) return null

  const byFramework = new Map<string, CrosswalkMapping[]>()
  for (const m of mappings) {
    const list = byFramework.get(m.framework_id) ?? []
    list.push(m)
    byFramework.set(m.framework_id, list)
  }

  return (
    <div className="mt-3 border-t border-border pt-2">
      <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-text-muted mb-2">
        <ArrowLeftRight size={12} />
        Crosswalk — satisfies toward {byFramework.size} other framework{byFramework.size === 1 ? '' : 's'}
      </div>
      <div className="space-y-2">
        {[...byFramework.entries()].map(([fw, list]) => (
          <div key={fw}>
            <div className="text-xs font-medium text-text-secondary mb-1">{frameworkNames[fw] ?? fw}</div>
            <div className="flex flex-wrap gap-1.5">
              {list.map(m => (
                <span
                  key={`${m.framework_id}:${m.control_id}`}
                  className={`inline-flex items-center gap-1.5 px-2 py-0.5 text-xs border ${REL_TONE[m.relationship] ?? REL_TONE.related}`}
                  title={`${REL_LABELS[m.relationship] ?? m.relationship} · ${m.confidence}${m.path !== 'direct' ? ` · ${m.path}` : ''}${m.rationale ? `\n${m.rationale}` : ''}`}
                >
                  <span className="font-mono">{m.control_id}</span>
                  {m.title && <span className="text-text-muted max-w-[220px] truncate">{m.title}</span>}
                  <span className="text-[10px] uppercase tracking-wider opacity-75">{REL_LABELS[m.relationship] ?? m.relationship}</span>
                  {m.confidence === 'derived' && (
                    <span className="text-[10px] uppercase tracking-wider text-text-muted" title={m.path}>via hub</span>
                  )}
                  {m.open_findings > 0 && (
                    <span
                      className="text-[10px] font-medium px-1 border border-[var(--danger)]/60 text-[var(--danger)]"
                      title={`${m.open_findings} active finding${m.open_findings === 1 ? '' : 's'} on this mapped control`}
                    >
                      {m.open_findings} finding{m.open_findings === 1 ? '' : 's'}
                    </span>
                  )}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
