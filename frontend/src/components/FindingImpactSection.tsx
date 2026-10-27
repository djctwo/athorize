import { useQuery } from '@tanstack/react-query'
import { ArrowLeftRight } from 'lucide-react'
import { api } from '../lib/api'

interface Impact {
  framework_id: string
  control_id: string
  title: string
  relationship: string
  confidence: string
  path: string
  implementation_status: string | null
}

interface ImpactResponse {
  finding_id: number
  impacts: Impact[]
}

// Implementation statuses whose compliance posture this finding undermines
const AT_RISK_STATUSES = new Set(['IMPLEMENTED', 'INHERITED', 'PARTIAL'])

interface Props {
  findingId: number
  frameworkNames?: Record<string, string>
}

export default function FindingImpactSection({ findingId, frameworkNames = {} }: Props) {
  const { data } = useQuery({
    queryKey: ['crosswalk-impact', findingId],
    queryFn: () => api.get<ImpactResponse>(`/crosswalk/findings/${findingId}`),
    staleTime: 60 * 1000,
  })

  const impacts = data?.impacts ?? []
  if (impacts.length === 0) return null

  const byFramework = new Map<string, Impact[]>()
  for (const i of impacts) {
    const list = byFramework.get(i.framework_id) ?? []
    list.push(i)
    byFramework.set(i.framework_id, list)
  }

  return (
    <div className="pt-3 border-t border-[var(--border)]">
      <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-[var(--text-secondary)] mb-2">
        <ArrowLeftRight size={12} />
        Cross-Framework Impact
      </div>
      <p className="text-xs text-[var(--text-secondary)] mb-2">
        This finding's control maps into {byFramework.size} other active framework{byFramework.size === 1 ? '' : 's'} — the weakness likely affects their compliance too.
      </p>
      <div className="space-y-2">
        {[...byFramework.entries()].map(([fw, list]) => (
          <div key={fw}>
            <div className="text-xs font-medium text-[var(--text-secondary)] mb-1">{frameworkNames[fw] ?? fw}</div>
            <div className="flex flex-wrap gap-1.5">
              {list.map(i => {
                const atRisk = i.implementation_status !== null && AT_RISK_STATUSES.has(i.implementation_status)
                return (
                  <span
                    key={`${i.framework_id}:${i.control_id}`}
                    className={`inline-flex items-center gap-1.5 px-2 py-0.5 text-xs border ${
                      atRisk
                        ? 'border-[var(--danger)]/50 text-[var(--danger)]'
                        : 'border-[var(--border)] text-[var(--text-secondary)]'
                    }`}
                    title={`${i.relationship} · ${i.confidence}${i.path !== 'direct' ? ` · ${i.path}` : ''}`}
                  >
                    <span className="font-mono">{i.control_id}</span>
                    {i.title && <span className="opacity-75 max-w-[180px] truncate">{i.title}</span>}
                    {atRisk && (
                      <span className="text-[10px] uppercase tracking-wider">
                        {i.implementation_status} at risk
                      </span>
                    )}
                  </span>
                )
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
