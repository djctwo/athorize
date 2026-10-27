import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ArrowLeftRight, Check } from 'lucide-react'
import { api } from '../lib/api'
import type { Framework, System } from '../types'
import { useCan } from '../hooks/useRole'
import { toast } from '../store/toastStore'
import { SkeletonTable } from '../components/Skeleton'

interface Suggestion {
  framework_id: string
  control_id: string
  title: string
  relationship: string
  confidence: string
  path: string
  source_framework_id: string
  source_control_id: string
  source_status: string
}

interface SuggestionStats {
  active_frameworks: number
  satisfied_controls: number
  qualifying_mappings: number
  weaker_mappings: number
  already_implemented: number
}

// R2USER-15: "every qualifying control already has an implementation" was shown
// even when nothing could ever qualify (e.g. CMMC ↔ 800-53 share only
// "intersects" mappings). Say which case it is.
function emptyMessage(stats?: SuggestionStats): string {
  if (!stats) return 'No pending suggestions.'
  if (stats.active_frameworks < 2) return 'Activate a second framework to see where this system\'s work carries over.'
  if (stats.satisfied_controls === 0)
    return 'No control on this system is Implemented or Inherited yet — suggestions appear once you implement controls.'
  if (stats.qualifying_mappings === 0)
    return `Your active frameworks share only partial-overlap mappings ("intersects" or "related", ${stats.weaker_mappings} here) with this system's implemented controls. Those are never proposed automatically — review them in each control's Crosswalk section on the Controls page.`
  return 'No pending suggestions — every equivalent mapped control already has an implementation.'
}

export default function CrosswalkReview() {
  const [systemId, setSystemId] = useState<number | ''>('')
  const canAssess = useCan('assess:control')
  const queryClient = useQueryClient()

  const { data: systems = [] } = useQuery({
    queryKey: ['systems'],
    queryFn: () => api.get<System[]>('/systems'),
  })
  const { data: frameworks = [] } = useQuery({
    queryKey: ['frameworks'],
    queryFn: () => api.get<Framework[]>('/frameworks'),
  })
  const fwName = (id: string) => frameworks.find(f => f.id === id)?.short_name || id

  const { data, isLoading } = useQuery({
    queryKey: ['crosswalk-suggestions', systemId],
    queryFn: () => api.get<{ suggestions: Suggestion[]; stats?: SuggestionStats }>(`/crosswalk/suggestions?system_id=${systemId}`),
    enabled: systemId !== '',
  })
  const suggestions = data?.suggestions ?? []

  const accept = useMutation({
    mutationFn: (s: Suggestion) =>
      api.post('/crosswalk/suggestions/accept', {
        system_id: systemId,
        framework_id: s.framework_id,
        control_id: s.control_id,
        source_framework_id: s.source_framework_id,
        source_control_id: s.source_control_id,
      }),
    onSuccess: (_d, s) => {
      queryClient.invalidateQueries({ queryKey: ['crosswalk-suggestions', systemId] })
      toast.success(`${s.control_id} (${fwName(s.framework_id)}) created as PLANNED — review and assess to confirm`)
    },
    onError: (e: Error, s) => toast.error(`Failed to accept ${s.control_id}: ${e.message}`),
  })

  const byFramework = new Map<string, Suggestion[]>()
  for (const s of suggestions) {
    const list = byFramework.get(s.framework_id) ?? []
    list.push(s)
    byFramework.set(s.framework_id, list)
  }

  return (
    <div>
      <div className="mb-6">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <ArrowLeftRight size={20} className="text-accent" />
          Crosswalk Review
        </h2>
        <p className="text-sm text-text-muted mt-1 max-w-3xl">
          Controls in other frameworks that your existing implementations likely already satisfy, derived
          from official control mappings. Accepting creates a PLANNED implementation seeded from the source
          narrative and evidence — nothing is marked implemented until an assessor confirms it.
        </p>
      </div>

      <div className="flex items-end gap-4 mb-4">
        <div>
          <div className="text-[11px] uppercase tracking-wider text-text-muted mb-1">System</div>
          <select
            className="text-sm bg-bg-secondary border border-border px-2 py-1.5"
            value={systemId}
            onChange={e => setSystemId(e.target.value === '' ? '' : Number(e.target.value))}
          >
            <option value="">Select system…</option>
            {systems.map(s => <option key={s.id} value={s.id}>{s.acronym} — {s.name}</option>)}
          </select>
        </div>
        {systemId !== '' && !isLoading && (
          <div className="text-xs text-text-muted pb-1.5">
            {suggestions.length} suggestion{suggestions.length === 1 ? '' : 's'} across {byFramework.size} framework{byFramework.size === 1 ? '' : 's'}
          </div>
        )}
      </div>

      {systemId === '' && (
        <div className="text-center py-16 text-text-muted">
          <ArrowLeftRight size={32} className="mx-auto mb-2" />
          <p>Select a system to see what its implementations already cover in other frameworks.</p>
        </div>
      )}

      {systemId !== '' && isLoading && <SkeletonTable rows={6} cols={5} />}

      {systemId !== '' && !isLoading && suggestions.length === 0 && (
        <div className="text-center py-16 text-text-muted">
          <Check size={32} className="mx-auto mb-2 text-success" />
          <p className="max-w-xl mx-auto">{emptyMessage(data?.stats)}</p>
        </div>
      )}

      {[...byFramework.entries()].map(([fw, list]) => (
        <div key={fw} className="mb-6">
          <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-2">
            {fwName(fw)} <span className="text-text-muted font-normal">({list.length})</span>
          </h3>
          <div className="bg-bg-secondary border border-border">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[11px] uppercase tracking-wider text-text-muted border-b border-border">
                  <th className="px-3 py-2 text-left">Control</th>
                  <th className="px-3 py-2 text-left">Satisfied By</th>
                  <th className="px-3 py-2 text-left">Mapping</th>
                  <th className="px-3 py-2 text-right"></th>
                </tr>
              </thead>
              <tbody>
                {list.map(s => (
                  <tr key={`${s.framework_id}:${s.control_id}`} className="border-b border-border last:border-b-0">
                    <td className="px-3 py-2">
                      <span className="font-mono text-accent">{s.control_id}</span>
                      {s.title && <span className="ml-2 text-text-secondary">{s.title}</span>}
                    </td>
                    <td className="px-3 py-2 text-xs text-text-secondary">
                      <span className="font-mono">{s.source_control_id}</span>
                      <span className="ml-1.5">({fwName(s.source_framework_id)}, {s.source_status})</span>
                    </td>
                    <td className="px-3 py-2 text-xs text-text-muted">
                      {s.relationship}
                      {s.confidence === 'derived' ? ' · via hub' : ' · official'}
                    </td>
                    <td className="px-3 py-2 text-right">
                      {canAssess && (
                        <button
                          onClick={() => accept.mutate(s)}
                          disabled={accept.isPending}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs border border-accent text-accent hover:bg-accent/10 disabled:opacity-40"
                        >
                          <Check size={12} /> Accept as Planned
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ))}
    </div>
  )
}
