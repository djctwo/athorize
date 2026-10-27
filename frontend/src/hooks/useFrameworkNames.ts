import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import type { Framework } from '../types'

/** framework id → display name, from the shared ['frameworks'] query. Use it
 * wherever a framework id would otherwise be shown raw ("hipaa-security"). */
export function useFrameworkNames(): Record<string, string> {
  const { data: frameworks = [] } = useQuery({
    queryKey: ['frameworks'],
    queryFn: () => api.get<Framework[]>('/frameworks'),
  })
  return Object.fromEntries(frameworks.map(f => [f.id, f.name]))
}

/** framework id → short label ("CMMC 2.0"), falling back to the full name, for
 * tight spaces such as chart axes and table cells (R2USER-20). */
export function useFrameworkShortNames(): Record<string, string> {
  const { data: frameworks = [] } = useQuery({
    queryKey: ['frameworks'],
    queryFn: () => api.get<Framework[]>('/frameworks'),
  })
  return Object.fromEntries(frameworks.map(f => [f.id, f.short_name || f.name]))
}
