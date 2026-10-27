import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Building2 } from 'lucide-react'
import { api } from '../lib/api'
import { useUserStore } from '../store/userStore'
import CompanyLogo from './CompanyLogo'
import { SlideInPanel } from './SlideInPanel'
import type { User } from '../types'

interface OrgListResponse {
  organizations: { id: number; name: string; slug: string }[]
  is_operator: boolean
  active_organization_id: number
}

/**
 * Company (organization) context in the sidebar header.
 * - Operators get a switcher <select> + "add company" panel. Switching sets the
 *   active company server-side, refreshes the user, and invalidates every query
 *   so the whole app re-scopes to the chosen company.
 * - Regular users see their company name as a static label (locked to one company).
 */
export default function OrgSwitcher() {
  const { user, setUser } = useUserStore()
  const queryClient = useQueryClient()
  const [addOpen, setAddOpen] = useState(false)
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const isOperator = !!user?.is_operator

  const { data } = useQuery({
    queryKey: ['orgs'],
    queryFn: () => api.get<OrgListResponse>('/orgs'),
    enabled: isOperator,
  })

  const refreshUser = async () => {
    setUser(await api.get<User>('/auth/me'))
  }

  const switchOrg = async (orgId: number) => {
    if (!orgId || orgId === user?.organization_id) return
    await api.post('/orgs/switch', { org_id: orgId })
    await refreshUser()
    // No key = invalidate everything; every page's data re-fetches under the new company.
    queryClient.invalidateQueries()
  }

  const createOrg = async () => {
    const trimmed = name.trim()
    if (!trimmed) return
    setBusy(true)
    setError('')
    try {
      const org = await api.post<{ id: number; name: string; slug: string }>('/orgs', { name: trimmed })
      await queryClient.invalidateQueries({ queryKey: ['orgs'] })
      setName('')
      setAddOpen(false)
      await switchOrg(org.id)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to create company')
    } finally {
      setBusy(false)
    }
  }

  // Active company's logo (from /auth/me) beside the name; icon/text-only fallback.
  const logo = user?.organization_logo

  if (!isOperator) {
    return (
      <div className="flex items-center gap-1.5 text-xs text-text-muted mt-1" title={user?.organization_name ?? ''}>
        {logo
          ? <CompanyLogo src={logo} name={user?.organization_name} className="h-4 max-w-[72px] shrink-0" />
          : <Building2 size={12} />}
        <span className="truncate">{user?.organization_name}</span>
      </div>
    )
  }

  const orgs = data?.organizations ?? []

  return (
    <div className="mt-2">
      <CompanyLogo src={logo} name={user?.organization_name} className="h-6 max-w-[140px] mb-1.5" />
      <div className="flex items-center gap-1">
        <select
          value={user?.organization_id ?? ''}
          onChange={(e) => switchOrg(Number(e.target.value))}
          className="flex-1 min-w-0 text-xs bg-bg-tertiary border border-border px-2 py-1 text-text-primary"
          title="Switch company"
        >
          {orgs.map((o) => (
            <option key={o.id} value={o.id}>{o.name}</option>
          ))}
        </select>
        <button
          onClick={() => setAddOpen(true)}
          className="text-text-muted hover:text-accent p-1 shrink-0"
          title="Add company"
          aria-label="Add company"
        >
          <Plus size={14} />
        </button>
      </div>

      <SlideInPanel
        open={addOpen}
        onClose={() => { setAddOpen(false); setName(''); setError('') }}
        width={420}
        eyebrow="Companies"
        title="Add a company"
        subtitle="Create a new company you can manage and switch to from this install."
        footer={
          <>
            <button
              onClick={createOrg}
              disabled={busy || !name.trim()}
              className="px-4 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm disabled:opacity-50"
            >
              {busy ? 'Creating…' : 'Create company'}
            </button>
            <button
              onClick={() => { setAddOpen(false); setName(''); setError('') }}
              className="px-3 py-1.5 text-text-secondary text-sm"
            >
              Cancel
            </button>
          </>
        }
      >
        <label className="block text-xs text-text-secondary mb-1">Company name</label>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') createOrg() }}
          placeholder="e.g. Contoso Energy"
          className="w-full text-sm bg-bg-tertiary border border-border px-2 py-1.5 text-text-primary"
        />
        {error && <div className="text-xs text-danger mt-2">{error}</div>}
      </SlideInPanel>
    </div>
  )
}
