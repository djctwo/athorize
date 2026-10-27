import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import FindingDetailPanel from './FindingDetailPanel'
import { api } from '../lib/api'
import { useUserStore } from '../store/userStore'
import type { Finding, User } from '../types'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}))

const auditor = {
  id: 5, username: 'aud', role: 'auditor', display_name: 'Aud', email: null, is_active: true,
  created_at: '', last_login: null, organization_id: 1, organization_name: null, is_operator: false,
} as User

const finding = {
  id: 7, organization_id: 1, system_id: 1, framework_id: 'nist-800-53-r5', control_id: 'AC-2',
  title: 'Stale accounts', description: '', weakness_description: '', severity: 'HIGH', status: 'OPEN',
  owner_id: null, owner_name: null, owner_email: null, due_date: null, scheduled_completion: null,
  actual_completion: null, closed_date: null, remediation_plan: '', risk_rationale: '', reopen_reason: null,
  milestones: [], extra_data: {}, aging_bucket: 'ON_TRACK', days_until_due: null, days_open: 3, is_open: true,
  created_at: '', updated_at: '',
} as Finding

describe('FindingDetailPanel', () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset()
    useUserStore.setState({ user: auditor })
  })

  it('shows framework names, not raw ids, in the detail row and Cross-Framework Impact (E2E-26)', async () => {
    vi.mocked(api.get).mockImplementation((path: string) => {
      if (path === '/frameworks') return Promise.resolve([
        { id: 'nist-800-53-r5', name: 'NIST SP 800-53 Rev. 5' },
        { id: 'cjis', name: 'CJIS Security Policy' },
      ])
      if (path.startsWith('/crosswalk/findings/7')) return Promise.resolve({ finding_id: 7, impacts: [
        { framework_id: 'cjis', control_id: '5.5.1', title: 'Account mgmt', relationship: 'equivalent',
          confidence: 'official', path: 'direct', implementation_status: 'IMPLEMENTED' },
      ] })
      return Promise.resolve([])
    })
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <FindingDetailPanel finding={finding} onClose={() => {}} onEdit={() => {}} />
      </QueryClientProvider>,
    )
    expect(await screen.findByText('CJIS Security Policy')).toBeInTheDocument()
    expect(await screen.findByText('NIST SP 800-53 Rev. 5')).toBeInTheDocument()
    expect(screen.queryByText('cjis')).not.toBeInTheDocument()
  })
})
