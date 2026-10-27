import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Controls from './Controls'
import { useUserStore } from '../store/userStore'
import type { User } from '../types'
import { api } from '../lib/api'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
  getCsrfToken: () => 'test-csrf',
}))

const CONTROL = {
  framework_id: 'fw', control_id: 'AC-1', family: 'AC', family_name: 'Access Control',
  title: 'Access policy', description: '', supplemental_guidance: '', baselines: ['LOW'],
  parent_id: null, related_controls: [], typical_evidence: [], assessment_objectives: [],
  external_references: [],
}

function mockGet() {
  vi.mocked(api.get).mockImplementation((url: string) => {
    if (url === '/frameworks') return Promise.resolve([{ id: 'fw', name: 'Test FW', short_name: 'FW', is_active: true }])
    if (url === '/systems') return Promise.resolve([{ id: 1, name: 'ERP', acronym: 'ERP' }])
    if (url.startsWith('/controls/baselines')) return Promise.resolve(['LOW'])
    if (url.startsWith('/controls/systems/')) return Promise.resolve([])
    if (url.startsWith('/controls?')) return Promise.resolve([CONTROL])
    return Promise.resolve([]) // /users/assignable, /views
  })
}

function mountAs(role: string) {
  useUserStore.setState({ user: { id: 7, username: role, role, is_operator: false } as User })
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/controls?framework=fw&system=1']}>
        <Controls />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

// The backend guards every control-editing endpoint (single PUT, /controls/bulk,
// /systems/{id}/scope) with assess:control = admin + assessor. The UI must offer
// the editors to exactly those roles.
describe('Controls page — edit gating mirrors assess:control', () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset()
    mockGet()
  })

  it.each(['admin', 'assessor'])('%s gets the status picker, bulk select and scoping', async (role) => {
    mountAs(role)
    await screen.findByText('Access policy')
    expect(screen.getByDisplayValue('Not Assessed')).toBeInTheDocument()
    expect(await screen.findByLabelText('Select AC-1')).toBeInTheDocument()
    expect(screen.getByText(/Scope to baseline/)).toBeInTheDocument()
  })

  it.each(['compliance_manager', 'auditor', 'system_owner', 'evidence_contributor'])(
    '%s sees status read-only (the server would 403 their edits)', async (role) => {
      mountAs(role)
      await screen.findByText('Access policy')
      expect(screen.queryByLabelText('Select AC-1')).not.toBeInTheDocument()
      expect(screen.queryByText(/Scope to baseline/)).not.toBeInTheDocument()
      expect(screen.queryByDisplayValue('Not Assessed')).not.toBeInTheDocument()
      expect(screen.getByText('Not Assessed')).toBeInTheDocument()
    },
  )
})
