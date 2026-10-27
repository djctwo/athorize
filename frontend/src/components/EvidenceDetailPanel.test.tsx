import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import EvidenceDetailPanel from './EvidenceDetailPanel'
import { api } from '../lib/api'
import { useUserStore } from '../store/userStore'
import type { EvidenceArtifact, User } from '../types'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), delete: vi.fn() },
}))

const admin = {
  id: 1, username: 'admin', role: 'admin', display_name: 'Admin', email: null, is_active: true,
  created_at: '', last_login: null, organization_id: 1, organization_name: null, is_operator: false,
} as User

const artifact = {
  id: 9, organization_id: 1, system_id: 2, filename: 'policy.pdf', description: '', artifact_type: 'document',
  control_ids: [], framework_ids: [], date_collected: null, expiration_date: null, expiration_days: null,
  uploaded_by_id: 1, owner_id: null, file_path: 'x', file_hash: 'h', notes: '', created_at: '',
} as EvidenceArtifact

describe('EvidenceDetailPanel', () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset()
    vi.mocked(api.patch).mockReset()
    useUserStore.setState({ user: admin })
  })

  it('shows crosswalk suggestions right after saving a new linkage (E2E-20)', async () => {
    let linked = false
    vi.mocked(api.get).mockImplementation((path: string) => {
      if (path.startsWith('/crosswalk/evidence/9/suggestions')) {
        return Promise.resolve({ suggestions: linked ? [{
          framework_id: 'iso-27001-2022', control_id: 'A.5.15', title: 'Access control',
          relationship: 'equivalent', confidence: 'derived', path: 'via nist-800-53-r5',
          source_framework_id: 'nist-800-53-r5', source_control_id: 'AC-2',
        }] : [] })
      }
      return Promise.resolve([])
    })
    vi.mocked(api.patch).mockImplementation(() => { linked = true; return Promise.resolve({}) })
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <EvidenceDetailPanel open onClose={() => {}} artifact={artifact} systems={[]} />
      </QueryClientProvider>,
    )
    fireEvent.click(await screen.findByRole('button', { name: /Edit Linkage/ }))
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByText('Suggested by Crosswalk')).toBeInTheDocument()
  })
})
