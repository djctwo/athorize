import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import FindingEntryPanel from './FindingEntryPanel'
import { useUserStore } from '../store/userStore'
import type { Finding, User } from '../types'
import { api } from '../lib/api'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
  getCsrfToken: () => 'test-csrf',
}))

const MANAGER = { id: 2, username: 'manager', role: 'compliance_manager', is_operator: false } as User
const RECORD = {
  id: 9, organization_id: 1, system_id: 1, framework_id: 'nist-800-53-r5', control_id: 'AC-2',
  title: 'Shared admin acount', description: '', weakness_description: '', severity: 'MEDIUM',
  status: 'OPEN', owner_id: null, owner_name: '', owner_email: '', due_date: '2026-12-31',
  scheduled_completion: null, actual_completion: null, remediation_plan: '', risk_rationale: '',
  reopen_reason: '', updated_at: '2026-10-21T18:00:00.123456+00:00',
} as unknown as Finding

function mount(props: Partial<Parameters<typeof FindingEntryPanel>[0]> = {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <FindingEntryPanel open mode="edit" record={RECORD} systems={[]} frameworks={[]} onClose={() => {}} {...props} />
    </QueryClientProvider>,
  )
}

describe('FindingEntryPanel', () => {
  beforeEach(() => {
    useUserStore.setState({ user: MANAGER })
    vi.mocked(api.get).mockReset()
    vi.mocked(api.patch).mockReset()
    vi.mocked(api.post).mockReset()
    vi.mocked(api.get).mockImplementation((url: string) =>
      Promise.resolve(url.startsWith('/users/assignable')
        ? [{ id: 5, display_name: 'Jane Analyst', username: 'analyst' }]
        : []))
    vi.mocked(api.patch).mockResolvedValue({})
    vi.mocked(api.post).mockResolvedValue({})
  })

  it('INTEGRITY-20: edit PATCHes only the changed field plus the version it was based on', async () => {
    mount()
    fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'Shared admin account' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(api.patch).toHaveBeenCalled())
    expect(api.patch).toHaveBeenCalledWith('/findings/9', {
      title: 'Shared admin account',
      expected_updated_at: '2026-10-21T18:00:00.123456+00:00',
    })
  })

  it('E2E-16: the owner is picked from real users and sent as owner_id', async () => {
    mount({ mode: 'add', record: null, systems: [{ id: 1, name: 'ERP' } as never],
      frameworks: [{ id: 'fw', short_name: 'FW', is_active: true } as never] })
    const owner = screen.getByLabelText('Owner')
    // R2USER-12: owners are listed per system (people who can work a finding there),
    // so the list appears once a system is chosen.
    expect(screen.queryByRole('option', { name: 'Jane Analyst' })).toBeNull()
    fireEvent.change(screen.getByLabelText('System'), { target: { value: '1' } })
    await screen.findByRole('option', { name: 'Jane Analyst' })
    expect(api.get).toHaveBeenCalledWith('/users/assignable?finding_system_id=1')
    expect(screen.queryByLabelText('Owner Name')).toBeNull()
    fireEvent.change(screen.getByLabelText('Framework'), { target: { value: 'fw' } })
    fireEvent.change(screen.getByLabelText('Title'), { target: { value: 'New finding' } })
    fireEvent.change(owner, { target: { value: '5' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create' }))
    await waitFor(() => expect(api.post).toHaveBeenCalled())
    expect(vi.mocked(api.post).mock.calls[0][1]).toMatchObject({ owner_id: 5, title: 'New finding' })
  })
})
