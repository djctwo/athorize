import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import UsersList from './Users'
import { useUserStore } from '../store/userStore'
import type { User } from '../types'
import { api } from '../lib/api'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
  getCsrfToken: () => 'test-csrf',
}))

const base = { display_name: null, is_active: true, created_at: '2026-10-01T00:00:00Z', last_login: null,
  organization_id: 1, organization_name: null, organization_logo: null, is_operator: false }
const USERS = [
  { ...base, id: 2, username: 'pat', email: 'pat@example.com', role: 'auditor', sso_linked: true },
  { ...base, id: 3, username: 'kim', email: 'kim@example.com', role: 'auditor', sso_linked: false },
]

function mountAs(role: string) {
  useUserStore.setState({ user: { id: 1, username: role, role, is_operator: false } as User })
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}><MemoryRouter><UsersList /></MemoryRouter></QueryClientProvider>,
  )
}

// R2SEC-9: admins see which accounts are bound to an SSO identity and can unlink one.
describe('Users page — SSO link status and Unlink', () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset()
    vi.mocked(api.delete).mockReset()
    vi.mocked(api.get).mockImplementation((url: string) => Promise.resolve(url === '/users' ? USERS : []))
    vi.mocked(api.delete).mockResolvedValue({ ok: true })
  })

  it('shows "SSO linked" only for linked accounts and unlinks after confirming', async () => {
    mountAs('admin')
    await screen.findByText('pat')
    expect(screen.getAllByText('SSO linked')).toHaveLength(1)
    expect(screen.queryByLabelText('Unlink SSO for kim')).toBeNull()
    fireEvent.click(screen.getByLabelText('Unlink SSO for pat'))
    fireEvent.click(await screen.findByRole('button', { name: 'Unlink' }))
    await waitFor(() => expect(api.delete).toHaveBeenCalledWith('/users/2/sso'))
  })

  it('offers no Unlink action to a compliance manager (view only)', async () => {
    mountAs('compliance_manager')
    await screen.findByText('pat')
    expect(screen.getByText('SSO linked')).toBeInTheDocument()
    expect(screen.queryByLabelText('Unlink SSO for pat')).toBeNull()
  })
})
