import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Setup from './Setup'
import { api } from '../lib/api'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
  getCsrfToken: () => 'test-csrf',
}))

function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <Setup />
    </QueryClientProvider>,
  )
}

describe('First-run Setup: set up my company, or explore with demo data', () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset().mockResolvedValue({ setup_complete: false, setup_token_required: true })
    vi.mocked(api.post).mockReset()
  })

  it('offers both choices, and says where the token is and what the demo logins are', async () => {
    mount()
    expect(await screen.findByLabelText('Setup Token')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create Organization' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Explore with demo data' })).toBeInTheDocument()
    expect(screen.getByText(/password is the username/i)).toBeInTheDocument()
    expect(screen.getByText(/Start fresh/)).toBeInTheDocument()
    expect(screen.getByText(/server log/i)).toBeInTheDocument()
  })

  it('loads the demo with the pasted token', async () => {
    vi.mocked(api.post).mockResolvedValue({ user_id: 1, org_id: 1, demo_logins: ['admin'] })
    mount()
    fireEvent.change(await screen.findByLabelText('Setup Token'), { target: { value: ' tok-123 ' } })
    fireEvent.click(screen.getByRole('button', { name: 'Explore with demo data' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledWith('/auth/setup/demo', { setup_token: ' tok-123 ' }))
  })

  it('shows why the demo was refused', async () => {
    vi.mocked(api.post).mockRejectedValue(new Error('Invalid or missing setup token.'))
    mount()
    fireEvent.click(await screen.findByRole('button', { name: 'Explore with demo data' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid or missing setup token.')
    expect(screen.getByRole('button', { name: 'Create Organization' })).toBeEnabled()
  })

  it('still sets up a company exactly as before', async () => {
    vi.mocked(api.post).mockResolvedValue({ user_id: 1, org_id: 1 })
    mount()
    fireEvent.change(await screen.findByLabelText('Setup Token'), { target: { value: 'tok' } })
    fireEvent.change(screen.getByLabelText('Organization Name'), { target: { value: 'Acme Example Co' } })
    fireEvent.change(screen.getByLabelText('Admin Username'), { target: { value: 'founder' } })
    fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'Blue-Kestrel-42-Orbit' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create Organization' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledWith('/auth/setup', expect.objectContaining({
      org_name: 'Acme Example Co', username: 'founder', setup_token: 'tok',
    })))
  })
})
