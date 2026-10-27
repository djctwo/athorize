import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import Findings from './Findings'
import { useUserStore } from '../store/userStore'
import type { User } from '../types'
import { api } from '../lib/api'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
  getCsrfToken: () => 'test-csrf',
}))

const ME = { id: 7, username: 'me', role: 'admin', is_operator: false } as User

// is_open comes from the server (services/metrics.py) — the page must count it,
// not re-derive "open" from status (the Dashboard said 12, this page said 11).
const F = (id: number, status: string, severity: string, is_open: boolean) => ({
  id, title: `Finding ${id}`, status, severity, is_open, system_id: 1, framework_id: 'x',
  control_id: 'AC-2', aging_bucket: is_open ? 'DUE_30' : 'RESOLVED', days_until_due: null,
  days_open: 3, extra_data: {}, milestones: [], created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z',
})

function mount() {
  vi.mocked(api.get).mockImplementation((url: string) => {
    if (url.startsWith('/findings')) return Promise.resolve([
      F(1, 'OPEN', 'HIGH', true),
      F(2, 'IN_PROGRESS', 'CRITICAL', true),
      F(3, 'DELAYED', 'MEDIUM', true),
      F(4, 'CLOSED', 'HIGH', false),
      F(5, 'RISK_ACCEPTED', 'CRITICAL', false),
    ])
    return Promise.resolve([])
  })
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter><Findings /></MemoryRouter>
    </QueryClientProvider>,
  )
}

function tile(label: RegExp) {
  const el = screen.getAllByText(label).find(e => e.closest('.relative'))!
  return el.closest('.relative') as HTMLElement
}

describe('Findings KPI tiles use the one definition of open', () => {
  beforeEach(() => {
    useUserStore.setState({ user: ME })
    vi.mocked(api.get).mockReset()
  })

  it('Open counts Delayed (as the Dashboard does) and says so', async () => {
    mount()
    await screen.findByText('Finding 3')
    const open = tile(/^Open$/)
    expect(within(open).getByText('3')).toBeInTheDocument()
    expect(within(open).getByText('incl. 1 delayed')).toBeInTheDocument()
  })

  it('Critical/High counts open findings only', async () => {
    mount()
    await screen.findByText('Finding 3')
    const crit = tile(/Critical\/High/)
    expect(within(crit).getByText('2')).toBeInTheDocument()
  })
})
