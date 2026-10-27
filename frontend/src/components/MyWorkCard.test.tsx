import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import MyWorkCard from './MyWorkCard'
import { useUserStore } from '../store/userStore'
import type { User } from '../types'
import { api } from '../lib/api'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn() },
}))

const ME = { id: 7, username: 'me', role: 'admin', is_operator: false } as User

function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <MyWorkCard />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('MyWorkCard', () => {
  beforeEach(() => {
    useUserStore.setState({ user: ME })
    vi.mocked(api.get).mockReset()
  })

  it('renders nothing while loading and when the queue is empty', async () => {
    vi.mocked(api.get).mockResolvedValue({ findings: [], controls: [], evidence: [] })
    const { container } = mount()
    await vi.waitFor(() => expect(api.get).toHaveBeenCalledWith('/dashboard/my-work'))
    expect(container).toBeEmptyDOMElement()
  })

  it('shows all three work types with overdue/expired accents', async () => {
    vi.mocked(api.get).mockResolvedValue({
      findings: [
        { id: 1, title: 'A', overdue: true },
        { id: 2, title: 'B', overdue: false },
      ],
      controls: [{ system_id: 3, system: 'ERP', framework_id: 'pci-dss-v4', control_id: 'AC-2' }],
      evidence: [{ id: 9, filename: 'scan.pdf', days: -2, expired: true }],
    })
    mount()
    expect(await screen.findByText(/2 findings/)).toBeInTheDocument()
    expect(screen.getByText(/1 overdue/)).toBeInTheDocument()
    expect(screen.getByText(/1 control to implement/)).toBeInTheDocument()
    expect(screen.getByText(/1 evidence item to refresh/)).toBeInTheDocument()
    expect(screen.getByText(/1 expired/)).toBeInTheDocument()
    // control link deep-links into the right system+framework grid
    const controlLink = screen.getByText(/control to implement/).closest('a')
    expect(controlLink).toHaveAttribute('href', '/controls?framework=pci-dss-v4&system=3')
  })
})
