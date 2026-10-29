import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import Dashboard from './Dashboard'
import { useUserStore } from '../store/userStore'
import type { User } from '../types'
import { api } from '../lib/api'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
  getCsrfToken: () => 'test-csrf',
}))

// recharts' ResponsiveContainer needs ResizeObserver, which jsdom lacks.
globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as unknown as typeof ResizeObserver

const pair = (system_name: string, framework_id: string, score: number, assessed: number, open = 0) => ({
  system_id: 1, system_name, framework_id, score_percentage: score, total_controls: 10,
  implemented: Math.round(score / 10), open_findings: open, critical_findings: 0, assessed_controls: assessed,
  has_work: assessed > 0 || open > 0,
})

describe('Dashboard (SCA demo rehearsal)', () => {
  it('says Open Findings include Delayed and hides never-started system × framework pairs', async () => {
    useUserStore.setState({ user: { id: 1, username: 'admin', role: 'admin', is_operator: false } as User })
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.startsWith('/dashboard/snapshot')) return Promise.resolve({
        organization_name: 'Acme', total_systems: 4, open_findings: 12, delayed_findings: 1, critical_findings: 3,
        overdue_findings: 1, expiring_evidence: 1, expired_evidence: 1, fresh_evidence: 8, total_evidence: 10,
        active_frameworks: 19, open_risks: 3, cadence_overdue: 6,
      })
      if (url.startsWith('/dashboard/compliance')) return Promise.resolve([
        pair('ERP', 'pci-dss-v4', 81, 300), pair('ERP', 'dora', 0, 0), pair('SCADA', 'dora', 0, 0),
        pair('DEV', 'nist-800-53-r5', 0, 5),
      ])
      if (url.startsWith('/dashboard/onboarding')) return Promise.resolve({ steps: [], complete: true, dismissed: true })
      if (url.startsWith('/dashboard/my-work')) return Promise.resolve({ findings: [], controls: [], evidence: [] })
      return Promise.resolve(url.includes('aging') || url.includes('severity') || url.includes('freshness') ? {} : [])
    })
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={qc}><MemoryRouter><Dashboard /></MemoryRouter></QueryClientProvider>)
    expect(await screen.findByText('incl. 1 delayed')).toBeInTheDocument()
    expect(await screen.findByText(/2 not started yet \(no control assessed, no open finding\) are hidden/)).toBeInTheDocument()
  })

  it('says the trend average is over the active system × framework pairs, and how many', async () => {
    useUserStore.setState({ user: { id: 1, username: 'admin', role: 'admin', is_operator: false } as User })
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.startsWith('/dashboard/history')) return Promise.resolve([
        { date: '2026-10-22', avg_score: 33.1, active_pairs: 6, open_findings: 12, overdue_findings: 1, critical_findings: 3 },
        { date: '2026-10-29', avg_score: 35.7, active_pairs: 6, open_findings: 12, overdue_findings: 1, critical_findings: 3 },
      ])
      if (url.startsWith('/dashboard/compliance')) return Promise.resolve([pair('ERP', 'pci-dss-v4', 81, 300), pair('ERP', 'dora', 0, 0)])
      if (url.startsWith('/dashboard/onboarding')) return Promise.resolve({ steps: [], complete: true, dismissed: true })
      if (url.startsWith('/dashboard/my-work')) return Promise.resolve({ findings: [], controls: [], evidence: [] })
      return Promise.resolve(url.includes('aging') || url.includes('severity') || url.includes('freshness') || url.includes('snapshot') ? {} : [])
    })
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={qc}><MemoryRouter><Dashboard /></MemoryRouter></QueryClientProvider>)
    expect(await screen.findByText(/Avg compliance % is the mean score across 6 active system × framework pairs/)).toBeInTheDocument()
    expect(screen.getByText(/Frameworks nobody has started are left out/)).toBeInTheDocument()
  })
})
