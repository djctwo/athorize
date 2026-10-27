import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import InspectionPrep from './InspectionPrep'
import { api } from '../lib/api'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn() },
  getCsrfToken: () => 'test-csrf',
}))

// The demo showed AC at 100% ready while AC-2 had an open finding. Readiness now
// counts open findings, and the page says so where readiness is explained.
const PKG = {
  framework_id: 'nist-800-53-r5', control_count: 2, assessed_items: 2, not_applicable: 0,
  readiness_score: 50,
  families: [{ family: 'AC', family_name: 'Access Control', total: 2, ready: 1, readiness_pct: 50,
    implemented: 2, narrative_gaps: 0, evidence_gaps: 0, stale_evidence: 0, open_findings: 1 }],
  punch_list: [{ priority: 1, action: 'remediate', system_acronym: 'CORP', control_id: 'AC-2',
    control_title: 'Account Management', family: 'AC', status: 'IMPLEMENTED',
    issues: ['open finding: Account reviews skipped two quarters'], owner: 'IT Security' }],
  timeline: [],
}

describe('Inspection Prep explains and shows open findings', () => {
  it('has an Open findings column, a Remediate action and the readiness rule', async () => {
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url.startsWith('/inspection/prep')) return Promise.resolve(PKG)
      if (url === '/frameworks') return Promise.resolve([{ id: 'nist-800-53-r5', short_name: 'NIST 800-53r5', is_active: true }])
      if (url === '/systems') return Promise.resolve([{ id: 4, acronym: 'CORP', name: 'Corporate Security Program' }])
      return Promise.resolve([])
    })
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(<QueryClientProvider client={qc}><InspectionPrep /></QueryClientProvider>)
    const selects = await screen.findAllByRole('combobox')
    await screen.findByRole('option', { name: 'NIST 800-53r5' })
    fireEvent.change(selects[0], { target: { value: 'nist-800-53-r5' } })
    await screen.findByRole('option', { name: /CORP/ })
    fireEvent.change(selects[1], { target: { value: '4' } })
    expect(await screen.findByRole('columnheader', { name: 'Open findings' })).toBeInTheDocument()
    expect(screen.getByText(/no open finding \(Open, In Progress or Delayed\)/)).toBeInTheDocument()
    const row = screen.getByText('AC-2').closest('tr')!
    expect(within(row).getByText('Remediate')).toBeInTheDocument()
    expect(within(row).getByText(/open finding: Account reviews skipped/)).toBeInTheDocument()
  })
})
