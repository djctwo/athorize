import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { FindingCard } from './RedTeam'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn() },
  getCsrfToken: () => 'test-csrf',
}))

const FINDING = {
  id: 'RT-001', title: '29 controls have no linked evidence', description: 'An assessor would flag these.',
  severity: 'HIGH' as const, category: 'Evidence Gap', control_ids: ['AC-1'], affected_entities: [],
  remediation: 'Link evidence.', finding_language: { title: 't', description: 'd', remediation_plan: 'r', severity: 'HIGH', scheduled_completion_days: 30 },
  estimated_exposure_low: 2_100_000, estimated_exposure_high: 6_400_000,
  remediation_effort: 'MEDIUM' as const, effort_hours_low: 20, effort_hours_high: 60,
  priority_score: 4_108_750, cost_breakdown: [],
}

describe('Red Team finding card', () => {
  it('shows the priority as a rank a reader understands, not the raw ROI score', () => {
    const qc = new QueryClient()
    render(<QueryClientProvider client={qc}><FindingCard finding={FINDING} reportId={1} rank={2} total={8} /></QueryClientProvider>)
    fireEvent.click(screen.getByText(FINDING.title))
    expect(screen.getByText('#2 of 8')).toBeInTheDocument()
    expect(screen.getByText(/exposure avoided per hour of effort/i)).toBeInTheDocument()
    expect(screen.queryByText('4,108,750')).toBeNull()
    expect(screen.queryByText(/Priority Score/i)).toBeNull()
  })
})
