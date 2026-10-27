import { beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AuditLog from './AuditLog'
import { api } from '../lib/api'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
  getCsrfToken: () => 'test-csrf',
}))

function mount(verify: unknown) {
  vi.mocked(api.get).mockImplementation((url: string) =>
    Promise.resolve(url === '/audit/verify' ? verify : []))
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AuditLog />
    </QueryClientProvider>,
  )
}

describe('Audit Log integrity badge', () => {
  beforeEach(() => vi.mocked(api.get).mockReset())

  it('says "verified" only for a fully authenticated chain', async () => {
    mount({ valid: true, entries_checked: 5, broken_at_id: null, reason: null, legacy_entries: 0, unauthenticated_legacy_entries: 0 })
    expect(await screen.findByText('Chain verified')).toBeTruthy()
  })

  it('distinguishes legacy entries signed with the public default key', async () => {
    mount({ valid: true, entries_checked: 9, broken_at_id: null, legacy_entries: 4, unauthenticated_legacy_entries: 4,
      reason: '4 legacy entries were signed with the public default key' })
    expect(await screen.findByText(/4 older entries are unauthenticated/)).toBeTruthy()
    expect(screen.getByTestId('audit-integrity-reason').textContent).toContain('public default key')
    expect(screen.queryByText('Chain verified')).toBeNull()
  })

  it('shows truncation (no broken entry id) as broken with the reason', async () => {
    mount({ valid: false, entries_checked: 3, broken_at_id: null, reason: 'entries deleted or log truncated' })
    expect(await screen.findByText('Chain broken')).toBeTruthy()
    expect(screen.getByTestId('audit-integrity-reason').textContent).toContain('truncated')
  })
})
