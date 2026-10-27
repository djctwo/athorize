import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import Evidence from './Evidence'
import { useUserStore } from '../store/userStore'
import type { User } from '../types'
import { api } from '../lib/api'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
  getCsrfToken: () => 'test-csrf',
}))

const ME = { id: 7, username: 'me', role: 'admin', is_operator: false } as User

const ARTIFACT = {
  id: 1,
  organization_id: 1,
  system_id: 3,
  filename: 'password-policy.docx',
  description: '',
  artifact_type: 'POLICY',
  control_ids: [],
  framework_ids: [],
  date_collected: '2026-07-01',
  expiration_date: null,
  expiration_days: null,
  uploaded_by_id: 7,
  owner_id: 7,
  owner_name: 'Alice Admin',
  file_path: 'x',
  file_hash: 'y',
  notes: '',
  created_at: '2026-07-01T00:00:00Z',
}

function mockGet(views: unknown[] = []) {
  vi.mocked(api.get).mockImplementation((url: string) => {
    if (url.startsWith('/evidence')) return Promise.resolve([ARTIFACT])
    if (url.startsWith('/views')) return Promise.resolve(views)
    return Promise.resolve([]) // /systems, /frameworks, /users/assignable
  })
}

function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <Evidence />
    </QueryClientProvider>,
  )
}

describe('Evidence page — Owner column + SavedViews', () => {
  beforeEach(() => {
    useUserStore.setState({ user: ME })
    vi.mocked(api.get).mockReset()
    vi.mocked(api.post).mockReset()
  })

  it('renders the sortable Owner column with the owner display name', async () => {
    mockGet()
    mount()
    expect(await screen.findByText('Alice Admin')).toBeInTheDocument()
    // Owner header is a sortable button
    expect(screen.getByRole('button', { name: /Sort by Owner/ })).toBeInTheDocument()
  })

  it('"Assigned to me" refetches the list filtered to my owner_id', async () => {
    mockGet()
    mount()
    await screen.findByText('Alice Admin')
    expect(api.get).toHaveBeenCalledWith('/evidence?')
    fireEvent.click(screen.getByText('Assigned to me'))
    await vi.waitFor(() => expect(api.get).toHaveBeenCalledWith('/evidence?owner_id=7'))
  })

  it('saving a view posts the evidence page key with the current filter state', async () => {
    mockGet()
    vi.mocked(api.post).mockResolvedValue({ id: 2, page: 'evidence', name: 'Mine', params: { mineOnly: true } })
    mount()
    await screen.findByText('Alice Admin')
    fireEvent.click(screen.getByText('Assigned to me'))
    fireEvent.click(screen.getByText('Save view'))
    fireEvent.change(screen.getByPlaceholderText('View name…'), { target: { value: 'Mine' } })
    fireEvent.click(screen.getByText('Save'))
    await vi.waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/views', {
        page: 'evidence', name: 'Mine', params: { mineOnly: true },
      }),
    )
  })

  it('applying a saved view re-applies the mine filter', async () => {
    mockGet([{ id: 5, page: 'evidence', name: 'My queue', params: { mineOnly: true } }])
    mount()
    const select = await screen.findByDisplayValue('Apply a view…')
    fireEvent.change(select, { target: { value: '5' } })
    await vi.waitFor(() => expect(api.get).toHaveBeenCalledWith('/evidence?owner_id=7'))
  })
})
