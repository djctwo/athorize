import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import CommentsSection from './CommentsSection'
import { api } from '../lib/api'
import { useUserStore } from '../store/userStore'
import type { User } from '../types'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), delete: vi.fn() },
}))

const admin = {
  id: 1, username: 'admin', role: 'admin', display_name: 'Admin User',
  email: null, is_active: true, created_at: '', last_login: null,
  organization_id: 1, organization_name: null, is_operator: false,
} as User

const assignable = [
  { id: 1, display_name: 'Admin User', username: 'admin' },
  { id: 2, display_name: 'Jane Analyst', username: 'analyst' },
]

function mockGets(comments: unknown[] = []) {
  vi.mocked(api.get).mockImplementation((path: string) => {
    if (path.startsWith('/comments')) return Promise.resolve(comments)
    if (path.startsWith('/users/assignable')) return Promise.resolve(assignable)
    return Promise.resolve([])
  })
}

function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <CommentsSection entityType="finding" entityId={7} />
    </QueryClientProvider>,
  )
}

describe('CommentsSection', () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset()
    vi.mocked(api.post).mockReset()
    vi.mocked(api.delete).mockReset()
    useUserStore.setState({ user: admin })
  })

  it('lists fetched comments with author and highlighted mentions', async () => {
    mockGets([
      { id: 10, entity_type: 'finding', entity_id: 7, author_id: 2, author_name: 'Jane Analyst',
        body: 'Looping in @admin here', mentions: [1], created_at: new Date().toISOString() },
    ])
    mount()
    expect(await screen.findByText('Jane Analyst')).toBeInTheDocument()
    expect(screen.getByText('@admin')).toBeInTheDocument()
  })

  it('posting sends entity_type, entity_id and body', async () => {
    mockGets([])
    vi.mocked(api.post).mockResolvedValue({ id: 11 })
    mount()
    const box = await screen.findByPlaceholderText(/Add a comment/)
    fireEvent.change(box, { target: { value: 'First pass done' } })
    fireEvent.click(screen.getByText('Comment'))
    await vi.waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/comments', {
        entity_type: 'finding', entity_id: 7, body: 'First pass done',
      }),
    )
  })

  it('typing @ shows teammate suggestions and clicking inserts the username', async () => {
    mockGets([])
    mount()
    const box = await screen.findByPlaceholderText(/Add a comment/)
    fireEvent.change(box, { target: { value: 'ping @an', selectionStart: 8 } })
    const option = await screen.findByText('@analyst')
    fireEvent.mouseDown(option)
    expect((box as HTMLTextAreaElement).value).toBe('ping @analyst ')
  })

  it('the caret sits after the inserted mention in the same render (no frame-late jump)', async () => {
    mockGets([])
    mount()
    const box = (await screen.findByPlaceholderText(/Add a comment/)) as HTMLTextAreaElement
    fireEvent.change(box, { target: { value: 'ping @an and more', selectionStart: 8 } })
    box.setSelectionRange(8, 8)
    fireEvent.mouseDown(await screen.findByText('@analyst'))
    // synchronously — a keystroke right now must land after "@analyst "
    expect(box.value).toBe('ping @analyst  and more')
    expect(box.selectionStart).toBe('ping @analyst '.length)
    expect(document.activeElement).toBe(box)
  })

  it('admin sees delete on others comments and it calls the API', async () => {
    mockGets([
      { id: 12, entity_type: 'finding', entity_id: 7, author_id: 2, author_name: 'Jane Analyst',
        body: 'delete me', mentions: [], created_at: new Date().toISOString() },
    ])
    vi.mocked(api.delete).mockResolvedValue({ ok: true })
    mount()
    const btn = await screen.findByLabelText('Delete comment by Jane Analyst')
    fireEvent.click(btn)
    await vi.waitFor(() => expect(api.delete).toHaveBeenCalledWith('/comments/12'))
  })

  it('non-author non-admin gets no delete button', async () => {
    useUserStore.setState({ user: { ...admin, id: 3, role: 'assessor', username: 'other' } })
    mockGets([
      { id: 13, entity_type: 'finding', entity_id: 7, author_id: 2, author_name: 'Jane Analyst',
        body: 'not yours', mentions: [], created_at: new Date().toISOString() },
    ])
    mount()
    await screen.findByText('not yours')
    expect(screen.queryByLabelText(/Delete comment/)).not.toBeInTheDocument()
  })

  it('auditor reads the thread but gets no composer (server: post:comment) — SECCODE-17', async () => {
    useUserStore.setState({ user: { ...admin, id: 4, role: 'auditor', username: 'aud' } })
    mockGets([
      { id: 14, entity_type: 'finding', entity_id: 7, author_id: 2, author_name: 'Jane Analyst',
        body: 'visible to auditors', mentions: [], created_at: new Date().toISOString() },
    ])
    mount()
    await screen.findByText('visible to auditors')
    expect(screen.queryByPlaceholderText(/Add a comment/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Comment' })).not.toBeInTheDocument()
  })
})
