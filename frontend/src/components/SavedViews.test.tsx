import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SavedViews from './SavedViews'
import { api } from '../lib/api'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), delete: vi.fn() },
}))

function mount(onApply = vi.fn(), current = { filterSeverity: 'HIGH' }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <SavedViews page="findings" current={current} onApply={onApply} />
    </QueryClientProvider>,
  )
  return onApply
}

describe('SavedViews', () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset()
    vi.mocked(api.post).mockReset()
  })

  it('applying a view hands its params back to the host page', async () => {
    vi.mocked(api.get).mockResolvedValue([
      { id: 1, page: 'findings', name: 'Critical open', params: { filterSeverity: 'CRITICAL', filterStatus: 'OPEN' } },
    ])
    const onApply = mount()
    const select = await screen.findByDisplayValue('Apply a view…')
    fireEvent.change(select, { target: { value: '1' } })
    expect(onApply).toHaveBeenCalledWith({ filterSeverity: 'CRITICAL', filterStatus: 'OPEN' })
  })

  it('saving posts the current filter state with the typed name', async () => {
    vi.mocked(api.get).mockResolvedValue([])
    vi.mocked(api.post).mockResolvedValue({ id: 2, page: 'findings', name: 'Mine', params: {} })
    mount(vi.fn(), { filterSeverity: 'HIGH' })
    fireEvent.click(screen.getByText('Save view'))
    fireEvent.change(screen.getByPlaceholderText('View name…'), { target: { value: 'Mine' } })
    fireEvent.click(screen.getByText('Save'))
    await vi.waitFor(() =>
      expect(api.post).toHaveBeenCalledWith('/views', {
        page: 'findings', name: 'Mine', params: { filterSeverity: 'HIGH' },
      }),
    )
  })

  it('save button disabled until a name is typed', async () => {
    vi.mocked(api.get).mockResolvedValue([])
    mount()
    fireEvent.click(screen.getByText('Save view'))
    expect(screen.getByText('Save')).toBeDisabled()
  })
})
