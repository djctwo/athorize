import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import CustomFeedsPanel from './CustomFeedsPanel'
import { api } from '../lib/api'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), put: vi.fn() },
}))

function mount(onClose = vi.fn()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <CustomFeedsPanel open onClose={onClose} />
    </QueryClientProvider>,
  )
  return onClose
}

describe('CustomFeedsPanel', () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset()
    vi.mocked(api.put).mockReset()
  })

  it('renders configured feeds from the server', async () => {
    vi.mocked(api.get).mockResolvedValue({
      feeds: [{ name: 'Siemens PSIRT', url: 'https://cert.example.com/meta.json', format: 'csaf' }],
    })
    mount()
    expect(await screen.findByDisplayValue('Siemens PSIRT')).toBeInTheDocument()
    expect(screen.getByDisplayValue('https://cert.example.com/meta.json')).toBeInTheDocument()
  })

  it('shows the empty state when no feeds are configured', async () => {
    vi.mocked(api.get).mockResolvedValue({ feeds: [] })
    mount()
    expect(await screen.findByText(/No custom feeds configured/)).toBeInTheDocument()
  })

  it('adding a row and saving PUTs the feed list', async () => {
    vi.mocked(api.get).mockResolvedValue({ feeds: [] })
    vi.mocked(api.put).mockResolvedValue({
      feeds: [{ name: 'Acme', url: 'https://feeds.example.com/all.xml', format: 'rss' }],
    })
    mount()
    await screen.findByText(/No custom feeds configured/)
    fireEvent.click(screen.getByText('Add feed'))
    fireEvent.change(screen.getByPlaceholderText('e.g. Siemens PSIRT'), { target: { value: 'Acme' } })
    fireEvent.change(screen.getByPlaceholderText('https://vendor.example.com/security/advisories.xml'), {
      target: { value: 'https://feeds.example.com/all.xml' },
    })
    fireEvent.click(screen.getByText('Save feeds'))
    await vi.waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/advisories/custom-feeds', {
        feeds: [{ name: 'Acme', url: 'https://feeds.example.com/all.xml', format: 'rss' }],
      }),
    )
  })

  it('save is disabled while a row is missing name or url', async () => {
    vi.mocked(api.get).mockResolvedValue({ feeds: [] })
    mount()
    await screen.findByText(/No custom feeds configured/)
    fireEvent.click(screen.getByText('Add feed'))
    expect(screen.getByText('Save feeds')).toBeDisabled()
  })

  it('removing a row drops it from the save payload', async () => {
    vi.mocked(api.get).mockResolvedValue({
      feeds: [
        { name: 'Keep', url: 'https://keep.example.com/a.xml', format: 'rss' },
        { name: 'Drop', url: 'https://drop.example.com/a.xml', format: 'rss' },
      ],
    })
    vi.mocked(api.put).mockResolvedValue({ feeds: [] })
    mount()
    await screen.findByDisplayValue('Drop')
    fireEvent.click(screen.getAllByTitle('Remove feed')[1])
    fireEvent.click(screen.getByText('Save feeds'))
    await vi.waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/advisories/custom-feeds', {
        feeds: [{ name: 'Keep', url: 'https://keep.example.com/a.xml', format: 'rss' }],
      }),
    )
  })
})
