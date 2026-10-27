import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { StartFreshPanel } from './Settings'
import { api } from '../lib/api'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
  apiErrorMessage: (b: { detail?: string }) => b?.detail ?? 'error',
  getCsrfToken: () => 'test-csrf',
  responseError: vi.fn(),
}))

function mount(autoseed = false) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <StartFreshPanel autoseed={autoseed} />
    </QueryClientProvider>,
  )
}

describe('Settings → Start fresh (demo instances)', () => {
  const assign = vi.fn()
  beforeEach(() => {
    vi.mocked(api.post).mockReset()
    assign.mockReset()
    vi.stubGlobal('location', { ...window.location, assign })
  })
  afterEach(() => vi.unstubAllGlobals())

  it('warns that EVERYTHING is deleted, and needs the password and the typed confirmation', async () => {
    mount()
    expect(screen.getByText(/deletes everything on this instance/i)).toBeInTheDocument()
    expect(screen.getByText(/including anything you added/i)).toBeInTheDocument()
    const go = screen.getByRole('button', { name: 'Start fresh' })
    expect(go).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Your password'), { target: { value: 'admin' } })
    expect(go).toBeDisabled()
    fireEvent.change(screen.getByLabelText(/Type START FRESH/), { target: { value: 'start fresh' } })
    expect(go).toBeDisabled()
    fireEvent.change(screen.getByLabelText(/Type START FRESH/), { target: { value: 'START FRESH' } })
    expect(go).toBeEnabled()
  })

  it('wipes, then sends the user to the Setup screen', async () => {
    vi.mocked(api.post).mockResolvedValue({ ok: true, next: 'setup' })
    mount()
    fireEvent.change(screen.getByLabelText('Your password'), { target: { value: 'admin' } })
    fireEvent.change(screen.getByLabelText(/Type START FRESH/), { target: { value: 'START FRESH' } })
    fireEvent.click(screen.getByRole('button', { name: 'Start fresh' }))
    await waitFor(() => expect(api.post).toHaveBeenCalledWith('/auth/start-fresh', { password: 'admin', confirm: 'START FRESH' }))
    await waitFor(() => expect(assign).toHaveBeenCalledWith('/'))
  })

  it('shows the server refusal (wrong password)', async () => {
    vi.mocked(api.post).mockRejectedValue(new Error('Current password is incorrect'))
    mount()
    fireEvent.change(screen.getByLabelText('Your password'), { target: { value: 'nope' } })
    fireEvent.change(screen.getByLabelText(/Type START FRESH/), { target: { value: 'START FRESH' } })
    fireEvent.click(screen.getByRole('button', { name: 'Start fresh' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Current password is incorrect')
    expect(assign).not.toHaveBeenCalled()
  })

  it('is called "Reset demo data" on builds that re-load the demo', () => {
    mount(true)
    expect(screen.getByRole('button', { name: 'Reset demo data' })).toBeInTheDocument()
    expect(screen.getByText(/clean copy of the demo/i)).toBeInTheDocument()
  })
})
