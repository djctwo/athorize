import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BackupPanel } from './Settings'
import { api } from '../lib/api'

vi.mock('../lib/api', () => ({
  api: { get: vi.fn(), post: vi.fn(), patch: vi.fn(), put: vi.fn(), delete: vi.fn() },
  getCsrfToken: () => 'test-csrf',
}))

const INFO = {
  supported: true,
  unsupported_reason: null,
  db_size_bytes: 4096,
  evidence_file_count: 2,
  custom_framework_count: 1,
  last_backup_name: null,
  last_backup_at: null,
  last_backup_bytes: null,
  max_restore_upload_bytes: 512 * 1024 * 1024,
  keep_backups: 10,
  keep_rollbacks: 3,
  restore_nonce: 'nonce-1',
}

function mount() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <BackupPanel />
    </QueryClientProvider>,
  )
}

describe('Settings → Backup & Restore', () => {
  beforeEach(() => {
    vi.mocked(api.get).mockReset()
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('shows the server-side retention (decision #8)', async () => {
    vi.mocked(api.get).mockResolvedValue(INFO)
    mount()
    expect(await screen.findByText(/newest 10 backups and 3 rollback copies/)).toBeInTheDocument()
  })

  it('says everything is kept when retention is 0', async () => {
    vi.mocked(api.get).mockResolvedValue({ ...INFO, keep_backups: 0, keep_rollbacks: 0 })
    mount()
    expect(await screen.findByText(/all backups and all rollback copies/)).toBeInTheDocument()
  })

  it('explains why a company admin of a multi-company install cannot back up (SECCODE-1)', async () => {
    vi.mocked(api.get).mockRejectedValue(new Error('Backups contain every company on this instance, so only an instance operator can back up or restore.'))
    mount()
    expect(await screen.findByText(/only an instance operator/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /download/i })).toBeNull()
  })

  it('tells a PostgreSQL install that in-app backup is unsupported instead of offering an empty backup (IMPORTS-26)', async () => {
    vi.mocked(api.get).mockResolvedValue({ ...INFO, supported: false, unsupported_reason: 'This instance stores its data in PostgreSQL (DATABASE_URL)' })
    mount()
    expect(await screen.findByRole('alert')).toHaveTextContent('PostgreSQL')
    expect(screen.queryByRole('button', { name: /download/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /restore/i })).toBeNull()
  })

  it('shows restore warnings (audit key mismatch) and waits for the user instead of redirecting (INTEGRITY-23)', async () => {
    vi.mocked(api.get).mockResolvedValue(INFO)
    const result = {
      restored_db: true, restored_evidence_files: 2, restored_custom_frameworks: 1,
      sessions_revoked: 3, api_tokens_revoked: 1, rollback_path: 'rollback-2026-10-22',
      audit_key_matches: false, note: 'Restore complete.',
      warnings: ["This backup's audit log was signed with a different audit key than this instance uses"],
    }
    const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(result) })
    vi.stubGlobal('fetch', fetchMock)
    const { container } = mount()
    await screen.findByRole('button', { name: /download/i })
    const input = container.querySelector('input[type=file]') as HTMLInputElement
    fireEvent.change(input, { target: { files: [new File(['x'], 'b.tar.gz')] } })
    fireEvent.click(screen.getByRole('button', { name: 'Restore…' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm — overwrite everything' }))
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Restore complete'))
    expect(screen.getByText(/different audit key/)).toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent('1 API')
    expect(screen.getByRole('button', { name: 'Sign in again' })).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledWith('/api/backup/restore', expect.objectContaining({ method: 'POST' }))
  })
})
