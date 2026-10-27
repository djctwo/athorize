import { useId, useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api, apiErrorMessage, getCsrfToken, responseError } from '../lib/api'
import { formatDate, formatDateTime } from '../lib/datetime'
import type { User } from '../types'
import { useUserStore } from '../store/userStore'
import { useCan } from '../hooks/useRole'
import { UserPlus, Download, Upload, ShieldAlert, Terminal, Trash2, Mail, Image as ImageIcon, KeyRound } from 'lucide-react'
import { toast } from '../store/toastStore'
import CompanyLogo from '../components/CompanyLogo'
import { plural } from '../lib/plural'

export default function Settings() {
  const { user } = useUserStore()
  const canViewUsers = useCan('view:users')
  const canManageUsers = useCan('manage:users')
  const canManageSettings = useCan('manage:settings')
  const canViewDigest = useCan('view:digest')
  const queryClient = useQueryClient()
  const [showAddUser, setShowAddUser] = useState(false)
  const [newUser, setNewUser] = useState({ username: '', password: '', email: '', display_name: '', role: 'evidence_contributor' })

  // The version comes from the server (backend/version.py), the one place it is set.
  const { data: version } = useQuery({
    queryKey: ['app-version'],
    queryFn: () => api.get<{ version: string }>('/health').then(h => h.version),
    staleTime: Infinity,
  })

  const { data: users = [] } = useQuery({
    queryKey: ['users'],
    queryFn: () => api.get<User[]>('/users'),
    enabled: canViewUsers,
  })

  const createUser = useMutation({
    mutationFn: () => api.post('/users', newUser),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      setShowAddUser(false)
      setNewUser({ username: '', password: '', email: '', display_name: '', role: 'evidence_contributor' })
    },
  })

  return (
    <div className="max-w-4xl">
      <h2 className="text-xl font-bold mb-6">Settings</h2>

      <section className="mb-8">
        <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-3">Your Profile</h3>
        <div className="bg-bg-secondary border border-border p-4">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div><span className="text-text-muted">Username:</span> <span className="ml-2">{user?.username}</span></div>
            <div><span className="text-text-muted">Role:</span> <span className="ml-2 capitalize">{user?.role?.replace('_', ' ')}</span></div>
            <div><span className="text-text-muted">Email:</span> <span className="ml-2">{user?.email || '—'}</span></div>
            <div><span className="text-text-muted">Last Login:</span> <span className="ml-2">{user?.last_login ? formatDateTime(user.last_login) : '—'}</span></div>
          </div>
          <ChangePasswordForm />
        </div>
      </section>

      {canViewUsers && (
        <section className="mb-8">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider">Team Members</h3>
            {canManageUsers && (
              <button onClick={() => setShowAddUser(true)} className="flex items-center gap-2 px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm">
                <UserPlus size={14} /> Add User
              </button>
            )}
          </div>

          {showAddUser && (
            <div className="bg-bg-secondary border border-border p-4 mb-4">
              <form onSubmit={(e) => { e.preventDefault(); createUser.mutate() }} className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-text-muted mb-1">Username</label>
                  <input className="w-full" value={newUser.username} onChange={(e) => setNewUser({ ...newUser, username: e.target.value })} required />
                </div>
                <div>
                  <label className="block text-xs text-text-muted mb-1">Password</label>
                  <input className="w-full" type="password" value={newUser.password} onChange={(e) => setNewUser({ ...newUser, password: e.target.value })} required />
                </div>
                <div>
                  <label className="block text-xs text-text-muted mb-1">Display Name</label>
                  <input className="w-full" value={newUser.display_name} onChange={(e) => setNewUser({ ...newUser, display_name: e.target.value })} />
                </div>
                <div>
                  <label className="block text-xs text-text-muted mb-1">Role</label>
                  <select className="w-full" value={newUser.role} onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}>
                    <option value="admin">Admin</option>
                    <option value="compliance_manager">Compliance Manager</option>
                    <option value="assessor">Assessor</option>
                    <option value="system_owner">System Owner</option>
                    <option value="evidence_contributor">Evidence Contributor</option>
                    <option value="auditor">Auditor (Read-only)</option>
                  </select>
                </div>
                <div className="col-span-2 flex gap-2">
                  <button type="submit" className="px-4 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm">Create User</button>
                  <button type="button" onClick={() => setShowAddUser(false)} className="px-4 py-1.5 border border-border text-text-secondary text-sm hover:bg-bg-tertiary">Cancel</button>
                </div>
              </form>
            </div>
          )}

          <div className="bg-bg-secondary border border-border">
            <table>
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Display Name</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Last Login</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id}>
                    <td className="font-medium">{u.username}</td>
                    <td className="text-text-secondary">{u.display_name}</td>
                    <td className="text-xs capitalize">{u.role.replace('_', ' ')}</td>
                    <td>{u.is_active ? <span className="text-xs text-success">Active</span> : <span className="text-xs text-danger">Inactive</span>}</td>
                    <td className="text-xs text-text-muted">{u.last_login ? formatDate(u.last_login) : 'Never'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {canManageSettings && <BrandingPanel />}
      {canManageSettings && <BackupPanel />}
      {canViewDigest && <DigestPanel isAdmin={canManageSettings} />}
      <ApiTokensPanel />
      {/* Demo instances only; instance-wide, so instance operators only (like restore). */}
      {canManageSettings && user?.demo_instance && user?.is_operator && (
        <StartFreshPanel autoseed={!!user.demo_autoseed} />
      )}

      <section>
        <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-3">About</h3>
        <div className="bg-bg-secondary border border-border p-4 text-sm text-text-secondary">
          <p>Athorize{version ? ` v${version}` : ''}</p>
          <p className="text-text-muted mt-1">Multi-framework compliance operations platform</p>
          <p className="text-text-muted mt-3 pt-3 border-t border-border">
            © 2026 Douglas Cleary
          </p>
          <p className="text-text-muted mt-1">
            Free and open-source software under the GNU Affero General Public License v3.0.
            It comes with no warranty. See the LICENSE file for the full terms.
          </p>
        </div>
      </section>
    </div>
  )
}

const LOGO_MAX_BYTES = 300 * 1024

const START_FRESH_PHRASE = 'START FRESH'

/**
 * Settings → Start fresh (demo instances only). Deletes all demo data and
 * returns to the first-run Setup screen with a new setup token
 * (POST /auth/start-fresh, backend/services/start_fresh.py). Builds that
 * always run with demo data (ATHORIZE_DEMO_SEED=1, the Demo desktop app) get
 * "Reset demo data" instead: a clean copy of the demo, then the sign-in page.
 */
export function StartFreshPanel({ autoseed }: { autoseed: boolean }) {
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const label = autoseed ? 'Reset demo data' : 'Start fresh'
  const go = useMutation({
    mutationFn: () => api.post<{ ok: boolean; next: string }>('/auth/start-fresh', { password, confirm }),
    // Everyone is signed out: reload into the Setup screen (or the sign-in page).
    onSuccess: () => window.location.assign('/'),
    onError: (e: Error) => setError(e.message),
  })
  const ready = password.length > 0 && confirm.trim() === START_FRESH_PHRASE

  return (
    <section className="mb-8">
      <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-3">{label}</h3>
      <div className="bg-bg-secondary border border-danger/40 p-4 space-y-3">
        {autoseed ? (
          <p className="text-sm">
            This build always runs with demo data. Resetting deletes everything on this instance, including anything you added, and loads a clean copy of the demo. Everyone is signed out.
          </p>
        ) : (
          <>
            <p className="text-sm">
              Done exploring? Starting fresh deletes everything on this instance, including anything you added: every company, all users, evidence files, custom frameworks, the backups made with demo data, sessions and API tokens. You then get the Setup screen to set up your own company.
            </p>
            <p className="text-xs text-text-muted">
              The Setup screen asks for a new one-time token. It is printed in the server log (the desktop app's console window; <code>docker compose logs</code> for Docker) and saved as <code>setup-token</code> in the data folder. Keys and settings in the data folder are kept.
            </p>
          </>
        )}
        <form
          className="grid grid-cols-1 sm:grid-cols-2 gap-3 items-end"
          onSubmit={(e) => { e.preventDefault(); setError(''); if (ready) go.mutate() }}
        >
          <div>
            <label className="block text-xs text-text-muted mb-1" htmlFor="start-fresh-password">Your password</label>
            <input id="start-fresh-password" type="password" autoComplete="current-password" className="w-full"
              value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>
          <div>
            <label className="block text-xs text-text-muted mb-1" htmlFor="start-fresh-confirm">Type {START_FRESH_PHRASE} to confirm</label>
            <input id="start-fresh-confirm" className="w-full" autoComplete="off" spellCheck={false}
              value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder={START_FRESH_PHRASE} />
          </div>
          {error && <p role="alert" className="sm:col-span-2 text-sm text-danger">{error}</p>}
          <div className="sm:col-span-2">
            <button type="submit" disabled={!ready || go.isPending}
              className="flex items-center gap-2 px-3 py-1.5 bg-danger text-white text-sm disabled:opacity-40">
              <Trash2 size={14} /> {go.isPending ? 'Deleting…' : label}
            </button>
          </div>
        </form>
      </div>
    </section>
  )
}

/**
 * Self-service password change (R2USER-13). Needs the current password; the
 * server applies the same policy as setup/admin resets, keeps this session,
 * signs out every other session and revokes the user's API tokens.
 */
function ChangePasswordForm() {
  const [open, setOpen] = useState(false)
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const queryClient = useQueryClient()
  const id = useId()

  const change = useMutation({
    mutationFn: () => api.post<{ ok: boolean; other_sessions_signed_out: number; api_tokens_revoked: number }>(
      '/auth/change-password', { current_password: current, new_password: next }),
    onSuccess: (res) => {
      setOpen(false); setCurrent(''); setNext(''); setConfirm(''); setError('')
      queryClient.invalidateQueries({ queryKey: ['api-tokens'] })
      const extra = [
        res.other_sessions_signed_out ? `${res.other_sessions_signed_out} other session(s) signed out` : '',
        res.api_tokens_revoked ? `${res.api_tokens_revoked} API token(s) revoked` : '',
      ].filter(Boolean).join(', ')
      toast.success(`Password changed${extra ? ` — ${extra}` : ''}`)
    },
    onError: (e) => setError(e instanceof Error ? e.message : 'Could not change the password'),
  })

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    if (next !== confirm) { setError('The new passwords do not match.'); return }
    setError('')
    change.mutate()
  }

  if (!open) {
    return (
      <div className="mt-4 pt-4 border-t border-border">
        <button type="button" onClick={() => setOpen(true)}
          className="flex items-center gap-2 px-3 py-1.5 border border-border text-text-secondary text-sm hover:bg-bg-tertiary">
          <KeyRound size={14} /> Change password
        </button>
      </div>
    )
  }
  return (
    <form onSubmit={submit} className="mt-4 pt-4 border-t border-border grid grid-cols-1 sm:grid-cols-3 gap-3 text-sm" aria-label="Change password">
      <div>
        <label className="block text-xs text-text-muted mb-1" htmlFor={`${id}-current`}>Current password</label>
        <input id={`${id}-current`} className="w-full" type="password" autoComplete="current-password"
          value={current} onChange={e => setCurrent(e.target.value)} required />
      </div>
      <div>
        <label className="block text-xs text-text-muted mb-1" htmlFor={`${id}-new`}>New password</label>
        <input id={`${id}-new`} className="w-full" type="password" autoComplete="new-password"
          value={next} onChange={e => setNext(e.target.value)} required minLength={12} />
      </div>
      <div>
        <label className="block text-xs text-text-muted mb-1" htmlFor={`${id}-confirm`}>Confirm new password</label>
        <input id={`${id}-confirm`} className="w-full" type="password" autoComplete="new-password"
          value={confirm} onChange={e => setConfirm(e.target.value)} required />
      </div>
      <p className="sm:col-span-3 text-xs text-text-muted">
        At least 12 characters with three of: lowercase, uppercase, digits, symbols. Changing it signs out your other
        sessions and revokes your API tokens.
      </p>
      {error && (
        <div role="alert" className="sm:col-span-3 text-sm text-danger p-2 bg-danger/10 border border-danger/20">{error}</div>
      )}
      <div className="sm:col-span-3 flex gap-2">
        <button type="submit" disabled={change.isPending} className="px-4 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm disabled:opacity-50">
          {change.isPending ? 'Changing…' : 'Change password'}
        </button>
        <button type="button" onClick={() => { setOpen(false); setError('') }}
          className="px-4 py-1.5 border border-border text-text-secondary text-sm hover:bg-bg-tertiary">Cancel</button>
      </div>
    </form>
  )
}

function BrandingPanel() {
  const { user, setUser } = useUserStore()
  const fileRef = useRef<HTMLInputElement>(null)
  const [preview, setPreview] = useState<string | null>(null)
  const [fileError, setFileError] = useState('')
  const [busy, setBusy] = useState(false)

  const currentLogo = user?.organization_logo

  const resetPicker = () => {
    setPreview(null)
    setFileError('')
    if (fileRef.current) fileRef.current.value = ''
  }

  const onFile = (f: File | null) => {
    setPreview(null)
    setFileError('')
    if (!f) return
    if (!['image/png', 'image/jpeg'].includes(f.type)) {
      setFileError('PNG or JPEG only (SVG is not accepted).')
      return
    }
    if (f.size > LOGO_MAX_BYTES) {
      setFileError('Logo must be 300 KB or smaller.')
      return
    }
    const reader = new FileReader()
    reader.onload = () => setPreview(String(reader.result))
    reader.readAsDataURL(f)
  }

  const refreshUser = async () => setUser(await api.get<User>('/auth/me'))

  const upload = async () => {
    if (!preview) return
    setBusy(true)
    try {
      await api.put('/orgs/branding', { logo_data_uri: preview })
      await refreshUser()
      resetPicker()
      toast.success('Company logo updated')
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Upload failed')
    } finally {
      setBusy(false)
    }
  }

  const remove = async () => {
    setBusy(true)
    try {
      await api.delete('/orgs/branding')
      await refreshUser()
      resetPicker()
      toast.success('Company logo removed')
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Remove failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="mb-8">
      <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-3 flex items-center gap-2">
        <ImageIcon size={14} /> Branding
      </h3>
      <div className="bg-bg-secondary border border-border p-4 space-y-3 text-sm">
        <p className="text-xs text-text-muted">
          Logo for <span className="text-text-secondary font-medium">{user?.organization_name}</span> — the
          company you are currently viewing. It appears in the sidebar and on Audit Binder covers.
          PNG or JPEG, up to 300 KB.
        </p>

        <div className="flex items-center gap-3">
          <span className="text-text-muted text-xs w-24 shrink-0">Current logo</span>
          {currentLogo ? (
            <CompanyLogo src={currentLogo} name={user?.organization_name} className="h-10 max-w-[200px] bg-bg-tertiary border border-border p-1" />
          ) : (
            <span className="text-xs text-text-muted">None — the sidebar shows the company name only.</span>
          )}
          {currentLogo && (
            <button onClick={remove} disabled={busy}
              title="Remove logo"
              className="flex items-center gap-1.5 px-2 py-1 text-xs border border-border text-text-secondary hover:text-danger hover:border-danger disabled:opacity-50">
              <Trash2 size={12} /> Remove
            </button>
          )}
        </div>

        <div className="border-t border-border pt-3 space-y-2">
          <div className="flex items-center gap-3">
            <span className="text-text-muted text-xs w-24 shrink-0">{currentLogo ? 'Replace with' : 'Upload'}</span>
            <input
              ref={fileRef}
              type="file"
              accept="image/png,image/jpeg"
              onChange={(e) => onFile(e.target.files?.[0] ?? null)}
              className="text-xs text-text-secondary"
            />
          </div>
          {fileError && <div className="text-xs text-danger">{fileError}</div>}
          {preview && (
            <div className="flex items-center gap-3">
              <span className="text-text-muted text-xs w-24 shrink-0">Preview</span>
              <img src={preview} alt="Logo preview" className="h-10 max-w-[200px] object-contain bg-bg-tertiary border border-border p-1" />
              <button onClick={upload} disabled={busy}
                className="px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-xs disabled:opacity-50">
                {busy ? 'Uploading…' : 'Save logo'}
              </button>
              <button onClick={resetPicker} disabled={busy}
                className="px-2 py-1.5 text-xs text-text-muted hover:text-text-primary">
                Cancel
              </button>
            </div>
          )}
        </div>
      </div>
    </section>
  )
}

function formatBytes(n: number): string {
  if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`
  if (n >= 1024) return `${(n / 1024).toFixed(0)} KB`
  return `${n} B`
}

interface BackupInfo {
  supported: boolean
  unsupported_reason: string | null
  db_size_bytes: number
  evidence_file_count: number
  custom_framework_count: number
  last_backup_name: string | null
  last_backup_at: string | null
  last_backup_bytes: number | null
  max_restore_upload_bytes: number
  keep_backups: number
  keep_rollbacks: number
  restore_nonce: string
}

interface RestoreResult {
  restored_evidence_files: number
  restored_custom_frameworks: number
  sessions_revoked: number
  api_tokens_revoked: number
  rollback_path: string
  warnings: string[]
  note: string
}

export function BackupPanel() {
  const [passphrase, setPassphrase] = useState('')
  const [downloading, setDownloading] = useState(false)
  const [restoreFile, setRestoreFile] = useState<File | null>(null)
  const [restorePass, setRestorePass] = useState('')
  const [restoring, setRestoring] = useState(false)
  const [confirmRestore, setConfirmRestore] = useState(false)
  const [restored, setRestored] = useState<RestoreResult | null>(null)
  const { data: info, error: infoError, refetch } = useQuery({
    queryKey: ['backup-info'],
    queryFn: () => api.get<BackupInfo>('/backup/info'),
    retry: false,
  })

  const handleDownload = async () => {
    setDownloading(true)
    try {
      const body = new FormData()
      body.append('passphrase', passphrase)
      const res = await fetch('/api/backup/download', {
        method: 'POST', credentials: 'include',
        headers: { 'X-CSRF-Token': getCsrfToken() },
        body,
      })
      if (!res.ok) throw await responseError(res)
      const disposition = res.headers.get('Content-Disposition') ?? ''
      const name = disposition.match(/filename="?(.+?)"?$/)?.[1] ?? 'backup.tar.gz'
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url; a.download = name; a.click()
      URL.revokeObjectURL(url)
      toast.success(`Backup downloaded: ${name}`)
      const warning = res.headers.get('X-Backup-Warning')
      if (warning) toast.info(warning)
      refetch()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Backup failed')
    } finally {
      setDownloading(false)
    }
  }

  const handleRestore = async () => {
    if (!restoreFile || !info) return
    setRestoring(true)
    try {
      const body = new FormData()
      body.append('file', restoreFile)
      body.append('nonce', info.restore_nonce)
      body.append('passphrase', restorePass)
      const res = await fetch('/api/backup/restore', {
        method: 'POST', credentials: 'include',
        headers: { 'X-CSRF-Token': getCsrfToken() },
        body,
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) throw new Error(apiErrorMessage(data, res.status))
      const result = data as RestoreResult
      setRestored(result)
      toast.success('Restore complete. You will be signed out — please log in again.')
      // Warnings (e.g. a different audit key) must be read before leaving the page.
      if (!result.warnings?.length) setTimeout(() => { window.location.href = '/login' }, 2500)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Restore failed')
      setRestoring(false)
      setConfirmRestore(false)
      refetch() // the confirmation nonce was used up
    }
  }

  if (infoError) {
    return (
      <section className="mb-8">
        <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-3">Backup &amp; Restore</h3>
        <div className="bg-bg-secondary border border-border p-4 text-sm text-text-muted">
          {infoError instanceof Error ? infoError.message : 'Backup information is unavailable.'}
        </div>
      </section>
    )
  }

  const tooBigToRestore = !!info?.last_backup_bytes && info.last_backup_bytes > info.max_restore_upload_bytes

  return (
    <section className="mb-8">
      <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-3">Backup &amp; Restore</h3>
      <div className="bg-bg-secondary border border-border p-4 space-y-4">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
          <div><span className="text-text-muted">Database</span><div>{info ? formatBytes(info.db_size_bytes) : '—'}</div></div>
          <div><span className="text-text-muted">Evidence files</span><div>{info?.evidence_file_count ?? '—'}</div></div>
          <div><span className="text-text-muted">Custom frameworks</span><div>{info?.custom_framework_count ?? '—'}</div></div>
          <div><span className="text-text-muted">Last backup</span><div>{info?.last_backup_at ? formatDateTime(info.last_backup_at) : 'Never'}</div></div>
        </div>
        {info && (
          <p className="text-xs text-text-muted">
            The server keeps {info.keep_backups ? `the newest ${plural(info.keep_backups, 'backup')}` : 'all backups'} and{' '}
            {info.keep_rollbacks ? `${info.keep_rollbacks} rollback copies` : 'all rollback copies'} in its backup folder;
            older ones are removed automatically (ATHORIZE_BACKUP_KEEP / ATHORIZE_BACKUP_KEEP_ROLLBACKS, 0 = keep all).
          </p>
        )}

        {info && !info.supported ? (
          <p role="alert" className="text-sm text-warning border-t border-border pt-4">{info.unsupported_reason}</p>
        ) : restored ? (
          <div role="status" className="border-t border-border pt-4 space-y-2 text-sm">
            <div className="font-medium">Restore complete</div>
            <p className="text-text-muted">
              {restored.restored_evidence_files} evidence file(s) and {restored.restored_custom_frameworks} custom
              framework(s) restored; {restored.sessions_revoked} session(s) signed out and {restored.api_tokens_revoked} API
              token(s) revoked. The replaced data was kept on the server in {restored.rollback_path}.
            </p>
            {restored.warnings.map(w => (
              <p key={w} className="text-warning flex gap-2"><ShieldAlert size={14} className="shrink-0 mt-0.5" />{w}</p>
            ))}
            <button onClick={() => { window.location.href = '/login' }}
              className="px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm">
              Sign in again
            </button>
          </div>
        ) : (
          <>
            <div className="border-t border-border pt-4">
              <div className="text-sm font-medium mb-2">Download backup</div>
              <p className="text-xs text-text-muted mb-2">Archives the database, all evidence files and your custom frameworks — for every company on this instance. Optionally encrypt with a passphrase (you'll need it to restore).</p>
              <div className="flex items-center gap-2">
                <input type="password" placeholder="Optional passphrase" value={passphrase}
                  onChange={e => setPassphrase(e.target.value)}
                  className="text-sm bg-bg-tertiary border border-border px-2 py-1.5 flex-1" />
                <button onClick={handleDownload} disabled={downloading}
                  className="flex items-center gap-2 px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm disabled:opacity-50">
                  <Download size={14} /> {downloading ? 'Preparing…' : 'Download'}
                </button>
              </div>
              {tooBigToRestore && (
                <p className="text-xs text-warning mt-2">
                  The last backup is larger than the in-app restore limit ({formatBytes(info!.max_restore_upload_bytes)}).
                  Restore it with the command-line tool described in the install guide (section 10).
                </p>
              )}
            </div>

            <div className="border-t border-border pt-4">
              <div className="flex items-center gap-2 text-sm font-medium mb-2 text-danger">
                <ShieldAlert size={14} /> Restore from backup
              </div>
              <p className="text-xs text-text-muted mb-2">
                <strong className="text-danger">Destructive.</strong> Replaces the entire database, evidence store and custom frameworks with the archive's contents. A timestamped rollback copy is kept. All users are signed out and API tokens in the backup are revoked.
              </p>
              <div className="flex items-center gap-2 flex-wrap">
                <input type="file" accept=".tar.gz,.enc,.gz"
                  onChange={e => setRestoreFile(e.target.files?.[0] ?? null)}
                  className="text-xs text-text-secondary" />
                <input type="password" placeholder="Passphrase (if encrypted)" value={restorePass}
                  onChange={e => setRestorePass(e.target.value)}
                  className="text-sm bg-bg-tertiary border border-border px-2 py-1.5" />
                {!confirmRestore ? (
                  <button onClick={() => setConfirmRestore(true)} disabled={!restoreFile}
                    className="flex items-center gap-2 px-3 py-1.5 border border-danger text-danger hover:bg-danger/10 text-sm disabled:opacity-40">
                    <Upload size={14} /> Restore…
                  </button>
                ) : (
                  <button onClick={handleRestore} disabled={restoring}
                    className="flex items-center gap-2 px-3 py-1.5 bg-danger text-white text-sm disabled:opacity-50">
                    {restoring ? 'Restoring…' : 'Confirm — overwrite everything'}
                  </button>
                )}
              </div>
            </div>
          </>
        )}
      </div>
    </section>
  )
}

function DigestPanel({ isAdmin }: { isAdmin: boolean }) {
  const [sending, setSending] = useState(false)
  const { data } = useQuery({
    queryKey: ['digest-config'],
    queryFn: () => api.get<{ smtp_configured: boolean; recipients: string[] }>('/digest/config'),
  })

  const sendTest = async () => {
    setSending(true)
    try {
      const res = await api.post<{ sent_to: string }>('/digest/send-test', {})
      toast.success(`Test digest sent to ${res.sent_to}`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Send failed')
    } finally {
      setSending(false)
    }
  }

  return (
    <section className="mb-8">
      <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-3 flex items-center gap-2">
        <Mail size={14} /> Email Digest
      </h3>
      <div className="bg-bg-secondary border border-border p-4 space-y-3 text-sm">
        <p className="text-xs text-text-muted">
          A scheduled summary of overdue findings, expiring evidence, and overdue monitoring cadences,
          emailed to admins and compliance managers. Enable scheduling with <code className="px-1 bg-bg-tertiary">DIGEST_INTERVAL_HOURS</code> (e.g. 24).
        </p>
        <div className="flex items-center gap-2 text-xs">
          <span className="text-text-muted">SMTP:</span>
          <span className={data?.smtp_configured ? 'text-success' : 'text-warning'}>
            {data?.smtp_configured ? 'configured' : 'not configured (set SMTP_HOST / SMTP_FROM)'}
          </span>
        </div>
        <div className="text-xs">
          <span className="text-text-muted">Recipients:</span>{' '}
          {data?.recipients?.length ? data.recipients.join(', ') : <span className="text-text-muted">none (no admin/manager has an email set)</span>}
        </div>
        {isAdmin && (
          <button onClick={sendTest} disabled={sending || !data?.smtp_configured}
            className="px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm disabled:opacity-50">
            {sending ? 'Sending…' : 'Send test digest to me'}
          </button>
        )}
      </div>
    </section>
  )
}

interface ApiToken {
  id: number
  name: string
  token_prefix: string
  created_at: string | null
  last_used_at: string | null
  expires_at: string | null
  revoked_at: string | null
}

function ApiTokensPanel() {
  const queryClient = useQueryClient()
  const [name, setName] = useState('')
  const [expiresDays, setExpiresDays] = useState('')
  const [neverExpires, setNeverExpires] = useState(false)
  const [created, setCreated] = useState<string | null>(null)
  const isAdmin = useCan('manage:settings')  // admin-only, mirrors routers/api_tokens.py

  const { data: tokens = [] } = useQuery({
    queryKey: ['api-tokens'],
    queryFn: () => api.get<ApiToken[]>('/tokens'),
  })

  const create = useMutation({
    mutationFn: () => api.post<{ token: string }>('/tokens', {
      name: name.trim(),
      expires_in_days: !neverExpires && expiresDays ? Number(expiresDays) : null,
      never_expires: neverExpires,
    }),
    onSuccess: (res) => {
      setCreated(res.token)
      setName(''); setExpiresDays(''); setNeverExpires(false)
      queryClient.invalidateQueries({ queryKey: ['api-tokens'] })
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Could not create token'),
  })

  const revoke = useMutation({
    mutationFn: (id: number) => api.delete(`/tokens/${id}`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['api-tokens'] }),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Could not revoke token'),
  })

  const active = tokens.filter(t => !t.revoked_at)

  return (
    <section className="mb-8">
      <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-3 flex items-center gap-2">
        <Terminal size={14} /> API Tokens
      </h3>
      <div className="bg-bg-secondary border border-border p-4 space-y-3 text-sm">
        <p className="text-xs text-text-muted">
          Bearer tokens for automation and integrations. A token acts as you (your role and system access) and is sent as
          <code className="mx-1 px-1 bg-bg-tertiary">Authorization: Bearer …</code>. The full value is shown once, here, at creation.
          Tokens expire after 90 days unless you choose otherwise, and are revoked when your password changes (by you or an
          admin), when your role changes, or when your account is deactivated.
        </p>

        {created && (
          <div className="border border-success/40 bg-success/5 p-3">
            <div className="text-xs text-success mb-1">New token — copy it now, it won't be shown again:</div>
            <div className="flex items-center gap-2">
              <code className="flex-1 text-xs font-mono break-all bg-bg-tertiary px-2 py-1.5">{created}</code>
              <button
                onClick={() => {
                  if (navigator.clipboard) {
                    navigator.clipboard.writeText(created)
                      .then(() => toast.success('Copied'))
                      .catch(() => toast.error('Copy failed — select the token and copy it manually'))
                  } else {
                    toast.error('Clipboard unavailable (insecure context) — copy the token manually')
                  }
                }}
                className="px-2 py-1.5 text-xs border border-border hover:border-accent"
              >Copy</button>
              <button onClick={() => setCreated(null)} className="px-2 py-1.5 text-xs text-text-muted hover:text-text-primary">Done</button>
            </div>
          </div>
        )}

        <div className="flex items-end gap-2 border-t border-border pt-3">
          <div className="flex-1">
            <label className="text-xs text-text-muted block mb-1">Name</label>
            <input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. ci-pipeline"
              className="w-full text-xs bg-bg-tertiary border border-border px-2 py-1.5" />
          </div>
          <div className="w-28">
            <label className="text-xs text-text-muted block mb-1">Expires (days)</label>
            <input value={expiresDays} onChange={e => setExpiresDays(e.target.value.replace(/\D/g, ''))}
              placeholder="90" disabled={neverExpires} aria-label="Expires (days)"
              className="w-full text-xs bg-bg-tertiary border border-border px-2 py-1.5 disabled:opacity-50" />
          </div>
          {isAdmin && (
            <label className="flex items-center gap-1 text-xs text-text-muted pb-1.5">
              <input type="checkbox" checked={neverExpires} onChange={e => setNeverExpires(e.target.checked)} />
              Never expires
            </label>
          )}
          <button onClick={() => create.mutate()} disabled={create.isPending || !name.trim()}
            className="px-3 py-1.5 bg-accent hover:bg-accent-hover text-white text-sm disabled:opacity-50">
            Create
          </button>
        </div>

        {active.length > 0 && (
          <table className="w-full text-xs border-t border-border pt-1">
            <thead>
              <tr className="text-text-muted text-left">
                <th className="py-1 font-medium">Name</th>
                <th className="py-1 font-medium">Prefix</th>
                <th className="py-1 font-medium">Last used</th>
                <th className="py-1 font-medium">Expires</th>
                <th className="py-1"></th>
              </tr>
            </thead>
            <tbody>
              {active.map(t => (
                <tr key={t.id} className="border-t border-border/50">
                  <td className="py-1.5">{t.name}</td>
                  <td className="py-1.5 font-mono text-text-muted">{t.token_prefix}…</td>
                  <td className="py-1.5 text-text-muted">{t.last_used_at ? formatDate(t.last_used_at) : 'never'}</td>
                  <td className="py-1.5 text-text-muted">{t.expires_at ? formatDate(t.expires_at) : 'never'}</td>
                  <td className="py-1.5 text-right">
                    <button onClick={() => revoke.mutate(t.id)} disabled={revoke.isPending}
                      title="Revoke" className="text-text-muted hover:text-danger">
                      <Trash2 size={13} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  )
}