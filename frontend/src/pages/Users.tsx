import { useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { formatDateTime } from '../lib/datetime'
import type { System, User } from '../types'
import { useCan } from '../hooks/useRole'
import { SlideInPanel } from '../components/SlideInPanel'
import ConfirmDialog from '../components/ConfirmDialog'
import { Pill } from '../components/Pill'
import { EmptyState } from '../components/EmptyState'
import { toast } from '../store/toastStore'
import { Plus, Users as UsersIcon, Pencil, UserX, Server, Unlink } from 'lucide-react'

const ROLES = [
  'admin', 'compliance_manager', 'assessor', 'system_owner', 'evidence_contributor', 'auditor',
] as const

const ROLE_TONE: Record<string, 'info' | 'ok' | 'warn' | 'neutral'> = {
  admin: 'info',
  compliance_manager: 'ok',
  assessor: 'warn',
  system_owner: 'neutral',
  evidence_contributor: 'neutral',
  auditor: 'neutral',
}

export default function UsersList() {
  // Server: list + system access = admin/CM; create/edit/deactivate = admin only.
  const canView = useCan('view:users')
  const canManage = useCan('manage:users')
  const canAssignSystems = useCan('assign:systems')
  const qc = useQueryClient()
  const [panel, setPanel] = useState<{ open: boolean; mode: 'add' | 'edit'; user: User | null }>({ open: false, mode: 'add', user: null })
  const [deactivateTarget, setDeactivateTarget] = useState<User | null>(null)
  const [systemsTarget, setSystemsTarget] = useState<User | null>(null)
  const [unlinkTarget, setUnlinkTarget] = useState<User | null>(null)

  const [form, setForm] = useState({ username: '', password: '', email: '', display_name: '', role: 'evidence_contributor' })

  const { data: users = [], isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: () => api.get<User[]>('/users'),
    enabled: canView,
  })

  const openAdd = () => {
    setForm({ username: '', password: '', email: '', display_name: '', role: 'evidence_contributor' })
    setPanel({ open: true, mode: 'add', user: null })
  }

  const openEdit = (u: User) => {
    setForm({ username: u.username, password: '', email: u.email || '', display_name: u.display_name || '', role: u.role })
    setPanel({ open: true, mode: 'edit', user: u })
  }

  const handleSubmit = async () => {
    try {
      if (panel.mode === 'add') {
        await api.post('/users', form)
        toast.success('User created')
      } else if (panel.user) {
        const updates: Record<string, unknown> = {}
        if (form.email !== (panel.user.email || '')) updates.email = form.email
        if (form.display_name !== (panel.user.display_name || '')) updates.display_name = form.display_name
        if (form.role !== panel.user.role) updates.role = form.role
        if (form.password) updates.password = form.password
        await api.patch(`/users/${panel.user.id}`, updates)
        toast.success('User updated')
      }
      qc.invalidateQueries({ queryKey: ['users'] })
      setPanel({ open: false, mode: 'add', user: null })
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed')
    }
  }

  const handleDeactivate = async () => {
    if (!deactivateTarget) return
    try {
      await api.delete(`/users/${deactivateTarget.id}`)
      toast.success('User deactivated')
      qc.invalidateQueries({ queryKey: ['users'] })
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed')
    }
    setDeactivateTarget(null)
  }

  const handleUnlink = async () => {
    if (!unlinkTarget) return
    try {
      await api.delete(`/users/${unlinkTarget.id}/sso`)
      toast.success('SSO link removed')
      qc.invalidateQueries({ queryKey: ['users'] })
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed')
    }
    setUnlinkTarget(null)
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-xl font-bold text-[var(--text-primary)]">Users</h2>
          <p className="text-xs text-[var(--text-secondary)] mt-0.5">Manage user accounts and role assignments.</p>
        </div>
        {canManage && (
          <button onClick={openAdd}
            className="flex items-center gap-2 px-3 py-1.5 bg-[var(--accent)] hover:opacity-90 text-white text-sm">
            <Plus size={16} /> Add User
          </button>
        )}
      </div>

      {!canView ? (
        <div className="text-sm text-[var(--text-secondary)]">Only admins and compliance managers can view the user directory.</div>
      ) : isLoading ? (
        <div className="text-sm text-[var(--text-secondary)]">Loading...</div>
      ) : users.length === 0 ? (
        <EmptyState icon={UsersIcon} title="No users" description="Create users to grant access to the platform." />
      ) : (
        <div className="bg-[var(--bg-secondary)] border border-[var(--border)]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--border)] text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">
                <th className="text-left px-3 py-2">Username</th>
                <th className="text-left px-3 py-2">Display Name</th>
                <th className="text-left px-3 py-2">Email</th>
                <th className="text-left px-3 py-2">Role</th>
                <th className="text-left px-3 py-2">Status</th>
                <th className="text-left px-3 py-2">Last Login</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id} className="border-b border-[var(--border)] last:border-b-0 hover:bg-[var(--bg-tertiary)]">
                  <td className="px-3 py-2 font-medium text-[var(--text-primary)]">{u.username}</td>
                  <td className="px-3 py-2 text-[var(--text-secondary)]">{u.display_name || '—'}</td>
                  <td className="px-3 py-2 text-[var(--text-secondary)] text-xs">{u.email || '—'}</td>
                  <td className="px-3 py-2">
                    <Pill tone={ROLE_TONE[u.role] ?? 'neutral'}>{u.role.replace(/_/g, ' ')}</Pill>
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-1">
                      <Pill tone={u.is_active ? 'ok' : 'danger'}>{u.is_active ? 'Active' : 'Inactive'}</Pill>
                      {u.sso_linked && <Pill tone="info">SSO linked</Pill>}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-xs text-[var(--text-secondary)]">
                    {u.last_login ? formatDateTime(u.last_login) : '—'}
                  </td>
                  <td className="px-3 py-2">
                    {(canManage || canAssignSystems) && (
                      <div className="flex items-center gap-1">
                        {canManage && (
                          <button onClick={() => openEdit(u)} className="p-1 text-[var(--text-secondary)] hover:text-[var(--accent)]" title="Edit">
                            <Pencil size={14} />
                          </button>
                        )}
                        {canAssignSystems && (
                          <button onClick={() => setSystemsTarget(u)} className="p-1 text-[var(--text-secondary)] hover:text-[var(--accent)]" title="System access">
                            <Server size={14} />
                          </button>
                        )}
                        {canManage && u.sso_linked && (
                          <button onClick={() => setUnlinkTarget(u)} className="p-1 text-[var(--text-secondary)] hover:text-[var(--danger)]" title="Unlink SSO" aria-label={`Unlink SSO for ${u.username}`}>
                            <Unlink size={14} />
                          </button>
                        )}
                        {canManage && u.is_active && (
                          <button onClick={() => setDeactivateTarget(u)} className="p-1 text-[var(--text-secondary)] hover:text-[var(--danger)]" title="Deactivate">
                            <UserX size={14} />
                          </button>
                        )}
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <SlideInPanel
        open={panel.open}
        onClose={() => setPanel({ open: false, mode: 'add', user: null })}
        eyebrow={panel.mode === 'add' ? 'New User' : 'Edit User'}
        title={panel.mode === 'add' ? 'Create User Account' : `Edit ${panel.user?.username}`}
        footer={
          <button onClick={handleSubmit}
            className="px-4 py-1.5 text-xs uppercase tracking-wider bg-[var(--accent)] text-white hover:opacity-90">
            {panel.mode === 'add' ? 'Create' : 'Save'}
          </button>
        }
      >
        <div className="space-y-3">
          <div>
            <label className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] block mb-1" htmlFor="user-username">Username *</label>
            <input id="user-username" value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
              disabled={panel.mode === 'edit'}
              className="w-full bg-[var(--bg-primary)] border border-[var(--border)] px-2 py-1.5 text-sm text-[var(--text-primary)] disabled:opacity-50" />
          </div>
          <div>
            <label className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] block mb-1" htmlFor="user-password">
              {panel.mode === 'add' ? 'Password *' : 'New Password (leave blank to keep)'}
            </label>
            <input id="user-password" type="password" value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
              className="w-full bg-[var(--bg-primary)] border border-[var(--border)] px-2 py-1.5 text-sm text-[var(--text-primary)]" />
          </div>
          <div>
            <label className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] block mb-1" htmlFor="user-display-name">Display Name</label>
            <input id="user-display-name" value={form.display_name} onChange={e => setForm(f => ({ ...f, display_name: e.target.value }))}
              className="w-full bg-[var(--bg-primary)] border border-[var(--border)] px-2 py-1.5 text-sm text-[var(--text-primary)]" />
          </div>
          <div>
            <label className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] block mb-1" htmlFor="user-email">Email</label>
            <input id="user-email" type="email" value={form.email} onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
              className="w-full bg-[var(--bg-primary)] border border-[var(--border)] px-2 py-1.5 text-sm text-[var(--text-primary)]" />
          </div>
          <div>
            <label className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)] block mb-1" htmlFor="user-role">Role</label>
            <select id="user-role" value={form.role} onChange={e => setForm(f => ({ ...f, role: e.target.value }))}
              className="w-full bg-[var(--bg-primary)] border border-[var(--border)] px-2 py-1.5 text-sm text-[var(--text-primary)]">
              {ROLES.map(r => <option key={r} value={r}>{r.replace(/_/g, ' ')}</option>)}
            </select>
          </div>
        </div>
      </SlideInPanel>

      <ConfirmDialog
        open={!!deactivateTarget}
        title="Deactivate User"
        message={`Deactivate ${deactivateTarget?.username}? They will no longer be able to log in.`}
        confirmLabel="Deactivate"
        onConfirm={handleDeactivate}
        onCancel={() => setDeactivateTarget(null)}
      />

      <ConfirmDialog
        open={!!unlinkTarget}
        title="Unlink SSO"
        message={`Remove the SSO identity linked to ${unlinkTarget?.username}? They are signed out and their API tokens are revoked; their next SSO sign-in links again by email.`}
        confirmLabel="Unlink"
        onConfirm={handleUnlink}
        onCancel={() => setUnlinkTarget(null)}
      />

      <SystemAccessPanel target={systemsTarget} onClose={() => setSystemsTarget(null)} />
    </div>
  )
}

const ORG_WIDE_ROLES = new Set(['admin', 'compliance_manager'])

/** Assign a user to specific systems — they then see ONLY those systems' data.
 * Empty selection = unrestricted (org-wide). Admins/compliance managers are
 * org-wide by role regardless. */
function SystemAccessPanel({ target, onClose }: { target: User | null; onClose: () => void }) {
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [saving, setSaving] = useState(false)

  const { data: systems = [] } = useQuery({
    queryKey: ['systems'],
    queryFn: () => api.get<System[]>('/systems'),
    enabled: !!target,
  })
  const { data: current } = useQuery({
    queryKey: ['user-systems', target?.id],
    queryFn: () => api.get<{ system_ids: number[] }>(`/users/${target!.id}/systems`),
    enabled: !!target,
  })

  useEffect(() => {
    setSelected(new Set(current?.system_ids ?? []))
  }, [current?.system_ids, target?.id])

  if (!target) return null
  const orgWideByRole = ORG_WIDE_ROLES.has(target.role)

  const save = async () => {
    setSaving(true)
    try {
      await api.put(`/users/${target.id}/systems`, { system_ids: [...selected] })
      toast.success(selected.size
        ? `${target.username} limited to ${selected.size} system(s)`
        : `${target.username} restored to org-wide access`)
      onClose()
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to save system access')
    } finally {
      setSaving(false)
    }
  }

  return (
    <SlideInPanel
      open={!!target}
      onClose={onClose}
      width={440}
      eyebrow="System access"
      title={target.display_name || target.username}
      subtitle={target.role.replace(/_/g, ' ')}
      footer={
        <>
          <button onClick={save} disabled={saving}
            className="px-4 py-1.5 bg-[var(--accent)] hover:opacity-90 text-white text-sm disabled:opacity-50">
            {saving ? 'Saving…' : 'Save access'}
          </button>
          <button onClick={onClose} className="px-3 py-1.5 text-[var(--text-secondary)] text-sm">Cancel</button>
        </>
      }
    >
      {orgWideByRole && (
        <p className="text-xs text-[var(--warning)] mb-3">
          {target.role.replace(/_/g, ' ')}s are org-wide by role — assignments are stored but have no effect.
        </p>
      )}
      <p className="text-xs text-[var(--text-secondary)] mb-3">
        Check the systems this user may access. <b>No selection = unrestricted</b> (all systems).
        A scoped user sees only their systems' findings, evidence, controls, assets, and dashboards.
      </p>
      <div className="space-y-1.5">
        {systems.map(s => (
          <label key={s.id} className="flex items-center gap-2 text-sm text-[var(--text-primary)] cursor-pointer">
            <input
              type="checkbox"
              checked={selected.has(s.id)}
              onChange={e => setSelected(prev => {
                const n = new Set(prev)
                e.target.checked ? n.add(s.id) : n.delete(s.id)
                return n
              })}
            />
            {s.acronym} — {s.name}
          </label>
        ))}
        {systems.length === 0 && <p className="text-xs text-[var(--text-secondary)]">No systems yet.</p>}
      </div>
    </SlideInPanel>
  )
}
