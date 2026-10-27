import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import type { ITAsset, System } from '../types'
import { useCan } from '../hooks/useRole'
import { Pill } from '../components/Pill'
import { KpiCard } from '../components/KpiCard'
import { EmptyState } from '../components/EmptyState'
import ITAssetEntryPanel from '../components/ITAssetEntryPanel'
import { Plus, Monitor, Search } from 'lucide-react'

const ENV_ORDER = ['PRODUCTION', 'STAGING', 'DEVELOPMENT', 'TEST']

const PATCH_TONE: Record<string, 'ok' | 'warn' | 'danger' | 'neutral'> = {
  CURRENT: 'ok',
  BEHIND: 'warn',
  END_OF_LIFE: 'danger',
  NOT_PATCHABLE: 'neutral',
}

export default function ITAssets() {
  const [search, setSearch] = useState('')
  const [filterEnv, setFilterEnv] = useState('')
  const [filterRole, setFilterRole] = useState('')
  const [panel, setPanel] = useState<{ open: boolean; mode: 'add' | 'edit'; record: ITAsset | null }>({ open: false, mode: 'add', record: null })
  const canWrite = useCan('edit:system')

  const { data: assets = [] } = useQuery({
    queryKey: ['it-assets'],
    queryFn: () => api.get<ITAsset[]>('/it-assets'),
  })

  const { data: systems = [] } = useQuery({
    queryKey: ['systems'],
    queryFn: () => api.get<System[]>('/systems'),
  })

  const filtered = useMemo(() => {
    let list = assets
    if (filterEnv) list = list.filter(a => a.environment === filterEnv)
    if (filterRole) list = list.filter(a => a.asset_role === filterRole)
    if (search) {
      const q = search.toLowerCase()
      list = list.filter(a =>
        a.asset_name.toLowerCase().includes(q) ||
        (a.hostname || '').toLowerCase().includes(q) ||
        (a.ip_address || '').toLowerCase().includes(q) ||
        (a.vendor || '').toLowerCase().includes(q)
      )
    }
    return list
  }, [assets, filterEnv, filterRole, search])

  const stats = useMemo(() => {
    const behind = assets.filter(a => a.patch_status === 'BEHIND').length
    const eol = assets.filter(a => a.patch_status === 'END_OF_LIFE').length
    const stigScope = assets.filter(a => a.stig_applicable).length
    const stigNonCompliant = assets.filter(a => a.stig_applicable && a.stig_compliance_status === 'NON_COMPLIANT').length
    return { total: assets.length, behind, eol, stigScope, stigNonCompliant }
  }, [assets])

  const roles = useMemo(() => [...new Set(assets.map(a => a.asset_role).filter(Boolean))].sort(), [assets])

  const systemMap = useMemo(() => {
    const m: Record<number, string> = {}
    systems.forEach(s => { m[s.id] = s.name })
    return m
  }, [systems])

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-[var(--text-primary)]">IT Assets</h2>
        {canWrite && (
          <button
            onClick={() => setPanel({ open: true, mode: 'add', record: null })}
            className="flex items-center gap-2 px-3 py-1.5 bg-[var(--accent)] hover:opacity-90 text-white text-sm"
          >
            <Plus size={16} /> Add Asset
          </button>
        )}
      </div>

      <div className="flex border border-[var(--border)] bg-[var(--bg-secondary)] mb-4">
        <KpiCard label="Total" value={stats.total} />
        <KpiCard label="Patch Behind" value={stats.behind} tone={stats.behind > 0 ? 'warning' : 'default'} />
        <KpiCard label="End of Life" value={stats.eol} tone={stats.eol > 0 ? 'danger' : 'default'} />
        <KpiCard label="STIG Scope" value={stats.stigScope} />
        <KpiCard label="STIG Non-Compliant" value={stats.stigNonCompliant} tone={stats.stigNonCompliant > 0 ? 'danger' : 'default'} />
      </div>

      <div className="flex gap-3 mb-4 items-center">
        <div className="relative flex-1 max-w-xs">
          <Search size={14} className="absolute left-2 top-1/2 -translate-y-1/2 text-[var(--text-secondary)]" />
          <input
            className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] pl-7 pr-2 py-1.5"
            placeholder="Search name, hostname, IP, vendor..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <select className="text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5" value={filterEnv} onChange={e => setFilterEnv(e.target.value)}>
          <option value="">All Environments</option>
          {ENV_ORDER.map(e => <option key={e} value={e}>{e}</option>)}
        </select>
        <select className="text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5" value={filterRole} onChange={e => setFilterRole(e.target.value)}>
          <option value="">All Roles</option>
          {roles.map(r => <option key={r} value={r}>{r.replace(/_/g, ' ')}</option>)}
        </select>
      </div>

      {filtered.length === 0 ? (
        <EmptyState
          icon={Monitor}
          title="No IT assets"
          description="Add IT assets to track hardware, VMs, and cloud resources across your systems."
        />
      ) : (
        <div className="bg-[var(--bg-secondary)] border border-[var(--border)]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--border)] text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">
                <th className="text-left px-3 py-2">Name</th>
                <th className="text-left px-3 py-2">System</th>
                <th className="text-left px-3 py-2">Role</th>
                <th className="text-left px-3 py-2">OS</th>
                <th className="text-left px-3 py-2">IP</th>
                <th className="text-left px-3 py-2">Env</th>
                <th className="text-left px-3 py-2">Patch</th>
                <th className="text-left px-3 py-2">Criticality</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(a => (
                <tr
                  key={a.id}
                  onClick={() => setPanel({ open: true, mode: 'edit', record: a })}
                  className="border-b border-[var(--border)] hover:bg-[var(--bg-tertiary)] cursor-pointer"
                >
                  <td className="px-3 py-2 font-medium text-[var(--text-primary)] max-w-[200px] truncate">{a.asset_name}</td>
                  <td className="px-3 py-2 text-[var(--text-secondary)] text-xs">{systemMap[a.system_id] || '—'}</td>
                  <td className="px-3 py-2 text-xs">{a.asset_role ? <Pill tone="neutral">{a.asset_role.replace(/_/g, ' ')}</Pill> : '—'}</td>
                  <td className="px-3 py-2 text-[var(--text-secondary)] text-xs">{[a.os_family, a.os_version].filter(Boolean).join(' ') || '—'}</td>
                  <td className="px-3 py-2 text-[var(--text-secondary)] text-xs font-mono">{a.ip_address || '—'}</td>
                  <td className="px-3 py-2 text-xs">{a.environment ? <Pill tone="neutral">{a.environment}</Pill> : '—'}</td>
                  <td className="px-3 py-2 text-xs">
                    {a.patch_status ? <Pill tone={PATCH_TONE[a.patch_status] ?? 'neutral'}>{a.patch_status.replace(/_/g, ' ')}</Pill> : '—'}
                  </td>
                  <td className="px-3 py-2 text-xs">{a.criticality || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ITAssetEntryPanel
        open={panel.open}
        mode={panel.mode}
        record={panel.record}
        systems={systems}
        onClose={() => setPanel({ open: false, mode: 'add', record: null })}
      />
    </div>
  )
}
