import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import type { OTAsset, System } from '../types'
import { useCan } from '../hooks/useRole'
import { Pill } from '../components/Pill'
import { KpiCard } from '../components/KpiCard'
import { EmptyState } from '../components/EmptyState'
import OTAssetEntryPanel from '../components/OTAssetEntryPanel'
import { Plus, Cpu, Search, Wifi } from 'lucide-react'

const PURDUE_ORDER = ['DMZ', 'LEVEL_3', 'LEVEL_2', 'LEVEL_1', 'LEVEL_0']

const PATCH_TONE: Record<string, 'ok' | 'warn' | 'danger' | 'neutral'> = {
  CURRENT: 'ok',
  BEHIND: 'warn',
  NOT_PATCHABLE: 'neutral',
  VENDOR_ONLY: 'warn',
}

export default function OTAssets() {
  const [search, setSearch] = useState('')
  const [filterPurdue, setFilterPurdue] = useState('')
  const [filterType, setFilterType] = useState('')
  const [panel, setPanel] = useState<{ open: boolean; mode: 'add' | 'edit'; record: OTAsset | null }>({ open: false, mode: 'add', record: null })
  const canWrite = useCan('edit:system')

  const { data: assets = [] } = useQuery({
    queryKey: ['ot-assets'],
    queryFn: () => api.get<OTAsset[]>('/ot-assets'),
  })

  const { data: systems = [] } = useQuery({
    queryKey: ['systems'],
    queryFn: () => api.get<System[]>('/systems'),
  })

  const filtered = useMemo(() => {
    let list = assets
    if (filterPurdue) list = list.filter(a => a.purdue_level === filterPurdue)
    if (filterType) list = list.filter(a => a.asset_type === filterType)
    if (search) {
      const q = search.toLowerCase()
      list = list.filter(a =>
        a.asset_name.toLowerCase().includes(q) ||
        (a.ip_address || '').toLowerCase().includes(q) ||
        (a.vendor || '').toLowerCase().includes(q) ||
        (a.protocols || []).some(p => p.toLowerCase().includes(q))
      )
    }
    return list
  }, [assets, filterPurdue, filterType, search])

  const stats = useMemo(() => {
    const behind = assets.filter(a => a.patch_status === 'BEHIND').length
    const notPatchable = assets.filter(a => a.patch_status === 'NOT_PATCHABLE').length
    const stigScope = assets.filter(a => a.stig_applicable).length
    const stigNonCompliant = assets.filter(a => a.stig_applicable && a.stig_compliance_status === 'NON_COMPLIANT').length
    return { total: assets.length, behind, notPatchable, stigScope, stigNonCompliant }
  }, [assets])

  const types = useMemo(() => [...new Set(assets.map(a => a.asset_type).filter(Boolean))].sort(), [assets])

  const systemMap = useMemo(() => {
    const m: Record<number, string> = {}
    systems.forEach(s => { m[s.id] = s.name })
    return m
  }, [systems])

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-[var(--text-primary)]">OT Assets</h2>
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
        <KpiCard label="Not Patchable" value={stats.notPatchable} tone={stats.notPatchable > 0 ? 'danger' : 'default'} />
        <KpiCard label="STIG Scope" value={stats.stigScope} />
        <KpiCard label="STIG Non-Compliant" value={stats.stigNonCompliant} tone={stats.stigNonCompliant > 0 ? 'danger' : 'default'} />
      </div>

      <div className="flex gap-3 mb-4 items-center">
        <div className="relative flex-1 max-w-xs">
          <Search size={14} className="absolute left-2 top-1/2 -translate-y-1/2 text-[var(--text-secondary)]" />
          <input
            className="w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] pl-7 pr-2 py-1.5"
            placeholder="Search name, IP, vendor, protocol..."
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>
        <select className="text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5" value={filterPurdue} onChange={e => setFilterPurdue(e.target.value)}>
          <option value="">All Purdue Levels</option>
          {PURDUE_ORDER.map(l => <option key={l} value={l}>{l.replace(/_/g, ' ')}</option>)}
        </select>
        <select className="text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5" value={filterType} onChange={e => setFilterType(e.target.value)}>
          <option value="">All Types</option>
          {types.map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
        </select>
      </div>

      {filtered.length === 0 ? (
        <EmptyState
          icon={Cpu}
          title="No OT assets"
          description="Add OT assets to track PLCs, HMIs, RTUs, and other industrial control devices."
        />
      ) : (
        <div className="bg-[var(--bg-secondary)] border border-[var(--border)]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--border)] text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">
                <th className="text-left px-3 py-2">Name</th>
                <th className="text-left px-3 py-2">System</th>
                <th className="text-left px-3 py-2">Type</th>
                <th className="text-left px-3 py-2">Purdue</th>
                <th className="text-left px-3 py-2">IP</th>
                <th className="text-left px-3 py-2">Firmware</th>
                <th className="text-left px-3 py-2">Protocols</th>
                <th className="text-left px-3 py-2">Patch</th>
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
                  <td className="px-3 py-2 text-xs">{a.asset_type ? <Pill tone="neutral">{a.asset_type.replace(/_/g, ' ')}</Pill> : '—'}</td>
                  <td className="px-3 py-2 text-xs">{a.purdue_level ? <Pill tone="neutral">{a.purdue_level.replace(/_/g, ' ')}</Pill> : '—'}</td>
                  <td className="px-3 py-2 text-[var(--text-secondary)] text-xs font-mono">{a.ip_address || '—'}</td>
                  <td className="px-3 py-2 text-[var(--text-secondary)] text-xs">{a.firmware_version || '—'}</td>
                  <td className="px-3 py-2 text-xs">
                    {(a.protocols || []).length > 0 ? (
                      <span className="flex items-center gap-1">
                        <Wifi size={12} className="text-[var(--text-secondary)]" />
                        {a.protocols.slice(0, 3).join(', ')}
                        {a.protocols.length > 3 && <span className="text-[var(--text-secondary)]">+{a.protocols.length - 3}</span>}
                      </span>
                    ) : '—'}
                  </td>
                  <td className="px-3 py-2 text-xs">
                    {a.patch_status ? <Pill tone={PATCH_TONE[a.patch_status] ?? 'neutral'}>{a.patch_status.replace(/_/g, ' ')}</Pill> : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <OTAssetEntryPanel
        open={panel.open}
        mode={panel.mode}
        record={panel.record}
        systems={systems}
        onClose={() => setPanel({ open: false, mode: 'add', record: null })}
      />
    </div>
  )
}
