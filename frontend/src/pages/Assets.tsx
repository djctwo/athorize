import { useState, useMemo, useRef, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '../lib/api'
import type { ITAsset, OTAsset, System } from '../types'
import { useCan } from '../hooks/useRole'
import { Pill } from '../components/Pill'
import { KpiCard } from '../components/KpiCard'
import { EmptyState } from '../components/EmptyState'
import ITAssetEntryPanel from '../components/ITAssetEntryPanel'
import OTAssetEntryPanel from '../components/OTAssetEntryPanel'
import { AssetImportPanel } from '../components/AssetImportPanel'
import SavedViews from '../components/SavedViews'
import { Plus, Boxes, Search, ChevronDown, Upload } from 'lucide-react'

type Kind = 'IT' | 'OT'

const PATCH_TONE: Record<string, 'ok' | 'warn' | 'danger' | 'neutral'> = {
  CURRENT: 'ok',
  BEHIND: 'warn',
  END_OF_LIFE: 'danger',
  NOT_PATCHABLE: 'neutral',
  VENDOR_ONLY: 'warn',
}

// A unified row keeps the original typed record so the correct (type-aware)
// detail/entry panel can edit it without losing IT- or OT-specific fields.
type Row =
  | { kind: 'IT'; it: ITAsset }
  | { kind: 'OT'; ot: OTAsset }

export default function Assets() {
  const [search, setSearch] = useState('')
  const [filterKind, setFilterKind] = useState<'' | Kind>('')
  const [addMenuOpen, setAddMenuOpen] = useState(false)
  const [itPanel, setItPanel] = useState<{ open: boolean; mode: 'add' | 'edit'; record: ITAsset | null }>({ open: false, mode: 'add', record: null })
  const [otPanel, setOtPanel] = useState<{ open: boolean; mode: 'add' | 'edit'; record: OTAsset | null }>({ open: false, mode: 'add', record: null })
  const [importOpen, setImportOpen] = useState(false)
  const addRef = useRef<HTMLDivElement>(null)
  const canWrite = useCan('edit:system')

  const { data: itAssets = [] } = useQuery({
    queryKey: ['it-assets'],
    queryFn: () => api.get<ITAsset[]>('/it-assets'),
  })
  const { data: otAssets = [] } = useQuery({
    queryKey: ['ot-assets'],
    queryFn: () => api.get<OTAsset[]>('/ot-assets'),
  })
  const { data: systems = [] } = useQuery({
    queryKey: ['systems'],
    queryFn: () => api.get<System[]>('/systems'),
  })

  useEffect(() => {
    if (!addMenuOpen) return
    const onClick = (e: MouseEvent) => {
      if (addRef.current && !addRef.current.contains(e.target as Node)) setAddMenuOpen(false)
    }
    document.addEventListener('mousedown', onClick)
    return () => document.removeEventListener('mousedown', onClick)
  }, [addMenuOpen])

  const rows = useMemo<Row[]>(() => {
    const combined: Row[] = [
      ...itAssets.map((it): Row => ({ kind: 'IT', it })),
      ...otAssets.map((ot): Row => ({ kind: 'OT', ot })),
    ]
    let list = combined
    if (filterKind) list = list.filter(r => r.kind === filterKind)
    if (search) {
      const q = search.toLowerCase()
      list = list.filter(r => {
        if (r.kind === 'IT') {
          const a = r.it
          return a.asset_name.toLowerCase().includes(q) ||
            (a.hostname || '').toLowerCase().includes(q) ||
            (a.ip_address || '').toLowerCase().includes(q) ||
            (a.vendor || '').toLowerCase().includes(q)
        }
        const a = r.ot
        return a.asset_name.toLowerCase().includes(q) ||
          (a.ip_address || '').toLowerCase().includes(q) ||
          (a.vendor || '').toLowerCase().includes(q) ||
          (a.protocols || []).some(p => p.toLowerCase().includes(q))
      })
    }
    return list.sort((a, b) => name(a).localeCompare(name(b)))
  }, [itAssets, otAssets, filterKind, search])

  const stats = useMemo(() => {
    const all = [...itAssets, ...otAssets]
    const behind = all.filter(a => a.patch_status === 'BEHIND').length
    const stigNonCompliant = all.filter(a => a.stig_applicable && a.stig_compliance_status === 'NON_COMPLIANT').length
    return { total: all.length, it: itAssets.length, ot: otAssets.length, behind, stigNonCompliant }
  }, [itAssets, otAssets])

  const systemMap = useMemo(() => {
    const m: Record<number, string> = {}
    systems.forEach(s => { m[s.id] = s.name })
    return m
  }, [systems])

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-bold text-[var(--text-primary)]">Assets</h2>
        {canWrite && (
          <div className="flex items-center gap-2">
          <button
            onClick={() => setImportOpen(true)}
            className="flex items-center gap-2 px-3 py-1.5 border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] text-sm"
          >
            <Upload size={16} /> Import
          </button>
          <div className="relative" ref={addRef}>
            <button
              onClick={() => setAddMenuOpen(o => !o)}
              className="flex items-center gap-2 px-3 py-1.5 bg-[var(--accent)] hover:opacity-90 text-white text-sm"
            >
              <Plus size={16} /> Add Asset <ChevronDown size={14} />
            </button>
            {addMenuOpen && (
              <div className="absolute right-0 mt-1 z-10 bg-[var(--bg-secondary)] border border-[var(--border)] shadow-lg min-w-[140px]">
                <button
                  onClick={() => { setItPanel({ open: true, mode: 'add', record: null }); setAddMenuOpen(false) }}
                  className="w-full text-left px-3 py-2 text-sm text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)]"
                >
                  IT Asset
                </button>
                <button
                  onClick={() => { setOtPanel({ open: true, mode: 'add', record: null }); setAddMenuOpen(false) }}
                  className="w-full text-left px-3 py-2 text-sm text-[var(--text-primary)] hover:bg-[var(--bg-tertiary)] border-t border-[var(--border)]"
                >
                  OT Asset
                </button>
              </div>
            )}
          </div>
          </div>
        )}
      </div>

      <div className="flex border border-[var(--border)] bg-[var(--bg-secondary)] mb-4">
        <KpiCard label="Total" value={stats.total} />
        <KpiCard label="IT" value={stats.it} />
        <KpiCard label="OT" value={stats.ot} />
        <KpiCard label="Patch Behind" value={stats.behind} tone={stats.behind > 0 ? 'warning' : 'default'} />
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
        <select
          className="text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
          value={filterKind}
          onChange={e => setFilterKind(e.target.value as '' | Kind)}
        >
          <option value="">All Types</option>
          <option value="IT">IT</option>
          <option value="OT">OT</option>
        </select>
        <div className="ml-auto">
          <SavedViews
            page="assets"
            current={{ search, filterKind }}
            onApply={(p) => {
              setSearch(typeof p.search === 'string' ? p.search : '')
              setFilterKind(p.filterKind === 'IT' || p.filterKind === 'OT' ? p.filterKind : '')
            }}
          />
        </div>
      </div>

      {rows.length === 0 ? (
        <EmptyState
          icon={Boxes}
          title="No assets"
          description="Add IT and OT assets to track hardware, VMs, cloud resources, and industrial control devices across your systems."
        />
      ) : (
        <div className="bg-[var(--bg-secondary)] border border-[var(--border)]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--border)] text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">
                <th className="text-left px-3 py-2">Type</th>
                <th className="text-left px-3 py-2">Name</th>
                <th className="text-left px-3 py-2">System</th>
                <th className="text-left px-3 py-2">Category</th>
                <th className="text-left px-3 py-2">IP</th>
                <th className="text-left px-3 py-2">Detail</th>
                <th className="text-left px-3 py-2">Patch</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(r => {
                const a = r.kind === 'IT' ? r.it : r.ot
                const onClick = r.kind === 'IT'
                  ? () => setItPanel({ open: true, mode: 'edit', record: r.it })
                  : () => setOtPanel({ open: true, mode: 'edit', record: r.ot })
                return (
                  <tr
                    key={`${r.kind}-${a.id}`}
                    onClick={onClick}
                    className="border-b border-[var(--border)] hover:bg-[var(--bg-tertiary)] cursor-pointer"
                  >
                    <td className="px-3 py-2 text-xs">
                      <Pill tone={r.kind === 'OT' ? 'warn' : 'neutral'}>{r.kind}</Pill>
                    </td>
                    <td className="px-3 py-2 font-medium text-[var(--text-primary)] max-w-[200px] truncate">{a.asset_name}</td>
                    <td className="px-3 py-2 text-[var(--text-secondary)] text-xs">{systemMap[a.system_id] || '—'}</td>
                    <td className="px-3 py-2 text-xs">{category(r)}</td>
                    <td className="px-3 py-2 text-[var(--text-secondary)] text-xs font-mono">{a.ip_address || '—'}</td>
                    <td className="px-3 py-2 text-[var(--text-secondary)] text-xs">{detail(r)}</td>
                    <td className="px-3 py-2 text-xs">
                      {a.patch_status ? <Pill tone={PATCH_TONE[a.patch_status] ?? 'neutral'}>{a.patch_status.replace(/_/g, ' ')}</Pill> : '—'}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      <ITAssetEntryPanel
        open={itPanel.open}
        mode={itPanel.mode}
        record={itPanel.record}
        systems={systems}
        onClose={() => setItPanel({ open: false, mode: 'add', record: null })}
      />
      <OTAssetEntryPanel
        open={otPanel.open}
        mode={otPanel.mode}
        record={otPanel.record}
        systems={systems}
        onClose={() => setOtPanel({ open: false, mode: 'add', record: null })}
      />
      <AssetImportPanel open={importOpen} onClose={() => setImportOpen(false)} />
    </div>
  )
}

function name(r: Row): string {
  return r.kind === 'IT' ? r.it.asset_name : r.ot.asset_name
}

function category(r: Row) {
  const v = r.kind === 'IT' ? r.it.asset_role : r.ot.asset_type
  return v ? <Pill tone="neutral">{v.replace(/_/g, ' ')}</Pill> : '—'
}

function detail(r: Row): string {
  if (r.kind === 'IT') {
    return [r.it.os_family, r.it.os_version].filter(Boolean).join(' ') || '—'
  }
  return [r.ot.purdue_level?.replace(/_/g, ' '), r.ot.firmware_version].filter(Boolean).join(' · ') || '—'
}
