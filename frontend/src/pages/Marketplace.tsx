import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import type { Framework } from '../types'
import { Shield, Check, Lock, KeyRound, Wrench } from 'lucide-react'
import { useCan } from '../hooks/useRole'
import { plural } from '../lib/plural'

const CATEGORY_LABELS: Record<string, string> = {
  federal: 'Federal / DoD',
  finance: 'Financial Services',
  healthcare: 'Healthcare',
  privacy: 'Privacy',
  energy: 'Energy / Utilities',
  general: 'General / Cross-Industry',
  government: 'Government',
}

export default function Marketplace() {
  const queryClient = useQueryClient()
  const canManage = useCan('manage:frameworks')

  const { data: frameworks = [] } = useQuery({
    queryKey: ['frameworks'],
    queryFn: () => api.get<Framework[]>('/frameworks'),
  })

  const activate = useMutation({
    mutationFn: (vars: { id: string; license_key?: string }) =>
      api.post(`/frameworks/${vars.id}/activate`, { license_key: vars.license_key ?? '' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['frameworks'] }),
  })

  const deactivate = useMutation({
    mutationFn: (id: string) => api.post(`/frameworks/${id}/deactivate`),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['frameworks'] }),
  })

  const pendingId =
    (activate.isPending ? activate.variables?.id : undefined) ??
    (deactivate.isPending ? deactivate.variables : undefined)

  const categories = [...new Set(frameworks.map(f => f.category))].sort()

  return (
    <div>
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h2 className="text-xl font-bold">Framework Marketplace</h2>
          <p className="text-sm text-text-muted mt-1">Activate compliance frameworks to load their control catalogs</p>
          {!canManage && (
            <p className="text-xs text-text-muted mt-1">Only an admin can activate or deactivate frameworks — ask yours to turn on the ones you need.</p>
          )}
        </div>
        {canManage && (
          <Link to="/framework-builder"
            className="flex items-center gap-2 px-3 py-1.5 text-sm border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--accent)] hover:border-[var(--accent)]">
            <Wrench size={14} /> Build custom framework
          </Link>
        )}
      </div>

      {categories.map(category => {
        const categoryFrameworks = frameworks.filter(f => f.category === category)
        if (categoryFrameworks.length === 0) return null
        return (
          <div key={category} className="mb-8">
            <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-3">
              {CATEGORY_LABELS[category] || category}
            </h3>
            <div className="grid grid-cols-2 gap-3">
              {categoryFrameworks.map(fw => (
                <FrameworkCard
                  key={fw.id}
                  framework={fw}
                  isAdmin={canManage}
                  onActivate={(licenseKey?: string) => activate.mutate({ id: fw.id, license_key: licenseKey })}
                  onDeactivate={() => deactivate.mutate(fw.id)}
                  isPending={pendingId === fw.id}
                />
              ))}
            </div>
          </div>
        )
      })}
    </div>
  )
}

function FrameworkCard({
  framework,
  isAdmin,
  onActivate,
  onDeactivate,
  isPending,
}: {
  framework: Framework
  isAdmin: boolean
  onActivate: (licenseKey?: string) => void
  onDeactivate: () => void
  isPending: boolean
}) {
  const [showKey, setShowKey] = useState(false)
  const [keyValue, setKeyValue] = useState('')
  // Every bundled framework is free to activate. Only `attestable` frameworks
  // (third-party content) stay locked until an admin enters their OWN publisher
  // license key.
  const attestable = framework.license?.restriction === 'licensed'
  const locked = framework.entitled !== true && !framework.is_active
  const licensor = framework.license?.licensor || 'the publisher'
  return (
    <div className={`relative bg-bg-secondary border p-4 flex items-start gap-3 ${framework.is_active ? 'border-success/50' : 'border-border'}`}>
      <div className="w-10 h-10 flex items-center justify-center" style={{ backgroundColor: framework.color + '20' }}>
        <Shield size={20} style={{ color: framework.color }} />
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <h4 className="text-sm font-semibold truncate">{framework.name}</h4>
          {framework.is_active && <Check size={14} className="text-success flex-shrink-0" />}
        </div>
        <p className="text-xs text-text-muted mt-0.5 truncate">{framework.description}</p>
        <div className="flex items-center gap-2 mt-2">
          <span className="text-xs text-text-muted">{framework.publisher}</span>
          <span className="text-xs text-text-muted">v{framework.version}</span>
          <span className="text-xs text-text-muted">{plural(framework.control_count, 'control')}</span>
          {framework.license?.restriction === 'licensed' && (
            <span className="text-xs text-warning">Licensed add-on</span>
          )}
        </div>
      </div>
      <div className="flex-shrink-0">
        {framework.status === 'coming_soon' ? (
          <span className="flex items-center gap-1 text-xs text-text-muted"><Lock size={12} /> Coming Soon</span>
        ) : locked && !isAdmin ? (
          <span
            title="Licensed third-party content — an admin can enable it with your organization's own publisher license key."
            className="flex items-center gap-1 text-xs text-warning"
          >
            <Lock size={12} /> Locked
          </span>
        ) : locked && isAdmin && attestable ? (
          <button onClick={() => setShowKey(v => !v)} disabled={isPending} className="flex items-center gap-1 px-3 py-1 text-xs border border-warning/50 text-warning hover:bg-warning/10 transition-colors">
            <KeyRound size={12} /> Enter license key
          </button>
        ) : isAdmin ? (
          framework.is_active ? (
            <button onClick={onDeactivate} disabled={isPending} className="px-3 py-1 text-xs border border-border text-text-secondary hover:border-danger hover:text-danger transition-colors">
              Deactivate
            </button>
          ) : (
            <button onClick={() => onActivate()} disabled={isPending} className="px-3 py-1 text-xs bg-accent hover:bg-accent-hover text-white transition-colors">
              Activate
            </button>
          )
        ) : (
          framework.is_active ? (
            <span className="text-xs text-success">Active</span>
          ) : (
            <span className="text-xs text-text-muted">Inactive</span>
          )
        )}
        {locked && isAdmin && attestable && showKey && (
          <div className="absolute right-4 mt-2 w-72 bg-bg-primary border border-border p-3 z-10 shadow-lg">
            <label className="text-xs text-text-secondary block mb-1">Your {licensor} license key / reference</label>
            <input
              autoFocus
              value={keyValue}
              onChange={e => setKeyValue(e.target.value)}
              placeholder={`${licensor} license number`}
              className="w-full text-xs bg-bg-secondary border border-border px-2 py-1 mb-2 focus:outline-none focus:border-accent"
            />
            <p className="text-[11px] text-text-muted mb-2">
              By enabling, you confirm your organization holds a valid {licensor} license. Responsibility for that license is yours; this is recorded in the audit log.
            </p>
            <div className="flex justify-end gap-2">
              <button onClick={() => { setShowKey(false); setKeyValue('') }} className="px-2 py-1 text-xs text-text-secondary hover:text-text-primary">Cancel</button>
              <button
                onClick={() => { onActivate(keyValue.trim()); setShowKey(false); setKeyValue('') }}
                disabled={isPending || !keyValue.trim()}
                className="px-3 py-1 text-xs bg-accent hover:bg-accent-hover text-white disabled:opacity-50 transition-colors"
              >
                Confirm &amp; enable
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
