import { useState, useEffect } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useCan } from '../hooks/useRole'
import type { ITAsset, System } from '../types'
import { SlideInPanel } from './SlideInPanel'
import ConfirmDialog from './ConfirmDialog'

const ASSET_ROLES = ['WORKSTATION', 'LAPTOP', 'SERVER', 'VM', 'NETWORK_DEVICE', 'MOBILE', 'PRINTER', 'APPLIANCE', 'CLOUD_RESOURCE', 'CONTAINER', 'OTHER']
const OS_FAMILIES = ['WINDOWS', 'LINUX', 'MACOS', 'IOS', 'ANDROID', 'OTHER']
const ENVIRONMENTS = ['PRODUCTION', 'STAGING', 'DEVELOPMENT', 'TEST']
const CRITICALITY = ['LOW', 'MODERATE', 'HIGH']
const DATA_CLASS = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'CUI']
const CLOUD_PROVIDERS = ['AWS', 'AZURE', 'GCP', 'OTHER']
const PATCH_STATUSES = ['CURRENT', 'BEHIND', 'END_OF_LIFE', 'NOT_PATCHABLE']
const STIG_STATUSES = ['COMPLIANT', 'NON_COMPLIANT', 'NA', 'NOT_REVIEWED']

interface Props {
  open: boolean
  mode: 'add' | 'edit'
  record: ITAsset | null
  systems: System[]
  onClose: () => void
}

const empty = {
  system_id: 0,
  asset_name: '',
  asset_role: '',
  vendor: '',
  model: '',
  os_family: '',
  os_version: '',
  hostname: '',
  ip_address: '',
  mac_address: '',
  environment: '',
  criticality: '',
  data_classification: '',
  location: '',
  owner_name: '',
  cloud_provider: '',
  patch_status: '',
  patch_notes: '',
  last_patch_date: '',
  stig_applicable: false,
  stig_id: '',
  stig_compliance_status: '',
  tags: '',
  connected_to: '',
  notes: '',
}

export default function ITAssetEntryPanel({ open, mode, record, systems, onClose }: Props) {
  // Rows open this panel for every role; only edit:system may save/delete.
  const canEdit = useCan('edit:system')
  const [form, setForm] = useState(empty)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const qc = useQueryClient()

  useEffect(() => {
    if (open && mode === 'edit' && record) {
      setForm({
        system_id: record.system_id,
        asset_name: record.asset_name || '',
        asset_role: record.asset_role || '',
        vendor: record.vendor || '',
        model: record.model || '',
        os_family: record.os_family || '',
        os_version: record.os_version || '',
        hostname: record.hostname || '',
        ip_address: record.ip_address || '',
        mac_address: record.mac_address || '',
        environment: record.environment || '',
        criticality: record.criticality || '',
        data_classification: record.data_classification || '',
        location: record.location || '',
        owner_name: record.owner_name || '',
        cloud_provider: record.cloud_provider || '',
        patch_status: record.patch_status || '',
        patch_notes: record.patch_notes || '',
        last_patch_date: record.last_patch_date || '',
        stig_applicable: record.stig_applicable || false,
        stig_id: record.stig_id || '',
        connected_to: (record.connected_to || []).join(', '),
        stig_compliance_status: record.stig_compliance_status || '',
        tags: (record.tags || []).join(', '),
        notes: record.notes || '',
      })
    } else if (open && mode === 'add') {
      setForm({ ...empty, system_id: systems[0]?.id || 0 })
    }
  }, [open, mode, record, systems])

  const create = useMutation({
    mutationFn: (data: Record<string, unknown>) => api.post('/it-assets', data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['it-assets'] }); onClose() },
  })

  const update = useMutation({
    mutationFn: (data: Record<string, unknown>) => api.patch(`/it-assets/${record?.id}`, data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['it-assets'] }); onClose() },
  })

  const remove = useMutation({
    mutationFn: () => api.delete(`/it-assets/${record?.id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['it-assets'] }); onClose() },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!canEdit) return
    const payload: Record<string, unknown> = {
      ...form,
      tags: form.tags ? form.tags.split(',').map(t => t.trim()).filter(Boolean) : [],
      connected_to: form.connected_to ? form.connected_to.split(',').map(c => c.trim()).filter(Boolean) : [],
      last_patch_date: form.last_patch_date || null,
    }
    if (mode === 'edit') {
      delete payload.system_id
      update.mutate(payload)
    } else {
      create.mutate(payload)
    }
  }

  const set = (field: string, value: unknown) => setForm(prev => ({ ...prev, [field]: value }))

  const selectClass = "w-full text-sm bg-[var(--bg-tertiary)] border border-[var(--border)] px-2 py-1.5"
  const inputClass = selectClass

  return (
    <>
      <SlideInPanel
        open={open}
        onClose={onClose}
        width={580}
        title={mode === 'edit' ? 'Edit IT Asset' : 'Add IT Asset'}
        footer={
          <div className="flex items-center justify-between">
            <div>
              {canEdit && mode === 'edit' && (
                <button type="button" onClick={() => setConfirmDelete(true)} className="text-xs text-[var(--danger)] hover:underline">
                  Delete Asset
                </button>
              )}
            </div>
            <div className="flex gap-2">
              <button type="button" onClick={onClose} className="px-3 py-1.5 text-sm border border-[var(--border)]">Cancel</button>
              {canEdit && (
                <button type="submit" form="it-asset-form" className="px-3 py-1.5 text-sm bg-[var(--accent)] text-white">
                  {mode === 'edit' ? 'Save' : 'Create'}
                </button>
              )}
            </div>
          </div>
        }
      >
        <form id="it-asset-form" onSubmit={handleSubmit} className="space-y-3 text-sm">
          <div>
            <label className="block text-xs text-[var(--text-secondary)] mb-1">System *</label>
            <select className={selectClass} value={form.system_id} onChange={e => set('system_id', Number(e.target.value))} disabled={mode === 'edit'}>
              <option value={0}>Select system...</option>
              {systems.map(s => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
          </div>

          <div>
            <label className="block text-xs text-[var(--text-secondary)] mb-1">Asset Name *</label>
            <input className={inputClass} value={form.asset_name} onChange={e => set('asset_name', e.target.value)} required />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1">Role</label>
              <select className={selectClass} value={form.asset_role} onChange={e => set('asset_role', e.target.value)}>
                <option value="">—</option>
                {ASSET_ROLES.map(r => <option key={r} value={r}>{r.replace(/_/g, ' ')}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1">Environment</label>
              <select className={selectClass} value={form.environment} onChange={e => set('environment', e.target.value)}>
                <option value="">—</option>
                {ENVIRONMENTS.map(e => <option key={e} value={e}>{e}</option>)}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1">Vendor</label>
              <input className={inputClass} value={form.vendor} onChange={e => set('vendor', e.target.value)} />
            </div>
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1">Model</label>
              <input className={inputClass} value={form.model} onChange={e => set('model', e.target.value)} />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1">OS Family</label>
              <select className={selectClass} value={form.os_family} onChange={e => set('os_family', e.target.value)}>
                <option value="">—</option>
                {OS_FAMILIES.map(o => <option key={o} value={o}>{o}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1">OS Version</label>
              <input className={inputClass} value={form.os_version} onChange={e => set('os_version', e.target.value)} />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1">Hostname</label>
              <input className={inputClass} value={form.hostname} onChange={e => set('hostname', e.target.value)} />
            </div>
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1">IP Address</label>
              <input className={inputClass} value={form.ip_address} onChange={e => set('ip_address', e.target.value)} />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1">MAC Address</label>
              <input className={inputClass} value={form.mac_address} onChange={e => set('mac_address', e.target.value)} />
            </div>
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1">Location</label>
              <input className={inputClass} value={form.location} onChange={e => set('location', e.target.value)} />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1">Criticality</label>
              <select className={selectClass} value={form.criticality} onChange={e => set('criticality', e.target.value)}>
                <option value="">—</option>
                {CRITICALITY.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1">Data Classification</label>
              <select className={selectClass} value={form.data_classification} onChange={e => set('data_classification', e.target.value)}>
                <option value="">—</option>
                {DATA_CLASS.map(d => <option key={d} value={d}>{d}</option>)}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1">Owner</label>
              <input className={inputClass} value={form.owner_name} onChange={e => set('owner_name', e.target.value)} />
            </div>
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1">Cloud Provider</label>
              <select className={selectClass} value={form.cloud_provider} onChange={e => set('cloud_provider', e.target.value)}>
                <option value="">—</option>
                {CLOUD_PROVIDERS.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1">Patch Status</label>
              <select className={selectClass} value={form.patch_status} onChange={e => set('patch_status', e.target.value)}>
                <option value="">—</option>
                {PATCH_STATUSES.map(p => <option key={p} value={p}>{p.replace(/_/g, ' ')}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1">Last Patch Date</label>
              <input type="date" className={inputClass} value={form.last_patch_date} onChange={e => set('last_patch_date', e.target.value)} />
            </div>
          </div>

          <div>
            <label className="block text-xs text-[var(--text-secondary)] mb-1">Patch Notes</label>
            <textarea className={inputClass} rows={2} value={form.patch_notes} onChange={e => set('patch_notes', e.target.value)} />
          </div>

          <div className="flex items-center gap-3 pt-1">
            <label className="flex items-center gap-2 text-xs text-[var(--text-secondary)] cursor-pointer">
              <input type="checkbox" checked={form.stig_applicable} onChange={e => set('stig_applicable', e.target.checked)} />
              STIG Applicable
            </label>
          </div>

          {form.stig_applicable && (
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-[var(--text-secondary)] mb-1">STIG ID</label>
                <input className={inputClass} value={form.stig_id} onChange={e => set('stig_id', e.target.value)} />
              </div>
              <div>
                <label className="block text-xs text-[var(--text-secondary)] mb-1">STIG Compliance</label>
                <select className={selectClass} value={form.stig_compliance_status} onChange={e => set('stig_compliance_status', e.target.value)}>
                  <option value="">—</option>
                  {STIG_STATUSES.map(s => <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>)}
                </select>
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs text-[var(--text-secondary)] mb-1">Tags (comma-separated)</label>
            <input className={inputClass} value={form.tags} onChange={e => set('tags', e.target.value)} placeholder="web, dmz, critical" />
          </div>

          <div>
            <label className="block text-xs text-[var(--text-secondary)] mb-1">Connected To (comma-separated asset names)</label>
            <input className={inputClass} value={form.connected_to} onChange={e => set('connected_to', e.target.value)} placeholder="FW-CORE-01, ERP-DB-01" />
          </div>
          <div>
            <label className="block text-xs text-[var(--text-secondary)] mb-1">Notes</label>
            <textarea className={inputClass} rows={2} value={form.notes} onChange={e => set('notes', e.target.value)} />
          </div>
        </form>
      </SlideInPanel>

      <ConfirmDialog
        open={confirmDelete}
        title="Delete IT Asset"
        message={`Delete "${record?.asset_name}"? This cannot be undone.`}
        confirmLabel="Delete"
        onConfirm={() => { setConfirmDelete(false); remove.mutate() }}
        onCancel={() => setConfirmDelete(false)}
      />
    </>
  )
}
