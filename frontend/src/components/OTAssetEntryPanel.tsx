import { useState, useEffect } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '../lib/api'
import { useCan } from '../hooks/useRole'
import type { OTAsset, System } from '../types'
import { SlideInPanel } from './SlideInPanel'
import ConfirmDialog from './ConfirmDialog'

const ASSET_TYPES = ['PLC', 'HMI', 'ENGINEERING_WORKSTATION', 'HISTORIAN', 'RTU', 'FIELD_DEVICE', 'NETWORK_DEVICE', 'SERVER', 'OTHER']
const PURDUE_LEVELS = ['LEVEL_0', 'LEVEL_1', 'LEVEL_2', 'LEVEL_3', 'DMZ']
const PATCH_STATUSES = ['CURRENT', 'BEHIND', 'NOT_PATCHABLE', 'VENDOR_ONLY']
const STIG_STATUSES = ['COMPLIANT', 'NON_COMPLIANT', 'NA', 'NOT_REVIEWED']

interface Props {
  open: boolean
  mode: 'add' | 'edit'
  record: OTAsset | null
  systems: System[]
  onClose: () => void
}

const empty = {
  system_id: 0,
  asset_name: '',
  asset_type: '',
  vendor: '',
  model: '',
  firmware_version: '',
  ip_address: '',
  mac_address: '',
  purdue_level: '',
  protocols: '',
  network_zone: '',
  patch_status: '',
  patch_notes: '',
  last_firmware_review: '',
  stig_applicable: false,
  stig_id: '',
  stig_compliance_status: '',
  connected_to: '',
  notes: '',
}

export default function OTAssetEntryPanel({ open, mode, record, systems, onClose }: Props) {
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
        asset_type: record.asset_type || '',
        vendor: record.vendor || '',
        model: record.model || '',
        firmware_version: record.firmware_version || '',
        ip_address: record.ip_address || '',
        mac_address: record.mac_address || '',
        purdue_level: record.purdue_level || '',
        protocols: (record.protocols || []).join(', '),
        network_zone: record.network_zone || '',
        patch_status: record.patch_status || '',
        patch_notes: record.patch_notes || '',
        last_firmware_review: record.last_firmware_review || '',
        stig_applicable: record.stig_applicable || false,
        stig_id: record.stig_id || '',
        stig_compliance_status: record.stig_compliance_status || '',
        connected_to: (record.connected_to || []).join(', '),
        notes: record.notes || '',
      })
    } else if (open && mode === 'add') {
      setForm({ ...empty, system_id: systems[0]?.id || 0 })
    }
  }, [open, mode, record, systems])

  const create = useMutation({
    mutationFn: (data: Record<string, unknown>) => api.post('/ot-assets', data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['ot-assets'] }); onClose() },
  })

  const update = useMutation({
    mutationFn: (data: Record<string, unknown>) => api.patch(`/ot-assets/${record?.id}`, data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['ot-assets'] }); onClose() },
  })

  const remove = useMutation({
    mutationFn: () => api.delete(`/ot-assets/${record?.id}`),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['ot-assets'] }); onClose() },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!canEdit) return
    const payload: Record<string, unknown> = {
      ...form,
      protocols: form.protocols ? form.protocols.split(',').map(p => p.trim()).filter(Boolean) : [],
      connected_to: form.connected_to ? form.connected_to.split(',').map(c => c.trim()).filter(Boolean) : [],
      last_firmware_review: form.last_firmware_review || null,
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
        title={mode === 'edit' ? 'Edit OT Asset' : 'Add OT Asset'}
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
                <button type="submit" form="ot-asset-form" className="px-3 py-1.5 text-sm bg-[var(--accent)] text-white">
                  {mode === 'edit' ? 'Save' : 'Create'}
                </button>
              )}
            </div>
          </div>
        }
      >
        <form id="ot-asset-form" onSubmit={handleSubmit} className="space-y-3 text-sm">
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
              <label className="block text-xs text-[var(--text-secondary)] mb-1">Asset Type</label>
              <select className={selectClass} value={form.asset_type} onChange={e => set('asset_type', e.target.value)}>
                <option value="">—</option>
                {ASSET_TYPES.map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1">Purdue Level</label>
              <select className={selectClass} value={form.purdue_level} onChange={e => set('purdue_level', e.target.value)}>
                <option value="">—</option>
                {PURDUE_LEVELS.map(l => <option key={l} value={l}>{l.replace(/_/g, ' ')}</option>)}
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

          <div>
            <label className="block text-xs text-[var(--text-secondary)] mb-1">Firmware Version</label>
            <input className={inputClass} value={form.firmware_version} onChange={e => set('firmware_version', e.target.value)} />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1">IP Address</label>
              <input className={inputClass} value={form.ip_address} onChange={e => set('ip_address', e.target.value)} />
            </div>
            <div>
              <label className="block text-xs text-[var(--text-secondary)] mb-1">MAC Address</label>
              <input className={inputClass} value={form.mac_address} onChange={e => set('mac_address', e.target.value)} />
            </div>
          </div>

          <div>
            <label className="block text-xs text-[var(--text-secondary)] mb-1">Network Zone</label>
            <input className={inputClass} value={form.network_zone} onChange={e => set('network_zone', e.target.value)} />
          </div>

          <div>
            <label className="block text-xs text-[var(--text-secondary)] mb-1">Protocols (comma-separated)</label>
            <input className={inputClass} value={form.protocols} onChange={e => set('protocols', e.target.value)} placeholder="Modbus, DNP3, OPC-UA" />
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
              <label className="block text-xs text-[var(--text-secondary)] mb-1">Last Firmware Review</label>
              <input type="date" className={inputClass} value={form.last_firmware_review} onChange={e => set('last_firmware_review', e.target.value)} />
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
            <label className="block text-xs text-[var(--text-secondary)] mb-1">Connected To (comma-separated asset names)</label>
            <input className={inputClass} value={form.connected_to} onChange={e => set('connected_to', e.target.value)} placeholder="Switch-01, RTU-03" />
          </div>

          <div>
            <label className="block text-xs text-[var(--text-secondary)] mb-1">Notes</label>
            <textarea className={inputClass} rows={2} value={form.notes} onChange={e => set('notes', e.target.value)} />
          </div>
        </form>
      </SlideInPanel>

      <ConfirmDialog
        open={confirmDelete}
        title="Delete OT Asset"
        message={`Delete "${record?.asset_name}"? This cannot be undone.`}
        confirmLabel="Delete"
        onConfirm={() => { setConfirmDelete(false); remove.mutate() }}
        onCancel={() => setConfirmDelete(false)}
      />
    </>
  )
}
