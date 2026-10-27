import { useQuery } from '@tanstack/react-query'
import {
  ArrowRight, Clock, History, Plus, PenSquare, RefreshCw,
  Trash2, Upload, User,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { api } from '../lib/api'
import { formatRelative } from '../lib/datetime'
import type { AuditEntry } from '../types'
import { SkeletonBar } from './Skeleton'

const ACTION_META: Record<string, { label: string; icon: LucideIcon; tone: string }> = {
  CREATE: { label: 'Created', icon: Plus, tone: 'var(--success)' },
  UPDATE: { label: 'Updated', icon: PenSquare, tone: 'var(--info)' },
  DELETE: { label: 'Deleted', icon: Trash2, tone: 'var(--danger)' },
  UPLOAD: { label: 'Uploaded', icon: Upload, tone: 'var(--success)' },
  REPLACE_FILE: { label: 'Replaced file', icon: RefreshCw, tone: 'var(--info)' },
  BULK_IMPORT: { label: 'Bulk imported', icon: ArrowRight, tone: 'var(--accent)' },
  SPAWN_FINDING: { label: 'Spawned finding', icon: ArrowRight, tone: 'var(--warning)' },
  RUN: { label: 'Ran analysis', icon: RefreshCw, tone: 'var(--accent)' },
}

function actionMeta(action: string) {
  return ACTION_META[action] ?? { label: action, icon: ArrowRight, tone: 'var(--text-secondary)' }
}

export default function EntityAuditTrail({
  entityType,
  entityId,
  limit = 15,
}: {
  entityType: string
  entityId: string | number
  limit?: number
}) {
  const { data: entries = [], isLoading } = useQuery<AuditEntry[]>({
    queryKey: ['audit', entityType, String(entityId)],
    queryFn: () =>
      api.get(`/audit?entity_type=${entityType}&entity_id=${entityId}&limit=${limit}`),
  })

  return (
    <section className="border-t border-[var(--border)] pt-4">
      <div className="flex items-center gap-2 mb-3">
        <History size={14} className="text-[var(--text-secondary)]" />
        <div className="text-[11px] uppercase tracking-wider text-[var(--text-secondary)]">
          Activity
        </div>
        {entries.length > 0 && (
          <div className="text-[11px] text-[var(--text-secondary)]">
            · {entries.length}
          </div>
        )}
      </div>

      {isLoading ? (
        <div className="space-y-2">
          <SkeletonBar className="h-3 w-full" />
          <SkeletonBar className="h-3 w-3/4" />
          <SkeletonBar className="h-3 w-1/2" />
        </div>
      ) : entries.length === 0 ? (
        <div className="flex items-center gap-2 text-[11px] text-[var(--text-secondary)]">
          <Clock size={12} className="opacity-50" />
          No recorded activity yet.
        </div>
      ) : (
        <ol className="space-y-2">
          {entries.map((e) => {
            const meta = actionMeta(e.action)
            const Icon = meta.icon
            return (
              <li key={e.id} className="flex items-start gap-2 text-[12px]">
                <span
                  className="shrink-0 mt-0.5 flex items-center justify-center w-5 h-5 border"
                  style={{
                    borderColor: `color-mix(in srgb, ${meta.tone} 45%, transparent)`,
                    color: meta.tone,
                    backgroundColor: `color-mix(in srgb, ${meta.tone} 12%, transparent)`,
                  }}
                >
                  <Icon size={11} />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline gap-2">
                    <span style={{ color: meta.tone }} className="font-mono text-[11px] uppercase">
                      {meta.label}
                    </span>
                    <span className="flex items-center gap-1 text-[11px] text-[var(--text-secondary)]">
                      <User size={10} />
                      {e.actor_username}
                    </span>
                    <span className="text-[11px] text-[var(--text-secondary)] ml-auto">
                      {formatRelative(e.timestamp)}
                    </span>
                  </div>
                  {e.summary && (
                    <div className="text-[var(--text-primary)] truncate" title={e.summary}>
                      {e.summary}
                    </div>
                  )}
                </div>
              </li>
            )
          })}
        </ol>
      )}
    </section>
  )
}
