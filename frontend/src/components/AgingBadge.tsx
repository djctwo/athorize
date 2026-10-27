import { Pill } from './Pill'
import type { ComponentProps } from 'react'

type PillTone = ComponentProps<typeof Pill>['tone']

export type AgingBucket = 'OVERDUE' | 'DUE_7' | 'DUE_30' | 'ON_TRACK' | 'RESOLVED'
export type FreshnessStatus = 'FRESH' | 'EXPIRING_SOON' | 'EXPIRED' | 'NO_EXPIRATION'

const AGING_MAP: Record<AgingBucket, { label: string; tone: PillTone }> = {
  OVERDUE: { label: 'Overdue', tone: 'danger' },
  DUE_7: { label: 'Due 7', tone: 'warn' },
  DUE_30: { label: 'Due 30', tone: 'info' },
  ON_TRACK: { label: 'On Track', tone: 'ok' },
  RESOLVED: { label: 'Resolved', tone: 'neutral' },
}

export function AgingBadge({ bucket }: { bucket: AgingBucket }) {
  const { label, tone } = AGING_MAP[bucket]
  return <Pill tone={tone}>{label}</Pill>
}

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

const SEVERITY_MAP: Record<SeverityLevel, { tone: PillTone }> = {
  CRITICAL: { tone: 'danger' },
  HIGH: { tone: 'danger' },
  MEDIUM: { tone: 'warn' },
  LOW: { tone: 'info' },
}

export function SeverityBadge({ severity }: { severity: SeverityLevel }) {
  const { tone } = SEVERITY_MAP[severity]
  return <Pill tone={tone}>{severity}</Pill>
}

const FRESHNESS_MAP: Record<FreshnessStatus, { label: string; tone: PillTone }> = {
  FRESH: { label: 'Fresh', tone: 'ok' },
  EXPIRING_SOON: { label: 'Expiring', tone: 'warn' },
  EXPIRED: { label: 'Expired', tone: 'danger' },
  NO_EXPIRATION: { label: 'No Expiration', tone: 'neutral' },
}

export function FreshnessBadge({ status }: { status: FreshnessStatus }) {
  const { label, tone } = FRESHNESS_MAP[status]
  return <Pill tone={tone}>{label}</Pill>
}
