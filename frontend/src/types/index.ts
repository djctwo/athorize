export interface User {
  id: number
  username: string
  email: string | null
  display_name: string | null
  role: string
  is_active: boolean
  created_at: string
  last_login: string | null
  organization_id: number
  organization_name: string | null
  /** Active company's logo as a server-validated PNG/JPEG data URI (/auth/me only). */
  organization_logo: string | null
  is_operator: boolean
  /** An SSO identity (IdP issuer + subject) is bound to this account. */
  sso_linked?: boolean
  /** Demo-seeded instance with public default passwords (/auth/me only) → persistent banner. */
  demo_instance?: boolean
  /** This build re-loads the demo into an empty database at every start (ATHORIZE_DEMO_SEED=1 / Demo build). */
  demo_autoseed?: boolean
}

export interface System {
  id: number
  organization_id: number
  name: string
  acronym: string
  description: string
  system_type: string
  owner_id: number | null
  environment: string
  criticality: string
  impact_level: string
  authorization_status: string
  is_ot_enabled: boolean
  metadata: Record<string, unknown>
  created_at: string
  updated_at: string
}

export interface Finding {
  id: number
  organization_id: number
  system_id: number
  framework_id: string
  control_id: string
  title: string
  description: string
  weakness_description: string
  severity: string
  status: string
  owner_id: number | null
  owner_name: string | null
  owner_email: string | null
  due_date: string | null
  scheduled_completion: string | null
  actual_completion: string | null
  closed_date: string | null
  remediation_plan: string
  risk_rationale: string
  reopen_reason: string | null
  milestones: { title: string; due: string; complete: boolean }[]
  extra_data: Record<string, unknown>
  aging_bucket: AgingBucket
  days_until_due: number | null
  days_open: number | null
  created_at: string
  updated_at: string
}

export interface EvidenceArtifact {
  id: number
  organization_id: number
  system_id: number
  filename: string
  description: string
  artifact_type: string
  control_ids: string[]
  framework_ids: string[]
  date_collected: string | null
  expiration_date: string | null
  expiration_days: number | null
  uploaded_by_id: number | null
  owner_id: number | null
  /** Refresh owner's display name — provided by the list endpoint. */
  owner_name?: string | null
  file_path: string
  file_hash: string
  notes: string
  created_at: string
}

export interface Control {
  framework_id: string
  control_id: string
  family: string
  family_name: string
  title: string
  description: string
  supplemental_guidance: string
  baselines: string[]
  parent_id: string | null
  related_controls: string[]
  typical_evidence: { type: string; freshness_days: number }[]
  assessment_objectives: string[]
  external_references: { source: string; url: string }[]
}

export interface Framework {
  id: string
  name: string
  short_name: string
  version: string
  description: string
  publisher: string
  category: string
  tags: string[]
  status: string
  icon: string
  color: string
  control_count: number
  is_active: boolean
  activated_at: string | null
  license?: {
    restriction?: string
    licensor?: string
    basis?: string
    addon?: boolean
    note?: string
  } | null
  entitled?: boolean
}

export interface Assessment {
  id: number
  organization_id: number
  system_id: number
  framework_id: string
  assessment_type: string
  assessor_id: number | null
  status: string
  started_at: string | null
  completed_at: string | null
  item_states: Record<string, unknown>
  notes: string
  created_at: string
}

export interface CalendarEvent {
  /** null for derived (read-only) deadlines */
  id: number | null
  /** "manual" = added on the Calendar page; "derived" = computed from a finding, milestone, evidence, assessment or ConMon cadence */
  source?: 'manual' | 'derived'
  derived_key?: string
  link?: string | null
  organization_id: number
  system_id: number | null
  framework_id: string | null
  event_type: string
  title: string
  description: string
  event_date: string
  recurring: string | null
  related_entity_type: string | null
  related_entity_id: number | null
  created_at?: string
}

export interface AuditEntry {
  id: number
  timestamp: string
  organization_id: number
  actor_id: number | null
  actor_username: string
  action: string
  entity_type: string
  entity_id: number | null
  system_id: number | null
  summary: string
  integrity_hash: string
}

export interface DashboardSnapshot {
  cadence_overdue: number
  total_systems: number
  open_findings: number
  critical_findings: number
  overdue_findings: number
  expiring_evidence: number
  expired_evidence: number
  fresh_evidence: number
  total_evidence: number
  active_frameworks: number
  open_risks: number
}

export interface FindingAging {
  overdue: number
  due_7: number
  due_30: number
  on_track: number
}

export interface EvidenceFreshness {
  fresh: number
  expiring: number
  expired: number
  total: number
}

export interface ActivityEntry {
  id: number
  action: string
  entity_type: string
  entity_id: number | null
  actor: string
  summary: string
  created_at: string | null
}

export interface ComplianceScore {
  system_id: number
  system_name: string
  framework_id: string
  score_percentage: number
  total_controls: number
  implemented: number
  open_findings: number
  critical_findings: number
}

export interface ConMonEntry {
  id: number
  organization_id: number
  system_id: number
  framework_id: string | null
  entry_date: string
  activity_type: string
  description: string
  performed_by: string
  findings: string
  actions_taken: string
  follow_up_required: boolean
  follow_up_date: string | null
  evidence_artifact_id: number | null
  created_at: string
}

export interface ITAsset {
  id: number
  organization_id: number
  system_id: number
  asset_name: string
  asset_role: string
  vendor: string
  model: string
  os_family: string
  os_version: string
  hostname: string
  ip_address: string
  mac_address: string
  environment: string
  criticality: string
  data_classification: string
  location: string
  owner_name: string
  cloud_provider: string
  patch_status: string
  patch_notes: string
  last_patch_date: string | null
  stig_applicable: boolean
  stig_id: string
  stig_compliance_status: string
  connected_to: string[]
  tags: string[]
  notes: string
  created_at: string
  updated_at: string
}

export interface OTAsset {
  id: number
  organization_id: number
  system_id: number
  asset_name: string
  asset_type: string
  vendor: string
  model: string
  firmware_version: string
  ip_address: string
  mac_address: string
  purdue_level: string
  protocols: string[]
  network_zone: string
  patch_status: string
  patch_notes: string
  last_firmware_review: string | null
  stig_applicable: boolean
  stig_id: string
  stig_compliance_status: string
  connected_to: string[]
  notes: string
  created_at: string
  updated_at: string
}

export type AssetRole = 'WORKSTATION' | 'LAPTOP' | 'SERVER' | 'VM' | 'NETWORK_DEVICE' | 'MOBILE' | 'PRINTER' | 'APPLIANCE' | 'CLOUD_RESOURCE' | 'CONTAINER' | 'OTHER'
export type OTAssetType = 'PLC' | 'HMI' | 'ENGINEERING_WORKSTATION' | 'HISTORIAN' | 'RTU' | 'FIELD_DEVICE' | 'NETWORK_DEVICE' | 'SERVER' | 'OTHER'
export type PurdueLevel = 'LEVEL_0' | 'LEVEL_1' | 'LEVEL_2' | 'LEVEL_3' | 'DMZ'
export type PatchStatus = 'CURRENT' | 'BEHIND' | 'END_OF_LIFE' | 'NOT_PATCHABLE' | 'VENDOR_ONLY'
export interface IcsAdvisory {
  id: number
  organization_id: number
  advisory_id: string
  title: string
  summary: string
  severity: string
  cvss_score: string | null
  cve_ids: string[]
  affected_vendor: string
  affected_product: string
  affected_firmware_range: string
  recommended_mitigations: string
  published_date: string | null
  source: string
  source_url: string
  /** Bundled offline/demo advisory: fictional vendor and product, DEMO- ids. */
  is_sample?: boolean
  status: string
  triaged_by: string | null
  triaged_at: string | null
  notes: string | null
  related_controls: string[]
  matches: IcsAdvisoryMatch[]
  match_count: number
  system_acronyms: string[]
  created_at: string
  updated_at: string
}

export interface IcsAdvisoryMatch {
  id: number
  advisory_id: number
  ot_asset_id: number | null
  it_asset_id: number | null
  asset_kind?: 'OT' | 'IT'
  system_id: number
  confidence: string
  dismissed: boolean
  asset_name?: string
  asset_vendor?: string
  asset_model?: string
  asset_firmware?: string
  asset_purdue_level?: string
  created_at: string
}

export interface CustomFeed {
  name: string
  url: string
  format: 'rss' | 'csaf'
}

export interface RiskRegisterEntry {
  id: number
  organization_id: number
  system_id: number
  title: string
  description: string | null
  category: string
  control_id: string | null
  likelihood: string
  impact: string
  risk_level: string | null
  status: string
  treatment: string
  mitigation: string | null
  residual_risk: string | null
  owner_name: string | null
  owner_email: string | null
  review_date: string | null
  template_key: string | null
  linked_finding_id: number | null
  created_at: string
  updated_at: string
}

export type RiskCategory = 'TECH' | 'OPS' | 'COMPLIANCE' | 'SUPPLY_CHAIN' | 'OT' | 'OTHER'
export type RiskStatus = 'OPEN' | 'MITIGATING' | 'ACCEPTED' | 'TRANSFERRED' | 'CLOSED'
export type RiskTreatment = 'MITIGATE' | 'ACCEPT' | 'TRANSFER' | 'AVOID'
export type RiskLevel = 'LOW' | 'MODERATE' | 'HIGH'
export type ConfidenceTier = 'EXACT' | 'FIRMWARE_RANGE' | 'VENDOR_PRODUCT' | 'VENDOR_ONLY'

export const RISK_CATEGORIES: RiskCategory[] = ['TECH', 'OPS', 'COMPLIANCE', 'SUPPLY_CHAIN', 'OT', 'OTHER']
export const RISK_CATEGORY_LABELS: Record<RiskCategory, string> = {
  TECH: 'Technical', OPS: 'Operational', COMPLIANCE: 'Compliance',
  SUPPLY_CHAIN: 'Supply Chain', OT: 'OT / ICS', OTHER: 'Other',
}
export const RISK_STATUSES: RiskStatus[] = ['OPEN', 'MITIGATING', 'ACCEPTED', 'TRANSFERRED', 'CLOSED']
export const RISK_TREATMENTS: RiskTreatment[] = ['MITIGATE', 'ACCEPT', 'TRANSFER', 'AVOID']
export const RISK_LEVELS: RiskLevel[] = ['LOW', 'MODERATE', 'HIGH']

export type AgingBucket = 'OVERDUE' | 'DUE_7' | 'DUE_30' | 'ON_TRACK' | 'RESOLVED'
export type FreshnessStatus = 'FRESH' | 'EXPIRING_SOON' | 'EXPIRED' | 'NO_EXPIRATION'
export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
export type FindingStatus = 'OPEN' | 'IN_PROGRESS' | 'CLOSED' | 'RISK_ACCEPTED' | 'FALSE_POSITIVE' | 'DELAYED'
