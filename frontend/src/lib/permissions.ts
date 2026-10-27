// Single frontend permission map. Every UI capability gate goes through
// can(role, action) / useCan(action) — never a raw role comparison or a generic
// "write role" check, because each endpoint has its own server-side guard.
//
// Mirrors the backend: actions shared with backend/services/permissions.py
// carry the same names and roles; the rest mirror the require_role /
// require_min_role guard on the endpoints they gate.
// backend/tests/test_permission_parity.py evaluates every route's real guard
// against this table and fails on drift.
export type Role = 'admin' | 'compliance_manager' | 'assessor' | 'system_owner' | 'evidence_contributor' | 'auditor'

export type Action =
  // Shared with backend services/permissions.py MATRIX
  | 'read:any'
  | 'edit:finding'
  | 'upload:evidence'
  | 'edit:conmon'
  | 'edit:risk'
  | 'edit:system'
  | 'assess:control'
  | 'approve:finding_close'
  | 'work:own_finding'
  | 'manage:users'
  | 'post:comment'
  // Mirrors of role-based endpoint guards
  | 'delete:evidence'
  | 'delete:system'
  | 'edit:assessment'
  | 'delete:assessment'
  | 'edit:calendar'
  | 'delete:calendar'
  | 'run:redteam'
  | 'manage:redteam'
  | 'manage:frameworks'
  | 'manage:settings'
  | 'view:digest'
  | 'view:users'
  | 'assign:systems'

const MATRIX: Record<Action, Set<Role>> = {
  'read:any':              new Set(['admin', 'compliance_manager', 'assessor', 'system_owner', 'evidence_contributor', 'auditor']),
  'edit:finding':          new Set(['admin', 'compliance_manager']),
  'upload:evidence':       new Set(['admin', 'compliance_manager', 'evidence_contributor']),
  'edit:conmon':           new Set(['admin', 'compliance_manager']),
  'edit:risk':             new Set(['admin', 'compliance_manager']),
  'edit:system':           new Set(['admin', 'compliance_manager']),
  'assess:control':        new Set(['admin', 'assessor']),
  'approve:finding_close': new Set(['admin', 'compliance_manager']),
  // The assigned owner works their own finding: Open/In Progress/Delayed + milestones (R2USER-12).
  'work:own_finding':      new Set(['admin', 'compliance_manager', 'assessor', 'system_owner', 'evidence_contributor']),
  'manage:users':          new Set(['admin']),
  'post:comment':          new Set(['admin', 'compliance_manager', 'assessor', 'system_owner', 'evidence_contributor']),
  'delete:evidence':       new Set(['admin', 'compliance_manager']),
  'delete:system':         new Set(['admin', 'compliance_manager']),
  'edit:assessment':       new Set(['admin', 'compliance_manager', 'assessor']),
  'delete:assessment':     new Set(['admin', 'compliance_manager']),
  'edit:calendar':         new Set(['admin', 'compliance_manager', 'assessor']),
  'delete:calendar':       new Set(['admin', 'compliance_manager']),
  'run:redteam':           new Set(['admin', 'compliance_manager', 'assessor']),
  'manage:redteam':        new Set(['admin', 'compliance_manager']),
  'manage:frameworks':     new Set(['admin']),
  'manage:settings':       new Set(['admin']),
  'view:digest':           new Set(['admin', 'compliance_manager']),
  'view:users':            new Set(['admin', 'compliance_manager']),
  'assign:systems':        new Set(['admin', 'compliance_manager']),
}

export function can(role: string, action: Action): boolean {
  return MATRIX[action]?.has(role as Role) ?? false
}
