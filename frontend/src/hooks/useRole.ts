import { useUserStore } from '../store/userStore'
import { can, type Action } from '../lib/permissions'

export type UserRole = 'admin' | 'compliance_manager' | 'assessor' | 'system_owner' | 'evidence_contributor' | 'auditor'

export function useCurrentRole(): UserRole | null {
  return useUserStore((s) => s.user?.role as UserRole) ?? null
}

/** The one UI capability gate: may the current user perform `action`?
 * Actions mirror the server-side guard of the endpoint the control calls
 * (lib/permissions.ts). Do not gate on raw roles or a generic "write" role. */
export function useCan(action: Action): boolean {
  const role = useCurrentRole()
  return role !== null && can(role, action)
}
