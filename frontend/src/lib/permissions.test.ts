import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { describe, expect, it } from 'vitest'
import { can } from './permissions'

// This matrix mirrors the backend's endpoint guards — backend
// tests/test_permission_parity.py pins it against every route; these tests
// pin the frontend copy's key decisions.
describe('permissions matrix', () => {
  it('everyone can read', () => {
    for (const role of ['admin', 'compliance_manager', 'assessor', 'system_owner', 'evidence_contributor', 'auditor']) {
      expect(can(role, 'read:any')).toBe(true)
    }
  })

  it('finding edits are admin/compliance_manager only', () => {
    expect(can('admin', 'edit:finding')).toBe(true)
    expect(can('compliance_manager', 'edit:finding')).toBe(true)
    expect(can('assessor', 'edit:finding')).toBe(false)
    expect(can('auditor', 'edit:finding')).toBe(false)
  })

  it('evidence contributors can upload but not manage users', () => {
    expect(can('evidence_contributor', 'upload:evidence')).toBe(true)
    expect(can('evidence_contributor', 'manage:users')).toBe(false)
  })

  it('assessors assess controls; compliance managers do not', () => {
    expect(can('assessor', 'assess:control')).toBe(true)
    expect(can('compliance_manager', 'assess:control')).toBe(false)
  })

  it('user directory: CM can view and assign systems, only admin manages accounts', () => {
    expect(can('compliance_manager', 'view:users')).toBe(true)
    expect(can('compliance_manager', 'assign:systems')).toBe(true)
    expect(can('compliance_manager', 'manage:users')).toBe(false)
  })

  it('unknown roles and actions are denied, never throw', () => {
    expect(can('superhacker', 'edit:finding')).toBe(false)
    // @ts-expect-error — intentionally invalid action
    expect(can('admin', 'not:an:action')).toBe(false)
  })
})

// The class of bug this guards against: a page gating on a generic "write"
// role or a raw role comparison instead of the action its endpoint checks.
describe('UI gates go through useCan/can', () => {
  const SRC = join(__dirname, '..')
  const files: string[] = []
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name)
      if (statSync(p).isDirectory()) walk(p)
      else if (/\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name)) files.push(p)
    }
  }
  walk(SRC)

  // Object-level rules that mirror an inline server check, not a role gate.
  const ALLOWED: Record<string, RegExp> = {
    // DELETE /comments/{id}: server allows the author or an admin.
    'components/CommentsSection.tsx': /currentUser\.role === 'admin' \|\| c\.author_id === currentUser\.id/,
  }

  it('no raw role comparisons or generic write-role hooks', () => {
    const offenders: string[] = []
    for (const f of files) {
      const rel = relative(SRC, f)
      if (rel === 'lib/permissions.ts' || rel === 'hooks/useRole.ts') continue
      const text = readFileSync(f, 'utf8').replace(ALLOWED[rel] ?? /$^/, '')
      if (/\brole\s*[!=]==?\s*'(admin|compliance_manager|assessor|system_owner|evidence_contributor|auditor)'/.test(text) || /\b(useCanWrite|useMinRole|useIsAdmin|useIsRole|WRITE_ROLES)\b/.test(text)) {
        offenders.push(rel)
      }
    }
    expect(offenders).toEqual([])
  })
})
