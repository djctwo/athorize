/**
 * Journey 10 — role UX. Read-only roles (auditor, system owner) walk every sidebar page:
 * each page renders without errors, and the UI must not offer actions the server will
 * refuse (a button whose only outcome is a 403 toast is a defect).
 *
 * Server truth (backend/services/permissions.py + router dependencies):
 *  - auditor and system_owner hold only read:any. They may create their OWN API tokens,
 *    save personal filter views and comment.
 *  - calendar create = min assessor; advisories refresh/triage = edit:conmon;
 *    users list = admin|compliance_manager; users write = admin only.
 */
import { test, expect, apiLogin, api, SIDEBAR_PAGES, gotoViaSidebar, settle, badTextIn, shot } from './fixtures'

const READ_ONLY_ROLES = ['auditor', 'owner'] as const

/** Buttons a read-only user may legitimately see (navigation, filters, personal prefs, exports). */
const ALLOWED = /^(Save view|Assigned to me|Setup guide|Risk Context|Start Here.*|All Findings.*|Attack Chains.*|Enterprise|Purdue \(OT\)|SVG|PNG|Print|CSV|ZIP|Open|Executive Briefing.*|Report|Cadence Requirements.*|Show|Hide|Sort by.*|Create)$/
/** Names that mean "change data". Settings "Create" (own API token) is allowed and checked separately. */
const WRITE_VERB = /^(Add|New|Import|Upload|Refresh|Log Activity|Guided setup|Edit|Delete|Deactivate|Activate|Mark|Run Analysis|Choose CSV|Preview|Save implementation|Generate|Triage|Dismiss|Spawn|Accept)/i

for (const role of READ_ONLY_ROLES) {
  test.describe(`${role} — read-only walk`, () => {
    for (const { label, path } of SIDEBAR_PAGES) {
      test(`${label} renders and offers no refused actions`, async ({ page, watcher }) => {

        await apiLogin(page, role)
        await page.goto('/')
        await settle(page)
        watcher.reset()
        if (path !== '/') await gotoViaSidebar(page, label)
        await settle(page)

        const main = page.locator('main')
        await expect(main).not.toContainText('Something went wrong')
        expect((await main.innerText()).trim().length, 'page is not blank').toBeGreaterThan(20)
        expect.soft(watcher.pageErrors, 'unhandled errors').toEqual([])
        expect.soft(watcher.realConsoleErrors(), 'console errors').toEqual([])
        expect.soft(await badTextIn(page), 'garbage text').toEqual([])
        expect.soft(watcher.failedResponses, `API calls refused for ${role}`).toEqual([])

        if (path === '/help') return // Help topics are accordion buttons, not actions
        const names = (await main.getByRole('button').evaluateAll(els =>
          els.filter(e => (e as HTMLElement).offsetParent !== null && !(e as HTMLButtonElement).disabled)
            .map(e => (e.getAttribute('aria-label') || e.textContent || '').trim()),
        )).filter(Boolean)
        const offending = names.filter(n => WRITE_VERB.test(n) && !ALLOWED.test(n))
        if (offending.length) await shot(page, `role-${role}${path.replace(/\//g, '_')}`)
        expect(offending, `write actions offered to ${role} on ${path}`).toEqual([])
      })
    }
  })
}

test('server really refuses what the UI offers read-only roles (calendar / advisories)', async ({ page }) => {
  // Proof for E2E-ROLE-CAL / E2E-ROLE-ADV: the buttons lead to 403s.
  await apiLogin(page, 'auditor')
  const cal = await api(page, 'POST', '/api/calendar', { title: 'x', event_date: '2026-12-01', event_type: 'CUSTOM' })
  expect(cal.status()).toBe(403)
  const adv = await api(page, 'POST', '/api/advisories/refresh')
  expect(adv.status()).toBe(403)
  const users = await api(page, 'GET', '/api/users')
  expect(users.status()).toBe(403)
})

test.describe('compliance manager — UI vs server', () => {
  test('Users page: manager is offered Add/Edit/Deactivate but the server only lets admins', async ({ page }) => {
    await apiLogin(page, 'manager')
    await page.goto('/users')
    await settle(page)
    const add = page.locator('main').getByRole('button', { name: 'Add User' })
    if (await add.isVisible()) await shot(page, 'role-manager-users')
    await expect(add).toHaveCount(0)
    await expect(page.locator('main').getByTitle('Deactivate')).toHaveCount(0)
  })

  test('server refuses manager user writes (proof)', async ({ page }) => {
    await apiLogin(page, 'manager')
    const r = await api(page, 'POST', '/api/users', { username: 'mgr-made', password: 'Correct-Horse-9!', role: 'auditor', email: 'x@example.com', display_name: 'x' })
    expect(r.status()).toBe(403)
  })
})

test.describe('Red Team actions vs server permissions', () => {
  test('auditor is not offered "Run Analysis" (server: min assessor)', async ({ page, watcher }) => {
    await apiLogin(page, 'auditor')
    await page.goto('/red-team')
    await settle(page)
    const selects = page.locator('main select')
    await selects.nth(0).selectOption({ index: 1 })
    await selects.nth(1).selectOption({ index: 1 })
    const run = page.getByRole('button', { name: 'Run Analysis' })
    // Not offered = hidden or disabled (the fix hides it; isEnabled() on a missing button would wait forever).
    if (await run.count() && await run.isEnabled()) {
      watcher.reset()
      await run.click()
      await settle(page)
      await shot(page, 'role-auditor-redteam-run')
    }
    expect(watcher.failedResponses.filter(r => r.status === 403), 'refused calls').toEqual([])
    expect(await run.count() === 0 || await run.isDisabled(), 'Run Analysis hidden or disabled').toBe(true)
  })

  test('auditor is not offered "Save Risk Context" (server: min compliance_manager)', async ({ page, watcher }) => {
    await apiLogin(page, 'auditor')
    await page.goto('/red-team')
    await settle(page)
    await page.getByRole('button', { name: 'Risk Context' }).click()
    const save = page.getByRole('button', { name: 'Save Risk Context' })
    if (await save.isVisible()) {
      watcher.reset()
      await save.click()
      await settle(page)
    }
    expect(watcher.failedResponses.filter(r => r.status === 403), 'refused calls').toEqual([])
    await expect(save).toHaveCount(0)
  })
})

test.describe('system scoping (contributor is limited to SCADA)', () => {
  test('Red Team page only shows reports for systems the user can access', async ({ page }) => {
    await apiLogin(page, 'contributor')
    const systems = await (await api(page, 'GET', '/api/systems')).json()
    const allowed = new Set(systems.map((s: { id: number }) => s.id))
    const resp = page.waitForResponse(r => /\/api\/redteam(\?|$)/.test(r.url()))
    await page.goto('/red-team')
    const reports = await (await resp).json()
    await settle(page)
    const foreign = reports.filter((r: { system_id: number }) => !allowed.has(r.system_id)).map((r: { system_id: number; framework_id: string }) => `${r.system_id}:${r.framework_id}`)
    if (foreign.length) await shot(page, 'scope-contributor-redteam')
    expect(foreign, 'reports for systems outside the user\'s scope').toEqual([])
  })

  test('Audit Log only shows entries for systems the user can access', async ({ page }) => {
    await apiLogin(page, 'contributor')
    const systems = await (await api(page, 'GET', '/api/systems')).json()
    const allowed = new Set(systems.map((s: { id: number }) => s.id))
    const resp = page.waitForResponse(r => /\/api\/audit(\?|$)/.test(r.url()))
    await page.goto('/audit')
    const entries = await (await resp).json()
    await settle(page)
    const foreign = entries.filter((e: { system_id: number | null }) => e.system_id != null && !allowed.has(e.system_id))
    if (foreign.length) await shot(page, 'scope-contributor-audit')
    expect(foreign.map((e: { summary: string }) => e.summary).slice(0, 5)).toEqual([])
  })

  test('Inspection Prep refuses a system outside the user\'s scope', async ({ page }) => {
    await apiLogin(page, 'contributor')
    const all = await (await api(page, 'GET', '/api/systems')).json()
    const allowed = new Set(all.map((s: { id: number }) => s.id))
    const outside = [1, 2, 3, 4].find(id => !allowed.has(id))!
    const r = await api(page, 'GET', `/api/inspection/prep?framework_id=nist-800-53-r5&system_ids=${outside}`)
    expect([403, 404]).toContain(r.status())
  })
})
