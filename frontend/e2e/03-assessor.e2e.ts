/**
 * Journey 3 — assessing controls. The assessor role (demo user `analyst`) is the role the
 * server authorises for `assess:control` (admin + assessor). The journey: open Controls
 * for a system + framework, assess one control (status + narrative), bulk edit several,
 * scope to a baseline, see crosswalk chips, and accept a Crosswalk Review suggestion.
 */
import { test, expect, apiLogin, api, settle, uniq, shot, toast, type Watcher } from './fixtures'
import type { Page } from '@playwright/test'

const FW = 'nist-800-53-r5'
const FW_NAME = 'NIST Special Publication 800-53 Revision 5'

async function newSystem(page: Page, prefix: string) {
  const name = uniq(prefix)
  const res = await api(page, 'POST', '/api/systems', { name, acronym: name.slice(0, 14).toUpperCase() })
  expect(res.status()).toBe(200)
  return (await res.json()) as { id: number; name: string; acronym: string }
}

async function openGrid(page: Page, sys: { id: number; acronym: string; name: string }) {
  await page.goto('/controls')
  await settle(page)
  const selects = page.locator('main select')
  await selects.nth(0).selectOption({ label: FW_NAME })
  await selects.nth(1).selectOption({ label: `${sys.acronym} — ${sys.name}` })
  await expect(page.getByRole('heading', { name: 'Assess Controls' })).toBeVisible()
  await settle(page)
}

function controlRow(page: Page, id: string) {
  return page.locator('main .divide-y > div').filter({ has: page.locator('span.font-mono', { hasText: new RegExp(`^${id}$`) }) })
}

async function impls(page: Page, systemId: number) {
  const r = await api(page, 'GET', `/api/controls/systems/${systemId}?framework_id=${FW}`)
  expect(r.status()).toBe(200)
  const list = (await r.json()) as { control_id: string; implementation_status: string; narrative?: string }[]
  return Object.fromEntries(list.map(i => [i.control_id, i]))
}

test.describe('assessor (analyst) can do the assessor job', () => {
  test('analyst is offered the control status editor', async ({ page }) => {
    await apiLogin(page, 'admin')
    const sys = await newSystem(page, 'E2E-ANALYST')
    await apiLogin(page, 'analyst')
    await openGrid(page, sys)
    const row = controlRow(page, 'AC-2')
    const statusSelect = row.locator('select')
    if (!(await statusSelect.count())) await shot(page, 'assessor-readonly-controls')
    await expect(statusSelect).toBeVisible()
    await row.getByRole('button').first().click()
    await expect(page.getByRole('button', { name: 'Save implementation' })).toBeVisible()
    await expect(page.getByRole('button', { name: /Scope to baseline/ })).toBeVisible()
  })

  test('analyst can bulk-select controls', async ({ page }) => {
    await apiLogin(page, 'admin')
    const sys = await newSystem(page, 'E2E-ANALYST-B')
    await apiLogin(page, 'analyst')
    await openGrid(page, sys)
    await expect(page.getByRole('checkbox', { name: 'Select AC-2', exact: true })).toBeVisible()
  })
})

test('compliance manager is not offered assessment edits the server refuses', async ({ page, watcher }) => {
  await apiLogin(page, 'admin')
  const sys = await newSystem(page, 'E2E-MGR')
  await apiLogin(page, 'manager')
  await openGrid(page, sys)
  const sel = controlRow(page, 'AC-3').locator('select')
  if (await sel.count()) {
    watcher.reset()
    await sel.selectOption('IMPLEMENTED')
    await settle(page)
    const refused = watcher.failedResponses.filter(r => r.status === 403)
    if (refused.length) await shot(page, 'manager-assess-403')
    expect(refused, 'UI offered an edit the server refused').toEqual([])
  }
})

test.describe('assessment workflow (as admin, who holds assess:control)', () => {
  test('assess one control, bulk edit, scope to baseline, crosswalk chips', async ({ page, watcher }) => {
    await apiLogin(page, 'admin')
    const sys = await newSystem(page, 'E2E-ASSESS')
    await openGrid(page, sys)

    // --- single control: status + narrative
    const row = controlRow(page, 'AC-2')
    await row.getByRole('button').first().click()
    const editor = page.locator('main').filter({ hasText: 'Implementation' }).locator('div.mt-3.p-3')
    await editor.locator('select').first().selectOption('IMPLEMENTED')
    const narrative = `E2E narrative ${Date.now()} — accounts reviewed quarterly by IAM team.`
    await editor.locator('textarea').fill(narrative)
    await editor.locator('input[placeholder="Responsible party (team)"]').fill('IAM Team')
    await editor.getByRole('button', { name: 'Save implementation' }).click()
    await expect(toast(page)).toContainText('Saved')
    await expect(row.locator('select').first()).toHaveValue('IMPLEMENTED')

    // crosswalk chips render for the expanded control
    await expect(page.locator('main')).toContainText(/Crosswalk — satisfies toward \d+ other framework/)

    // persisted after reload
    await page.reload()
    await settle(page)
    let state = await impls(page, sys.id)
    expect(state['AC-2']?.implementation_status).toBe('IMPLEMENTED')
    expect(state['AC-2']?.narrative).toBe(narrative)

    // --- bulk edit three controls
    await openGrid(page, sys)
    for (const id of ['AC-3', 'AC-4', 'AC-5']) await page.getByRole('checkbox', { name: `Select ${id}` }).check()
    await page.getByRole('button', { name: 'Set status…' }).click()
    const bulkPanel = page.locator('aside').filter({ hasText: 'Set implementation status' })
    await bulkPanel.locator('select').selectOption('PARTIALLY')
    await bulkPanel.getByRole('button', { name: 'Apply to 3' }).click()
    await expect(toast(page)).toContainText('Updated 3 control(s)')
    state = await impls(page, sys.id)
    for (const id of ['AC-3', 'AC-4', 'AC-5']) expect(state[id]?.implementation_status, id).toBe('PARTIALLY')

    // --- scope to a baseline
    await page.getByRole('button', { name: /Scope to baseline/ }).click()
    const scope = page.locator('aside').filter({ hasText: 'Scope to a baseline' })
    const baselines = await scope.locator('select option').allTextContents()
    expect(baselines.length).toBeGreaterThan(0)
    const pick = baselines.find(b => /low/i.test(b)) ?? baselines[0]
    await scope.locator('select').selectOption(pick)
    await scope.getByRole('button', { name: 'Apply scope' }).click()
    await expect(toast(page)).toContainText(/Scoped: \d+ in scope, \d+ marked N\/A/)
    state = await impls(page, sys.id)
    // assessed work is never overwritten by scoping
    expect(state['AC-2'].implementation_status).toBe('IMPLEMENTED')
    expect(Object.values(state).some(i => i.implementation_status === 'NOT_APPLICABLE')).toBe(true)
    expectNoUnexpectedFailures(watcher)
  })

  test('Crosswalk Review: accept one suggestion as Planned (as analyst)', async ({ page, watcher }) => {
    await apiLogin(page, 'admin')
    const sys = await newSystem(page, 'E2E-XW')
    // seed one implemented 800-53 control so the crosswalk has something to propose
    const put = await api(page, 'PUT', `/api/controls/systems/${sys.id}/${FW}/AC-2`, { implementation_status: 'IMPLEMENTED', narrative: 'Seeded for crosswalk review.' })
    expect(put.status()).toBe(200)

    await apiLogin(page, 'analyst')
    await page.goto('/crosswalk')
    await settle(page)
    await page.locator('main select').selectOption({ label: `${sys.acronym} — ${sys.name}` })
    await settle(page)
    await expect(page.locator('main')).toContainText(/[1-9]\d* suggestions? across \d+ framework/)
    const firstRow = page.locator('main tbody tr').first()
    const controlId = (await firstRow.locator('span.font-mono').first().innerText()).trim()
    await firstRow.getByRole('button', { name: 'Accept as Planned' }).click()
    await expect(toast(page)).toContainText(`${controlId}`)
    await expect(toast(page)).toContainText('created as PLANNED')
    expectNoUnexpectedFailures(watcher)
  })
})

function expectNoUnexpectedFailures(w: Watcher) {
  expect.soft(w.pageErrors).toEqual([])
  expect.soft(w.failedResponses).toEqual([])
  expect.soft(w.reactWarnings).toEqual([])
}
