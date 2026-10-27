/**
 * Journey 2 — admin: framework lifecycle in the Marketplace, New System wizard (OT),
 * user administration (each role, role edit, deactivate → cannot log in).
 */
import { test, expect, apiLogin, api, uiLogin, labelled, settle, uniq, shot, toast, confirmDialog } from './fixtures'

const STRONG = 'Quartz-Falcon-73-Mesa'

function frameworkCard(page: import('@playwright/test').Page, name: string) {
  return page.locator('main div.relative').filter({ has: page.getByRole('heading', { level: 4, name, exact: true }) })
}

test.describe('Marketplace', () => {
  test('deactivate then reactivate a framework', async ({ page, watcher }) => {
    const name = 'Gramm-Leach-Bliley Act Safeguards Rule'
    await apiLogin(page, 'admin')
    await page.goto('/marketplace')
    await settle(page)
    const card = frameworkCard(page, name)
    await expect(card.getByRole('button', { name: 'Deactivate' })).toBeVisible()

    await card.getByRole('button', { name: 'Deactivate' }).click()
    await expect(card.getByRole('button', { name: 'Activate' })).toBeVisible()

    // Gone from the Controls framework picker.
    await page.goto('/controls')
    await settle(page)
    await expect(page.locator('main select').first().locator('option', { hasText: name })).toHaveCount(0)

    await page.goto('/marketplace')
    await card.getByRole('button', { name: 'Activate' }).click()
    await expect(card.getByRole('button', { name: 'Deactivate' })).toBeVisible()

    await page.goto('/controls')
    await settle(page)
    await page.locator('main select').first().selectOption({ label: name })
    await expect(page.locator('main')).toContainText(/[1-9]\d* controls/)
    expect(watcher.failedResponses).toEqual([])
  })

  test('deactivating a framework in one company must not wipe it for another company', async ({ page, browser }) => {
    // Northwind Health (org 2) also has HIPAA active in the demo seed.
    const hipaa = 'HIPAA Security Rule'
    await apiLogin(page, 'admin') // Acme
    await page.goto('/marketplace')
    await settle(page)
    const card = frameworkCard(page, hipaa)
    await card.getByRole('button', { name: 'Deactivate' }).click()
    await expect(card.getByRole('button', { name: 'Activate' })).toBeVisible()

    const ctx = await browser.newContext()
    const op = await ctx.newPage()
    try {
      await apiLogin(op, 'operator')
      const sw = await api(op, 'POST', '/api/orgs/switch', { org_id: 2 })
      expect(sw.status()).toBe(200)
      await op.goto('/controls')
      await settle(op)
      await op.locator('main select').first().selectOption({ label: hipaa })
      await settle(op)
      const counter = op.locator('main').getByText(/^\d+ controls$/)
      const txt = await counter.innerText()
      if (txt.startsWith('0 ')) await shot(op, 'xtenant-catalog-northwind-hipaa')
      expect(txt, 'Northwind still has HIPAA active — its catalog must still load').not.toBe('0 controls')
    } finally {
      // restore Acme's activation (reloads the global catalog)
      await page.goto('/marketplace')
      await settle(page)
      await card.getByRole('button', { name: 'Activate' }).click()
      await expect(card.getByRole('button', { name: 'Deactivate' })).toBeVisible()
      await ctx.close()
    }
  })
})

test('New System wizard creates an OT system and lands in its control grid', async ({ page, watcher }) => {
  const name = uniq('Water Treatment PLC Net')
  const acronym = uniq('WTP').slice(0, 12).toUpperCase()
  await apiLogin(page, 'admin')
  await page.goto('/systems')
  await settle(page)
  await page.getByRole('button', { name: 'Guided setup' }).click()
  await expect(page.getByText('New system — step 1 of 2')).toBeVisible()
  await labelled(page, 'Name').fill(name)
  await labelled(page, 'Acronym').fill(acronym)
  await labelled(page, 'Criticality').selectOption('high')
  await page.getByLabel('OT / industrial system').check()
  await page.getByRole('button', { name: 'Next' }).click()
  await expect(page.getByText('New system — step 2 of 2')).toBeVisible()
  await page.getByRole('radio', { name: 'NIST Special Publication 800-82 Revision 3' }).check()
  await page.getByRole('button', { name: 'Create & start assessing' }).click()

  await expect(page).toHaveURL(/\/controls\?system=\d+&framework=nist-800-82-r3/)
  await expect(page.getByRole('heading', { name: 'Assess Controls' })).toBeVisible()
  await expect(page.locator('main')).toContainText(/[1-9]\d* controls/)

  const systems = await (await api(page, 'GET', '/api/systems')).json()
  const created = systems.find((s: { name: string }) => s.name === name)
  expect(created, 'system persisted').toBeTruthy()
  expect(created.is_ot_enabled).toBe(true)
  expect(created.criticality).toBe('high')
  expect(watcher.failedResponses).toEqual([])
})

test.describe('Users', () => {
  const roles = ['admin', 'compliance_manager', 'assessor', 'system_owner', 'evidence_contributor', 'auditor']
  const made: Record<string, string> = {}

  test('admin adds a user with each role, edits a role, deactivates a user who then cannot log in', async ({ page, browser, watcher }) => {
    await apiLogin(page, 'admin')
    await page.goto('/users')
    await settle(page)

    for (const role of roles) {
      const username = uniq(`e2e-${role.split('_')[0]}`)
      made[role] = username
      await page.getByRole('button', { name: 'Add User' }).click()
      const panel = page.locator('aside').filter({ hasText: 'Create User Account' })
      await labelled(panel, 'Username').fill(username)
      await labelled(panel, 'Password').fill(STRONG)
      await labelled(panel, 'Display Name').fill(`E2E ${role}`)
      await labelled(panel, 'Email').fill(`${username}@example.com`)
      await labelled(panel, 'Role').selectOption(role)
      await panel.getByRole('button', { name: 'Create' }).click()
      await expect(toast(page)).toContainText('User created')
      const row = page.locator('main tbody tr').filter({ hasText: username })
      await expect(row).toContainText(role.replace(/_/g, ' '))
      await expect(row).toContainText('Active')
    }

    // Edit: auditor → assessor
    const target = made.auditor
    const row = page.locator('main tbody tr').filter({ hasText: target })
    await row.getByTitle('Edit').click()
    const edit = page.locator('aside').filter({ hasText: `Edit ${target}` })
    await labelled(edit, 'Role').selectOption('assessor')
    await edit.getByRole('button', { name: 'Save' }).click()
    await expect(toast(page)).toContainText('User updated')
    await expect(row).toContainText('assessor')

    // The new user can log in…
    const victim = made.evidence_contributor
    const ctx = await browser.newContext()
    const other = await ctx.newPage()
    await uiLogin(other, victim, STRONG)
    await expect(other.getByRole('heading', { name: 'Compliance Dashboard' })).toBeVisible()

    // …until deactivated.
    const vrow = page.locator('main tbody tr').filter({ hasText: victim })
    await vrow.getByTitle('Deactivate').click()
    await confirmDialog(page, 'Deactivate User').getByRole('button', { name: 'Deactivate', exact: true }).click()
    await expect(vrow).toContainText('Inactive')

    // Existing session is cut off…
    const me = await other.request.get('/api/auth/me')
    expect(me.status(), 'deactivated user\'s live session').toBe(401)
    await ctx.close()

    // …and a fresh login is refused.
    const ctx2 = await browser.newContext()
    const p2 = await ctx2.newPage()
    await uiLogin(p2, victim, STRONG)
    await expect(p2.locator('.text-danger').first()).toBeVisible()
    await expect(p2.getByRole('heading', { name: 'Compliance Dashboard' })).toHaveCount(0)
    await ctx2.close()
    expect(watcher.failedResponses).toEqual([])
  })

  test('creating a user with a too-short password shows a readable error', async ({ page }) => {
    await apiLogin(page, 'admin')
    await page.goto('/users')
    await settle(page)
    await page.getByRole('button', { name: 'Add User' }).click()
    const panel = page.locator('aside').filter({ hasText: 'Create User Account' })
    await labelled(panel, 'Username').fill(uniq('shortpw'))
    await labelled(panel, 'Password').fill('Ab1!')
    await panel.getByRole('button', { name: 'Create' }).click()
    await expect(toast(page)).not.toBeEmpty()
    const t = await toast(page).innerText()
    if (t.includes('object Object')) await shot(page, 'users-short-password-toast')
    expect(t).not.toContain('[object Object]')
  })
})
