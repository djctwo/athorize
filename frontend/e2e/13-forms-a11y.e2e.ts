/**
 * Small, high-leverage accessibility checks that also decide whether the UI can be driven
 * by role-based locators (and screen readers): form labels bound to their inputs, and
 * confirmation dialogs exposed as dialogs; plus control lists in natural order.
 */
import { test, expect, apiLogin, settle, shot } from './fixtures'

test('login fields are reachable by their labels', async ({ browser }) => {
  const ctx = await browser.newContext()
  const page = await ctx.newPage()
  await page.goto('/')
  await expect(page.getByLabel('Username')).toBeVisible({ timeout: 3000 })
  await expect(page.getByLabel('Password')).toBeVisible({ timeout: 3000 })
  await ctx.close()
})

test('confirmation dialogs are exposed as dialogs', async ({ page }) => {
  await apiLogin(page, 'admin')
  await page.goto('/users')
  await settle(page)
  await page.locator('main tbody tr').filter({ has: page.locator('td:first-child', { hasText: /^auditor$/ }) }).getByTitle('Deactivate').click()
  await expect(page.getByRole('heading', { name: 'Deactivate User' })).toBeVisible()
  try {
    await expect(page.getByRole('dialog', { name: 'Deactivate User' })).toBeVisible({ timeout: 3000 })
  } finally {
    await page.keyboard.press('Escape') // never actually deactivate the demo auditor
  }
})

test('Controls are listed in natural order (AC-2 before AC-10)', async ({ page }) => {
  await apiLogin(page, 'admin')
  await page.goto('/controls?framework=nist-800-53-r5')
  await settle(page)
  const ids = await page.locator('main .divide-y > div span.font-mono').allInnerTexts()
  expect(ids.length).toBeGreaterThan(20)
  const i2 = ids.indexOf('AC-2'), i10 = ids.indexOf('AC-10')
  if (i10 < i2) await shot(page, 'controls-lexicographic-order')
  expect(i2).toBeLessThan(i10)
})
