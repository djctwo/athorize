/**
 * Journey 15 — round-2 W2-UX fixes on the DEMO instance (the blank-instance journey is
 * blank/02-real-user-day). Checks that the fixes hold with a lived-in data set and that the
 * touched panels fit at 1280 px and 390 px:
 *  - R2USER-18: demo systems are backdated, so the never-logged cadences still read overdue
 *  - R2USER-4:  the demo calendar mixes manual events with derived deadlines
 *  - R2USER-12: a demo system owner sees only workable owners in the picker (as admin)
 *  - R2USER-3 / -2: the control editor, calendar and crosswalk pages fit both widths
 */
import type { Page } from '@playwright/test'
import { test, expect, apiLogin, api, settle } from './fixtures'

test('ConMon still shows the demo\'s overdue cadences (systems monitored for over a year)', async ({ page }) => {
  await apiLogin(page, 'manager')
  const snap = await (await api(page, 'GET', '/api/dashboard/snapshot')).json()
  expect(snap.cadence_overdue).toBeGreaterThan(0)
  await page.goto('/conmon')
  await settle(page)
  await expect(page.locator('main')).toContainText(/Cadence Overdue \(\d+\)/)
})

test('the demo calendar shows manual events and derived deadlines side by side', async ({ page }) => {
  await apiLogin(page, 'manager')
  const items = await (await api(page, 'GET', '/api/calendar')).json() as { source: string; event_type: string }[]
  expect(items.some(i => i.source === 'manual')).toBe(true)
  expect(items.some(i => i.source === 'derived' && i.event_type === 'FINDING_DUE')).toBe(true)
  const manualOnly = await (await api(page, 'GET', '/api/calendar?derived=false')).json() as { source: string }[]
  expect(manualOnly.every(i => i.source === 'manual')).toBe(true)
  await page.goto('/calendar')
  await settle(page)
  await expect(page.locator('main [data-source="derived"]').first()).toContainText('Auto')
})

test('the finding owner picker never offers the read-only auditor', async ({ page }) => {
  await apiLogin(page, 'admin')
  const systems = await (await api(page, 'GET', '/api/systems')).json() as { id: number }[]
  const r = await api(page, 'GET', `/api/users/assignable?finding_system_id=${systems[0].id}`)
  expect(r.status()).toBe(200)
  const names = (await r.json() as { username: string }[]).map(u => u.username)
  expect(names).toContain('admin')
  expect(names).not.toContain('auditor')
})

for (const vp of [{ width: 390, height: 844 }, { width: 1280, height: 800 }]) {
  test.describe(`touched pages fit at ${vp.width}px`, () => {
    test.use({ viewport: vp })

    async function noSideScroll(page: Page, what: string) {
      const w = await page.evaluate(() => document.documentElement.scrollWidth)
      expect(w, `${what}: no horizontal page scroll`).toBeLessThanOrEqual(Math.max(vp.width, vp.width < 768 ? vp.width : 1280) + 1)
    }

    test('control editor, calendar, crosswalk review, settings', async ({ page }) => {
      await apiLogin(page, 'analyst')
      await page.goto('/controls')
      await settle(page)
      const selects = page.locator('main select')
      await selects.nth(0).selectOption({ index: 1 })
      await selects.nth(1).selectOption({ index: 1 })
      await expect(page.getByRole('heading', { name: 'Assess Controls' })).toBeVisible()
      await settle(page)
      await page.locator('main .divide-y > div').first().getByRole('button').first().click()
      const narrative = page.getByLabel('Implementation narrative')
      await expect(narrative).toBeVisible()
      const box = (await narrative.boundingBox())!
      expect(box.x).toBeGreaterThanOrEqual(0)
      expect(box.x + box.width).toBeLessThanOrEqual(vp.width + 1)
      await expect(page.getByRole('button', { name: 'Save implementation' })).toBeVisible()
      await noSideScroll(page, 'controls')

      for (const path of ['/calendar', '/crosswalk', '/settings']) {
        await page.goto(path)
        await settle(page)
        await noSideScroll(page, path)
      }
    })
  })
}
