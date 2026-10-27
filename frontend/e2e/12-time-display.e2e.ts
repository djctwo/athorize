/**
 * Journey 12 — time display across browser timezones. Something created "now" must read
 * as just now in every timezone, and absolute times must match the browser's wall clock.
 *
 * The API serialises naive UTC datetimes without an offset ("2026-10-21T18:36:59"), which
 * JavaScript parses as LOCAL time — east of UTC everything looks hours old, west of UTC it is "in the future" (shown as a
 * full date). E2E-TZ.
 */
import { test, expect, apiLogin, api, settle, uniq, shot } from './fixtures'
import type { Page } from '@playwright/test'

const ZONES = ['Europe/Berlin', 'America/Los_Angeles'] as const

async function freshFindingWithComment(page: Page) {
  const systems = await (await api(page, 'GET', '/api/systems')).json()
  const title = uniq('E2E tz finding')
  const created = await api(page, 'POST', '/api/findings', {
    system_id: systems[0].id, framework_id: 'nist-800-53-r5', control_id: 'AC-2', title, severity: 'LOW',
  })
  expect(created.status()).toBe(200)
  const f = await created.json()
  const c = await api(page, 'POST', '/api/comments', { entity_type: 'finding', entity_id: f.id, body: 'tz probe' })
  expect(c.status()).toBe(200)
  return { id: f.id as number, title }
}

/** "12s ago" / "3m ago" are fine for something created seconds ago. */
const JUST_NOW = /^(\d{1,2}s ago|[0-4]m ago|just now)$/

for (const timezoneId of ZONES) {
  test.describe(`browser timezone ${timezoneId}`, () => {
    test.use({ timezoneId })

    test('a comment posted seconds ago reads as "just now"', async ({ page }) => {
      await apiLogin(page, 'admin')
      const f = await freshFindingWithComment(page)
      await page.goto(`/findings?focus=${f.id}`)
      await settle(page)
      const panel = page.locator('aside').filter({ has: page.getByRole('heading', { name: f.title }) })
      const item = panel.locator('ol li').filter({ hasText: 'tz probe' })
      await item.scrollIntoViewIfNeeded()
      const when = (await item.locator('span.text-\\[11px\\]').nth(1).innerText()).trim()
      test.info().annotations.push({ type: 'shown', description: when })
      if (!JUST_NOW.test(when)) await shot(page, `tz-comment-${timezoneId.replace('/', '-')}`)
      expect(when, `comment age shown in ${timezoneId}`).toMatch(JUST_NOW)
    })

    test('the finding audit trail entry for a just-created finding reads as recent', async ({ page }) => {
      await apiLogin(page, 'admin')
      const f = await freshFindingWithComment(page)
      await page.goto(`/findings?focus=${f.id}`)
      await settle(page)
      const panel = page.locator('aside').filter({ has: page.getByRole('heading', { name: f.title }) })
      const trail = panel.locator('section').filter({ has: page.getByText('Activity', { exact: true }) })
      const times = await trail.locator('span.ml-auto').allInnerTexts()
      expect(times.length, 'activity entries rendered').toBeGreaterThan(0)
      test.info().annotations.push({ type: 'shown', description: times[0] })
      await trail.scrollIntoViewIfNeeded()
      if (!JUST_NOW.test(times[0].trim())) await shot(page, `tz-activity-${timezoneId.replace('/', '-')}`)
      expect(times[0].trim(), `activity age in ${timezoneId}`).toMatch(JUST_NOW)
    })

    test('Settings → Last Login shows the browser-local time of this login', async ({ page }) => {
      await apiLogin(page, 'admin')
      await page.goto('/settings')
      await settle(page)
      const shown = await page.locator('main').getByText('Last Login:').locator('xpath=..').innerText()
      const value = shown.replace(/^Last Login:\s*/, '').trim()
      const parsedShown = await page.evaluate(v => new Date(v).getTime(), value)
      const browserNow = await page.evaluate(() => Date.now())
      const driftMin = Math.abs(browserNow - parsedShown) / 60000
      test.info().annotations.push({ type: 'shown', description: `${value} (drift ${driftMin.toFixed(0)} min)` })
      if (driftMin > 5) await shot(page, `tz-last-login-${timezoneId.replace('/', '-')}`)
      expect(driftMin, `"${value}" vs browser now in ${timezoneId}`).toBeLessThan(5)
    })
  })
}

test('API timestamps carry a timezone designator', async ({ page }) => {
  await apiLogin(page, 'admin')
  const me = await (await api(page, 'GET', '/api/auth/me')).json()
  expect(me.last_login).toMatch(/(Z|[+-]\d\d:\d\d)$/)
})
