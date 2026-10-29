/**
 * Journey 16 — the Dashboard's "Avg compliance %" means something.
 * It used to average every system × framework pair, including frameworks nobody had
 * started, so the demo trend sat near 2–3%. Now every average (trend points, Portfolio)
 * is over the pairs with work (an assessed control or an open finding: the same pairs the
 * "Compliance Scores by System × Framework" chart shows), and the page says how many.
 */
import { test, expect, apiLogin, api, settle } from './fixtures'

type Pair = { score_percentage: number; has_work: boolean }
type Point = { avg_score: number | null; active_pairs: number }

test('the trend averages the active pairs and says how many', async ({ page }) => {
  await apiLogin(page, 'admin')
  const pairs = (await (await api(page, 'GET', '/api/dashboard/compliance')).json()) as Pair[]
  const worked = pairs.filter(p => p.has_work)
  expect(worked.length).toBeGreaterThan(0)
  expect(worked.length).toBeLessThan(pairs.length) // the demo has frameworks nobody started
  const mean = Math.round(worked.reduce((s, p) => s + p.score_percentage, 0) / worked.length * 10) / 10

  const hist = (await (await api(page, 'GET', '/api/dashboard/history')).json()) as Point[]
  const now = hist[hist.length - 1]
  expect(now.active_pairs).toBe(worked.length)
  expect(now.avg_score).toBe(mean)
  expect(now.avg_score!).toBeGreaterThan(20) // not pinned near 0% by untouched frameworks
  expect(hist.every(p => p.active_pairs > 0 && p.avg_score !== null)).toBe(true)

  await page.goto('/')
  await settle(page)
  const card = page.locator('div').filter({ has: page.getByRole('heading', { name: 'Compliance Trend' }) }).last()
  await expect(card).toContainText(
    `Avg compliance % is the mean score across ${worked.length} active system × framework pairs`)
  // The tooltip on today's point says the same.
  const axis = (await card.locator('.recharts-xAxis .recharts-cartesian-axis-line').boundingBox())!
  await page.mouse.move(axis.x + axis.width - 2, axis.y - 40)
  await expect(card.locator('.recharts-tooltip-wrapper'))
    .toContainText(`${mean}% across ${worked.length} active system × framework pairs`)
})

test('Portfolio shows each company\'s average with its active pair count', async ({ page }) => {
  await apiLogin(page, 'operator')
  const { companies } = (await (await api(page, 'GET', '/api/orgs/portfolio')).json()) as
    { companies: { name: string; avg_score: number | null; active_pairs: number }[] }
  const acme = companies.find(c => c.name === 'Acme Industrial Corp')!
  expect(acme.active_pairs).toBeGreaterThan(0)
  await page.goto('/portfolio')
  await settle(page)
  const row = page.getByRole('row').filter({ hasText: 'Acme Industrial Corp' })
  await expect(row).toContainText(`${acme.avg_score}%`)
  await expect(row).toContainText(`across ${acme.active_pairs} active system × framework pair`)
})
