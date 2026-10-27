/**
 * Journey 6 — operations pages: ConMon cadence, Calendar, Inspection Prep (score, punch list,
 * print, CSV), Risk Register, Red Team (attack chains), Threat Advisories (mock feed),
 * Assets (IT/OT) and Topology export.
 */
import { test, expect, apiLogin, api, labelled, settle, uniq, shot, downloadBytes } from './fixtures'
import { parseCsv } from './zip'

async function openConMonPanel(page: import('@playwright/test').Page) {
  await page.getByRole('button', { name: 'Log Activity' }).click()
  return page.locator('aside').filter({ has: page.getByRole('heading', { name: 'Log ConMon Activity' }) })
}
/** Org-wide cadences currently overdue/never logged, as activity_type values (e.g. ACCOUNT_REVIEW). */
async function orgWideOverdue(page: import('@playwright/test').Page): Promise<string[]> {
  const text = await page.locator('main').innerText()
  return [...text.matchAll(/Org-wide · ([A-Z ]+?) —/gi)].map(m => m[1].trim().toUpperCase().replace(/ /g, '_'))
}
const cadenceOverdue = async (page: import('@playwright/test').Page) =>
  Number((await page.locator('main').innerText()).match(/Cadence Overdue \((\d+)\)/i)![1])
/** Overdue cadences of one activity type in ANY scope (org-wide + each framework). An
 *  org-wide log entry satisfies all of them, so that is exactly how far the count drops. */
const overdueOfType = async (page: import('@playwright/test').Page, type: string) =>
  [...(await page.locator('main').innerText()).matchAll(new RegExp(`· ${type.replace(/_/g, ' ')} —`, 'gi'))].length

test('ConMon: log an activity with only the required fields', async ({ page }) => {
  await apiLogin(page, 'manager')
  await page.goto('/conmon')
  await settle(page)
  const panel = await openConMonPanel(page)
  await labelled(panel, 'System').selectOption({ index: 1 })
  await labelled(panel, 'Activity Type').selectOption('LOG_REVIEW')
  await labelled(panel, 'Description').fill('Weekly SIEM log review — nothing anomalous.')
  await panel.getByRole('button', { name: 'Log Activity' }).click()
  await expect(panel).toHaveCount(0, { timeout: 5000 }).catch(async e => { await shot(page, 'conmon-422-object-object'); throw e })
})

test('ConMon: logging an activity (all fields) clears its org-wide overdue cadence', async ({ page, watcher }) => {
  await apiLogin(page, 'manager')
  await page.goto('/conmon')
  await settle(page)
  const before = await cadenceOverdue(page)
  const pending = await orgWideOverdue(page)
  test.skip(pending.length === 0, 'no org-wide cadence left overdue on this instance')
  const type = pending[0]
  const cleared = await overdueOfType(page, type)
  expect(cleared).toBeGreaterThanOrEqual(1)

  const panel = await openConMonPanel(page)
  await labelled(panel, 'System').selectOption({ index: 1 })
  await labelled(panel, 'Activity Type').selectOption(type)
  await labelled(panel, 'Description').fill('Restored nightly backup to a scratch host and verified checksums.')
  // filled only because blank optional fields are rejected (E2E-CONMON-422)
  await labelled(panel, 'Performed By').fill('Ops on-call')
  await labelled(panel, 'Findings').fill('None')
  await labelled(panel, 'Actions Taken').fill('None required')
  await panel.getByRole('button', { name: 'Log Activity' }).click()
  await expect(panel).toHaveCount(0)
  await expect(page.locator('main tbody')).toContainText('Restored nightly backup')
  // (reload: the banner itself does not refresh — E2E-CONMON-STALE, asserted below)
  await page.reload()
  await settle(page)
  expect(await cadenceOverdue(page)).toBe(before - cleared)
  expect(await orgWideOverdue(page)).not.toContain(type)
  expect(await overdueOfType(page, type)).toBe(0)

  await page.getByRole('button', { name: /Cadence Requirements/ }).click()
  await expect(page.locator('main')).toContainText(new RegExp(type.replace(/_/g, '.'), 'i'))
  expect(watcher.failedResponses).toEqual([])
})

test('ConMon: the Cadence Overdue banner updates right after logging (no reload)', async ({ page }) => {
  await apiLogin(page, 'manager')
  await page.goto('/conmon')
  await settle(page)
  const before = await cadenceOverdue(page)
  const pending = await orgWideOverdue(page)
  test.skip(pending.length === 0, 'no org-wide cadence left overdue on this instance')
  const cleared = await overdueOfType(page, pending[0])
  const panel = await openConMonPanel(page)
  await labelled(panel, 'System').selectOption({ index: 1 })
  await labelled(panel, 'Activity Type').selectOption(pending[0])
  await labelled(panel, 'Description').fill('Annual security awareness training completed.')
  await labelled(panel, 'Performed By').fill('HR')
  await labelled(panel, 'Findings').fill('None')
  await labelled(panel, 'Actions Taken').fill('None')
  await panel.getByRole('button', { name: 'Log Activity' }).click()
  await expect(panel).toHaveCount(0)
  await expect.poll(() => cadenceOverdue(page), { timeout: 5000 }).toBe(before - cleared)
})

test('ConMon: a framework-specific cadence (PCI DSS · VULNERABILITY SCAN) can be satisfied from the UI', async ({ page }) => {
  await apiLogin(page, 'manager')
  await page.goto('/conmon')
  await settle(page)
  const banner = page.locator('main').getByText(/PCI DSS[^·]*· VULNERABILITY SCAN — /)
  await expect(banner, 'demo data: PCI DSS vulnerability-scan cadence is overdue').toBeVisible()
  const panel = await openConMonPanel(page)
  const fw = labelled(panel, 'Framework')
  await expect(fw).toBeVisible({ timeout: 3000 }).catch(async e => { await shot(page, 'conmon-no-framework-field'); throw e })
  await fw.selectOption({ label: 'PCI DSS v4.0' })
  await labelled(panel, 'System').selectOption({ index: 1 })
  await labelled(panel, 'Activity Type').selectOption('VULNERABILITY_SCAN')
  await labelled(panel, 'Description').fill('Quarterly ASV external scan — passing.')
  await panel.getByRole('button', { name: 'Log Activity' }).click()
  await expect(panel).toHaveCount(0)
  // The framework cadence clears without a reload.
  await expect(banner).toHaveCount(0)
})

test('Calendar: add an event; it shows on the right day; delete it', async ({ page, watcher }) => {
  await apiLogin(page, 'manager')
  await page.goto('/calendar')
  await settle(page)
  const title = uniq('E2E audit kickoff')
  await page.getByRole('button', { name: 'Add Event' }).click()
  const form = page.locator('main form')
  await labelled(form, 'Title').fill(title)
  await labelled(form, 'Date').fill('2026-12-15')
  await labelled(form, 'Type').selectOption('ASSESSMENT')
  await form.getByRole('button', { name: 'Create' }).click()
  const item = page.locator('main div.p-3').filter({ hasText: title })
  await expect(item).toBeVisible()
  await expect(item).toContainText('Dec')
  await expect(item).toContainText('15')
  await item.getByRole('button').click()
  await expect(page.locator('main').getByText(title)).toHaveCount(0)
  expect(watcher.failedResponses).toEqual([])
})

test.describe('Calendar west of UTC', () => {
  test.use({ timezoneId: 'America/Los_Angeles' })
  test('an event on Dec 15 is shown on Dec 15 (not Dec 14)', async ({ page }) => {
    await apiLogin(page, 'manager')
    const title = uniq('E2E LA event')
    const r = await api(page, 'POST', '/api/calendar', { title, event_date: '2026-12-15', event_type: 'DEADLINE' })
    expect(r.status()).toBe(200)
    await page.goto('/calendar')
    await settle(page)
    const item = page.locator('main div.p-3').filter({ hasText: title })
    await expect(item).toBeVisible()
    const text = await item.innerText()
    if (!/\b15\b/.test(text)) await shot(page, 'calendar-off-by-one-LA')
    expect(text).toMatch(/\b15\b/)
  })
})

test('Inspection Prep: score, punch list, print and CSV', async ({ page, watcher }) => {
  await apiLogin(page, 'manager')
  await page.goto('/inspection')
  await settle(page)
  const selects = page.locator('main select')
  await selects.nth(0).selectOption({ label: 'NIST 800-53r5' })
  await selects.nth(1).selectOption({ label: 'ERP — Enterprise Resource Planning' })
  await settle(page)
  const score = page.locator('main').getByText(/^\d+%$/).first()
  await expect(score).toBeVisible()
  await expect(page.locator('main')).toContainText(/\d+ punch-list items? · \d+ control famil(y|ies)/)
  // Counts are pluralized correctly everywhere on the page (the timeline used to say "1 items").
  await expect(page.locator('main')).not.toContainText(/(?<!\d)1 (items|controls|control families|punch-list items)\b/)

  // CORP × 800-53 with an inspection ~75 days out has exactly one item in the
  // final window: it must read "1 item", not "1 items".
  const corp = await selects.nth(1).locator('option', { hasText: /^CORP/ }).getAttribute('value')
  await selects.nth(1).selectOption(corp!)
  const d = new Date(Date.now() + 75 * 864e5).toISOString().slice(0, 10)
  await page.locator('main input[type="date"]').fill(d)
  await page.locator('main input[type="date"]').blur()
  await settle(page)
  const lastWindow = page.locator('main').locator('div.border', { hasText: 'T-30 to inspection' }).first()
  await expect(lastWindow).toContainText(/(?<!\d)1 item(?!s)/)
  await expect(page.locator('main')).not.toContainText(/(?<!\d)1 items\b/)
  await selects.nth(1).selectOption({ label: 'ERP — Enterprise Resource Planning' })
  await page.locator('main input[type="date"]').fill('')
  await page.locator('main input[type="date"]').blur()
  await settle(page)

  // Print → window.print() is invoked (stubbed so the test does not block).
  await page.evaluate(() => { (window as unknown as { __printed: number }).__printed = 0; window.print = () => { (window as unknown as { __printed: number }).__printed++ } })
  await page.getByRole('button', { name: 'Print' }).click()
  expect(await page.evaluate(() => (window as unknown as { __printed: number }).__printed)).toBe(1)

  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('link', { name: 'Punch list CSV' }).click()])
  const rows = parseCsv((await downloadBytes(dl)).toString('utf8'))
  expect(rows.length, 'CSV has a header + rows').toBeGreaterThan(1)
  expect(rows[0].join(',').toLowerCase()).toMatch(/control/)
  const width = rows[0].length
  for (const r of rows.slice(1).filter(r => r.length > 1)) expect(r.length).toBe(width)
  expect(watcher.failedResponses).toEqual([])
})

test('Risk Register: add a risk; counts and matrix update', async ({ page, watcher }) => {
  await apiLogin(page, 'manager')
  await page.goto('/risks')
  await settle(page)
  const total = async () => Number((await page.locator('main').innerText()).match(/Total\s*(\d+)/i)![1])
  const before = await total()
  await page.getByRole('button', { name: 'Add Risk' }).click()
  const panel = page.locator('aside').filter({ has: page.getByRole('heading', { name: 'Add Risk Entry' }) })
  const title = uniq('E2E vendor remote access risk')
  await labelled(panel, 'Title').fill(title)
  await panel.getByRole('button', { name: 'Create Risk' }).click()
  await expect(page.locator('main')).toContainText(title)
  await expect.poll(total).toBe(before + 1)
  expect(watcher.failedResponses).toEqual([])
})

test('Red Team: latest report renders attack chains', async ({ page, watcher }) => {
  await apiLogin(page, 'admin')
  await page.goto('/red-team')
  await settle(page)
  const chainsTab = page.getByRole('button', { name: /^Attack Chains \(\d+\)$/ })
  await expect(chainsTab).toBeVisible()
  const n = Number((await chainsTab.innerText()).match(/\((\d+)\)/)![1])
  expect(n).toBeGreaterThan(0)
  await chainsTab.click()
  await expect(page.locator('main')).toContainText(/combined/)
  await expect(page.locator('main')).toContainText(/\d+ findings/)
  // Run a fresh analysis for SCADA × NIST 800-82r3
  const selects = page.locator('main select')
  await selects.nth(0).selectOption({ label: 'Plant Floor SCADA (SCADA)' })
  await selects.nth(1).selectOption({ label: 'NIST 800-82r3' })
  const resp = page.waitForResponse(r => r.url().includes('/api/redteam/analyze/'))
  await page.getByRole('button', { name: 'Run Analysis' }).click()
  expect((await resp).status()).toBe(200)
  await settle(page)
  await expect(page.getByRole('button', { name: /^All Findings \(\d+\)$/ })).toBeVisible()
  expect(watcher.failedResponses).toEqual([])
})

test('Red Team: chain and company exposure are model-based estimates, never above the report/cap (INTEGRITY-22)', async ({ page }) => {
  await apiLogin(page, 'admin')
  type Chain = { id: string; estimated_exposure_low?: number; estimated_exposure_high?: number }
  type Report = { id: number; total_exposure_high: number; attack_chains: Chain[] }
  const reports: Report[] = await (await api(page, 'GET', '/api/redteam')).json()
  const withChains = reports.filter(r => r.attack_chains.length > 0)
  expect(withChains.length).toBeGreaterThan(0)
  for (const r of withChains) {
    for (const c of r.attack_chains) {
      expect(c.estimated_exposure_high, `report ${r.id} ${c.id} has a server-side estimate`).toBeDefined()
      expect(c.estimated_exposure_high!, `report ${r.id} ${c.id} ≤ report total`).toBeLessThanOrEqual(r.total_exposure_high)
      expect(c.estimated_exposure_low!).toBeLessThanOrEqual(c.estimated_exposure_high!)
    }
  }
  const ctx = (await (await api(page, 'GET', '/api/redteam/risk-context')).json()).risk_context
  const summary = await (await api(page, 'GET', '/api/redteam/exposure-summary')).json()
  expect(summary.is_estimate).toBe(true)
  if (ctx.annual_revenue) expect(summary.total_exposure_high).toBeLessThanOrEqual(Math.round(1.5 * ctx.annual_revenue))
  expect(summary.top5_reduction_high).toBeLessThanOrEqual(summary.total_exposure_high)
  await page.goto('/red-team')
  await settle(page)
  await page.getByRole('button', { name: /^Attack Chains \(\d+\)$/ }).click()
  await expect(page.locator('main')).toContainText(/est\. \$[\d.]+[MK]?–\$[\d.]+[MK]? combined/)
})

test('Threat Advisories: sample feed refresh, filter, open detail (labelled sample data)', async ({ page, watcher }) => {
  await apiLogin(page, 'admin')
  await page.goto('/advisories')
  await settle(page)
  await expect(page.locator('main')).toContainText(/demo fixtures \(sample data, fictional vendors\)/i)
  const resp = page.waitForResponse(r => r.url().includes('/api/advisories/refresh'))
  await page.getByRole('button', { name: 'Refresh feeds' }).click()
  expect((await resp).status()).toBe(200)
  await settle(page)
  await page.getByRole('combobox', { name: 'Source' }).selectOption('MOCK')
  await expect(page.locator('main')).toContainText(/\d+ of \d+ shown/)
  const first = page.locator('main').getByRole('button', { name: /^DEMO-ICSA-/ }).first()
  await first.click()
  const panel = page.locator('aside, [role=dialog]').last()
  await expect(panel).toContainText(/DEMO-ICSA-/)
  await expect(panel).toContainText('Sample data')
  await expect(panel).toContainText('It is not a real advisory')
  // Sample items never link out to a real advisory site.
  await expect(panel.getByRole('link', { name: /Source advisory/ })).toHaveCount(0)
  expect(watcher.failedResponses).toEqual([])
})

test('Assets: IT/OT filter and Topology SVG export', async ({ page, watcher }) => {
  await apiLogin(page, 'admin')
  await page.goto('/assets')
  await settle(page)
  const typeFilter = page.locator('main select').first()
  await typeFilter.selectOption('OT')
  const otRows = page.locator('main tbody tr')
  await expect(otRows.first()).toBeVisible()
  for (const t of await otRows.locator('td:first-child').allInnerTexts()) expect(t.trim()).toBe('OT')
  await typeFilter.selectOption('IT')
  for (const t of await otRows.locator('td:first-child').allInnerTexts()) expect(t.trim()).toBe('IT')

  await page.goto('/topology')
  await settle(page)
  await expect(page.locator('main')).toContainText(/\d+ assets · \d+ connections/)
  for (const view of ['Enterprise', 'Purdue (OT)']) {
    await page.getByRole('button', { name: view, exact: true }).click()
    const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'SVG' }).click()])
    const svg = (await downloadBytes(dl)).toString('utf8')
    expect(dl.suggestedFilename()).toMatch(/^topology-.*\.svg$/)
    expect(svg).toMatch(/^<\?xml/)
    expect(svg).toContain('<svg')
    expect(svg.length).toBeGreaterThan(500)
  }
  expect(watcher.failedResponses).toEqual([])
})
