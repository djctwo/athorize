/**
 * Journey 7 — reports. Every download is saved and VALIDATED, not just "a file arrived":
 *  - Executive Briefing PPTX opens as a zip with ppt/slides/slideN.xml and no garbage text
 *  - Assessment report (HTML deliverable) prints to a non-empty PDF
 *  - Audit binder ZIP contains binder.html
 *  - every CSV parses, has a header, rectangular rows, and user data that starts with
 *    = + - @ is neutralised (formula injection)
 */
import { test, expect, apiLogin, api, settle, uniq, shot, downloadBytes, BAD_TEXT } from './fixtures'
import { readZip, parseCsv, isFormulaCell } from './zip'
import type { Page } from '@playwright/test'

test.describe.configure({ mode: 'serial' })

const EVIL_TITLE = `=HYPERLINK("http://example.com/x","${uniq('e2e')}")`
const EVIL_PARTY = `@SUM(1+1)*cmd|' /C calc'!A0`

test.beforeAll(async ({ browser }) => {
  const ctx = await browser.newContext({ baseURL: process.env.E2E_BASE_URL || 'http://127.0.0.1:8042' })
  const page = await ctx.newPage()
  await apiLogin(page, 'admin')
  const systems = await (await api(page, 'GET', '/api/systems')).json()
  const erp = systems.find((s: { acronym: string }) => s.acronym === 'ERP')
  const f = await api(page, 'POST', '/api/findings', {
    system_id: erp.id, framework_id: 'nist-800-53-r5', control_id: 'AC-6', title: EVIL_TITLE,
    description: '+1-555 call me', severity: 'LOW', owner_name: '-Mallory',
  })
  expect(f.status()).toBe(200)
  const impl = await api(page, 'PUT', `/api/controls/systems/${erp.id}/nist-800-53-r5/AC-6`, {
    implementation_status: 'PARTIALLY', narrative: 'least privilege partly enforced', responsible_party: EVIL_PARTY,
  })
  expect(impl.status()).toBe(200)
  await ctx.close()
})

async function openReports(page: Page) {
  await apiLogin(page, 'admin')
  await page.goto('/reports')
  await settle(page)
}

test('Executive Briefing PPTX is a real deck with slides and no garbage text', async ({ page }) => {
  await openReports(page)
  const [dl] = await Promise.all([
    page.waitForEvent('download', { timeout: 60_000 }),
    page.getByRole('button', { name: 'Executive Briefing (PPTX)' }).click(),
  ])
  expect(dl.suggestedFilename()).toMatch(/\.pptx$/)
  const zip = readZip(await downloadBytes(dl))
  expect(zip.has('[Content_Types].xml')).toBe(true)
  expect(zip.has('ppt/presentation.xml')).toBe(true)
  const slides = [...zip.keys()].filter(k => /^ppt\/slides\/slide\d+\.xml$/.test(k))
  expect(slides.length, 'slide count').toBeGreaterThan(0)
  const garbage: string[] = []
  for (const s of slides) {
    const text = [...zip.get(s)!.toString('utf8').matchAll(/<a:t>([^<]*)<\/a:t>/g)].map(m => m[1]).join(' ')
    expect(text.trim().length, `${s} has text`).toBeGreaterThan(0)
    if (BAD_TEXT.test(text)) garbage.push(`${s}: ${text.match(BAD_TEXT)![0]}`)
  }
  expect(garbage).toEqual([])
})

test('Assessment report opens and prints to a non-empty PDF', async ({ page, context }) => {
  await openReports(page)
  const assessmentSelect = page.locator('main select').nth(2)
  await assessmentSelect.selectOption({ label: 'ERP × pci-dss-v4 — PCI-DSS Self-Assessment Q2' })
  const [popup] = await Promise.all([context.waitForEvent('page'), page.getByRole('button', { name: 'Open' }).click()])
  await popup.waitForLoadState('load')
  const body = await popup.locator('body').innerText()
  expect(body).toMatch(/PCI-DSS Self-Assessment Q2/)
  expect(body).toMatch(/sign/i)
  expect(body.match(BAD_TEXT), 'garbage text in the report').toBeNull()
  await popup.emulateMedia({ media: 'print' })
  const pdf = await popup.pdf({ format: 'Letter' })
  expect(pdf.subarray(0, 4).toString()).toBe('%PDF')
  const pages = (pdf.toString('latin1').match(/\/Type\s*\/Page[^s]/g) || []).length
  expect(pages, 'PDF pages').toBeGreaterThan(0)
})

test('Audit binder ZIP contains a populated binder.html', async ({ page }) => {
  await openReports(page)
  const selects = page.locator('main select')
  await selects.nth(0).selectOption({ label: 'ERP — Enterprise Resource Planning' })
  await selects.nth(1).selectOption({ label: 'NIST 800-53r5' })
  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'ZIP' }).click()])
  expect(dl.suggestedFilename()).toMatch(/^audit-binder_erp_nist-800-53-r5_\d{4}-\d{2}-\d{2}\.zip$/)
  const zip = readZip(await downloadBytes(dl))
  const html = zip.get('binder.html')?.toString('utf8') ?? ''
  expect(html).toContain('Enterprise Resource Planning')
  expect(html).toMatch(/Evidence Inventory/)
  expect(html).toContain('AC-6')
  expect(html.match(/>[^<]*(undefined|NaN|Invalid Date|\[object Object\])[^<]*</), 'garbage text in binder').toBeNull()
})

const CSV_REPORTS = [
  { card: 'Findings Export', header: ['id', 'title', 'framework_id', 'control_id', 'severity', 'status'] },
  { card: 'Evidence Export', header: [] as string[] },
  { card: 'Risk Register Export', header: [] as string[] },
  { card: 'Compliance Summary', header: [] as string[] },
  { card: 'ConMon Activity Export', header: [] as string[] },
]

for (const r of CSV_REPORTS) {
  test(`CSV: ${r.card} parses, is rectangular, and neutralises formulas`, async ({ page }) => {
    await openReports(page)
    const card = page.locator('main div').filter({ hasText: r.card }).filter({ has: page.getByRole('button', { name: 'CSV' }) }).last()
    const [dl] = await Promise.all([page.waitForEvent('download'), card.getByRole('button', { name: 'CSV' }).click()])
    expect(dl.suggestedFilename()).toMatch(/\.csv$/)
    const text = (await downloadBytes(dl)).toString('utf8')
    expect(text.trim(), 'CSV not empty').not.toBe('')
    expect(text.trim()).not.toBe('No data')
    const rows = parseCsv(text).filter(x => x.length > 1 || x[0] !== '')
    expect(rows.length).toBeGreaterThan(1)
    for (const h of r.header) expect(rows[0]).toContain(h)
    for (const row of rows.slice(1)) expect(row.length, `row width: ${row.join('|').slice(0, 80)}`).toBe(rows[0].length)
    const risky = rows.slice(1).flat().filter(v => isFormulaCell(v) && !/^-?\d+(\.\d+)?$/.test(v))
    expect(risky, 'cells a spreadsheet would execute').toEqual([])
    for (const row of rows.slice(1)) expect(row.join(' ').match(BAD_TEXT)).toBeNull()
    if (r.card === 'Findings Export') {
      expect(rows.some(row => row.includes(`'${EVIL_TITLE}`)), 'injected title exported as text').toBe(true)
    }
  })
}

test('CSV: Inspection Prep punch list neutralises formulas from user data', async ({ page }) => {
  await apiLogin(page, 'admin')
  await page.goto('/inspection')
  await settle(page)
  const selects = page.locator('main select')
  await selects.nth(0).selectOption({ label: 'NIST 800-53r5' })
  await selects.nth(1).selectOption({ label: 'ERP — Enterprise Resource Planning' })
  await settle(page)
  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('link', { name: 'Punch list CSV' }).click()])
  const rows = parseCsv((await downloadBytes(dl)).toString('utf8'))
  const risky = rows.slice(1).flat().filter(v => isFormulaCell(v) && !/^-?\d+(\.\d+)?$/.test(v))
  if (risky.length) await shot(page, 'punch-list-formula')
  expect(risky, 'cells a spreadsheet would execute').toEqual([])
})
