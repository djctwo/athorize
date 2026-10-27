/**
 * Journey 5 — findings lifecycle as a compliance manager: create (owner + due date),
 * comment with an @mention, cross-framework impact, assign, close; Dashboard and My Work
 * counts follow.
 */
import { test, expect, apiLogin, api, labelled, settle, uniq, shot, toast, confirmDialog } from './fixtures'
import type { Page } from '@playwright/test'

test.describe.configure({ mode: 'serial' })

const title = uniq('E2E finding: shared admin account on ERP')
const ERP = 'Enterprise Resource Planning'

async function dashboardOpenFindings(page: Page): Promise<number> {
  await page.goto('/')
  await settle(page)
  const text = await page.locator('main').innerText()
  const m = text.match(/Open Findings\s*(\d+)/i)
  expect(m, 'Open Findings KPI on dashboard').toBeTruthy()
  return Number(m![1])
}

async function myWorkFindings(page: Page): Promise<number> {
  await page.goto('/')
  await settle(page)
  const card = page.locator('main').getByText('Your work').locator('xpath=..')
  if (!(await card.count())) return 0
  const t = await card.innerText()
  const m = t.match(/(\d+) findings?/i)
  return m ? Number(m[1]) : 0
}

function findingRow(page: Page) {
  return page.locator('main tbody tr').filter({ hasText: title })
}

let before = 0
let mineBefore = 0

test('manager creates a finding with owner and due date; dashboard count goes up', async ({ page, watcher }) => {
  await apiLogin(page, 'manager')
  before = await dashboardOpenFindings(page)
  mineBefore = await myWorkFindings(page)

  await page.goto('/findings')
  await settle(page)
  await page.getByRole('button', { name: 'New Finding' }).click()
  const panel = page.locator('aside').filter({ has: page.getByRole('heading', { name: 'New Finding' }) })
  await labelled(panel, 'System').selectOption({ label: ERP })
  await labelled(panel, 'Framework').selectOption({ label: 'NIST 800-53r5' })
  await labelled(panel, 'Title').fill(title)
  await labelled(panel, 'Description').fill('Two operators share the ERP "sysadm" account.')
  await labelled(panel, 'Severity').selectOption('HIGH')
  await labelled(panel, 'Control ID').fill('AC-2')
  const due = new Date(Date.now() + 10 * 86400_000).toISOString().slice(0, 10)
  await labelled(panel, 'Due Date').fill(due)
  // Owner is a real user (owner_id), not free text — E2E-16. The demo 'analyst' is Jane Analyst.
  await labelled(panel, 'Owner').selectOption({ label: 'Jane Analyst' })
  await panel.getByRole('button', { name: 'Create' }).click()
  await expect(panel).toHaveCount(0)
  const row = findingRow(page)
  await expect(row).toContainText('OPEN')
  await expect(row).toContainText(due)

  expect(await dashboardOpenFindings(page)).toBe(before + 1)
  expect(watcher.failedResponses).toEqual([])
})

test('detail shows cross-framework impact; @mention comment posts', async ({ page, watcher }) => {
  await apiLogin(page, 'manager')
  await page.goto('/findings')
  await settle(page)
  await findingRow(page).click()
  const panel = page.locator('aside').filter({ has: page.getByRole('heading', { name: title }) })
  await expect(panel.getByText('Cross-Framework Impact')).toBeVisible()
  await expect(panel).toContainText(/maps into \d+ other active framework/)

  const box = panel.getByPlaceholder('Add a comment… use @username to mention a teammate')
  await box.click()
  await box.pressSequentially('Please verify @anal')
  const list = page.getByRole('listbox', { name: 'Mention a teammate' })
  await expect(list).toBeVisible()
  await list.getByRole('option').filter({ hasText: '@analyst' }).getByRole('button').dispatchEvent('mousedown')
  await expect(box).toHaveValue(/@analyst /)
  await box.pressSequentially('before Friday.')
  await panel.getByRole('button', { name: 'Comment', exact: true }).click()
  const item = panel.locator('ol li').filter({ hasText: 'before Friday.' })
  await expect(item).toBeVisible()
  await expect(item).toContainText('@analyst')
  const mentions = await (await api(page, 'GET', '/api/comments?entity_type=finding&entity_id=' + (await findingId(page)))).json()
  const posted = (Array.isArray(mentions) ? mentions : mentions.comments ?? []).find((c: { body: string }) => c.body.includes('before Friday.'))
  expect(posted?.mentions?.length, 'the @mention resolved to a user').toBe(1)
  expect(watcher.failedResponses).toEqual([])
})

test('the "Owner" set in the form makes the finding show up in that person\'s My Work', async ({ page }) => {
  await apiLogin(page, 'analyst')
  const r = await (await api(page, 'GET', '/api/dashboard/my-work')).json()
  const titles = r.findings.map((f: { title: string }) => f.title)
  expect(titles).toContain(title)
})

test('assign to me → My Work counts it; close → counts drop back', async ({ page, watcher }) => {
  await apiLogin(page, 'manager')
  await page.goto('/findings')
  await settle(page)
  await page.getByRole('checkbox', { name: `Select ${title}` }).check()
  await page.getByRole('button', { name: 'Assign to me' }).click()
  await expect(toast(page)).toContainText('Updated 1 finding(s)')
  expect(await myWorkFindings(page)).toBe(mineBefore + 1)

  await page.goto('/findings')
  await settle(page)
  await findingRow(page).click()
  const panel = page.locator('aside').filter({ has: page.getByRole('heading', { name: title }) })
  await panel.getByRole('button', { name: 'Mark Closed' }).click()
  await confirmDialog(page, 'Close Finding').getByRole('button', { name: 'Confirm' }).click()
  await expect(findingRow(page)).toContainText('CLOSED')

  expect(await dashboardOpenFindings(page)).toBe(before)
  expect(await myWorkFindings(page)).toBe(mineBefore)
  expect(watcher.failedResponses).toEqual([])
})

async function findingId(page: Page): Promise<number> {
  const list = await (await api(page, 'GET', '/api/findings')).json()
  return list.find((f: { title: string }) => f.title === title).id
}



