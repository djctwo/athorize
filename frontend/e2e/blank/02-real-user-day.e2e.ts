/**
 * Journey B2 — a real user's first days on a BLANK instance (round-2 W2-UX fixes).
 * Runs after blank/01-first-run (which creates the org and the admin `founder`). The demo
 * seed hid most of these: it writes calendar rows, backdates nothing, and never types a
 * narrative before touching the row dropdown.
 *
 *  R2USER-18 first dashboard has no overdue cadence; checklist names ConMon
 *  R2USER-19 About reads the server version; OT toggle editable; only admins activate
 *  R2USER-10 CMMC offers a LEVEL_1 baseline
 *  R2USER-2  a typed narrative survives the row status dropdown
 *  R2DATA-12 a stale control editor gets "changed by someone else", keeps the draft
 *  R2USER-15 Crosswalk Review explains an empty queue
 *  R2USER-21 / -11 evidence upload needs a system; expiry defaults by type and is editable
 *  R2USER-12 owner picker lists only people who can work the finding; the owner works it
 *  R2USER-13 self-service password change
 *  R2USER-6 / -1 Days Open 0; a finding's Activity shows only its own history
 *  R2USER-4  Calendar shows derived deadlines
 *  R2USER-16 native .nessus import
 *  R2USER-20 / -14 no raw framework ids; Help describes what exists
 *  R2USER-3  panels fit the viewport at 390 px and 1280 px
 */
import type { Page } from '@playwright/test'
import { test, expect, apiLogin, api, uiLogin, labelled, settle, toast } from '../fixtures'

const ADMIN = 'founder'
const ADMIN_PW = 'Blue-Kestrel-42-Orbit'
const OWNER = 'sam.owner'
const OWNER_PW = 'Granite-Harbor-71-Lamp'
const OWNER_NEW_PW = 'Copper-Willow-38-Kite'
const CMMC = 'cmmc-2.0'
const CMMC_NAME = 'Cybersecurity Maturity Model Certification 2.0'
const SYS = { name: 'Customer Portal', acronym: 'PORTAL' }

test.describe.configure({ mode: 'serial' })

const localDate = (offsetDays = 0) => {
  const d = new Date()
  d.setDate(d.getDate() + offsetDays)
  return d.toLocaleDateString('en-CA')
}

async function asAdmin(page: Page) { await apiLogin(page, ADMIN, ADMIN_PW) }

async function systemId(page: Page): Promise<number> {
  const list = await (await api(page, 'GET', '/api/systems')).json() as { id: number; name: string }[]
  const s = list.find(x => x.name === SYS.name)
  expect(s, 'the journey system exists').toBeTruthy()
  return s!.id
}

async function findingByTitle(page: Page, title: string) {
  const list = await (await api(page, 'GET', '/api/findings')).json() as { id: number; title: string; status: string; milestones: { title: string }[] }[]
  return list.find(f => f.title === title)!
}

function controlRow(page: Page, id: string) {
  return page.locator('main .divide-y > div').filter({ has: page.locator('span.font-mono', { hasText: new RegExp(`^${id.replace(/\./g, '\\.')}$`) }) })
}

async function openGrid(page: Page) {
  await page.goto('/controls')
  await settle(page)
  const selects = page.locator('main select')
  await selects.nth(0).selectOption({ label: CMMC_NAME })
  await selects.nth(1).selectOption({ label: `${SYS.acronym} — ${SYS.name}` })
  await expect(page.getByRole('heading', { name: 'Assess Controls' })).toBeVisible()
  await settle(page)
}

test('first dashboard: no overdue cadences, the checklist names ConMon, About shows the server version', async ({ page }) => {
  await asAdmin(page)
  const snap = await (await api(page, 'GET', '/api/dashboard/snapshot')).json()
  expect(snap.cadence_overdue).toBe(0)
  await page.goto('/')
  await settle(page)
  await expect(page.getByText('Log a continuous-monitoring activity')).toBeVisible()
  await page.goto('/conmon')
  await settle(page)
  await expect(page.locator('main')).not.toContainText(/Cadence Overdue \(/)
  const version = (await (await api(page, 'GET', '/api/health')).json()).version
  await page.goto('/settings')
  await expect(page.locator('main')).toContainText(`Athorize v${version}`)
})

test('register a system in the UI and change its OT flag later', async ({ page }) => {
  await asAdmin(page)
  for (const fw of [CMMC, 'nist-800-53-r5']) {
    expect((await api(page, 'POST', `/api/frameworks/${fw}/activate`, {})).status()).toBe(200)
  }
  await page.goto('/systems')
  await settle(page)
  await page.getByRole('button', { name: 'Add System' }).click()
  await page.getByLabel('Name', { exact: true }).fill(SYS.name)
  await page.getByLabel('Acronym').fill(SYS.acronym)
  await page.getByLabel(/OT \/ industrial system/).check()
  await page.getByRole('button', { name: 'Create' }).click()
  await expect(page.locator('main')).toContainText(SYS.name)
  const sid = await systemId(page)
  expect((await (await api(page, 'GET', `/api/systems/${sid}`)).json()).is_ot_enabled).toBe(true)
  // still a blank org: one system registered today means cadences are due, not overdue
  expect((await (await api(page, 'GET', '/api/dashboard/snapshot')).json()).cadence_overdue).toBe(0)
})

test('CMMC can be scoped to Level 1', async ({ page }) => {
  await asAdmin(page)
  await openGrid(page)
  await page.getByRole('button', { name: /Scope to baseline/ }).click()
  const panel = page.locator('aside').filter({ has: page.getByRole('heading', { name: 'Scope to a baseline' }) })
  await expect(panel.locator('select option')).toHaveText(['LEVEL_1', 'LEVEL_2'])
  await panel.getByRole('button', { name: 'Cancel' }).click()
})

test('a typed narrative survives the row status dropdown, and Save stores both', async ({ page }) => {
  await asAdmin(page)
  await openGrid(page)
  const row = controlRow(page, 'AC.L2-3.1.1')
  await row.getByRole('button').first().click()
  const narrative = 'Access is limited to authorized users through the IdP; quarterly account reviews by IT.'
  const editor = row.getByLabel('Implementation narrative')
  await editor.fill(narrative)
  const saved = page.waitForResponse(r => r.request().method() === 'PUT' && r.url().includes('/AC.L2-3.1.1'))
  await row.locator('select').first().selectOption('IMPLEMENTED')
  await saved
  await settle(page)
  await expect(editor).toHaveValue(narrative)
  await expect(row.getByLabel('Implementation status')).toHaveValue('IMPLEMENTED')
  await row.getByRole('button', { name: 'Save implementation' }).click()
  await expect(toast(page)).toContainText('Saved')
  const impls = await (await api(page, 'GET', `/api/controls/systems/${await systemId(page)}?framework_id=${CMMC}`)).json()
  const impl = impls.find((i: { control_id: string }) => i.control_id === 'AC.L2-3.1.1')
  expect(impl.narrative).toBe(narrative)
  expect(impl.implementation_status).toBe('IMPLEMENTED')
  expect(impl.assessed_date).toBeTruthy()
})

test('a stale control editor is told someone else saved, keeps its draft, and can load the latest', async ({ page }) => {
  await asAdmin(page)
  await openGrid(page)
  const row = controlRow(page, 'AC.L2-3.1.2')
  await row.getByRole('button').first().click()
  const editor = row.getByLabel('Implementation narrative')
  await editor.fill('Tab A draft that started before the colleague saved.')
  // a colleague (another tab) saves the same control meanwhile
  const sid = await systemId(page)
  expect((await api(page, 'PUT', `/api/controls/systems/${sid}/${CMMC}/AC.L2-3.1.2`, {
    implementation_status: 'IMPLEMENTED', narrative: 'Colleague: role-based access via AD groups.',
  })).status()).toBe(200)
  await row.getByRole('button', { name: 'Save implementation' }).click()
  const alert = row.getByRole('alert')
  await expect(alert).toContainText('changed by someone else')
  await expect(editor).toHaveValue('Tab A draft that started before the colleague saved.')
  await settle(page)
  await alert.getByRole('button', { name: 'Load latest version' }).click()
  await expect(editor).toHaveValue('Colleague: role-based access via AD groups.')
  const impls = await (await api(page, 'GET', `/api/controls/systems/${sid}?framework_id=${CMMC}`)).json()
  expect(impls.find((i: { control_id: string }) => i.control_id === 'AC.L2-3.1.2').narrative)
    .toBe('Colleague: role-based access via AD groups.')
})

test('Crosswalk Review explains why a CMMC + 800-53 queue is empty', async ({ page }) => {
  await asAdmin(page)
  await page.goto('/crosswalk')
  await settle(page)
  await page.locator('main select').first().selectOption({ label: `${SYS.acronym} — ${SYS.name}` })
  await settle(page)
  await expect(page.locator('main')).toContainText('partial-overlap')
  await expect(page.locator('main')).not.toContainText('every qualifying mapped control already has an implementation')
})

test('evidence upload: a system is required; expiry defaults by type and can be edited', async ({ page }) => {
  await asAdmin(page)
  await page.goto('/evidence')
  await settle(page)
  await page.getByRole('main').getByRole('button', { name: 'Upload' }).first().click()
  const form = page.locator('main form')
  await form.getByLabel('File').setInputFiles({ name: 'portal-scan.csv', mimeType: 'text/csv', buffer: Buffer.from('host,finding\n10.0.5.10,none\n') })
  let posted = false
  page.on('request', r => { if (r.url().includes('/api/evidence/upload')) posted = true })
  await form.getByRole('button', { name: 'Upload' }).click()
  expect(await form.getByLabel('System').evaluate(el => (el as HTMLSelectElement).validity.valid)).toBe(false)
  expect(posted, 'no request without a system').toBe(false)

  await form.getByLabel('System').selectOption({ label: SYS.name })
  await form.getByLabel('Type').selectOption('SCAN_RESULT')
  await expect(form.getByLabel('Expires in (days)')).toHaveValue('90')
  await form.getByRole('button', { name: 'Upload' }).click()
  await expect(toast(page)).toContainText('Evidence uploaded')
  const ev = (await (await api(page, 'GET', '/api/evidence')).json()).find((e: { filename: string }) => e.filename === 'portal-scan.csv')
  expect(ev.expiration_date).toBe(localDate(90))

  await page.locator('main tr').filter({ hasText: 'portal-scan.csv' }).first().click()
  const panel = page.locator('aside').filter({ hasText: 'Evidence Artifact' })
  await panel.getByRole('button', { name: 'Edit Linkage' }).click()
  await panel.getByLabel('Expires on').fill(localDate(30))
  await panel.getByRole('button', { name: 'Save' }).click()
  await expect(toast(page)).toContainText('updated')
  const after = (await (await api(page, 'GET', '/api/evidence')).json()).find((e: { id: number }) => e.id === ev.id)
  expect(after.expiration_date).toBe(localDate(30))
})

test('findings: owner picker lists only people who can work it; Days Open 0; Activity is per finding', async ({ page }) => {
  await asAdmin(page)
  for (const [username, role, pw] of [[OWNER, 'system_owner', OWNER_PW], ['audrey.audit', 'auditor', 'Silver-Meadow-55-Rope']]) {
    expect((await api(page, 'POST', '/api/users', { username, password: pw, role, email: `${username}@example.com`, display_name: username })).status()).toBe(200)
  }
  const sid = await systemId(page)
  for (const [title, sev, due] of [['Zerologon on the portal DC', 'CRITICAL', localDate(7)], ['Brute-force lockout missing', 'MEDIUM', localDate(-1)]]) {
    expect((await api(page, 'POST', '/api/findings', {
      system_id: sid, framework_id: CMMC, control_id: 'AC.L2-3.1.1', title, severity: sev, due_date: due,
    })).status()).toBe(200)
  }
  const other = await findingByTitle(page, 'Brute-force lockout missing')
  expect((await api(page, 'PATCH', `/api/findings/${other.id}`, { remediation_plan: 'Enable lockout policy' })).status()).toBe(200)

  await page.goto('/findings')
  await settle(page)
  await page.locator('main tr').filter({ hasText: 'Zerologon on the portal DC' }).click()
  const detail = page.locator('aside').filter({ has: page.getByRole('heading', { name: 'Zerologon on the portal DC' }) })
  await expect(detail).toBeVisible()
  await expect(detail.getByText('Days Open', { exact: true }).locator('..')).toContainText('0')
  await expect(detail).toContainText('Activity')
  await settle(page)
  await expect(detail).not.toContainText('Brute-force lockout missing')

  await detail.getByRole('button', { name: 'Edit' }).click()
  const edit = page.locator('aside').filter({ has: page.getByLabel('Owner') })
  const owner = edit.getByLabel('Owner')
  await expect(owner.locator('option', { hasText: OWNER })).toHaveCount(1)
  await expect(owner.locator('option', { hasText: 'audrey.audit' })).toHaveCount(0)
  await owner.selectOption({ label: OWNER })
  await edit.getByRole('button', { name: 'Save' }).click()
  await expect.poll(async () => (await findingByTitle(page, 'Zerologon on the portal DC') as unknown as { owner_id: number | null }).owner_id).not.toBeNull()
})

test('the assigned system owner works their finding: status and milestones', async ({ page }) => {
  await uiLogin(page, OWNER, OWNER_PW)
  await expect(page.getByRole('heading', { name: 'Compliance Dashboard' })).toBeVisible()
  const f = await findingByTitle(page, 'Zerologon on the portal DC')
  await page.goto(`/findings?focus=${f.id}`)
  await settle(page)
  const detail = page.locator('aside').filter({ has: page.getByRole('heading', { name: 'Zerologon on the portal DC' }) })
  await detail.getByLabel('Your finding — status').selectOption('IN_PROGRESS')
  await expect(toast(page)).toContainText('Status updated')
  await detail.getByPlaceholder('New milestone…').fill('Patch both domain controllers')
  await detail.locator('input[type="date"]').fill(localDate(3))
  await detail.getByRole('button', { name: 'Add' }).click()
  await expect(detail).toContainText('Patch both domain controllers')
  const after = await findingByTitle(page, 'Zerologon on the portal DC')
  expect(after.status).toBe('IN_PROGRESS')
  expect(after.milestones.map(m => m.title)).toContain('Patch both domain controllers')
  // no editor rights beyond that
  await expect(detail.getByRole('button', { name: 'Mark Closed' })).toHaveCount(0)
})

test('a user changes their own password', async ({ page }) => {
  await uiLogin(page, OWNER, OWNER_PW)
  await expect(page.getByRole('heading', { name: 'Compliance Dashboard' })).toBeVisible()
  await page.goto('/settings')
  await page.getByRole('button', { name: 'Change password' }).click()
  const form = page.getByRole('form', { name: 'Change password' })
  await form.getByLabel('Current password').fill('wrong-password')
  await form.getByLabel('New password', { exact: true }).fill(OWNER_NEW_PW)
  await form.getByLabel('Confirm new password').fill(OWNER_NEW_PW)
  await form.getByRole('button', { name: 'Change password' }).click()
  await expect(form.getByRole('alert')).toContainText('Current password is incorrect')
  await form.getByLabel('Current password').fill(OWNER_PW)
  await form.getByRole('button', { name: 'Change password' }).click()
  await expect(toast(page)).toContainText('Password changed')
  await page.getByTitle('Logout').click()
  await uiLogin(page, OWNER, OWNER_PW)
  await expect(page.locator('.text-danger').first()).toBeVisible()
  await uiLogin(page, OWNER, OWNER_NEW_PW)
  await expect(page.getByRole('heading', { name: 'Compliance Dashboard' })).toBeVisible()
})

test('Calendar shows the deadlines from findings, milestones and evidence, read-only and linked', async ({ page }) => {
  await asAdmin(page)
  expect((await api(page, 'POST', '/api/calendar', { title: 'Auditor kickoff call', event_date: localDate(10), event_type: 'ASSESSMENT' })).status()).toBe(200)
  await page.goto('/calendar')
  await settle(page)
  const main = page.locator('main')
  for (const t of ['Finding due: Zerologon on the portal DC', 'Milestone: Patch both domain controllers',
    'Evidence expires: portal-scan.csv', 'Auditor kickoff call']) {
    await expect(main.getByText(t)).toBeVisible()
  }
  await expect(main).toContainText('Finding due: Brute-force lockout missing') // overdue, in Past
  const auto = main.locator('[data-source="derived"]').filter({ hasText: 'Zerologon on the portal DC' }).first()
  await expect(auto).toContainText('Auto')
  await expect(auto.getByRole('button')).toHaveCount(0)
  const manual = main.locator('[data-source="manual"]').filter({ hasText: 'Auditor kickoff call' })
  await expect(manual.getByRole('button', { name: /Delete/ })).toHaveCount(1)
  await main.getByLabel(/Show deadlines from findings/).uncheck()
  await expect(main.getByText('Finding due: Zerologon on the portal DC')).toHaveCount(0)
  await main.getByLabel(/Show deadlines from findings/).check()
  await main.getByRole('link', { name: 'Finding due: Zerologon on the portal DC' }).click()
  await expect(page).toHaveURL(/\/findings\?focus=\d+/)
  await expect(page.locator('aside').getByRole('heading', { name: 'Zerologon on the portal DC' })).toBeVisible()
})

test('a native .nessus export imports; informational plugins are skipped and counted', async ({ page }) => {
  await asAdmin(page)
  await page.goto('/findings')
  await settle(page)
  await page.getByRole('button', { name: 'Import' }).click()
  const panel = page.locator('aside').filter({ hasText: 'Import SIEM / Scanner Output' })
  const nessus = `<?xml version="1.0" ?>
<NessusClientData_v2><Report name="Portal scan"><ReportHost name="10.0.5.10">
<ReportItem port="445" protocol="tcp" severity="3" pluginID="142960" pluginName="SMB signing not required" pluginFamily="Misc."><synopsis>SMB signing</synopsis></ReportItem>
<ReportItem port="0" protocol="tcp" severity="0" pluginID="19506" pluginName="Nessus Scan Information" pluginFamily="Settings"><synopsis>info</synopsis></ReportItem>
</ReportHost></Report></NessusClientData_v2>`
  await panel.locator('input[type="file"]').setInputFiles({ name: 'portal.nessus', mimeType: 'application/xml', buffer: Buffer.from(nessus) })
  await labelled(panel, /System/).selectOption({ label: `${SYS.acronym} — ${SYS.name}` })
  await labelled(panel, /Framework/).selectOption({ label: CMMC_NAME })
  await panel.getByRole('button', { name: 'Preview Import' }).click()
  await expect(panel).toContainText('Detected format: nessus_xml', { ignoreCase: true })
  await expect(panel).toContainText('SMB signing not required')
  await expect(panel).not.toContainText('Nessus Scan Information')
  await expect(panel).toContainText('Risk=None')
})

test('no raw framework ids on the dashboard chart or the Assessments table; Help matches the app', async ({ page }) => {
  await asAdmin(page)
  const sid = await systemId(page)
  expect((await api(page, 'POST', '/api/assessments', { system_id: sid, framework_id: CMMC, assessment_type: 'Annual Review' })).status()).toBe(200)
  await page.goto('/assessments')
  await settle(page)
  await expect(page.locator('main table')).toContainText('CMMC 2.0')
  expect(await page.locator('main').textContent()).not.toContain(CMMC)
  await page.goto('/')
  await settle(page)
  expect(await page.locator('main').textContent()).not.toContain(CMMC)
  await page.goto('/help')
  await settle(page)
  const help = (await page.locator('main').textContent()) ?? ''
  expect(help).not.toContain('assessment template')
  expect(help).not.toContain('Verify Integrity')
  expect(help).toContain('Record an assessment and print its report')
  expect(help).toContain('18 compliance frameworks')
})

for (const vp of [{ width: 390, height: 844 }, { width: 1280, height: 800 }]) {
  test.describe(`panels fit the viewport at ${vp.width}px (R2USER-3)`, () => {
    test.use({ viewport: vp })

    async function expectInside(page: Page, panel: import('@playwright/test').Locator, what: string) {
      await expect(panel, what).toBeVisible()
      const box = (await panel.boundingBox())!
      expect(box.x, `${what}: left edge on screen`).toBeGreaterThanOrEqual(0)
      expect(box.x + box.width, `${what}: right edge on screen`).toBeLessThanOrEqual(vp.width + 1)
    }

    test('finding detail, finding form, import, evidence detail, owner status and password form', async ({ page }) => {
      await asAdmin(page)
      await page.goto('/findings')
      await settle(page)
      if (vp.width < 768) await page.getByRole('main').scrollIntoViewIfNeeded()
      await page.locator('main tr').filter({ hasText: 'Zerologon on the portal DC' }).click()
      const detail = page.locator('aside').filter({ has: page.getByRole('heading', { name: 'Zerologon on the portal DC' }) })
      await expectInside(page, detail, 'finding detail')
      await expect(detail.getByRole('heading', { name: 'Zerologon on the portal DC' })).toBeInViewport()
      await page.keyboard.press('Escape')
      await page.getByRole('button', { name: 'New Finding' }).click()
      const form = page.locator('aside').filter({ has: page.getByLabel('Owner') })
      await expectInside(page, form, 'new finding')
      await expect(form.getByLabel('Title')).toBeInViewport()
      await page.keyboard.press('Escape')
      await page.getByRole('button', { name: 'Import' }).click()
      await expectInside(page, page.locator('aside').filter({ hasText: 'Import SIEM / Scanner Output' }), 'SIEM import')
      await page.keyboard.press('Escape')

      await page.goto('/evidence')
      await settle(page)
      await page.locator('main tr').filter({ hasText: 'portal-scan.csv' }).first().click()
      const ev = page.locator('aside').filter({ hasText: 'Evidence Artifact' })
      await expectInside(page, ev, 'evidence detail')
      await ev.getByRole('button', { name: 'Edit Linkage' }).click()
      await expect(ev.getByLabel('Expires on')).toBeVisible()
      await page.keyboard.press('Escape')

      await page.goto('/settings')
      await page.getByRole('button', { name: 'Change password' }).click()
      const pw = page.getByRole('form', { name: 'Change password' })
      await expectInside(page, pw, 'change-password form')

      await page.goto('/calendar')
      await settle(page)
      expect(await page.evaluate(() => document.documentElement.scrollWidth), 'calendar: no horizontal scroll')
        .toBeLessThanOrEqual(vp.width + 1)
    })

    test('the owner sees the status control inside the panel', async ({ page }) => {
      await apiLogin(page, OWNER, OWNER_NEW_PW)
      const f = await findingByTitle(page, 'Zerologon on the portal DC')
      await page.goto(`/findings?focus=${f.id}`)
      await settle(page)
      const detail = page.locator('aside').filter({ has: page.getByRole('heading', { name: 'Zerologon on the portal DC' }) })
      await expectInside(page, detail, 'owner finding detail')
      await detail.getByLabel('Your finding — status').scrollIntoViewIfNeeded()
      await expect(detail.getByLabel('Your finding — status')).toBeInViewport()
    })
  })
}
