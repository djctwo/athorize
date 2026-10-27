/**
 * Journey 14 — fix-wave checks for Team F findings that had no browser spec:
 *  - DOCKER-4: a demo-seeded instance shows a persistent warning banner after login, and the
 *    anonymous login page / status endpoint reveal nothing about demo passwords.
 *  - SECLIVE-8: user-controlled text (finding title/description, comment, system name,
 *    company name) renders as inert text — no script/handler runs, no element is injected.
 *  - INTEGRITY-20: an edit made from a stale panel is refused with an explanation instead of
 *    silently reverting the other tab's change.
 */
import { test, expect, apiLogin, api, labelled, settle, uniq } from './fixtures'

test.describe('demo instance banner (DOCKER-4)', () => {
  test('shown after login on every page, for every role', async ({ page }) => {
    await apiLogin(page, 'auditor')
    for (const path of ['/', '/findings', '/settings']) {
      await page.goto(path)
      await settle(page)
      await expect(page.getByRole('note').filter({ hasText: 'Demo instance' })).toBeVisible()
    }
  })

  test('the anonymous login page and /api/auth/status say nothing about demo mode', async ({ browser }) => {
    const ctx = await browser.newContext()
    const page = await ctx.newPage()
    await page.goto('/')
    await expect(page.getByRole('button', { name: 'Sign In' })).toBeVisible()
    await expect(page.locator('body')).not.toContainText(/demo/i)
    const status = await (await page.request.get('/api/auth/status')).json()
    expect(Object.keys(status).filter(k => /demo/i.test(k))).toEqual([])
    await ctx.close()
  })
})

test.describe('phone width (E2E-19)', () => {
  test.use({ viewport: { width: 390, height: 844 } })
  test('the menu button opens the sidebar drawer; picking a page navigates and closes it', async ({ page }) => {
    await apiLogin(page, 'admin')
    await page.goto('/')
    await settle(page)
    const nav = page.locator('aside nav')
    await expect(nav).not.toBeInViewport()
    await page.getByRole('button', { name: 'Open menu' }).click()
    await expect(nav).toBeInViewport()
    await nav.getByRole('link', { name: 'Findings', exact: true }).click()
    await expect(page).toHaveURL(/\/findings$/)
    await expect(nav).not.toBeInViewport()
    await expect(page.getByRole('heading', { name: 'Findings' })).toBeVisible()
  })
})

test('user-controlled text renders inert (SECLIVE-8)', async ({ page }) => {
  const PAYLOAD = `<img src=x onerror="window.__xss=(window.__xss||0)+1"><script>window.__xss=99</script>`
  const dialogs: string[] = []
  page.on('dialog', d => { dialogs.push(d.message()); void d.dismiss() })
  await apiLogin(page, 'admin')

  const sysRes = await api(page, 'POST', '/api/systems', { name: `XSS ${PAYLOAD}`, acronym: 'XSS' })
  expect(sysRes.status()).toBe(200)
  const sys = await sysRes.json()
  try {
    const tag = uniq('XSS finding')
    const title = `${tag} ${PAYLOAD}`
    const fRes = await api(page, 'POST', '/api/findings', {
      system_id: sys.id, framework_id: 'nist-800-53-r5', title, description: PAYLOAD, severity: 'LOW',
    })
    expect(fRes.status()).toBe(200)
    const finding = await fRes.json()
    const cRes = await api(page, 'POST', '/api/comments', { entity_type: 'finding', entity_id: finding.id, body: PAYLOAD })
    expect(cRes.status()).toBe(200)
    const orgRes = await api(page, 'POST', '/api/orgs', { name: `XSS Co ${uniq('')} ${PAYLOAD}` })
    expect(orgRes.status()).toBe(200)

    // finding list + detail panel (title, description, comment)
    await page.goto(`/findings?focus=${finding.id}`)
    await settle(page)
    const panel = page.locator('aside').filter({ has: page.getByRole('heading', { name: tag }) })
    await expect(panel).toContainText('<img src=x onerror=')
    // the comment body (and the description where the panel shows it) render the payload verbatim
    await expect.poll(() => panel.getByText(PAYLOAD, { exact: true }).count()).toBeGreaterThanOrEqual(1)
    // systems list (system name) and portfolio / company switcher (company name)
    await page.goto('/systems')
    await settle(page)
    await expect(page.locator('main')).toContainText(`XSS <img src=x`)
    await page.goto('/portfolio')
    await settle(page)
    await expect(page.locator('main')).toContainText('XSS Co')

    for (const path of ['/findings', '/systems', '/portfolio', '/']) {
      await page.goto(path)
      await settle(page)
      expect(await page.locator('img[src="x"]').count(), `injected <img> on ${path}`).toBe(0)
      expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss ?? 0), `script ran on ${path}`).toBe(0)
    }
    expect(dialogs).toEqual([])
  } finally {
    await api(page, 'DELETE', `/api/systems/${sys.id}`)
  }
})

test('a stale edit is refused with an explanation, not saved over the other tab (INTEGRITY-20)', async ({ page }) => {
  await apiLogin(page, 'manager')
  const systems = await (await api(page, 'GET', '/api/systems')).json()
  const title = uniq('E2E two-tab finding')
  const created = await (await api(page, 'POST', '/api/findings', {
    system_id: systems[0].id, framework_id: 'nist-800-53-r5', title, severity: 'MEDIUM', due_date: '2026-12-31',
  })).json()

  // Tab A opens the edit panel…
  await page.goto(`/findings?focus=${created.id}`)
  await settle(page)
  await page.locator('aside').getByRole('button', { name: 'Edit', exact: true }).click()
  const panel = page.locator('aside').filter({ has: page.getByRole('heading', { name: `Edit: ${title}` }) })
  await expect(panel).toBeVisible()

  // …tab B escalates meanwhile.
  const b = await api(page, 'PATCH', `/api/findings/${created.id}`, { severity: 'CRITICAL', due_date: '2026-11-01' })
  expect(b.status()).toBe(200)

  // Tab A fixes a typo and saves.
  await labelled(panel, 'Title').fill(`${title} (typo fixed)`)
  await panel.getByRole('button', { name: 'Save' }).click()
  await expect(panel.getByRole('alert')).toContainText(/changed by someone else/i)

  const now = await (await api(page, 'GET', `/api/findings/${created.id}`)).json()
  expect(now.severity).toBe('CRITICAL')
  expect(now.due_date).toBe('2026-11-01')
})
