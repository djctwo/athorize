/**
 * Journey 1 — a brand-new install (no demo seed). Run with the `blank` project against
 * an instance started by `e2e/serve.sh blank <dir>`, with E2E_DATA_DIR=<dir>.
 *
 * Setup screen → token from <DATA_DIR>/setup-token → weak passwords rejected with a
 * readable message → strong password accepted → lands logged in → logout → login.
 */
import fs from 'node:fs'
import path from 'node:path'
import { test, expect, labelled, uiLogin, shot, settle } from '../fixtures'

const DATA_DIR = process.env.E2E_DATA_DIR || ''
const ADMIN = 'founder'
const STRONG = 'Blue-Kestrel-42-Orbit'

test.describe.configure({ mode: 'serial' })

test.beforeAll(() => {
  if (!DATA_DIR) throw new Error('E2E_DATA_DIR must point at the blank instance data dir')
})

function setupToken(): string {
  return fs.readFileSync(path.join(DATA_DIR, 'setup-token'), 'utf8').trim()
}

async function fillSetup(page: import('@playwright/test').Page, password: string, token = setupToken()) {
  await labelled(page, 'Setup Token').fill(token)
  await labelled(page, 'Organization Name').fill('Acme Example Co')
  await labelled(page, 'Admin Username').fill(ADMIN)
  await labelled(page, 'Email').fill('founder@example.com')
  await labelled(page, 'Password').fill(password)
  await page.getByRole('button', { name: 'Create Organization' }).click()
}

test('setup screen is shown and asks for the setup token', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByText('Set up your organization')).toBeVisible()
  await expect(page.getByText('Setup Token')).toBeVisible()
  expect(setupToken().length).toBeGreaterThan(10)
})

test('wrong setup token is refused', async ({ page }) => {
  await page.goto('/')
  await fillSetup(page, STRONG, 'not-the-token')
  await expect(page.locator('.text-danger').first()).toContainText(/setup token/i)
  await expect(page.getByRole('button', { name: 'Create Organization' })).toBeVisible()
})

test('weak password (policy) is rejected with a readable message', async ({ page }) => {
  await page.goto('/')
  // 12+ chars so it passes the length check and hits the complexity policy.
  await fillSetup(page, 'alllowercaseletters')
  const err = page.locator('.text-danger').first()
  await expect(err).toContainText(/three of: lowercase, uppercase/i)
  await expect(page.getByRole('button', { name: 'Create Organization' })).toBeVisible()
})

test('short password is rejected with a readable message', async ({ page }) => {
  await page.goto('/')
  await fillSetup(page, 'password')
  const err = page.locator('.text-danger').first()
  await expect(err).toBeVisible()
  const text = await err.innerText()
  if (/object Object/.test(text)) await shot(page, 'setup-short-password')
  expect(text).not.toContain('[object Object]')
  expect(text).toMatch(/12|characters|short/i)
})

test('strong password creates the org and lands logged in', async ({ page }) => {
  await page.goto('/')
  await fillSetup(page, STRONG)
  await expect(page.getByRole('heading', { name: 'Compliance Dashboard' })).toBeVisible({ timeout: 15_000 })
  await expect(page.locator('aside')).toContainText(ADMIN)
  // DOCKER-4: a real (non-demo) install never shows the demo-instance banner
  await expect(page.getByText('Demo instance')).toHaveCount(0)
  // the one-time setup token is consumed
  expect(fs.existsSync(path.join(DATA_DIR, 'setup-token'))).toBe(false)
  await settle(page)
  await expect(page.locator('main')).not.toContainText('Something went wrong')
})

test('logout returns to the login screen; login works again; bad password refused', async ({ page }) => {
  await uiLogin(page, ADMIN, STRONG)
  await expect(page.getByRole('heading', { name: 'Compliance Dashboard' })).toBeVisible()
  await page.getByTitle('Logout').click()
  await expect(page.getByRole('button', { name: 'Sign In' })).toBeVisible()
  // the session is really gone server-side
  const me = await page.request.get('/api/auth/me')
  expect(me.status()).toBe(401)

  await labelled(page, 'Username').fill(ADMIN)
  await labelled(page, 'Password').fill('Wrong-Password-123')
  await page.getByRole('button', { name: 'Sign In' }).click()
  await expect(page.locator('.text-danger').first()).toBeVisible()

  await labelled(page, 'Password').fill(STRONG)
  await page.getByRole('button', { name: 'Sign In' }).click()
  await expect(page.getByRole('heading', { name: 'Compliance Dashboard' })).toBeVisible()
})

test('a fresh instance shows an empty, error-free first-run experience', async ({ page, watcher }) => {
  await uiLogin(page, ADMIN, STRONG)
  await expect(page.getByRole('heading', { name: 'Compliance Dashboard' })).toBeVisible()
  await settle(page)
  for (const p of ['/systems', '/marketplace', '/controls', '/findings', '/evidence', '/reports', '/inspection', '/red-team', '/topology', '/risks']) {
    watcher.reset()
    await page.goto(p)
    await settle(page)
    await expect(page.locator('main')).not.toContainText('Something went wrong')
    expect.soft(watcher.pageErrors, `${p} errors`).toEqual([])
    expect.soft(watcher.failedResponses, `${p} failed API calls`).toEqual([])
    expect.soft(watcher.realConsoleErrors(), `${p} console`).toEqual([])
  }
})
