/**
 * Journey 0 — try the demo first, then start for real. Runs FIRST in the `blank` project
 * (instance started by `e2e/serve.sh blank <dir>`, E2E_DATA_DIR=<dir>):
 *
 * Setup screen → "Explore with demo data" (needs the one-time token) → signed in as the
 * demo admin, demo banner + logins + sample data visible, other demo logins work →
 * Settings → Start fresh (password + typed START FRESH) → back on the Setup screen with a
 * NEW token, every session gone.
 *
 * blank/01-first-run then sets up a real company on this same reset instance (and checks
 * the demo banner is gone), proving that real setup works after Start fresh.
 */
import fs from 'node:fs'
import path from 'node:path'
import { test, expect, labelled, uiLogin, settle } from '../fixtures'

const DATA_DIR = process.env.E2E_DATA_DIR || ''

test.describe.configure({ mode: 'serial' })

test.beforeAll(() => {
  if (!DATA_DIR) throw new Error('E2E_DATA_DIR must point at the blank instance data dir')
})

function setupToken(): string {
  return fs.readFileSync(path.join(DATA_DIR, 'setup-token'), 'utf8').trim()
}

let firstToken = ''

test('the Setup screen offers both choices and says where the token is', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByText('Set up your organization')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Create Organization' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Explore with demo data' })).toBeVisible()
  await expect(page.getByText(/in the server log/)).toBeVisible()
  firstToken = setupToken()
  expect(firstToken.length).toBeGreaterThan(10)
})

test('demo data needs the setup token', async ({ page }) => {
  await page.goto('/')
  await page.getByRole('button', { name: 'Explore with demo data' }).click()
  await expect(page.getByRole('alert')).toContainText(/setup token/i)
  await expect(page.getByRole('button', { name: 'Explore with demo data' })).toBeEnabled()
  const status = await (await page.request.get('/api/auth/status')).json()
  expect(status.setup_complete).toBe(false)
})

test('Explore with demo data loads the sample companies and signs in as admin', async ({ page, watcher }) => {
  await page.goto('/')
  await labelled(page, 'Setup Token').fill(firstToken)
  await page.getByRole('button', { name: 'Explore with demo data' }).click()
  await expect(page.getByRole('heading', { name: 'Compliance Dashboard' })).toBeVisible({ timeout: 60_000 })
  await expect(page.locator('aside')).toContainText('admin')
  const banner = page.getByRole('note').filter({ hasText: 'Demo instance' })
  await expect(banner).toBeVisible()
  await expect(banner).toContainText('admin, operator, manager')
  await expect(banner).toContainText('Start fresh')
  // the one-time token is consumed
  expect(fs.existsSync(path.join(DATA_DIR, 'setup-token'))).toBe(false)
  // the sample data is really there
  await page.goto('/systems')
  await expect(page.locator('main')).toContainText('Plant Floor SCADA')
  await page.goto('/findings')
  await expect(page.locator('main')).toContainText('Unpatched SQL Server')
  await settle(page)
  expect.soft(watcher.pageErrors).toEqual([])
})

test('the other demo logins work (password = username)', async ({ page }) => {
  await uiLogin(page, 'manager')
  await expect(page.getByRole('heading', { name: 'Compliance Dashboard' })).toBeVisible()
  await expect(page.getByRole('note').filter({ hasText: 'Demo instance' })).toBeVisible()
  // a compliance manager cannot start fresh (admins of the whole instance only)
  await page.goto('/settings')
  await expect(page.getByRole('heading', { name: 'Settings', exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Start fresh' })).toHaveCount(0)
})

test('Start fresh needs the password and the typed confirmation', async ({ page }) => {
  await uiLogin(page, 'admin')
  await expect(page.getByRole('heading', { name: 'Compliance Dashboard' })).toBeVisible()
  await page.goto('/settings')
  const go = page.getByRole('button', { name: 'Start fresh' })
  await expect(go).toBeVisible()
  await expect(page.getByText(/deletes everything on this instance/)).toBeVisible()
  await expect(go).toBeDisabled()
  await page.getByLabel('Your password').fill('not-the-password')
  await page.getByLabel(/Type START FRESH/).fill('START FRESH')
  await go.click()
  await expect(page.getByRole('alert')).toContainText(/password is incorrect/i)
  // nothing was deleted
  await page.goto('/systems')
  await expect(page.locator('main')).toContainText('Plant Floor SCADA')
})

test('Start fresh deletes the demo and returns to the Setup screen with a new token', async ({ page, browser }) => {
  // a second signed-in browser, to prove every session ends
  const other = await browser.newContext()
  const otherPage = await other.newPage()
  expect((await otherPage.request.post('/api/auth/login', { data: { username: 'auditor', password: 'auditor' } })).status()).toBe(200)

  await uiLogin(page, 'admin')
  await expect(page.getByRole('heading', { name: 'Compliance Dashboard' })).toBeVisible()
  await page.goto('/settings')
  await page.getByLabel('Your password').fill('admin')
  await page.getByLabel(/Type START FRESH/).fill('START FRESH')
  await page.getByRole('button', { name: 'Start fresh' }).click()

  await expect(page.getByText('Set up your organization')).toBeVisible({ timeout: 30_000 })
  await expect(page.getByRole('button', { name: 'Explore with demo data' })).toBeVisible()
  const newToken = setupToken()
  expect(newToken.length).toBeGreaterThan(10)
  expect(newToken).not.toBe(firstToken)
  expect((await page.request.get('/api/auth/me')).status()).toBe(401)
  expect((await otherPage.request.get('/api/auth/me')).status()).toBe(401)
  // the demo's sign-ins are gone with it
  expect((await page.request.post('/api/auth/login', { data: { username: 'admin', password: 'admin' } })).status()).toBe(401)
  // the old token is spent
  const old = await page.request.post('/api/auth/setup/demo', { data: { setup_token: firstToken } })
  expect(old.status()).toBe(403)
  await other.close()
})
