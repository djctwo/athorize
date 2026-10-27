/**
 * Journey 9 — Settings: company logo upload (shows in the sidebar), API token create /
 * use / revoke, backup download (plain + encrypted) and restore into the same instance,
 * after which the data still loads.
 */
import fs from 'node:fs'
import { test, expect, apiLogin, api, uiLogin, settle, uniq, toast, downloadBytes } from './fixtures'
import type { Page } from '@playwright/test'

test.describe.configure({ mode: 'serial' })

async function settings(page: Page) {
  await apiLogin(page, 'admin')
  await page.goto('/settings')
  await settle(page)
}

test('branding: upload a PNG logo and it appears in the sidebar', async ({ page, watcher }) => {
  await settings(page)
  // a real 120x40 PNG drawn by the browser
  const dataUri = await page.evaluate(() => {
    const c = document.createElement('canvas'); c.width = 120; c.height = 40
    const g = c.getContext('2d')!; g.fillStyle = '#0a7'; g.fillRect(0, 0, 120, 40)
    g.fillStyle = '#fff'; g.font = '20px sans-serif'; g.fillText('E2E', 40, 28)
    return c.toDataURL('image/png')
  })
  const buffer = Buffer.from(dataUri.split(',')[1], 'base64')
  const branding = page.locator('section').filter({ has: page.getByRole('img', { name: 'Logo preview' }) }).or(page.locator('main section').filter({ hasText: /logo/i })).first()
  await branding.locator('input[type=file][accept="image/png,image/jpeg"]').setInputFiles({ name: 'logo.png', mimeType: 'image/png', buffer })
  await expect(page.getByRole('img', { name: 'Logo preview' })).toBeVisible()
  await page.getByRole('button', { name: 'Save logo' }).click()
  await expect(toast(page)).toContainText('Company logo updated')
  const sidebarLogo = page.locator('aside').first().getByRole('img', { name: /logo/i }).first()
  await expect(sidebarLogo).toHaveAttribute('src', dataUri)
  // survives a reload (persisted server-side)
  await page.reload()
  await settle(page)
  await expect(page.locator('aside').first().getByRole('img', { name: /logo/i }).first()).toHaveAttribute('src', dataUri)
  expect(watcher.failedResponses).toEqual([])
})

test('API token: create → works as Bearer → revoke → refused', async ({ page, playwright, watcher }) => {
  await settings(page)
  const name = uniq('ci-pipeline')
  await page.getByPlaceholder('e.g. ci-pipeline').fill(name)
  await page.getByLabel('Expires (days)').fill('30')  // default is now 90 days (SECCODE-10)
  await page.locator('main').getByRole('button', { name: 'Create', exact: true }).click()
  const tokenText = page.locator('main code.font-mono')
  await expect(tokenText).toBeVisible()
  const raw = ((await tokenText.textContent()) ?? '').trim()
  expect(raw.length).toBeGreaterThan(20)

  const anon = await playwright.request.newContext({ baseURL: process.env.E2E_BASE_URL || 'http://127.0.0.1:8042' })
  const ok = await anon.get('/api/auth/me', { headers: { Authorization: `Bearer ${raw}` } })
  expect(ok.status()).toBe(200)
  expect((await ok.json()).username).toBe('admin')

  await page.getByRole('button', { name: 'Done' }).click()
  const row = page.locator('main tr').filter({ hasText: name })
  await expect(row).toBeVisible()
  await row.getByRole('button', { name: /revoke/i }).click()
  await expect(row).toHaveCount(0)
  const refused = await anon.get('/api/auth/me', { headers: { Authorization: `Bearer ${raw}` } })
  expect(refused.status()).toBe(401)
  await anon.dispose()
  expect(watcher.failedResponses).toEqual([])
})

let encrypted: { path: string; name: string } | null = null
const PASS = 'Restore-Me-2026!'

test('backup: plain archive is a gzip tarball; encrypted archive downloads', async ({ page, watcher }) => {
  await settings(page)
  const backup = page.locator('section').filter({ hasText: 'Backup & Restore' })
  const [plain] = await Promise.all([page.waitForEvent('download'), backup.getByRole('button', { name: 'Download' }).click()])
  const bytes = await downloadBytes(plain)
  expect(plain.suggestedFilename()).toMatch(/\.tar\.gz$/)
  expect(bytes[0]).toBe(0x1f)
  expect(bytes[1]).toBe(0x8b)
  expect(bytes.length).toBeGreaterThan(10_000)
  await expect(toast(page)).toContainText('Backup downloaded')

  await backup.getByPlaceholder('Optional passphrase').fill(PASS)
  const [enc] = await Promise.all([page.waitForEvent('download'), backup.getByRole('button', { name: 'Download' }).click()])
  expect(enc.suggestedFilename()).toMatch(/\.enc$/)
  const encPath = test.info().outputPath(enc.suggestedFilename())
  await enc.saveAs(encPath)
  encrypted = { path: encPath, name: enc.suggestedFilename() }
  expect(fs.statSync(encPath).size).toBeGreaterThan(10_000)
  expect(watcher.failedResponses).toEqual([])
})

test('restore the encrypted backup into the same instance; data still loads', async ({ page, browser }) => {
  test.skip(!encrypted, 'needs the backup from the previous test')
  await settings(page)
  const before = {
    findings: (await (await api(page, 'GET', '/api/findings')).json()).length,
    evidence: (await (await api(page, 'GET', '/api/evidence')).json()).length,
    systems: (await (await api(page, 'GET', '/api/systems')).json()).length,
  }
  const backup = page.locator('section').filter({ hasText: 'Backup & Restore' })
  await backup.locator('input[type=file]').setInputFiles(encrypted!.path)
  await backup.getByPlaceholder('Passphrase (if encrypted)').fill(PASS)
  await backup.getByRole('button', { name: 'Restore…' }).click()
  const resp = page.waitForResponse(r => r.url().includes('/api/backup/restore'))
  await backup.getByRole('button', { name: 'Confirm — overwrite everything' }).click()
  const r = await resp
  expect(r.status(), await r.text()).toBe(200)
  await expect(toast(page)).toContainText('Restore complete')
  // signed out
  await expect(page.getByRole('button', { name: 'Sign In' })).toBeVisible({ timeout: 15_000 })

  const ctx = await browser.newContext()
  const p2 = await ctx.newPage()
  await uiLogin(p2, 'admin')
  await expect(p2.getByRole('heading', { name: 'Compliance Dashboard' })).toBeVisible()
  const after = {
    findings: (await (await api(p2, 'GET', '/api/findings')).json()).length,
    evidence: (await (await api(p2, 'GET', '/api/evidence')).json()).length,
    systems: (await (await api(p2, 'GET', '/api/systems')).json()).length,
  }
  test.info().annotations.push({ type: 'counts', description: `before ${JSON.stringify(before)} after ${JSON.stringify(after)}` })
  expect.soft(after, "data after restore == data at backup time").toEqual(before)
  for (const path of ['/findings', '/evidence', '/controls', '/audit']) {
    await p2.goto(path)
    await settle(p2)
    await expect(p2.locator('main')).not.toContainText('Something went wrong')
  }
  // audit chain still verifies after a restore
  const verify = await api(p2, 'GET', '/api/audit/verify')
  if (verify.status() === 200) expect(JSON.stringify(await verify.json())).not.toMatch(/"valid":\s*false|"ok":\s*false/)
  await ctx.close()
})
