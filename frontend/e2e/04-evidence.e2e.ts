/**
 * Journey 4 — evidence. An evidence contributor (scoped to SCADA only) uploads a file,
 * links it to a control, sees the crosswalk suggestion and accepts it, and the file can be
 * retrieved byte-for-byte (UI download, and inside the audit binder ZIP).
 */
import { test, expect, apiLogin, api, labelled, settle, uniq, shot, toast } from './fixtures'
import { readZip } from './zip'
import type { Page } from '@playwright/test'
import fs from 'node:fs'

const SCADA = 'Plant Floor SCADA'
const FILE_BYTES = Buffer.from(`historian export ${Date.now()}\nline-2\tβ-unicode ✓\n`, 'utf8')

test.describe.configure({ mode: 'serial' })
let fileName = ''

async function openEvidence(page: Page, name: string) {
  await page.goto('/evidence')
  await settle(page)
  await page.locator('main tbody tr').filter({ hasText: name }).click()
  return page.locator('aside').filter({ hasText: 'Evidence Artifact' })
}

test('contributor uploads evidence to SCADA (only SCADA is offered)', async ({ page, watcher }) => {
  fileName = `${uniq('scada-historian')}.txt`
  await apiLogin(page, 'contributor')
  await page.goto('/evidence')
  await settle(page)
  await page.getByRole('button', { name: 'Upload' }).click()
  const form = page.locator('main form')
  const sysSelect = labelled(form, 'System')
  const options = (await sysSelect.locator('option').allTextContents()).filter(o => !/Select system/.test(o))
  expect(options, 'contributor is scoped to SCADA only').toEqual([SCADA])
  await sysSelect.selectOption({ label: SCADA })
  await labelled(form, 'Type').selectOption('LOG')
  await labelled(form, 'Description').fill('Historian export for OT audit')
  await form.locator('input[type=file]').setInputFiles({ name: fileName, mimeType: 'text/plain', buffer: FILE_BYTES })
  await form.getByRole('button', { name: 'Upload', exact: true }).click()
  const row = page.locator('main tbody tr').filter({ hasText: fileName })
  await expect(row).toBeVisible()
  await expect(row).toContainText(SCADA)
  await expect(row).toContainText('Fresh')
  expect(watcher.failedResponses).toEqual([])
})

test('upload errors are shown to the user (disallowed file type)', async ({ page }) => {
  await apiLogin(page, 'contributor')
  await page.goto('/evidence')
  await settle(page)
  await page.getByRole('button', { name: 'Upload' }).click()
  const form = page.locator('main form')
  await labelled(form, 'System').selectOption({ label: SCADA })
  await form.locator('input[type=file]').setInputFiles({ name: 'payload.exe', mimeType: 'application/octet-stream', buffer: Buffer.from('MZ') })
  const resp = page.waitForResponse(r => r.url().includes('/api/evidence/upload'))
  await form.getByRole('button', { name: 'Upload', exact: true }).click()
  expect((await resp).status()).toBe(415)
  const visible = page.getByText(/not allowed|File type/i)
  if (!(await visible.count())) await shot(page, 'evidence-upload-error-silent')
  await expect(visible.first()).toBeVisible({ timeout: 3000 })
})

test('contributor links it to a control; crosswalk suggestions appear right away', async ({ page, watcher }) => {
  await apiLogin(page, 'contributor')
  const panel = await openEvidence(page, fileName)
  await panel.getByRole('button', { name: 'Edit Linkage' }).click()
  await labelled(panel, 'Linked Controls (comma-separated)').fill('AC-2')
  await panel.getByRole('checkbox', { name: 'NIST 800-53r5' }).check()
  await panel.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(toast(page)).toContainText('Evidence linkage updated')
  await expect(panel).toContainText('AC-2')
  expect(watcher.failedResponses).toEqual([])
  await expect(panel.getByText('Suggested by Crosswalk')).toBeVisible({ timeout: 5000 }).catch(async e => {
    await shot(page, 'evidence-suggestions-stale')
    throw e
  })
})

test('contributor accepts a crosswalk evidence suggestion (fresh page load)', async ({ page, watcher }) => {
  await apiLogin(page, 'contributor')
  const panel = await openEvidence(page, fileName)
  await expect(panel).toContainText('AC-2')
  await expect(panel.getByText('Suggested by Crosswalk')).toBeVisible()
  const first = panel.locator('div.flex.items-center.gap-2.text-xs').filter({ has: page.getByRole('button', { name: 'Link' }) }).first()
  const suggested = (await first.locator('span.font-mono').innerText()).trim()
  await first.getByRole('button', { name: 'Link' }).click()
  await expect(toast(page)).toContainText(`Linked ${suggested}`)
  await expect(panel.getByText('Linked Controls').locator('xpath=..')).toContainText(suggested)
  expect(watcher.failedResponses).toEqual([])
})

test('the uploaded file can be downloaded back from the Evidence page, byte-identical', async ({ page }) => {
  await apiLogin(page, 'contributor')
  const panel = await openEvidence(page, fileName)
  const dlButton = panel.getByRole('link', { name: /download/i }).or(panel.getByRole('button', { name: /download/i }))
  if (!(await dlButton.count())) await shot(page, 'evidence-no-download')
  const [dl] = await Promise.all([page.waitForEvent('download', { timeout: 5000 }), dlButton.first().click({ timeout: 3000 })])
  const bytes = fs.readFileSync((await dl.path())!)
  expect(Buffer.compare(bytes, FILE_BYTES)).toBe(0)
})

test('the uploaded file is archived byte-identical inside the audit binder ZIP', async ({ page }) => {
  await apiLogin(page, 'admin')
  const systems = await (await api(page, 'GET', '/api/systems')).json()
  const scada = systems.find((s: { name: string }) => s.name === SCADA)
  const res = await api(page, 'GET', `/api/reports/audit-binder?system_id=${scada.id}&framework_id=nist-800-53-r5`)
  expect(res.status()).toBe(200)
  const zip = readZip(await res.body())
  const html = zip.get('binder.html')?.toString('utf8') ?? ''
  expect(html).toContain(fileName)
  const archived = [...zip.entries()].find(([n]) => n.startsWith('evidence/') && n.endsWith(fileName))
  expect(archived, `evidence/${fileName} in the binder zip (entries: ${[...zip.keys()].join(', ')})`).toBeTruthy()
  expect(Buffer.compare(archived![1], FILE_BYTES)).toBe(0)
})

test('auditor (read-only) is not offered "Edit Linkage"', async ({ page }) => {
  await apiLogin(page, 'auditor')
  const panel = await openEvidence(page, fileName)
  if (await panel.getByRole('button', { name: 'Edit Linkage' }).count()) await shot(page, 'auditor-edit-linkage')
  await expect(panel.getByRole('button', { name: 'Edit Linkage' })).toHaveCount(0)
})

test('deleting evidence asks for confirmation', async ({ page }) => {
  await apiLogin(page, 'admin')
  // throwaway artifact so the real one survives
  const systems = await (await api(page, 'GET', '/api/systems')).json()
  const scada = systems.find((s: { name: string }) => s.name === SCADA)
  const name = `${uniq('delete-me')}.txt`
  const csrfTok = (await page.context().cookies()).find(c => c.name === 'universal_csrf')!.value
  const up = await page.request.post('/api/evidence/upload', {
    headers: { 'X-CSRF-Token': csrfTok },
    multipart: { system_id: String(scada.id), file: { name, mimeType: 'text/plain', buffer: Buffer.from('x') } },
  })
  expect(up.status()).toBe(200)
  await page.goto('/evidence')
  await settle(page)
  const row = page.locator('main tbody tr').filter({ hasText: name })
  await row.locator('td').last().getByRole('button').click()
  // A confirmation dialog must appear before anything is deleted.
  await expect(page.getByRole('heading', { name: /Delete/i })).toBeVisible({ timeout: 3000 }).catch(async e => {
    await shot(page, 'evidence-delete-no-confirm')
    throw e
  })
})
