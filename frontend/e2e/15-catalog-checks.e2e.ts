/**
 * W2-DATA — control ids are checked against the framework catalog (R2USER-7): the finding
 * panel offers the catalog's ids, a typo is refused with a message that names it, and the
 * saved id uses the catalog's spelling.
 */
import { test, expect, apiLogin, api, labelled, settle, uniq } from './fixtures'

const ERP = 'Enterprise Resource Planning'

test('finding Control ID: catalog picker, unknown id refused with a message, catalog spelling saved', async ({ page }) => {
  const title = uniq('E2E catalog check')
  await apiLogin(page, 'manager')
  await page.goto('/findings')
  await settle(page)
  await page.getByRole('button', { name: 'New Finding' }).click()
  const panel = page.locator('aside').filter({ has: page.getByRole('heading', { name: 'New Finding' }) })
  await labelled(panel, 'System').selectOption({ label: ERP })
  await labelled(panel, 'Framework').selectOption({ label: 'NIST 800-53r5' })
  await labelled(panel, 'Title').fill(title)
  const control = labelled(panel, 'Control ID')
  // The input is backed by a datalist of the framework's catalog ids.
  const listId = await control.getAttribute('list')
  expect(listId).toBeTruthy()
  await expect(page.locator(`datalist[id="${listId}"] option[value="AC-2"]`)).toHaveCount(1)
  await expect(control).toHaveAttribute('placeholder', /^e\.g\. /)

  await control.fill('AC-99999')
  await panel.getByRole('button', { name: 'Create' }).click()
  await expect(panel.getByRole('alert')).toContainText("Control id 'AC-99999' is not in the nist-800-53-r5 catalog")
  await expect(panel).toHaveCount(1)  // nothing saved, the panel stays open for the fix

  await control.fill('ac-2')
  await panel.getByRole('button', { name: 'Create' }).click()
  await expect(panel).toHaveCount(0)
  const res = await api(page, 'GET', '/api/findings')
  const created = (await res.json()).find((f: { title: string }) => f.title === title)
  expect(created.control_id).toBe('AC-2')
})

test('evidence linkage refuses a control id that is not in the catalog', async ({ page }) => {
  await apiLogin(page, 'manager')
  const list = await (await api(page, 'GET', '/api/evidence')).json()
  const ev = list.find((e: { framework_ids: string[] }) => e.framework_ids.includes('nist-800-53-r5'))
  expect(ev, 'a demo evidence item tagged with NIST 800-53').toBeTruthy()
  const res = await api(page, 'PATCH', `/api/evidence/${ev.id}`, { control_ids: [...ev.control_ids, 'AC-2(99)'] })
  expect(res.status()).toBe(422)
  expect((await res.json()).detail).toContain('AC-2(99)')
})
