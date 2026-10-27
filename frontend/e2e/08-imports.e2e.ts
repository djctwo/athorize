/**
 * Journey 8 — SIEM / scanner imports through the Findings → Import panel with small
 * synthetic files (formats from backend/services/siem_import.py). Each import: preview →
 * confirm → findings appear with their source; re-importing the same file is deduplicated.
 */
import { test, expect, apiLogin, settle, uniq, shot, toast } from './fixtures'
import type { Page } from '@playwright/test'
import { plural } from '../src/lib/plural'

const tag = uniq('e2e')
const FILES = [
  {
    format: 'splunk_csv',
    name: 'splunk-export.csv',
    title: `Splunk brute force ${tag}`,
    body: (t: string) =>
      'alert_name,severity,src_ip,dest_ip,dest_port,protocol,_time,description\n' +
      `${t},high,198.51.100.7,10.10.1.11,22,tcp,2026-10-21T08:00:00Z,Repeated SSH failures\n` +
      `${t} (2),medium,198.51.100.8,10.10.1.12,3389,tcp,2026-10-21T08:05:00Z,RDP sweep\n`,
    rows: 2,
  },
  {
    format: 'suricata_eve',
    name: 'eve.json',
    title: `ET SCAN Modbus probe ${tag}`,
    body: (t: string) =>
      JSON.stringify({ timestamp: '2026-10-21T09:00:00.000000+0000', event_type: 'alert', src_ip: '203.0.113.9', src_port: 40000, dest_ip: '10.30.0.5', dest_port: 502, proto: 'TCP', alert: { signature_id: 9100001, signature: t, severity: 2 } }) + '\n',
    rows: 1,
  },
  {
    format: 'nessus_csv',
    name: 'nessus-scan.csv',
    title: `SMB signing not required ${tag}`,
    body: (t: string) =>
      'Plugin ID,CVE,Risk,Host,Protocol,Port,Name,Synopsis\n' +
      `57608,,Medium,10.10.1.21,tcp,445,${t},Signing is not required on the remote SMB server.\n`,
    rows: 1,
  },
  {
    format: 'snort_fast',
    name: 'fast.log',
    title: `SNORT DNP3 unsolicited response ${tag}`,
    body: (t: string) =>
      `10/21-10:00:00.123456 [**] [1:9200001:1] ${t} [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.30.0.9:20000 -> 10.30.0.5:20000\n`,
    rows: 1,
  },
]

async function openImport(page: Page) {
  await page.goto('/findings')
  await settle(page)
  await page.getByRole('button', { name: 'Import', exact: true }).click()
  return page.locator('aside').filter({ has: page.getByRole('heading', { name: 'Import SIEM / Scanner Output' }) })
}

async function importFile(page: Page, f: (typeof FILES)[number], expectNew: number) {
  const panel = await openImport(page)
  await panel.locator('input[type=file]').setInputFiles({ name: f.name, mimeType: 'text/plain', buffer: Buffer.from(f.body(f.title)) })
  const selects = panel.locator('select')
  await selects.nth(0).selectOption({ label: 'SCADA — Plant Floor SCADA' })
  await selects.nth(1).selectOption({ label: 'NIST Special Publication 800-82 Revision 3' })
  await panel.getByRole('button', { name: 'Preview Import' }).click()
  await expect(panel).toContainText(`Detected format: ${f.format}`, { ignoreCase: true })
  const text = await panel.innerText()
  expect(Number(text.match(/Parsed\s*(\d+)/i)![1])).toBe(f.rows)
  expect(Number(text.match(/New\s*(\d+)/i)![1])).toBe(expectNew)
  return panel
}

test.describe.configure({ mode: 'serial' })

for (const f of FILES) {
  test(`import ${f.format}: preview → confirm → findings listed; re-import is deduplicated`, async ({ page, watcher }) => {
    await apiLogin(page, 'manager')
    const panel = await importFile(page, f, f.rows)
    await panel.getByRole('button', { name: `Import ${plural(f.rows, 'Finding')}`, exact: true }).click()
    await expect(toast(page)).toContainText(`Imported ${plural(f.rows, 'finding')} (`)
    await expect(panel).toContainText('Import Complete')
    await panel.getByRole('button', { name: 'Close' }).click()

    const row = page.locator('main tbody tr').filter({ hasText: f.title }).first()
    await expect(row).toBeVisible()
    const source = f.format.split('_')[0]
    await expect(row).toContainText(source)
    await expect(row).toContainText('OPEN')

    // same file again → nothing new
    const again = await importFile(page, f, 0)
    await expect(again.getByRole('button', { name: 'Import 0 Findings', exact: true })).toBeDisabled()
    expect(watcher.failedResponses).toEqual([])
  })
}

test('OpenVAS XML / Elastic NDJSON can be chosen in the file picker', async ({ page }) => {
  await apiLogin(page, 'manager')
  const panel = await openImport(page)
  const accept = (await panel.locator('input[type=file]').getAttribute('accept')) ?? ''
  if (!accept.includes('.xml')) await shot(page, 'import-accept-filter')
  expect(accept).toContain('.xml')
  expect(accept).toContain('.ndjson')
})

test('OpenVAS XML imports (file set programmatically)', async ({ page }) => {
  await apiLogin(page, 'manager')
  const title = `SSH server CBC mode ciphers enabled ${tag}`
  const f = {
    format: 'openvas_xml', name: 'openvas-report.xml', title, rows: 1,
    body: (t: string) => `<?xml version="1.0"?><report><results><result id="r1"><name>${t}</name><host>10.30.0.7</host><port>22/tcp</port><threat>Medium</threat><severity>5.3</severity><nvt oid="1.3.6.1.4.1.25623.1.0.105610"><refs><ref type="cve" id="CVE-2008-5161"/></refs></nvt><description>The SSH server supports CBC mode ciphers.</description></result></results></report>`,
  }
  const panel = await importFile(page, f, 1)
  await panel.getByRole('button', { name: 'Import 1 Finding', exact: true }).click()
  await expect(toast(page)).toContainText('Imported 1 finding (')
})

test('imported findings can be filtered by their source', async ({ page }) => {
  await apiLogin(page, 'manager')
  await page.goto('/findings')
  await settle(page)
  const sourceFilter = page.locator('main select').nth(3)
  const opts = (await sourceFilter.locator('option').allInnerTexts()).map(o => o.toLowerCase())
  expect(opts.some(o => o.includes('openvas'))).toBe(true)
})

test('import preview and result say what was merged and skipped (never silent)', async ({ page }) => {
  await apiLogin(page, 'manager')
  const t = `Repeated probe ${tag}`
  const alert = JSON.stringify({ timestamp: '2026-10-21T11:00:00Z', event_type: 'alert', src_ip: '203.0.113.20', dest_ip: '10.30.0.5', alert: { signature_id: 9100777, signature: t, severity: 2 } })
  const f = {
    format: 'suricata_eve', name: 'eve-dup.json', title: t, rows: 1,
    body: () => [alert, alert, '{"event_type":"flow","src_ip":"10.0.0.1"}', 'not json'].join('\n') + '\n',
  }
  const panel = await importFile(page, f, 1)
  await expect(panel).toContainText('1 repeated row(s) describe a finding already in this file')
  await expect(panel).toContainText('2 row(s) skipped')
  await panel.getByRole('button', { name: 'Import 1 Finding', exact: true }).click()
  await expect(toast(page)).toContainText('2 rows skipped')
  await expect(panel).toContainText('1 repeated row merged')
})
