import { test as base, expect, type Page, type Locator, type ConsoleMessage } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

/** Demo users seeded by ATHORIZE_DEMO_SEED=1 — password = username. */
export const DEMO_USERS = {
  admin: 'admin',
  operator: 'operator', // cross-company admin
  analyst: 'analyst', // assessor
  manager: 'manager', // compliance_manager
  owner: 'owner', // system_owner
  contributor: 'contributor', // evidence_contributor, scoped to SCADA
  auditor: 'auditor', // read-only
} as const
export type DemoUser = keyof typeof DEMO_USERS

/** Every sidebar destination (frontend/src/components/Layout.tsx). */
export const SIDEBAR_PAGES: { label: string; path: string }[] = [
  { label: 'Dashboard', path: '/' },
  { label: 'Frameworks', path: '/marketplace' },
  { label: 'Controls', path: '/controls' },
  { label: 'Crosswalk', path: '/crosswalk' },
  { label: 'Findings', path: '/findings' },
  { label: 'Evidence', path: '/evidence' },
  { label: 'Assessments', path: '/assessments' },
  { label: 'Inspection Prep', path: '/inspection' },
  { label: 'ConMon', path: '/conmon' },
  { label: 'Advisories', path: '/advisories' },
  { label: 'Red Team', path: '/red-team' },
  { label: 'Risk Register', path: '/risks' },
  { label: 'Calendar', path: '/calendar' },
  { label: 'Systems', path: '/systems' },
  { label: 'Assets', path: '/assets' },
  { label: 'Topology', path: '/topology' },
  { label: 'Reports', path: '/reports' },
  { label: 'Migration', path: '/migration' },
  { label: 'Users', path: '/users' },
  { label: 'Audit Log', path: '/audit' },
  { label: 'Settings', path: '/settings' },
  { label: 'Help', path: '/help' },
]

/** This folder. fileURLToPath, not URL.pathname: on Windows .pathname is "/D:/a/...". */
const HERE = path.dirname(fileURLToPath(import.meta.url))

/** Where a test can drop evidence screenshots that outlive the run (copied into findings). */
export const SHOT_DIR = process.env.E2E_SHOT_DIR || path.join(HERE, '.shots')

export async function shot(page: Page, name: string) {
  fs.mkdirSync(SHOT_DIR, { recursive: true })
  const file = path.join(SHOT_DIR, `${name}.png`)
  await page.screenshot({ path: file, fullPage: false }).catch(() => undefined)
  return file
}

/** Log in through the API — the session + csrf cookies land in the page's browser context. */
export async function apiLogin(page: Page, username: string, password = username) {
  const res = await page.request.post('/api/auth/login', { data: { username, password } })
  expect(res.status(), `login ${username}`).toBe(200)
}

/** Log in through the real Login screen. */
export async function uiLogin(page: Page, username: string, password = username) {
  await page.goto('/')
  await expect(page.getByRole('button', { name: 'Sign In' })).toBeVisible()
  await labelled(page, 'Username').fill(username)
  await labelled(page, 'Password').fill(password)
  await page.getByRole('button', { name: 'Sign In' }).click()
}

export async function csrf(page: Page): Promise<string> {
  const cookies = await page.context().cookies()
  return cookies.find(c => c.name === 'universal_csrf')?.value ?? ''
}

/** JSON API call as the logged-in browser user (adds the CSRF header). */
export async function api(page: Page, method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE', url: string, data?: unknown) {
  const headers: Record<string, string> = {}
  if (method !== 'GET') headers['X-CSRF-Token'] = await csrf(page)
  const res = await page.request.fetch(url, { method, data: data as never, headers })
  return res
}

/**
 * Locate a form control by its visible label text. Most forms in the app render
 * `<label>` and `<input>` as siblings without htmlFor/id, so getByLabel cannot
 * resolve them (see finding E2E about unassociated labels) — fall back to the
 * first control that follows the label in its container.
 */
export function labelled(scope: Page | Locator, text: string | RegExp): Locator {
  const lbl = typeof text === 'string'
    ? scope.locator('label').filter({ hasText: new RegExp(`^\\s*${escapeRe(text)}\\s*\\*?\\s*$`, 'i') })
    : scope.locator('label').filter({ hasText: text })
  return lbl.first().locator('xpath=(following-sibling::*[self::input or self::select or self::textarea] | .//input | .//select | .//textarea)[1]')
}

function escapeRe(s: string) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

export function sidebar(page: Page) {
  return page.locator('aside nav')
}

export async function gotoViaSidebar(page: Page, label: string) {
  await sidebar(page).getByRole('link', { name: label, exact: true }).click()
}

export function toast(page: Page) {
  return page.locator('[role="status"][aria-live="polite"]')
}

/** Collects everything a real user would hit as "broken" while a test runs. */
export class Watcher {
  consoleErrors: string[] = []
  reactWarnings: string[] = []
  pageErrors: string[] = []
  failedResponses: { url: string; status: number; method: string; page: string }[] = []

  constructor(private page: Page) {
    page.on('console', (m: ConsoleMessage) => {
      const text = m.text()
      if (/unique "key" prop|Each child in a list should have a unique/.test(text)) this.reactWarnings.push(text.slice(0, 300))
      if (m.type() === 'error') this.consoleErrors.push(`[${page.url()}] ${text.slice(0, 300)}`)
    })
    page.on('pageerror', e => this.pageErrors.push(`[${page.url()}] ${e.message}`))
    page.on('response', r => {
      const url = r.url()
      if (url.includes('/api/') && r.status() >= 400) {
        this.failedResponses.push({ url, status: r.status(), method: r.request().method(), page: page.url() })
      }
    })
  }

  reset() {
    this.consoleErrors = []
    this.reactWarnings = []
    this.pageErrors = []
    this.failedResponses = []
  }

  /** Console "Failed to load resource" lines are duplicates of failedResponses. */
  realConsoleErrors() {
    return this.consoleErrors.filter(e => !/Failed to load resource/.test(e))
  }
}

const ISSUE_LOG = path.join(HERE, '..', 'test-results', 'console-issues.jsonl')

export const test = base.extend<{ watcher: Watcher }>({
  watcher: [async ({ page }, use, testInfo) => {
    track(page)
    const w = new Watcher(page)
    await use(w)
    // Every journey doubles as a console/React-warning probe: log what it saw, and treat an
    // unhandled page error (uncaught exception / rejected promise) as a failure anywhere.
    if (w.reactWarnings.length || w.pageErrors.length || w.realConsoleErrors().length) {
      fs.mkdirSync(path.dirname(ISSUE_LOG), { recursive: true })
      fs.appendFileSync(ISSUE_LOG, JSON.stringify({
        test: testInfo.titlePath.join(' › '), react: w.reactWarnings, pageErrors: w.pageErrors, console: w.realConsoleErrors(),
      }) + '\n')
    }
    expect.soft(w.pageErrors, 'unhandled page errors during the journey').toEqual([])
  }, { auto: true }],
})

export { expect }

/** Strings that should never reach the screen. */
export const BAD_TEXT = /\bundefined\b|\bNaN\b|Invalid Date|\[object Object\]/

export async function badTextIn(page: Page): Promise<string[]> {
  const text = await page.locator('main').innerText().catch(() => '')
  const hits: string[] = []
  for (const line of text.split('\n')) {
    if (BAD_TEXT.test(line)) hits.push(line.trim().slice(0, 160))
  }
  return hits
}

/** In-flight /api/ request tracking per page, so SPA navigations can wait for data. */
const trackers = new WeakMap<Page, { inflight: number; last: number }>()
export function track(page: Page) {
  if (trackers.has(page)) return trackers.get(page)!
  const t = { inflight: 0, last: Date.now() }
  trackers.set(page, t)
  const isApi = (u: string) => u.includes('/api/')
  page.on('request', r => { if (isApi(r.url())) { t.inflight++; t.last = Date.now() } })
  const done = (r: import('@playwright/test').Request) => { if (isApi(r.url())) { t.inflight = Math.max(0, t.inflight - 1); t.last = Date.now() } }
  page.on('requestfinished', done)
  page.on('requestfailed', done)
  return t
}

/**
 * Wait until the page has gone quiet: no /api/ request in flight for `quietMs`
 * (react-query retries once after ~1s, so the default covers a retry).
 */
export async function settle(page: Page, quietMs = 1500) {
  const t = track(page)
  await page.waitForLoadState('domcontentloaded')
  const deadline = Date.now() + 30_000
  // eslint-disable-next-line no-constant-condition
  while (true) {
    if (t.inflight === 0 && Date.now() - t.last >= quietMs) return
    if (Date.now() > deadline) return
    await page.waitForTimeout(100)
  }
}

/** Read a download fully into memory. */
export async function downloadBytes(dl: import('@playwright/test').Download): Promise<Buffer> {
  const p = await dl.path()
  return fs.readFileSync(p!)
}

export const today = () => new Date().toISOString().slice(0, 10)
export const uniq = (p: string) => `${p}-${Date.now().toString(36)}${Math.floor(Math.random() * 1e4)}`

/**
 * The app's ConfirmDialog has no role="dialog" (see a11y finding), so locate it by its
 * title text inside the fixed overlay.
 */
export function confirmDialog(page: Page, title: string) {
  return page.locator('div.fixed.inset-0').filter({ has: page.getByRole('heading', { name: title, exact: true }) })
}
