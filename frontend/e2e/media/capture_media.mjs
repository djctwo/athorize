#!/usr/bin/env node
/**
 * README media capture — screenshots + demo video, from a real (throwaway) instance.
 *
 *   e2e/media/capture.sh <scratch-dir> [port]      ← one command: starts a BLANK instance, runs this, stops it
 *
 * or by hand, against an already running BLANK instance (`e2e/serve.sh blank <dir> <port>`):
 *   node e2e/media/capture_media.mjs --base http://127.0.0.1:8078 --data-dir <dir> \
 *        --shots ../docs/screenshots --media ../docs/media --work <scratch>/media-work
 *
 * The instance must be blank (first-run Setup screen): the script screenshots Setup, then
 * records the video of "Explore with demo data" → dashboard → controls/crosswalk → findings →
 * reports, then screenshots the seeded demo pages. Demo data only (Acme / Northwind / Contoso).
 *
 * Outputs
 *   <shots>/*.png               1440×900 viewport, 2× device scale
 *   <work>/demo.webm            raw Playwright recording (1440×900)
 *   <media>/athorize-demo.mp4   H.264, if ffmpeg is on PATH and the file is ≤ 15 MB
 *                               (otherwise it stays in <work>/ and the path is printed)
 *   <media>/athorize-demo-preview.gif  ≤ 8 MB animated preview for the README (ffmpeg)
 *
 * Exits non-zero if the page throws, an /api/ call fails, or an error alert is on screen.
 */
import { chromium } from '@playwright/test'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith('--') ? [...acc, [a.slice(2), all[i + 1]]] : acc), []),
)
const BASE = args.base || 'http://127.0.0.1:8078'
const DATA_DIR = args['data-dir']
const SHOTS = path.resolve(args.shots || 'docs/screenshots')
const MEDIA = path.resolve(args.media || 'docs/media')
const WORK = path.resolve(args.work || 'media-work')
if (!DATA_DIR) throw new Error('--data-dir <blank instance data dir> is required (the setup token lives there)')

const VIEW = { width: 1440, height: 900 }
const MAX_VIDEO_MB = 15
const MAX_PREVIEW_MB = 8

// Demo record names the shots/video open — all from backend/services/demo_seed.py.
const FRAMEWORK = 'nist-800-53-r5'
const SYSTEM_NAME = 'Corporate Security Program'
const CONTROL = 'AC-2'
const FINDING = 'Stale privileged accounts not disabled'
const EVIDENCE = 'corp-800-53-control-evidence-bundle.pdf'
const INSPECT_FRAMEWORK = 'nist-800-53-r5'
const INSPECT_SYSTEM = 'Corporate Security Program'

const problems = []
function watch(page, label) {
  page.on('pageerror', e => problems.push(`[${label}] page error: ${e.message}`))
  page.on('response', r => {
    if (r.url().includes('/api/') && r.status() >= 400) problems.push(`[${label}] ${r.request().method()} ${r.url()} → ${r.status()}`)
  })
}

/** Quiet = no /api/ request in flight for `ms`. */
async function settle(page, ms = 900) {
  await page.waitForLoadState('networkidle').catch(() => {})
  await page.waitForTimeout(ms)
}

async function assertClean(page, label) {
  const alerts = await page.locator('[role="alert"]').allInnerTexts().catch(() => [])
  const visible = alerts.map(t => t.trim()).filter(Boolean)
  if (visible.length) problems.push(`[${label}] error alert on screen: ${visible.join(' | ').slice(0, 200)}`)
  const body = await page.locator('body').innerText()
  if (/\bUniversal\b/.test(body)) problems.push(`[${label}] the word "Universal" is on screen`)
  if (/\bundefined\b|\bNaN\b|Invalid Date|\[object Object\]/.test(body)) problems.push(`[${label}] broken value text on screen`)
}

async function shoot(page, name, opts = {}) {
  await settle(page)
  await assertClean(page, name)
  const file = path.join(SHOTS, `${name}.png`)
  await page.screenshot({ path: file, animations: 'disabled', ...opts })
  console.log(`  shot ${path.relative(process.cwd(), file)}`)
}

async function systemId(page, name) {
  const res = await page.request.get(`${BASE}/api/systems`)
  const body = await res.json()
  const list = Array.isArray(body) ? body : body.items
  const s = list.find(x => x.name === name)
  if (!s) throw new Error(`demo system "${name}" not found`)
  return String(s.id)
}

// ---------- video helpers: a visible cursor + eased moves, so viewers can follow ----------
const CURSOR_JS = `
  window.addEventListener('DOMContentLoaded', () => {
    const c = document.createElement('div')
    c.id = '__media_cursor'
    Object.assign(c.style, { position: 'fixed', left: '0px', top: '0px', width: '18px', height: '18px',
      margin: '-9px 0 0 -9px', borderRadius: '50%', background: 'rgba(255,255,255,0.85)',
      border: '2px solid rgba(59,130,246,0.95)', boxShadow: '0 0 0 4px rgba(59,130,246,0.25)',
      zIndex: 2147483647, pointerEvents: 'none', transition: 'transform 120ms ease' })
    document.body.appendChild(c)
    document.addEventListener('mousemove', e => { c.style.left = e.clientX + 'px'; c.style.top = e.clientY + 'px' }, true)
    document.addEventListener('mousedown', () => { c.style.transform = 'scale(0.7)' }, true)
    document.addEventListener('mouseup', () => { c.style.transform = 'scale(1)' }, true)
  })`

let mouse = { x: VIEW.width / 2, y: VIEW.height / 2 }
async function moveTo(page, locator, pause = 350) {
  await locator.scrollIntoViewIfNeeded()
  const box = await locator.boundingBox()
  if (!box) throw new Error('target not visible for the video')
  const x = box.x + Math.min(box.width / 2, 120)
  const y = box.y + box.height / 2
  const steps = Math.max(12, Math.round(Math.hypot(x - mouse.x, y - mouse.y) / 18))
  await page.mouse.move(x, y, { steps })
  mouse = { x, y }
  await page.waitForTimeout(pause)
}
async function glide(page, locator, pause) {
  await moveTo(page, locator, pause)
  await page.mouse.down()
  await page.mouse.up()
}
async function smoothScroll(page, selector, dy, ms = 1200) {
  await page.evaluate(({ selector, dy, ms }) => new Promise(done => {
    const el = selector ? document.querySelector(selector) : document.scrollingElement
    const start = el.scrollTop
    const t0 = performance.now()
    const tick = now => {
      const k = Math.min(1, (now - t0) / ms)
      el.scrollTop = start + dy * (k < 0.5 ? 2 * k * k : 1 - Math.pow(-2 * k + 2, 2) / 2)
      k < 1 ? requestAnimationFrame(tick) : done()
    }
    requestAnimationFrame(tick)
  }), { selector, dy, ms })
}
async function selectVisibly(page, locator, value, pause = 900) {
  await moveTo(page, locator, 300)
  await locator.selectOption(value)
  await page.waitForTimeout(pause)
}

// ---------------------------------------------------------------------------------------
fs.mkdirSync(SHOTS, { recursive: true })
fs.mkdirSync(MEDIA, { recursive: true })
fs.mkdirSync(WORK, { recursive: true })

const browser = await chromium.launch()
const status = await (await fetch(`${BASE}/api/auth/status`)).json()
if (status.setup_complete) throw new Error(`${BASE} is already set up — start a BLANK instance (e2e/serve.sh blank …)`)
const token = fs.readFileSync(path.join(DATA_DIR, 'setup-token'), 'utf8').trim()

console.log('1/3 Setup screen')
{
  const ctx = await browser.newContext({ viewport: VIEW, deviceScaleFactor: 2, colorScheme: 'dark' })
  const page = await ctx.newPage()
  watch(page, 'setup')
  await page.goto(BASE + '/')
  await page.getByRole('button', { name: 'Explore with demo data' }).waitFor()
  await shoot(page, '07-setup', { fullPage: true })
  await ctx.close()
}

console.log('2/3 Demo video')
{
  const ctx = await browser.newContext({
    viewport: VIEW, deviceScaleFactor: 1, colorScheme: 'dark',
    recordVideo: { dir: WORK, size: VIEW },
  })
  await ctx.addInitScript(CURSOR_JS)
  const page = await ctx.newPage()
  watch(page, 'video')
  const t0 = Date.now()

  await page.goto(BASE + '/')
  const tokenBox = page.locator('#setup-token')
  await tokenBox.waitFor()
  await page.waitForTimeout(1800)
  await moveTo(page, tokenBox, 400)
  await tokenBox.click()
  await tokenBox.pressSequentially(token.slice(0, 12), { delay: 45 })
  await tokenBox.fill(token)
  await page.waitForTimeout(700)
  // The page is taller than 900 px; ease down to the demo choice.
  await smoothScroll(page, null, 400, 1200)
  await page.waitForTimeout(1500)
  await glide(page, page.getByRole('button', { name: 'Explore with demo data' }), 600)
  await page.getByRole('heading', { name: 'Compliance Dashboard' }).waitFor({ timeout: 60_000 })
  await settle(page, 2500)

  // Dashboard: the KPI strip, then the charts
  await moveTo(page, page.locator('main').getByText('Open findings', { exact: false }).first(), 1400)
  await moveTo(page, page.locator('main').getByText('Open by severity', { exact: false }).first(), 2200)
  await moveTo(page, page.locator('main').getByText('Finding aging', { exact: false }).first(), 2000)
  await moveTo(page, page.locator('main').getByText('Evidence freshness', { exact: false }).first(), 2400)

  // Controls → framework + system → expand a control → its crosswalk chips
  await glide(page, page.locator('aside nav').getByRole('link', { name: 'Controls', exact: true }), 300)
  await settle(page, 1000)
  const sysId = await systemId(page, SYSTEM_NAME)
  await selectVisibly(page, page.locator('main select').nth(0), FRAMEWORK, 1200)
  await selectVisibly(page, page.locator('main select').nth(1), sysId, 1400)
  await settle(page, 600)
  const ctl = page.locator('main button').filter({ has: page.locator(`span.font-mono:text-is("${CONTROL}")`) }).first()
  await glide(page, ctl, 500)
  const xw = page.getByText(/Crosswalk — satisfies toward/).first()
  await xw.waitFor()
  await page.waitForTimeout(1200)
  await page.evaluate(() => {
    const el = [...document.querySelectorAll('main div')].find(d => /^Crosswalk — satisfies toward/.test(d.textContent?.trim() ?? '') && d.children.length <= 2)
    const main = document.querySelector('main')
    if (el && main) main.scrollTo({ top: main.scrollTop + el.getBoundingClientRect().top - 160, behavior: 'smooth' })
  })
  await page.waitForTimeout(1600)
  await moveTo(page, xw, 3200)
  await smoothScroll(page, 'main', 260, 1200)
  await page.waitForTimeout(2500)

  // Findings → one finding → its cross-framework impact
  await glide(page, page.locator('aside nav').getByRole('link', { name: 'Findings', exact: true }), 300)
  await settle(page, 1800)
  const row = page.locator('main tr').filter({ hasText: FINDING }).first()
  await glide(page, row.getByText(FINDING, { exact: true }), 500)
  const panel = page.locator('aside.fixed.right-0')
  await panel.waitFor()
  await settle(page, 2200)
  const impact = panel.getByText('Cross-Framework Impact', { exact: true })
  await impact.waitFor()
  await impact.evaluate(el => el.scrollIntoView({ behavior: 'smooth', block: 'start' }))
  await page.waitForTimeout(1600)
  await moveTo(page, impact, 3800)
  await glide(page, panel.getByRole('button', { name: 'Close' }).first(), 300)
  await page.waitForTimeout(900)

  // Reports → executive briefing
  await glide(page, page.locator('aside nav').getByRole('link', { name: 'Reports', exact: true }), 300)
  await settle(page, 1800)
  await moveTo(page, page.getByRole('button', { name: /Executive Briefing/ }), 2600)
  await moveTo(page, page.getByText('Audit Binder', { exact: true }), 2200)
  await smoothScroll(page, 'main', 300, 1400)
  await page.waitForTimeout(2200)
  await assertClean(page, 'video-end')

  const video = page.video()
  await ctx.close()
  const raw = path.join(WORK, 'demo.webm')
  fs.renameSync(await video.path(), raw)
  console.log(`  video ${raw} (${((Date.now() - t0) / 1000).toFixed(0)} s)`)
}

console.log('3/3 Screenshots')
{
  const ctx = await browser.newContext({ viewport: VIEW, deviceScaleFactor: 2, colorScheme: 'dark' })
  const page = await ctx.newPage()
  watch(page, 'shots')
  const login = await page.request.post(`${BASE}/api/auth/login`, { data: { username: 'admin', password: 'admin' } })
  if (login.status() !== 200) throw new Error(`demo admin login failed: ${login.status()}`)

  await page.goto(BASE + '/')
  await page.getByRole('heading', { name: 'Compliance Dashboard' }).waitFor()
  await shoot(page, '01-dashboard')

  // catalog view (no system): the control, its text and the crosswalk chips fit on one screen
  await page.goto(`${BASE}/controls?framework=${FRAMEWORK}`)
  await settle(page)
  await page.locator('main button').filter({ has: page.locator(`span.font-mono:text-is("${CONTROL}")`) }).first().click()
  await page.getByText(/Crosswalk — satisfies toward/).first().waitFor()
  await settle(page)
  // the expanded control's row at the top, its crosswalk chips filling the rest of the screen
  const row = page.locator('main button').filter({ has: page.locator(`span.font-mono:text-is("${CONTROL}")`) }).first()
  await row.evaluate(el => {
    const main = document.querySelector('main')
    if (main) main.scrollTop += el.getBoundingClientRect().top - main.getBoundingClientRect().top - 12
  })
  await shoot(page, '02-controls-crosswalk')

  await page.goto(`${BASE}/findings`)
  await settle(page)
  await page.locator('main tr').filter({ hasText: FINDING }).first().getByText(FINDING, { exact: true }).click()
  const impact = page.locator('aside.fixed.right-0').getByText('Cross-Framework Impact', { exact: true })
  await impact.waitFor()
  await settle(page, 1200)
  await impact.evaluate(el => el.scrollIntoView({ block: 'center' }))
  await shoot(page, '03-finding-impact')

  await page.goto(`${BASE}/evidence`)
  await settle(page)
  await page.locator('main').getByText(EVIDENCE).first().click()
  await settle(page, 1500)
  await shoot(page, '04-evidence')

  await page.goto(`${BASE}/inspection`)
  await settle(page)
  await page.locator('main select').nth(0).selectOption(INSPECT_FRAMEWORK)
  await page.locator('main select').nth(1).selectOption(await systemId(page, INSPECT_SYSTEM))
  // an inspection ~75 days out, so the 90/60/30 timeline has something to show
  const d = new Date(Date.now() + 75 * 864e5).toISOString().slice(0, 10)
  await page.locator('main input[type="date"]').fill(d)
  await page.locator('main input[type="date"]').blur()
  await settle(page, 1500)
  await shoot(page, '05-inspection-prep')

  await page.goto(`${BASE}/reports`)
  await page.getByRole('button', { name: /Executive Briefing/ }).waitFor()
  await shoot(page, '06-reports')

  await ctx.close()
}
await browser.close()

// ---------- encode (ffmpeg optional) ----------
const raw = path.join(WORK, 'demo.webm')
const hasFfmpeg = spawnSync('ffmpeg', ['-version']).status === 0
const mb = f => fs.statSync(f).size / 1024 / 1024
if (hasFfmpeg) {
  const mp4 = path.join(WORK, 'athorize-demo.mp4')
  spawnSync('ffmpeg', ['-y', '-loglevel', 'error', '-i', raw, '-c:v', 'libx264', '-preset', 'slow', '-crf', '26',
    '-pix_fmt', 'yuv420p', '-movflags', '+faststart', '-an', mp4], { stdio: 'inherit' })
  if (mb(mp4) <= MAX_VIDEO_MB) {
    fs.copyFileSync(mp4, path.join(MEDIA, 'athorize-demo.mp4'))
    console.log(`  mp4 ${path.join(MEDIA, 'athorize-demo.mp4')} (${mb(mp4).toFixed(1)} MB)`)
  } else {
    console.log(`  mp4 is ${mb(mp4).toFixed(1)} MB (> ${MAX_VIDEO_MB} MB) — left at ${mp4}`)
  }
  // README preview: 1.5× speed, 960 px wide, 8 fps, 128-colour palette; shrink until ≤ 8 MB.
  const gif = path.join(MEDIA, 'athorize-demo-preview.gif')
  for (const [w, fps, colors] of [[960, 8, 128], [800, 7, 96], [720, 6, 64]]) {
    const vf = `setpts=PTS/1.5,fps=${fps},scale=${w}:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=${colors}:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle`
    spawnSync('ffmpeg', ['-y', '-loglevel', 'error', '-i', raw, '-vf', vf, '-loop', '0', gif], { stdio: 'inherit' })
    console.log(`  gif ${w}px/${fps}fps → ${mb(gif).toFixed(1)} MB`)
    if (mb(gif) <= MAX_PREVIEW_MB) break
  }
} else {
  console.log(`  ffmpeg not found — keeping the raw recording at ${raw}`)
}

if (problems.length) {
  console.error('\nPROBLEMS (fix before using this media):\n  ' + [...new Set(problems)].join('\n  '))
  process.exit(1)
}
console.log('\nclean: no page errors, failed API calls or error alerts')
