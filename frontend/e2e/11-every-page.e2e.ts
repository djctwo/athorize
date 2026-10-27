/**
 * Journey 11 — every sidebar page as admin: renders, no console errors, no unhandled
 * rejections, no failed API calls, no "undefined"/"NaN"/"Invalid Date"/"[object Object]"
 * on screen, no React key warnings (only emitted by a development build — run the suite
 * against `NODE_ENV=development vite build` output to exercise that check).
 * Plus: core pages usable at a 390px phone viewport.
 */
import { test, expect, apiLogin, SIDEBAR_PAGES, gotoViaSidebar, settle, badTextIn, shot } from './fixtures'

test.describe('admin — every sidebar page renders cleanly', () => {
  for (const { label, path } of SIDEBAR_PAGES) {
    test(`${label} (${path})`, async ({ page, watcher }) => {
      await apiLogin(page, 'admin')
      await page.goto('/')
      await settle(page)
      watcher.reset()
      if (path !== '/') await gotoViaSidebar(page, label)
      await expect(page).toHaveURL(new RegExp(`${path === '/' ? '/$' : path}`))
      await settle(page)

      const main = page.locator('main')
      await expect(main).toBeVisible()
      await expect(main).not.toContainText('Something went wrong')
      expect((await main.innerText()).trim().length, 'page is not blank').toBeGreaterThan(20)

      expect.soft(watcher.pageErrors, 'unhandled errors / rejections').toEqual([])
      expect.soft(watcher.failedResponses, 'failed API calls').toEqual([])
      expect.soft(watcher.realConsoleErrors(), 'console errors').toEqual([])
      expect.soft(watcher.reactWarnings, 'React key warnings').toEqual([])
      expect.soft(await badTextIn(page), 'garbage text on screen').toEqual([])
    })
  }
})

test.describe('phone width (390px)', () => {
  test.use({ viewport: { width: 390, height: 844 } })
  // E2E-PHONE (fixed): below md the sidebar is an off-canvas drawer behind a menu button, so
  // the working area gets the full phone width and wide tables scroll inside their box.
  for (const path of ['/', '/findings', '/evidence', '/controls']) {
    test(`core page ${path} is usable`, async ({ page }) => {
      await apiLogin(page, 'admin')
      await page.goto(path)
      await settle(page)
      const mainBox = await page.locator('main').boundingBox()
      await shot(page, `phone${path.replace(/\//g, '_') || '_root'}`)
      // The working area should get (nearly) the full width of the phone.
      expect(mainBox!.width, 'main content width at 390px').toBeGreaterThanOrEqual(340)
      // And the document must not scroll sideways.
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
      expect(overflow, 'horizontal overflow px').toBeLessThanOrEqual(0)
    })
  }
})
