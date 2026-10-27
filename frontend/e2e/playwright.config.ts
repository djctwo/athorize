import { defineConfig, devices } from '@playwright/test'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

/**
 * Athorize end-to-end journeys (real browser, real backend).
 *
 * The suite expects a running single-process instance (backend serving frontend/dist):
 *   demo  — `e2e/serve.sh demo  <scratch-data-dir> 8042`   then `npm run test:e2e`
 *   blank — `e2e/serve.sh blank <scratch-data-dir> 8042`   then
 *           `E2E_DATA_DIR=<scratch-data-dir> npm run test:e2e:blank`
 *
 * Env:
 *   E2E_BASE_URL   default http://127.0.0.1:8042
 *   E2E_DATA_DIR   data dir of the instance under test (blank project reads <dir>/setup-token)
 *
 * Specs that document a known app defect assert the CORRECT behaviour and are marked
 * `test.fail()` with the finding ID — when the defect is fixed they start "unexpectedly
 * passing", which tells you to drop the marker.
 */
const baseURL = process.env.E2E_BASE_URL || 'http://127.0.0.1:8042'
// fileURLToPath, not URL.pathname: on Windows .pathname is "/D:/a/...", which is not a path.
const here = path.dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  testDir: here,
  testMatch: '**/*.e2e.ts',
  outputDir: path.join(here, '..', 'test-results'),
  // Journeys share one server and mutate its data — run them in order, one at a time.
  fullyParallel: false,
  workers: 1,
  timeout: 90_000,
  expect: { timeout: 10_000 },
  reporter: [
    ['list'],
    ['html', { outputFolder: path.join(here, '..', 'playwright-report'), open: 'never' }],
  ],
  use: {
    baseURL,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
    acceptDownloads: true,
    viewport: { width: 1440, height: 900 },
  },
  projects: [
    {
      name: 'demo',
      testIgnore: '**/blank/**',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } },
    },
    {
      name: 'blank',
      testMatch: 'blank/**/*.e2e.ts',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } },
    },
  ],
})
