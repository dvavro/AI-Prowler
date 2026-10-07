// Playwright settings for the AI-Prowler HR E2E tests.
// Values come from run_tests_hr_e2e.py through environment variables,
// so this file never holds secrets and is safe to push to GitHub.
const { defineConfig } = require('@playwright/test');
const path = require('path');

const RUN_DIR  = process.env.HR_E2E_RUN_DIR || path.join(__dirname, 'logs', 'manual');
const WATCH    = process.env.HR_E2E_WATCH !== '0';           // visible browser unless --fast
const SLOW_MO  = parseInt(process.env.HR_E2E_SLOW_MO || '400', 10);

module.exports = defineConfig({
  testDir: './specs',
  outputDir: path.join(RUN_DIR, 'test-results'),   // screenshots, videos, traces per test
  timeout: 10 * 60 * 1000,                           // slow-motion runs take a while
  expect: { timeout: 15 * 1000 },
  fullyParallel: false,
  workers: 1,                                        // one test at a time, easy to watch
  retries: 0,
  reporter: [
    ['list'],
    ['json', { outputFile: path.join(RUN_DIR, 'results.json') }],
    ['html', { outputFolder: path.join(RUN_DIR, 'report'), open: 'never' }],
  ],
  use: {
    baseURL: process.env.HR_E2E_BASE_URL,
    headless: !WATCH,
    viewport: { width: 1280, height: 900 },
    launchOptions: { slowMo: WATCH ? SLOW_MO : 0 },
    video: 'on',
    screenshot: 'on',
    trace: 'on',
    serviceWorkers: 'block',      // always test the freshly deployed files, never a cached copy
    ignoreHTTPSErrors: false,
    actionTimeout: 20 * 1000,
    navigationTimeout: 45 * 1000,
  },
});
