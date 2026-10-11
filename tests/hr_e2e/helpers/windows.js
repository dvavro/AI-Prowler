// Side-by-side windows for two-app tests: Portal (left) and HR Admin (right),
// each recording its own video.
const { chromium } = require('@playwright/test');
const { addClickMarker } = require('./common');

const WATCH   = process.env.HR_E2E_WATCH !== '0';
const SLOW_MO = WATCH ? parseInt(process.env.HR_E2E_SLOW_MO || '400', 10) : 0;
const WIN_W = 960, WIN_H = 1000;

async function openWindow(name, x, testInfo) {
  const browser = await chromium.launch({ headless: !WATCH, slowMo: SLOW_MO,
    args: [`--window-position=${x},0`, `--window-size=${WIN_W},${WIN_H}`] });
  const context = await browser.newContext({
    baseURL: process.env.HR_E2E_BASE_URL, viewport: { width: WIN_W - 20, height: WIN_H - 140 },
    serviceWorkers: 'block',
    recordVideo: { dir: testInfo.outputPath(`video-${name}`), size: { width: WIN_W - 20, height: WIN_H - 140 } },
  });
  const page = await context.newPage();
  await addClickMarker(page);
  return { browser, context, page, name };
}
const openPortalWindow = (testInfo) => openWindow('portal', 0, testInfo);
const openAdminWindow  = (testInfo) => openWindow('admin', WIN_W, testInfo);

async function closeWindow(w, testInfo) {
  if (!w) return;
  const video = w.page.video();
  await w.context.close().catch(() => {});
  try { if (video) await testInfo.attach(`video (${w.name})`, { path: await video.path(), contentType: 'video/webm' }); } catch {}
  await w.browser.close().catch(() => {});
}

async function snap(page, testInfo, label) {
  const p = testInfo.outputPath(`${label}.png`);
  await page.screenshot({ path: p });
  await testInfo.attach(label, { path: p, contentType: 'image/png' });
}

// Click a button that asks "Are you sure?" and answer OK.
async function clickAndConfirm(page, locator) {
  page.once('dialog', d => d.accept());
  await locator.click();
}

module.exports = { openWindow, openPortalWindow, openAdminWindow, closeWindow, snap, clickAndConfirm };
