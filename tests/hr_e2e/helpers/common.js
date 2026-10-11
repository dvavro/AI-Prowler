// Shared helpers for the AI-Prowler HR E2E tests.
const { expect } = require('@playwright/test');

// ── Settings passed in by run_tests_hr_e2e.py ──────────────────────────────
function settings() {
  const s = {
    baseURL:  process.env.HR_E2E_BASE_URL,
    ttEmail:  process.env.HR_E2E_TT_EMAIL,
    ttPin:    process.env.HR_E2E_TT_PIN,     // fresh random PIN set for this run only
    ttName:   process.env.HR_E2E_TT_NAME || 'Test Tester',
  };
  for (const [k, v] of Object.entries(s)) {
    if (!v) throw new Error(`Missing setting "${k}". Start the tests with run_tests_hr_e2e.py, not directly.`);
  }
  return s;
}

// ── Red dot wherever the mouse clicks (shows up on screen and in videos) ────
async function addClickMarker(page) {
  await page.addInitScript(() => {
    const draw = (x, y) => {
      const d = document.createElement('div');
      d.style.cssText = `position:fixed;left:${x - 9}px;top:${y - 9}px;width:18px;height:18px;border-radius:50%;
        background:rgba(255,40,40,.85);box-shadow:0 0 0 4px rgba(255,40,40,.35);z-index:2147483647;
        pointer-events:none;transition:opacity .6s ease-out`;
      (document.body || document.documentElement).appendChild(d);
      setTimeout(() => { d.style.opacity = '0'; }, 500);
      setTimeout(() => d.remove(), 1200);
    };
    window.addEventListener('mousedown', e => draw(e.clientX, e.clientY), true);
  });
}

// ── Record console errors, page crashes and failed HR server calls ─────────
// Returns an object; call problems.list() at the end of the test.
const HARMLESS = [
  /favicon\.ico/i,
  /Download the React DevTools/i,
];
function watchForProblems(page, label = 'page') {
  const found = [];
  let where = '';                                   // current page/step, set by tests with problems.at('Recruiting')
  const tag = () => `[${label}${where ? ' · ' + where : ''}]`;
  page.on('console', msg => {
    if (msg.type() !== 'error') return;
    const text = msg.text();
    if (HARMLESS.some(r => r.test(text))) return;
    found.push(`${tag()} console error: ${text}`);
  });
  page.on('pageerror', err => found.push(`${tag()} page crash: ${err.message}${err.stack ? ' @ ' + (err.stack.split('\n')[1] || '').trim() : ''}`));
  page.on('response', res => {
    const url = res.url();
    if (url.includes('/hr-api/') && res.status() >= 400) {
      found.push(`${tag()} server call failed: ${res.status()} ${res.request().method()} ${url.replace(/^https?:\/\/[^/]+/, '')}`);
    }
  });
  return { list: () => found.slice(), clear: () => { found.length = 0; }, at: (w) => { where = w || ''; } };
}

// ── Log into the Employee Portal as Test Tester ────────────────────────────
async function loginPortal(page) {
  const s = settings();
  await page.goto('/hr_portal/');
  await expect(page.locator('#login-email')).toBeVisible();
  await page.locator('#login-email').click();
  await page.locator('#login-email').pressSequentially(s.ttEmail, { delay: 25 });   // typed like a person
  await page.locator('#login-pass').click();
  await page.locator('#login-pass').pressSequentially(s.ttPin, { delay: 60 });
  await page.locator('#login-btn').click();
  // If the network blips, the Portal shows "Could not reach HR server". A person would
  // simply click Sign in again — do the same once, and record it so blips stay visible.
  const opened = await expect(page.locator('#app')).toHaveClass(/visible/, { timeout: 15_000 }).then(() => true, () => false);
  if (!opened) {
    const msg = (await page.locator('body').innerText()).match(/Could not reach HR server[^\n]*/);
    if (!msg) {
      await expect(page.locator('#app')).toHaveClass(/visible/, { timeout: 15_000 });   // slow but fine, or a real failure with details
    } else {
      console.log(`⚠ NETWORK BLIP: Portal sign-in said "${msg[0].trim()}" — clicked Sign in again (like a person would)`);
      await page.locator('#login-btn').click();
      await expect(page.locator('#app')).toHaveClass(/visible/, { timeout: 30_000 });
    }
  }
  await closeGettingStarted(page, 5_000);          // pop-up appears a moment after sign-in
}

// ── Close the "🚀 Getting Started" pop-up new employees see ────────────────
// Every test starts in a fresh browser, so the pop-up appears on each login.
// Close it like a person would: click its ✕, then make sure it's gone.
async function closeGettingStarted(page, waitMs = 0) {
  const overlay = page.locator('#gs-overlay');
  if (waitMs > 0) {
    try { await expect(overlay).toBeVisible({ timeout: waitMs }); }
    catch { return; }                                 // didn't appear — nothing to close
  } else if (!(await overlay.isVisible())) {
    return;                                           // instant check — not showing
  }
  const dontShow = overlay.locator('#gs-dont-show');
  if (await dontShow.count()) await dontShow.check().catch(() => {});   // like an employee who's seen the tour
  await overlay.locator('button', { hasText: '✕' }).first().click();
  await expect(overlay).toBeHidden({ timeout: 5_000 });
}

// ── Text problems that should never be visible on a page ───────────────────
const BAD_TEXT = [
  { re: /\bundefined\b/, why: 'the word "undefined"' },
  { re: /\bNaN\b/,       why: '"NaN"' },
  { re: /\[object Object\]/, why: '"[object Object]"' },
  { re: /\bDEBUG:/,      why: 'a leftover "DEBUG:" message' },
];
function badTextIn(text) {
  return BAD_TEXT.filter(b => b.re.test(text)).map(b => b.why);
}

module.exports = { settings, addClickMarker, watchForProblems, loginPortal, closeGettingStarted, badTextIn };
