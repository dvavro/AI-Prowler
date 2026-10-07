// REG-17 — 🚀 Getting Started pop-up: closing it with ✕ must keep it closed.
// Bug found Sept 28 by the watch-mode run: on a page reload, startup ran twice and
// scheduled two pop-up timers, so the pop-up reopened right after it was closed.
const { test, expect } = require('@playwright/test');
const { settings, addClickMarker, watchForProblems } = require('../helpers/common');

test('REG-18 · Quiet retry: a network blip on loading data is retried; sends are NOT retried', async ({ page }, testInfo) => {
  const { loginPortal } = require('../helpers/common');
  const { adminApi, allMessages, postJson, testTag } = require('../helpers/api');
  await addClickMarker(page);
  const lines = [];
  const api = await adminApi();
  const tag = testTag('REG18');

  await loginPortal(page);

  // 1. Loading data: make the FIRST /portal/me fail with no answer; the Portal should retry quietly
  let meCalls = 0;
  await page.route('**/hr-api/portal/me', async (route) => {
    meCalls++;
    if (meCalls === 1) return route.abort('failed');       // simulated network blip
    return route.continue();
  });
  await page.reload();
  await expect(page.locator('#app')).toHaveClass(/visible/, { timeout: 20_000 });
  const nav = page.locator('.sidebar .nav-item[data-page="portfolio"]').first();
  await nav.scrollIntoViewIfNeeded(); await nav.click();
  await expect.poll(async () => (await page.locator('#emp-id').innerText()).trim(), { timeout: 15_000 }).not.toBe('—');
  expect(meCalls, 'profile load was not retried after the blip').toBeGreaterThanOrEqual(2);
  lines.push(`✓ Profile load failed once (simulated blip) → retried quietly (${meCalls} tries) → Portfolio filled in`);
  await page.unroute('**/hr-api/portal/me');

  // 2. Sending: make a message send fail with no answer; the Portal must NOT send it twice
  let postCalls = 0;
  await page.route('**/hr-api/messages', async (route) => {
    if (route.request().method() !== 'POST') return route.continue();
    postCalls++;
    return route.abort('failed');
  });
  const navM = page.locator('.sidebar .nav-item[data-page="messages"]').first();
  await navM.scrollIntoViewIfNeeded(); await navM.click();
  await page.locator('#portal-msg-subject').fill(`${tag} should not duplicate`);
  await page.locator('#portal-msg-body').fill('Automated retry test — safe to ignore.');
  await page.locator('#portal-msg-btn').click();
  await page.waitForTimeout(2500);
  expect(postCalls, 'a message send was retried (could create duplicates)').toBe(1);
  lines.push('✓ Message send failed (simulated blip) → NOT retried (1 try) → no duplicate risk');
  await page.unroute('**/hr-api/messages');

  // Cleanup: nothing should have reached the server, but verify
  for (const m of (await allMessages(api)).filter(m => String(m.subject || '').startsWith(tag))) await postJson(api, '/messages/delete', { id: m.id, box: 'inbox' });
  const left = (await allMessages(api)).filter(m => String(m.subject || '').startsWith(tag)).length;
  lines.push(left === 0 ? 'CLEANUP VERIFIED [REG18]: 0 test messages on the server' : `CLEANUP FAILED [REG18]: ${left} left`);
  await api.dispose();
  const summary = lines.join('\n');
  await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
  console.log('\n' + summary + '\n');
  expect(left).toBe(0);
});

test('REG-21 · Bug #20: "today" is the LOCAL date in both apps, even at 8 PM in Arizona', async ({ browser }, testInfo) => {
  const lines = [];
  // 8:00 PM Sept 30 in Arizona = 03:00 Oct 1 in UTC — the exact time the old code got wrong
  const ctx = await browser.newContext({ baseURL: process.env.HR_E2E_BASE_URL, timezoneId: 'America/Phoenix', serviceWorkers: 'block' });
  const page = await ctx.newPage();
  await page.clock.setFixedTime(new Date('2026-10-01T03:00:00Z'));
  for (const [app, path] of [['Portal', '/hr_portal/'], ['HR Admin', '/hr_admin/']]) {
    await page.goto(path);
    const r = await page.evaluate(() => ({
      helper: typeof _localYMD === 'function' ? _localYMD() : null,
      utcWouldSay: new Date().toISOString().slice(0, 10),
      source: document.documentElement.outerHTML,
    }));
    expect(r.helper, `${app}: local "today" helper missing`).not.toBeNull();
    expect(r.helper, `${app}: "today" at 8 PM Arizona`).toBe('2026-09-30');
    const leftovers = (r.source.match(/new Date\(\)\.toISOString\(\)\.(?:slice|substring|substr)\(0,\s*10\)/g) || []).length;
    expect(leftovers, `${app}: code still computes "today" in UTC in ${leftovers} place(s)`).toBe(0);
    lines.push(`✓ ${app}: at 8 PM Arizona, today = ${r.helper} (UTC would wrongly say ${r.utcWouldSay}); 0 UTC-"today" spots left in the code`);
  }
  await ctx.close();
  const summary = lines.join('\n');
  await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
  console.log('\n' + summary + '\n');
});

test('REG-17 · Getting Started pop-up stays closed after ✕, and "Don\'t show again" sticks', async ({ page }, testInfo) => {
  const s = settings();
  await addClickMarker(page);
  const problems = watchForProblems(page, 'portal');
  const overlay = page.locator('#gs-overlay');
  const lines = [];

  await test.step('Sign in (without the helper, so the pop-up is handled by hand here)', async () => {
    await page.goto('/hr_portal/');
    await page.locator('#login-email').fill(s.ttEmail);
    await page.locator('#login-pass').fill(s.ttPin);
    await page.locator('#login-btn').click();
    await expect(page.locator('#app')).toHaveClass(/visible/, { timeout: 30_000 });
  });

  await test.step('Pop-up appears for a new session; close with ✕ (no "Don\'t show again")', async () => {
    await expect(overlay).toBeVisible({ timeout: 8_000 });
    await overlay.locator('button', { hasText: '✕' }).first().click();
    await expect(overlay).toBeHidden();
    lines.push('✓ Pop-up shown on sign-in; ✕ closed it');
  });

  await test.step('Reload → pop-up shows once; after ✕ it must NOT reopen', async () => {
    await page.reload();
    await expect(page.locator('#app')).toHaveClass(/visible/, { timeout: 20_000 });
    await expect(overlay).toBeVisible({ timeout: 8_000 });
    await overlay.locator('button', { hasText: '✕' }).first().click();
    await expect(overlay).toBeHidden();
    await page.waitForTimeout(3000);                 // the bug reopened it within ~1 s
    await expect(overlay, 'pop-up reopened by itself after ✕ (double timer bug)').toBeHidden();
    lines.push('✓ After reload: shown once, ✕ closed it, stayed closed for 3 s');
  });

  await test.step('"Don\'t show again" → reload → pop-up stays away', async () => {
    await page.reload();
    await expect(page.locator('#app')).toHaveClass(/visible/, { timeout: 20_000 });
    await expect(overlay).toBeVisible({ timeout: 8_000 });
    await overlay.locator('#gs-dont-show').check();
    await overlay.locator('button', { hasText: '✕' }).first().click();
    await page.reload();
    await expect(page.locator('#app')).toHaveClass(/visible/, { timeout: 20_000 });
    await page.waitForTimeout(2500);
    await expect(overlay, '"Don\'t show again" was ignored').toBeHidden();
    lines.push('✓ "Don\'t show again" + ✕ → after reload the pop-up stays away');
  });

  const probs = problems.list();
  const summary = [...lines, `Console errors / failed server calls: ${probs.length}`, ...probs.map(x => '  ✗ ' + x)].join('\n');
  await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
  console.log('\n' + summary + '\n');
  expect.soft(probs).toEqual([]);
});
