// HR Admin → 📋 Scheduled Task (Time Off) tools.
//  ADM-TOF-07  Calendar event saved on the SERVER: add in one browser, see it in a second, separate browser
//  ADM-TOF-10  Bug #12: "+ Add Event → Time off" for an employee creates a real Pending request (used to crash)
//  ADM-TOF-09  Bug #13: Balances count approved "PTO (Vacation)" days (used to always show 0 used)
//  ADM-TOF-08  Every time-off sub-tab opens without errors
// Cleanup: test events and requests deleted, verified.
const { test, expect, chromium } = require('@playwright/test');
const { addClickMarker, watchForProblems } = require('../helpers/common');
const { loginAdmin, openAdminPage } = require('../helpers/admin');
const { adminApi, testTag, getJson, postJson } = require('../helpers/api');

const ymd = (d) => d.toISOString().slice(0, 10);
const todayNoon = () => { const d = new Date(); d.setHours(12, 0, 0, 0); return d; };
async function events(api) { return (await getJson(api, '/calendar/events')).events || []; }
async function ttRequests(api, tag) {
  const d = await getJson(api, '/pto');
  return (d.requests || []).filter(r => r.employee_id === process.env.HR_E2E_TT_ID && String(r.notes || '').includes(tag));
}
async function openAddEvent(page) {
  await openAdminPage(page, 'timeoff');
  await page.locator('[onclick="openAddCalendarEvent()"]').first().click();
  await expect(page.locator('#ce-title')).toBeVisible();
}

test('ADM-TOF-07 · Calendar event is saved on the server (shows in a second browser)', async ({ page }, testInfo) => {
  const tag = testTag('TOF07');
  const title = `${tag} Team Meeting`;
  const api = await adminApi();
  const lines = [];
  await addClickMarker(page);
  const problems = watchForProblems(page, 'admin');
  let other;
  try {
    await loginAdmin(page);
    problems.at('Time Off → Add Event');
    await openAddEvent(page);
    const type = await page.locator('#ce-type').evaluate(s => [...s.options].map(o => o.value).find(v => v && v !== 'timeoff'));
    await page.locator('#ce-type').selectOption(type);
    await page.locator('#ce-title').fill(title);
    await page.locator('#ce-start').fill(ymd(todayNoon()));
    await page.locator('#ce-notes').fill('Automated test — safe to ignore');
    await page.locator('[onclick="saveCalendarEvent()"]').click();
    await expect.poll(async () => (await events(api)).some(e => e.title === title), { timeout: 10_000 }).toBe(true);
    lines.push(`✓ Added "${title.replace(tag + ' ', '')}" (type "${type}") → saved on the server`);

    // A brand-new, separate browser (no shared storage) must see it too
    const browser2 = await chromium.launch({ headless: true });
    const ctx2 = await browser2.newContext({ baseURL: process.env.HR_E2E_BASE_URL, serviceWorkers: 'block' });
    const p2 = await ctx2.newPage();
    other = browser2;
    await loginAdmin(p2);
    await openAdminPage(p2, 'timeoff');
    await expect(p2.locator('#tab-timeoff')).toContainText(title, { timeout: 15_000 });
    lines.push('✓ A second, separate browser shows the event on its calendar (not stuck in one browser)');
  } finally {
    for (const e of (await events(api)).filter(e => String(e.title).startsWith('ZZTEST'))) await postJson(api, `/calendar/events/${e.id}/delete`, {});
    const left = (await events(api)).filter(e => String(e.title).startsWith('ZZTEST')).length;
    lines.push(left === 0 ? 'CLEANUP VERIFIED [TOF07]: 0 test events left' : `CLEANUP FAILED [TOF07]: ${left} left`);
    if (other) await other.close().catch(() => {});
    const probs = problems.list();
    const summary = [...lines, `Console errors / failed server calls: ${probs.length}`, ...probs.map(x => '  ✗ ' + x)].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await api.dispose();
    expect.soft(probs).toEqual([]);
    expect(left).toBe(0);
  }
});

test('ADM-TOF-10 · Bug #12: "+ Add Event → Time off" creates a real Pending request', async ({ page }, testInfo) => {
  const tag = testTag('TOF10');
  const api = await adminApi();
  const lines = [];
  await addClickMarker(page);
  const problems = watchForProblems(page, 'admin');
  try {
    await loginAdmin(page);
    problems.at('Time Off → Add Event → Time off');
    await openAddEvent(page);
    await page.locator('#ce-type').selectOption('timeoff');
    await expect(page.locator('#ce-emp')).toBeVisible();
    await page.locator('#ce-emp').selectOption(process.env.HR_E2E_TT_ID);
    const start = todayNoon(); start.setDate(start.getDate() + 40);
    await page.locator('#ce-title').fill(`${tag} Doctor appointment`);
    await page.locator('#ce-start').fill(ymd(start));
    await page.locator('[onclick="saveCalendarEvent()"]').click();
    await expect.poll(async () => (await ttRequests(api, tag)).length, { timeout: 10_000, message: 'no request reached the server (bug #12)' }).toBe(1);
    const r = (await ttRequests(api, tag))[0];
    expect(r.status).toBe('pending');
    expect(r.start_date).toBe(ymd(start));
    lines.push(`✓ Add Event → Time off for Test Tester → server request ${r.id}, pending, ${r.start_date}`);
  } finally {
    for (const r of await ttRequests(api, tag)) await postJson(api, `/pto/${r.id}/delete`, {});
    const left = (await ttRequests(api, tag)).length;
    lines.push(left === 0 ? 'CLEANUP VERIFIED [TOF10]: 0 test requests left' : `CLEANUP FAILED [TOF10]: ${left} left`);
    const probs = problems.list();
    const summary = [...lines, `Console errors / failed server calls: ${probs.length}`, ...probs.map(x => '  ✗ ' + x)].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await api.dispose();
    expect.soft(probs).toEqual([]);
    expect(left).toBe(0);
  }
});

test('ADM-TOF-09 · Bug #13: Balances count approved "PTO (Vacation)" days; ADM-TOF-08 sub-tabs open', async ({ page }, testInfo) => {
  const tag = testTag('TOF09');
  const api = await adminApi();
  const lines = [];
  await addClickMarker(page);
  const problems = watchForProblems(page, 'admin');
  try {
    // Clear leftover test time off (e.g. a run cut off by a server restart) so it can't skew the count
    const d0 = await getJson(api, '/pto');
    const old = (d0.requests || []).filter(r => r.employee_id === process.env.HR_E2E_TT_ID && String(r.notes || '').startsWith('ZZTEST'));
    for (const r of old) await postJson(api, `/pto/${r.id}/delete`, {});
    if (old.length) lines.push(`• Pre-sweep: removed ${old.length} leftover test request(s) (${old.map(r => r.id).join(', ')})`);

    // Setup: 3 approved vacation weekdays for Test Tester (next Mon–Wed)
    const mon = todayNoon(); mon.setDate(mon.getDate() + ((8 - mon.getDay()) % 7 || 7) + 21);
    const wed = new Date(mon); wed.setDate(wed.getDate() + 2);
    const cr = await postJson(api, '/pto/request', { employee_id: process.env.HR_E2E_TT_ID, type: 'PTO (Vacation)', start_date: ymd(mon), end_date: ymd(wed), notes: `${tag} balance check` });
    expect(cr.status, 'could not create the setup request').toBeLessThan(300);
    await postJson(api, `/pto/${cr.data.request.id}/approve`, {});
    lines.push(`• Setup: approved 3 vacation weekdays for Test Tester (${ymd(mon)} → ${ymd(wed)})`);

    await loginAdmin(page);
    await openAdminPage(page, 'timeoff');
    problems.at('Time Off → Balances');
    await page.locator(`[onclick*="setTimeOffFilter('balances'"]`).first().click();
    // Read Test Tester's whole Balances card: the smallest block that has both the name and "days used"
    const cardText = async () => page.evaluate((name) => {
      const hits = [...document.querySelectorAll('#tab-timeoff div')]
        .map(d => d.innerText || '').filter(t => t.includes(name) && t.includes('days used'));
      return hits.sort((a, b) => a.length - b.length)[0] || '';
    }, process.env.HR_E2E_TT_NAME || 'Test Tester');
    await expect.poll(cardText, { timeout: 10_000, message: 'Balances should count the 3 approved vacation days (bugs #13/#14)' }).toContain('3/10 days used');
    lines.push('✓ Balances: Test Tester shows 3/10 vacation days used (was always 0 before the fix)');

    // REG-20 (bug #14): the day counter must count the right weekdays in Arizona time
    const counts = await page.evaluate(() => ({
      monWed: calcBusinessDays('2026-10-26', '2026-10-28'),   // Mon–Wed
      friMon: calcBusinessDays('2026-10-30', '2026-11-02'),   // Fri–Mon (skips the weekend)
      oneTue: calcBusinessDays('2026-10-27', '2026-10-27'),   // a single Tuesday
    }));
    expect(counts, 'day counter is off (bug #14 — dates read as UTC)').toEqual({ monWed: 3, friMon: 2, oneTue: 1 });
    lines.push('✓ Day counter: Mon–Wed = 3, Fri–Mon = 2, single Tuesday = 1 (REG-20)');

    // ADM-TOF-08: every sub-tab opens
    const chips = page.locator('#tab-timeoff [onclick*="setTimeOffFilter("]');
    const n = await chips.count();
    const names = [];
    for (let i = 0; i < n; i++) { const c = chips.nth(i); const t = (await c.innerText()).trim(); if (!t) continue; problems.at(`Time Off → ${t}`); await c.click(); await page.waitForTimeout(400); names.push(t); }
    lines.push(`✓ Sub-tabs opened: ${names.join(', ')}`);
  } finally {
    for (const r of await ttRequests(api, tag)) await postJson(api, `/pto/${r.id}/delete`, {});
    const left = (await ttRequests(api, tag)).length;
    lines.push(left === 0 ? 'CLEANUP VERIFIED [TOF09]: test request + its calendar days removed' : `CLEANUP FAILED [TOF09]: ${left} left`);
    const probs = problems.list();
    const summary = [...lines, `Console errors / failed server calls: ${probs.length}`, ...probs.map(x => '  ✗ ' + x)].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await api.dispose();
    expect.soft(probs).toEqual([]);
    expect(left).toBe(0);
  }
});
