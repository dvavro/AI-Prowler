// E2E-07 — Manager view: a manager sees their team and who is out today (+ bug #25 guard).
//  Setup (API): ZZTEST manager Kevin + ZZTEST report Maria; HR assigns Maria to Kevin;
//               Maria has APPROVED time off TODAY
//  1. Kevin signs into the Portal → "👥 My Team" is in his menu → opens it
//  2. Team Members 1 · Out / PTO 1 · Active Today 0 · Maria's card says "🏖 Out today"
//     (bug #25: in Arizona, someone off TODAY never showed as out)
//  3. Test Tester (not a manager) does NOT see My Team
// Cleanup: time off + both test employees removed, verified.
const { test, expect } = require('@playwright/test');
const { addClickMarker, watchForProblems, loginPortal, closeGettingStarted } = require('../helpers/common');
const { adminApi, testTag, getJson, postJson, deleteEmployee, allEmployees, patchEmployee } = require('../helpers/api');

const isZZ = (e) => String(e.first_name || '').startsWith('ZZTEST');
const localYmd = () => { const n = new Date(); return `${n.getFullYear()}-${String(n.getMonth() + 1).padStart(2, '0')}-${String(n.getDate()).padStart(2, '0')}`; };

test('E2E-07 · Manager sees their team; a report off today shows "Out today"', async ({ page, browser }, testInfo) => {
  const tag = testTag('E2E07');
  const api = await adminApi();
  const lines = [];
  const pin = String(Math.floor(10000000 + Math.random() * 89999999));
  const mgrEmail = 'jamievavroaiprowler+zz-manager@gmail.com';
  const today = localYmd();
  let mgrId, repId;
  const problems = [];

  try {
    // Setup
    for (const e of (await allEmployees(api)).filter(isZZ)) await deleteEmployee(api, e.id);
    const mk = async (first, last, email, title) => {
      const r = await postJson(api, '/employees', {
        personal: { first_name: first, last_name: last, personal_email: email },
        employment: { title, department: 'ZZTEST Operations', start_date: '2026-01-05' }, compensation: {},
      });
      return (r.data.employee || r.data).id;
    };
    mgrId = await mk('ZZTEST', `Kevin ${tag.slice(-6)}`, mgrEmail, 'Shift Supervisor');
    repId = await mk('ZZTEST', `Maria ${tag.slice(-6)}`, 'jamievavroaiprowler+zz-report@gmail.com', 'Operations Associate');
    await patchEmployee(api, mgrId, { direct_reports: [repId] });
    await patchEmployee(api, repId, { manager_id: mgrId });
    expect((await postJson(api, '/portal/set-pin', { employee_id: mgrId, pin })).status).toBe(200);
    const pr = await postJson(api, '/pto/request', { employee_id: repId, type: 'PTO (Vacation)', start_date: today, end_date: today, notes: `${tag} out today` });
    expect(pr.status, 'could not create the setup time off').toBeLessThan(300);
    await postJson(api, `/pto/${pr.data.request.id}/approve`, {});
    lines.push(`• Setup: manager Kevin (${mgrId}) with report Maria (${repId}); Maria approved off today (${today})`);

    // 1. Manager signs in → My Team
    const ctx = await browser.newContext({ baseURL: process.env.HR_E2E_BASE_URL, serviceWorkers: 'block' });
    const m = await ctx.newPage();
    await addClickMarker(m);
    const watch = watchForProblems(m, 'manager');
    await m.goto('/hr_portal/');
    await m.locator('#login-email').fill(mgrEmail);
    await m.locator('#login-pass').fill(pin);
    await m.locator('#login-btn').click();
    await expect(m.locator('#app')).toHaveClass(/visible/, { timeout: 20_000 });
    await closeGettingStarted(m, 5_000);
    const nav = m.locator('.sidebar .nav-item[data-page="my-team"]').first();
    await expect(nav, 'a manager should see "My Team" in the menu').toBeVisible({ timeout: 10_000 });
    watch.at('My Team');
    await nav.scrollIntoViewIfNeeded(); await nav.click();
    await m.evaluate(() => renderMyTeam());
    lines.push('✓ Manager signed in; "👥 My Team" is in the menu and opens');

    // 2. Counts + "Out today"
    await expect(m.locator('#team-stat-total')).toHaveText('1', { timeout: 10_000 });
    await expect(m.locator('#team-stat-pto'), 'report off today not counted as out (bug #25)').toHaveText('1');
    await expect(m.locator('#team-stat-active')).toHaveText('0');
    const card = m.locator('#my-team-list > div > div', { hasText: `Maria ${tag.slice(-6)}` }).first();
    await expect(card).toBeVisible();
    await expect(card, 'Maria is off today but her card does not say so (bug #25)').toContainText('Out today');
    lines.push('✓ My Team: Team Members 1 · Out / PTO 1 · Active Today 0 · Maria shows "🏖 Out today" (bug #25 fixed)');
    const shot = testInfo.outputPath('my_team.png');
    await m.screenshot({ path: shot });
    await testInfo.attach('My Team', { path: shot, contentType: 'image/png' });
    problems.push(...watch.list());
    await ctx.close();

    // 3. Non-manager doesn't see My Team
    await addClickMarker(page);
    await loginPortal(page);
    await expect(page.locator('.sidebar .nav-item[data-page="my-team"]').first(), 'a non-manager can see My Team').toBeHidden();
    lines.push('✓ Test Tester (not a manager) does not see My Team');
  } finally {
    let cleanupLine;
    try {
      const reqs = ((await getJson(api, '/pto')).requests || []).filter(r => String(r.notes || '').includes(tag));
      for (const r of reqs) await postJson(api, `/pto/${r.id}/delete`, {});
      for (const e of (await allEmployees(api)).filter(isZZ)) await deleteEmployee(api, e.id);
      const leftEmp = (await allEmployees(api)).filter(isZZ).length;
      const leftReq = ((await getJson(api, '/pto')).requests || []).filter(r => String(r.notes || '').includes(tag)).length;
      cleanupLine = (leftEmp + leftReq) === 0 ? 'CLEANUP VERIFIED [E2E07]: time off + test manager and report removed'
                                              : `CLEANUP FAILED [E2E07]: employees ${leftEmp}, requests ${leftReq}`;
    } catch (e) { cleanupLine = `CLEANUP FAILED [E2E07]: ${e.message}`; }
    const summary = [...lines, `Console errors / failed server calls: ${problems.length}`, ...problems.map(x => '  ✗ ' + x), cleanupLine].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await api.dispose();
    expect.soft(problems).toEqual([]);
    expect(cleanupLine).toContain('CLEANUP VERIFIED');
  }
});
