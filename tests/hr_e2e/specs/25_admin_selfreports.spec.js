// ADM-TOF-11 — Accepted "Running Late" reports are stored on the server (approved Sept 29).
//  1. Portal (Test Tester): Time Clock → Running Late → success message
//  2. Server: a self-reported late record exists for Test Tester, not accepted yet
//  3. HR Admin: Time Off → Self-Reported → Accept → server record hr_accepted = true
//  4. A second, separate HR Admin browser also shows it as accepted (no Accept button)
// Cleanup: /test/cleanup removes Test Tester's attendance records; leftovers verified 0.
const { test, expect, chromium } = require('@playwright/test');
const { addClickMarker, watchForProblems, loginPortal } = require('../helpers/common');
const { loginAdmin, openAdminPage } = require('../helpers/admin');
const { adminApi, getJson, postJson } = require('../helpers/api');

async function ttSelfReports(api) {
  const d = await getJson(api, '/attendance?period=all');
  return (d.records || []).filter(r => r.employee_id === process.env.HR_E2E_TT_ID && String(r.note || '').includes('(self-reported)'));
}
async function acceptButton(page, id) {
  await openAdminPage(page, 'timeoff');
  const btn = page.locator(`[onclick="acceptSelfReport('${id}')"]`).first();
  if (!(await btn.isVisible().catch(() => false))) {
    const hdr = page.getByText('Self-Reported', { exact: false }).first();
    if (await hdr.isVisible().catch(() => false)) await hdr.click();
  }
  return btn;
}

test('ADM-TOF-11 · Accepted Running Late report is saved on the server (shows in a second browser)', async ({ page, browser }, testInfo) => {
  const api = await adminApi();
  const lines = [];
  let other, id;
  await addClickMarker(page);
  const problems = watchForProblems(page, 'portal/admin');
  try {
    await postJson(api, '/test/cleanup', {});   // start clean: no old Test Tester attendance

    // 1. Portal: Running Late
    await loginPortal(page);
    problems.at('Portal → Time Clock → Running Late');
    const nav = page.locator('.sidebar .nav-item[data-page="timeclock"]').first();
    await nav.scrollIntoViewIfNeeded(); await nav.click();
    await page.locator(`[onclick="selfReportAttendance('late')"]`).first().click();
    await expect(page.locator('#self-report-success')).toBeVisible({ timeout: 15_000 });
    lines.push('✓ Portal: Test Tester tapped Running Late → success message');

    // 2. Server: report exists, not accepted
    await expect.poll(async () => (await ttSelfReports(api)).length, { timeout: 10_000 }).toBe(1);
    const rec = (await ttSelfReports(api))[0];
    id = rec.id;
    expect(!!rec.hr_accepted, 'already accepted before HR did anything').toBe(false);
    lines.push(`✓ Server: late report ${id} saved for Test Tester, not accepted yet`);

    // 3. HR Admin accepts (in a separate admin browser window)
    const adminCtx = await browser.newContext({ baseURL: process.env.HR_E2E_BASE_URL, serviceWorkers: 'block' });
    const admin = await adminCtx.newPage();
    await addClickMarker(admin);
    const aProblems = watchForProblems(admin, 'admin');
    await loginAdmin(admin);
    aProblems.at('Time Off → Self-Reported → Accept');
    const btn = await acceptButton(admin, id);
    await expect(btn).toBeVisible({ timeout: 15_000 });
    await btn.click();
    await expect.poll(async () => !!(await ttSelfReports(api)).find(r => r.id === id)?.hr_accepted, { timeout: 10_000 }).toBe(true);
    lines.push('✓ HR Admin: Accept → server record marked accepted');
    for (const p of aProblems.list()) lines.push('  ✗ ' + p);

    // 4. A second, completely separate browser sees it as accepted (no Accept button)
    other = await chromium.launch({ headless: true });
    const p2 = await (await other.newContext({ baseURL: process.env.HR_E2E_BASE_URL, serviceWorkers: 'block' })).newPage();
    await loginAdmin(p2);
    await acceptButton(p2, id);
    await p2.waitForTimeout(1500);
    await expect(p2.locator(`[onclick="acceptSelfReport('${id}')"]`), 'second browser still offers Accept (stored only in one browser)').toHaveCount(0);
    lines.push('✓ A second, separate browser shows it as already accepted (not stuck in one browser)');
  } finally {
    let cleanupLine;
    try {
      await postJson(api, '/test/cleanup', {});
      const left = (await ttSelfReports(api)).length;
      cleanupLine = left === 0 ? 'CLEANUP VERIFIED [TOF11]: 0 Test Tester self-reports left' : `CLEANUP FAILED [TOF11]: ${left} left`;
    } catch (e) { cleanupLine = `CLEANUP FAILED [TOF11]: ${e.message}`; }
    if (other) await other.close().catch(() => {});
    const probs = problems.list();
    const summary = [...lines, `Console errors / failed server calls: ${probs.length}`, ...probs.map(x => '  ✗ ' + x), cleanupLine].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await api.dispose();
    expect.soft(probs).toEqual([]);
    expect(cleanupLine).toContain('CLEANUP VERIFIED');
  }
});
