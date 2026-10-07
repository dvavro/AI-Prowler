// E2E-02 / X-TC-01 / PRT-TC-01·02 / PRT-POR-05 / X-TC-02 — A workday: clock in → clock out → HR sees it.
//  1. Pre-sweep: remove any leftover Test Tester clock entries (admin-only /test/cleanup)
//  2. Portal: Time Clock → Clock In (location allowed, like an employee tapping "Allow")
//  3. Server: exactly one more clock-in, shift open
//  4. Portal: Clock Out → server: one more clock-out, shift closed, hours recorded
//  5. Portal Portfolio: "Days Clocked" tile shows the new in/out counts
//  6. HR Admin: 📍 Clock In/Out Log shows Test Tester's shift
//  7. Cleanup via /test/cleanup, then /test/leftovers must be all zero
const { test, expect } = require('@playwright/test');
const { watchForProblems, loginPortal } = require('../helpers/common');
const { loginAdmin, openAdminPage } = require('../helpers/admin');
const { adminApi, employeeApi, getJson, postJson } = require('../helpers/api');
const { openPortalWindow, openAdminWindow, closeWindow, snap } = require('../helpers/windows');

const CHANDLER = { latitude: 33.3062, longitude: -111.8413 };

async function leftovers(api) { return (await getJson(api, '/test/leftovers')).leftovers || {}; }
const total = (o) => Object.values(o || {}).reduce((a, b) => a + (b || 0), 0);

test('E2E-02 · A workday: Portal clock in/out → server → Portfolio → HR Admin log', async ({}, testInfo) => {
  const api = await adminApi();
  const report = [];
  let portal, admin, pP, aP, emp;

  try {
    await test.step('Pre-sweep: no leftover Test Tester clock entries', async () => {
      const lo = await getJson(api, '/test/leftovers').catch(e => { throw new Error('Server has no /test/leftovers route yet — deploy the latest ai_prowler_mcp.py and restart AI-Prowler. (' + e.message + ')'); });
      if (total(lo.leftovers)) await postJson(api, '/test/cleanup', {});
      expect(total(await leftovers(api)), 'could not clear old test clock entries').toBe(0);
      report.push(`• Pre-sweep: ${total(lo.leftovers)} leftover test record(s) cleared`);
    });

    emp = await employeeApi();
    const before = await getJson(emp, '/timeclock/summary');

    portal = await openPortalWindow(testInfo); admin = await openAdminWindow(testInfo);
    await portal.context.grantPermissions(['geolocation']);
    await portal.context.setGeolocation(CHANDLER);
    pP = watchForProblems(portal.page, 'portal'); aP = watchForProblems(admin.page, 'admin');
    await test.step('Sign in to both apps', async () => { await loginPortal(portal.page); await loginAdmin(admin.page); });
    const p = portal.page, a = admin.page;

    await test.step('PRT-TC-01: Clock In', async () => {
      pP.at('Time Clock');
      const nav = p.locator('.sidebar .nav-item[data-page="timeclock"]').first();
      await nav.scrollIntoViewIfNeeded(); await nav.click();
      const btn = p.locator('#clock-btn');
      await expect(btn).toHaveText(/Clock In/i);
      await btn.click();
      await expect(btn).toHaveText(/Clock Out/i, { timeout: 20_000 });
      await expect(p.locator('#clock-status-text')).not.toHaveText(/Not clocked in/i);
      const s = await getJson(emp, '/timeclock/summary');
      expect(s.clock_ins, 'server clock-in count').toBe(before.clock_ins + 1);
      expect(s.clock_outs, 'shift should still be open').toBe(before.clock_outs);
      report.push(`✓ Clock In: button → "Clock Out"; server clock-ins ${before.clock_ins} → ${s.clock_ins}, shift open`);
      await snap(p, testInfo, '1_clocked_in');
    });

    await p.waitForTimeout(3000);   // a short "shift"

    await test.step('PRT-TC-02: Clock Out', async () => {
      const btn = p.locator('#clock-btn');
      await btn.click();
      await expect(btn).toHaveText(/Clock In/i, { timeout: 20_000 });
      const s = await getJson(emp, '/timeclock/summary');
      expect(s.clock_outs, 'server clock-out count').toBe(before.clock_outs + 1);
      const last = ((await getJson(emp, '/timeclock/mine')).entries || [])[0];
      expect(last && last.clock_in && last.clock_out, 'latest shift has both times').toBeTruthy();
      const hasLoc = !!(last.location || last.lat || last.latitude || (last.clock_in_location));
      report.push(`✓ Clock Out: server clock-outs ${before.clock_outs} → ${s.clock_outs}; shift ${last.clock_in} → ${last.clock_out}${hasLoc ? ' (location recorded)' : ''}`);
      await snap(p, testInfo, '2_clocked_out');
    });

    await test.step('PRT-POR-05 / X-TC-02: Portfolio "Days Clocked" shows the new counts', async () => {
      const s = await getJson(emp, '/timeclock/summary');
      const nav = p.locator('.sidebar .nav-item[data-page="portfolio"]').first();
      await nav.scrollIntoViewIfNeeded(); await nav.click();
      await expect(p.locator('#stat-clock-inout')).toHaveText(`${s.clock_ins} in · ${s.clock_outs} out`, { timeout: 15_000 });
      await expect(p.locator('#stat-clock-days')).toHaveText(String(s.days_clocked));
      report.push(`✓ Portfolio: "${s.days_clocked}" days, "${s.clock_ins} in · ${s.clock_outs} out" — matches the server`);
    });

    await test.step('X-TC-01: HR Admin Clock In/Out Log shows the shift', async () => {
      aP.at('Clock In/Out Log');
      await openAdminPage(a, 'clocklog');
      await expect(a.locator('#tab-clocklog')).toContainText(/Test Tester/, { timeout: 15_000 });
      report.push('✓ HR Admin: 📍 Clock In/Out Log lists Test Tester\'s shift');
      await snap(a, testInfo, '3_admin_clocklog');
    });

  } finally {
    let cleanupLine;
    try {
      const del = await postJson(api, '/test/cleanup', {});
      const left = await leftovers(api);
      cleanupLine = total(left) === 0
        ? `CLEANUP VERIFIED [E2E02]: removed ${JSON.stringify(del.data.deleted || {})}; 0 Test Tester clock/attendance records left`
        : `CLEANUP FAILED [E2E02]: left ${JSON.stringify(left)}`;
    } catch (e) { cleanupLine = `CLEANUP FAILED [E2E02]: ${e.message}`; }
    const problems = [...(pP ? pP.list() : []), ...(aP ? aP.list() : [])];
    const summary = [...report, `Console errors / failed server calls: ${problems.length}`,
      ...problems.map(x => '  ✗ ' + x), cleanupLine].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await closeWindow(portal, testInfo); await closeWindow(admin, testInfo);
    if (emp) await emp.dispose();
    await api.dispose();
    expect.soft(problems, 'Console errors or failed server calls').toEqual([]);
    expect(cleanupLine).toContain('CLEANUP VERIFIED');
  }
});
