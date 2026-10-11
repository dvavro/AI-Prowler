// E2E-01 — Time-off lifecycle across both apps.
// Covers X-PTO-01…05, PRT-PTO-01…03/05, PRT-SCH-03, ADM-TOF-02…06, REG-15.
//
//  1. Portal: end-before-start is blocked (PRT-PTO-05)
//  2. Portal: request 3 vacation days (+21…+23 days) with date pickers → Pending (X-PTO-01)
//  3. HR Admin: Scheduled Task → ✅ Approve → 3 attendance days, Portal shows Approved (X-PTO-02)
//  4. HR Admin: approved → ❌ Deny → days removed, Portal shows Denied (X-PTO-03, ADM-TOF-04)
//  5. HR Admin: denied → ✅ Approve again → exactly 3 days, no duplicates (ADM-TOF-05, REG-15)
//  6. Portal: Schedule → 🗑 Delete (hide from own list) → still in HR Admin (X-PTO-04, PRT-SCH-03)
//  7. HR Admin: Remove → gone; stays gone after leaving and returning (X-PTO-05, ADM-TOF-06)
//  Cleanup: delete anything left + verify 0 requests and 0 attendance days.
const { test, expect } = require('@playwright/test');
const { watchForProblems, loginPortal } = require('../helpers/common');
const { loginAdmin, openAdminPage } = require('../helpers/admin');
const { adminApi, testTag, getJson, postJson } = require('../helpers/api');
const { openPortalWindow, openAdminWindow, closeWindow, snap, clickAndConfirm } = require('../helpers/windows');

const ymd = (d) => d.toISOString().slice(0, 10);
function daysFromToday(n) { const d = new Date(); d.setHours(12, 0, 0, 0); d.setDate(d.getDate() + n); return ymd(d); }

async function testerRequests(api, tag) {
  const d = await getJson(api, '/pto');
  return (d.requests || d || []).filter(r => r.employee_id === process.env.HR_E2E_TT_ID && String(r.notes || '').startsWith('ZZTEST') && (!tag || String(r.notes).startsWith(tag)));
}
async function ptoDays(api, start, end) {
  const d = await getJson(api, '/attendance?period=all');
  const recs = d.records || d.attendance || d || [];
  return recs.filter(a => a.employee_id === process.env.HR_E2E_TT_ID && a.status === 'pto' && a.date >= start && a.date <= end).length;
}
// A button inside the Time Off log. Sections can be collapsed, so open the section if needed.
async function logButton(a, selector, sectionTitle) {
  const b = a.locator(selector).first();
  if (!(await b.isVisible().catch(() => false))) {
    await a.getByText(sectionTitle).first().click();
    await expect(b).toBeVisible({ timeout: 10_000 });
  }
  await b.scrollIntoViewIfNeeded();
  return b;
}

test('E2E-01 · Time-off lifecycle: request → approve → deny → re-approve → hide → remove', async ({}, testInfo) => {
  const tag = testTag('E2E01');
  const start = daysFromToday(21), end = daysFromToday(23);
  const notes = `${tag} Family trip — automated test`;
  const api = await adminApi();
  const report = [];
  let portal, admin, pP, aP, reqId = null;

  try {
    await test.step('Pre-sweep leftover test time-off requests', async () => {
      const old = await testerRequests(api);
      for (const r of old) await postJson(api, `/pto/${r.id}/delete`, {});
      report.push(old.length ? `• Removed ${old.length} leftover test request(s) from earlier runs` : '• No leftover test requests');
    });

    portal = await openPortalWindow(testInfo);
    admin  = await openAdminWindow(testInfo);
    pP = watchForProblems(portal.page, 'portal');
    aP = watchForProblems(admin.page, 'admin');
    await test.step('Sign in to both apps', async () => { await loginPortal(portal.page); await loginAdmin(admin.page); });
    const p = portal.page, a = admin.page;

    await test.step('Portal: open PTO / Time Off', async () => {
      pP.at('PTO');
      const nav = p.locator('.sidebar .nav-item[data-page="pto"]').first();
      await nav.scrollIntoViewIfNeeded(); await nav.click();
      await expect(p.locator('#pto-type')).toBeVisible();
    });

    await test.step('PRT-PTO-05: end date before start is blocked', async () => {
      const before = (await testerRequests(api)).length;
      await p.locator('#pto-start').fill(end);
      await p.locator('#pto-end').fill(start);
      let msg = '';
      p.once('dialog', d => { msg = d.message(); d.accept(); });
      await p.getByRole('button', { name: 'Submit Request' }).click();
      await p.waitForTimeout(800);
      expect(msg, 'no warning shown for end-before-start').toMatch(/end date/i);
      expect((await testerRequests(api)).length, 'an invalid request was created').toBe(before);
      report.push(`✓ Portal: end-before-start blocked ("${msg}"), nothing created`);
    });

    await test.step('X-PTO-01: Portal submits 3 vacation days', async () => {
      await p.locator('#pto-type').selectOption('PTO (Vacation)');
      await p.locator('#pto-start').click();            // opens the pop-up calendar like a person would
      await p.locator('#pto-start').fill(start);
      await p.locator('#pto-end').click();
      await p.locator('#pto-end').fill(end);
      await p.locator('#pto-notes').fill(notes);
      await p.getByRole('button', { name: 'Submit Request' }).click();
      await expect(p.locator('#pto-success')).toBeVisible({ timeout: 15_000 });
      await expect(p.locator('#pto-history')).toContainText(tag, { timeout: 15_000 });
      await snap(p, testInfo, '1_portal_submitted');
      const r = (await testerRequests(api, tag))[0];
      expect(r, 'request not found on the server').toBeTruthy();
      reqId = r.id;
      expect(r.status).toBe('pending');
      expect(r.start_date).toBe(start); expect(r.end_date).toBe(end);
      expect(r.type).toBe('PTO (Vacation)');
      report.push(`✓ Portal submitted ${reqId}: ${start} → ${end}, pending, tied to Test Tester`);
    });

    await test.step('X-PTO-02 / ADM-TOF-02: HR Admin approves', async () => {
      aP.at('Scheduled Task');
      await openAdminPage(a, 'timeoff');
      await expect(a.getByText(notes).first()).toBeAttached({ timeout: 15_000 });
      const btn = await logButton(a, `[onclick*="approveTimeOff('${reqId}')"]`, 'Pending Requests');
      await snap(a, testInfo, '2_admin_pending');
      await btn.click();
      await expect.poll(async () => (await testerRequests(api, tag))[0]?.status, { timeout: 15_000 }).toBe('approved');
      expect(await ptoDays(api, start, end), 'attendance days after approve').toBe(3);
      report.push('✓ HR Admin approved → server "approved", 3 attendance days on the calendar');
    });

    await test.step('Portal shows Approved', async () => {
      await p.reload();
      await expect(p.locator('#app')).toHaveClass(/visible/, { timeout: 20_000 });
      const nav = p.locator('.sidebar .nav-item[data-page="pto"]').first();
      await nav.scrollIntoViewIfNeeded(); await nav.click();
      const hist = p.locator('#pto-history');
      await expect(hist).toContainText(tag, { timeout: 15_000 });
      await expect(hist).toContainText(/approved/i);
      report.push('✓ Portal: request shows Approved');
      await snap(p, testInfo, '3_portal_approved');
    });

    await test.step('X-PTO-03 / ADM-TOF-04: HR Admin changes Approved → Denied', async () => {
      const btn = await logButton(a, `[onclick*="denyTimeOff('${reqId}')"]`, 'Approved');
      await clickAndConfirm(a, btn);
      await expect.poll(async () => (await testerRequests(api, tag))[0]?.status, { timeout: 15_000 }).toBe('denied');
      expect(await ptoDays(api, start, end), 'attendance days after deny').toBe(0);
      report.push('✓ HR Admin: approved → denied; calendar days removed (0)');
    });

    await test.step('ADM-TOF-05 / REG-15: Denied → Approved again, no duplicate days', async () => {
      const btn = await logButton(a, `[onclick*="approveTimeOff('${reqId}')"]`, 'Denied');
      await clickAndConfirm(a, btn);
      await expect.poll(async () => (await testerRequests(api, tag))[0]?.status, { timeout: 15_000 }).toBe('approved');
      expect(await ptoDays(api, start, end), 'attendance days after re-approve (duplicates?)').toBe(3);
      report.push('✓ HR Admin: denied → approved; exactly 3 calendar days (no duplicates)');
      await snap(a, testInfo, '4_admin_reapproved');
    });

    await test.step('X-PTO-04 / PRT-SCH-03: Portal hides it from own list; HR Admin still has it', async () => {
      pP.at('Schedule');
      await p.reload();
      await expect(p.locator('#app')).toHaveClass(/visible/, { timeout: 20_000 });
      const nav = p.locator('.sidebar .nav-item[data-page="schedule"]').first();
      await nav.scrollIntoViewIfNeeded(); await nav.click();
      const del = p.locator(`[onclick*="ptoDeleteRequest('${reqId}'"]`).first();
      await expect(del).toBeVisible({ timeout: 15_000 });
      await clickAndConfirm(p, del);
      await expect(p.locator(`[onclick*="ptoDeleteRequest('${reqId}'"]`)).toHaveCount(0, { timeout: 15_000 });
      const r = (await testerRequests(api, tag))[0];
      expect(r, 'HR Admin lost the request when the employee hid it').toBeTruthy();
      expect(r.status).toBe('approved');
      expect(await ptoDays(api, start, end), 'hiding changed the calendar').toBe(3);
      report.push('✓ Portal 🗑 hid it from Test Tester\'s list; HR Admin still has it (approved, 3 days)');
    });

    await test.step('X-PTO-05 / ADM-TOF-06: HR Admin removes it; stays gone', async () => {
      const btn = await logButton(a, `[onclick*="deleteTimeOff('${reqId}')"]`, 'Approved');
      await clickAndConfirm(a, btn);
      await expect.poll(async () => (await testerRequests(api, tag)).length, { timeout: 15_000 }).toBe(0);
      expect(await ptoDays(api, start, end), 'calendar days left after remove').toBe(0);
      await openAdminPage(a, 'employees');
      await openAdminPage(a, 'timeoff');
      await a.waitForTimeout(1500);
      await expect(a.getByText(notes)).toHaveCount(0);
      report.push('✓ HR Admin Remove: gone from server + calendar, and still gone after leaving and returning');
      await snap(a, testInfo, '5_admin_removed');
      reqId = null;
    });

  } finally {
    let cleanupLine;
    try {
      for (const r of await testerRequests(api)) await postJson(api, `/pto/${r.id}/delete`, {});
      const left = (await testerRequests(api)).length;
      const days = await ptoDays(api, start, end);
      cleanupLine = (left === 0 && days === 0)
        ? 'CLEANUP VERIFIED [E2E01]: 0 test requests, 0 test calendar days left'
        : `CLEANUP FAILED [E2E01]: ${left} request(s), ${days} calendar day(s) left`;
    } catch (e) { cleanupLine = `CLEANUP FAILED [E2E01]: ${e.message}`; }
    const problems = [...(pP ? pP.list() : []), ...(aP ? aP.list() : [])];
    const summary = [...report, `Console errors / failed server calls: ${problems.length}`,
      ...problems.map(x => '  ✗ ' + x), cleanupLine].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await closeWindow(portal, testInfo); await closeWindow(admin, testInfo);
    await api.dispose();
    expect.soft(problems, 'Console errors or failed server calls').toEqual([]);
    expect(cleanupLine).toContain('CLEANUP VERIFIED');
  }
});
