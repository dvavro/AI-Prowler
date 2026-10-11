// E2E-06 / X-INC-01 / PRT-INC-01 — Incident report round trip.
//  1. Portal: + New Incident Report → fill required fields → Submit
//  2. Server: saved as incident_report, tied to Test Tester's sign-in, status open
//  3. Portal: My Submitted Reports lists it
//  4. HR Admin: 🚨 Incident Reports shows it → open → Under Review → Resolved
//  5. Portal: shows each new status
//  6. HR Admin: 🗑 Delete → gone from server and Portal (cleanup verified)
const { test, expect } = require('@playwright/test');
const { watchForProblems, loginPortal } = require('../helpers/common');
const { loginAdmin, openAdminPage } = require('../helpers/admin');
const { adminApi, testTag, allMessages, postJson } = require('../helpers/api');
const { openPortalWindow, openAdminWindow, closeWindow, snap, clickAndConfirm } = require('../helpers/windows');

const today = () => { const d = new Date(); d.setHours(12); return d.toISOString().slice(0, 10); };
async function testerReports(api, tag) {
  return (await allMessages(api)).filter(m => m.message_type === 'incident_report'
    && m.employee_id === process.env.HR_E2E_TT_ID
    && JSON.stringify(m.incident_data || {}).includes(tag || 'ZZTEST'));
}

test('E2E-06 · Incident report: Portal files → HR reviews → status back to Portal', async ({}, testInfo) => {
  const tag = testTag('E2E06');
  const description = `${tag} Slipped on a wet spot near the loading dock. No injury — automated test.`;
  const api = await adminApi();
  const report = [];
  let portal, admin, pP, aP, id = null;

  try {
    await test.step('Pre-sweep leftover test incident reports', async () => {
      const old = await testerReports(api);
      for (const m of old) await postJson(api, '/messages/delete', { id: m.id, box: 'inbox' });
      report.push(old.length ? `• Removed ${old.length} leftover test report(s)` : '• No leftover test reports');
    });

    portal = await openPortalWindow(testInfo); admin = await openAdminWindow(testInfo);
    pP = watchForProblems(portal.page, 'portal'); aP = watchForProblems(admin.page, 'admin');
    await test.step('Sign in to both apps', async () => { await loginPortal(portal.page); await loginAdmin(admin.page); });
    const p = portal.page, a = admin.page;

    await test.step('Portal: file an incident report', async () => {
      pP.at('Incident Reports');
      const nav = p.locator('.sidebar .nav-item[data-page="incident-reports"]').first();
      await nav.scrollIntoViewIfNeeded(); await nav.click();
      await p.getByRole('button', { name: /New Incident Report/i }).first().click();
      await expect(p.locator('#ir_name')).toBeVisible();
      await p.locator('#ir_name').fill('Test Tester');
      await p.locator('#ir_date').fill(today());
      await p.locator('#ir_location').fill(`${tag} Loading dock`);
      await p.locator('#ir_type').selectOption({ index: 1 });
      await p.locator('#ir_severity').selectOption({ index: 1 });
      await p.locator('#ir_description').fill(description);
      await p.locator('#ir_w1').fill('ZZTEST Maria Lopez');
      await snap(p, testInfo, '1_portal_form');
      await p.locator('#incidentSubmitBtn').click();
      await expect(p.locator('#incidentSuccess')).toBeVisible({ timeout: 15_000 });
      report.push('✓ Portal: report submitted, success message shown');
    });

    await test.step('Server: saved as an incident report tied to Test Tester', async () => {
      await expect.poll(async () => (await testerReports(api, tag)).length, { timeout: 10_000 }).toBe(1);
      const m = (await testerReports(api, tag))[0];
      id = m.id;
      expect(m.sender_name).toBe(process.env.HR_E2E_TT_NAME || 'Test Tester');
      expect(m.hr_status || 'open').toBe('open');
      expect(m.incident_data.description).toBe(description);
      report.push(`✓ Server: ${id} saved as incident_report, from ${m.sender_name} (${m.employee_id}), status open`);
    });

    const list = p.locator('#sent-reports-list');
    await test.step('Portal: My Submitted Reports lists it', async () => {
      await p.evaluate(() => { try { loadSentReports(); } catch (e) {} });   // same as the page's refresh
      await expect(list).toContainText(/loading dock|Incident/i, { timeout: 15_000 });
      report.push('✓ Portal: report appears in My Submitted Reports');
      await snap(p, testInfo, '2_portal_list');
    });

    await test.step('HR Admin: sees it → Under Review → Resolved', async () => {
      aP.at('Incident Reports');
      await openAdminPage(a, 'incidents');
      // Each row has TWO things with the report ID: the row (opens details) and a 🗑 delete
      // button in its corner. Click the row itself.
      const card = a.locator(`[onclick="openIncidentDetail('${id}')"]`).first();
      await expect(card).toBeVisible({ timeout: 15_000 });
      await snap(a, testInfo, '3_admin_list');
      await card.click();
      await a.locator(`[onclick*="updateIncidentStatus('${id}','under_review')"]`).click();
      await expect.poll(async () => (await testerReports(api, tag))[0]?.hr_status, { timeout: 10_000 }).toBe('under_review');
      report.push('✓ HR Admin: status → Under Review (saved)');

      await p.evaluate(() => { try { loadSentReports(); } catch (e) {} });
      await expect(list).toContainText(/under review/i, { timeout: 15_000 });
      report.push('✓ Portal: shows Under Review');

      await a.locator(`[onclick="openIncidentDetail('${id}')"]`).first().click();
      await a.locator(`[onclick*="updateIncidentStatus('${id}','resolved')"]`).click();
      await expect.poll(async () => (await testerReports(api, tag))[0]?.hr_status, { timeout: 10_000 }).toBe('resolved');
      await p.evaluate(() => { try { loadSentReports(); } catch (e) {} });
      await expect(list).toContainText(/resolved/i, { timeout: 15_000 });
      report.push('✓ HR Admin: status → Resolved; Portal shows Resolved');
      await snap(p, testInfo, '4_portal_resolved');
    });

    await test.step('HR Admin: 🗑 Delete → gone everywhere', async () => {
      await a.locator(`[onclick="openIncidentDetail('${id}')"]`).first().click();
      await clickAndConfirm(a, a.locator(`.modal-footer [onclick="deleteIncidentReport('${id}')"]`));
      await expect.poll(async () => (await testerReports(api, tag)).length, { timeout: 10_000 }).toBe(0);
      await p.evaluate(() => { try { loadSentReports(); } catch (e) {} });
      await expect(list).not.toContainText(`${tag} Loading dock`, { timeout: 10_000 });
      report.push('✓ HR Admin 🗑 Delete: gone from server and Portal');
      id = null;
    });

  } finally {
    let cleanupLine;
    try {
      for (const m of await testerReports(api)) await postJson(api, '/messages/delete', { id: m.id, box: 'inbox' });
      const left = (await testerReports(api)).length;
      cleanupLine = left === 0 ? 'CLEANUP VERIFIED [E2E06]: 0 test incident reports left'
                               : `CLEANUP FAILED [E2E06]: ${left} test incident report(s) left`;
    } catch (e) { cleanupLine = `CLEANUP FAILED [E2E06]: ${e.message}`; }
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
