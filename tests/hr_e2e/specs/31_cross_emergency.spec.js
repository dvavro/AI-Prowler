// E2E-04 / X-EMC-01 / PRT-EMC-01·02 — Emergency contacts: Portal → HR Admin.
//
// Portal (Test Tester) and HR Admin side by side:
//   1. Remember Test Tester's current emergency contacts (baseline)
//   2. Portal: 🚨 Emergency Contacts → ✏️ Edit → fill primary + backup → 💾 Save
//   3. Portal: status banner turns green "On file with HR"; server has the new contacts
//   4. HR Admin: Employees → Test Tester → 🚨 Emergency tab shows the same contacts
//   5. Restore the baseline and VERIFY it's back (cleanup)
const { test, expect, chromium } = require('@playwright/test');
const { settings, addClickMarker, watchForProblems, loginPortal } = require('../helpers/common');
const { loginAdmin, openAdminPage } = require('../helpers/admin');
const { adminApi, testTag, getEmployee, patchEmployee } = require('../helpers/api');

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

test('X-EMC-01 · Emergency contacts: Portal saves → HR Admin sees them', async ({}, testInfo) => {
  const s = settings();
  const ttId = process.env.HR_E2E_TT_ID;
  const tag = testTag('XEMC01');
  const contact = {
    name: `${tag} Alex Tester`, relationship: 'Spouse', phone: '(480) 555-0142',
    email: 'alex.tester.zztest@example.com', name2: `${tag} Jordan Tester`, phone2: '(480) 555-0143',
  };
  const api = await adminApi();
  const report = [];
  let portal, admin, pP, aP, baseline;

  try {
    await test.step('Remember Test Tester\'s current emergency contacts (baseline)', async () => {
      const emp = await getEmployee(api, ttId);
      expect(emp, 'Test Tester not found').toBeTruthy();
      baseline = emp.emergency_contact === undefined ? null : JSON.parse(JSON.stringify(emp.emergency_contact));
      report.push(`• Baseline saved (${baseline && baseline.name ? 'had a contact' : 'no contact on file'})`);
    });

    portal = await openWindow('portal', 0, testInfo);
    admin  = await openWindow('admin', WIN_W, testInfo);
    pP = watchForProblems(portal.page, 'portal');
    aP = watchForProblems(admin.page, 'admin');
    await test.step('Portal: sign in', async () => { await loginPortal(portal.page); });
    await test.step('HR Admin: sign in', async () => { await loginAdmin(admin.page); });

    const p = portal.page;
    await test.step('Portal: fill and save emergency contacts', async () => {
      pP.at('Emergency Contacts');
      const nav = p.locator('.sidebar .nav-item[data-page="emergency"]').first();
      await nav.scrollIntoViewIfNeeded();
      await nav.click();
      const card = p.locator('#ab-sec-emergency');
      await expect(card).toBeVisible();
      await card.getByRole('button', { name: /Edit/ }).click();
      await p.locator('#ab-emergency-name').fill(contact.name);
      await p.locator('#ab-emergency-relationship').selectOption(contact.relationship);
      await p.locator('#ab-emergency-phone').fill(contact.phone);
      await p.locator('#ab-emergency-email').fill(contact.email);
      await p.locator('#ab-emergency-name2').fill(contact.name2);
      await p.locator('#ab-emergency-phone2').fill(contact.phone2);
      await snap(p, testInfo, '1_portal_filled');
      await p.locator('#ab-save-emergency').click();
      await expect(p.locator('#ab-ec-status')).toContainText('On file with HR', { timeout: 15_000 });
      await expect(card).toContainText(contact.name);
      report.push('✓ Portal: saved; banner shows "✅ On file with HR"');
      await snap(p, testInfo, '2_portal_saved');
    });

    await test.step('Server: contacts saved on Test Tester\'s record', async () => {
      const ec = (await getEmployee(api, ttId)).emergency_contact || {};
      for (const k of ['name', 'relationship', 'phone', 'email', 'name2', 'phone2']) {
        expect(ec[k], `server field "${k}"`).toBe(contact[k]);
      }
      expect(ec.updated_at, 'no "last updated" time stamp').toBeTruthy();
      report.push('✓ Server: all 6 fields match, with a "last updated" time');
    });

    const a = admin.page;
    await test.step('HR Admin: Test Tester → 🚨 Emergency tab shows the contacts', async () => {
      aP.at('Employees → Test Tester → Emergency');
      await openAdminPage(a, 'employees');
      await a.locator('.emp-name', { hasText: s.ttName }).first().click();
      await a.locator('.emp-sheet-tab', { hasText: 'Emergency' }).click();
      const body = a.locator('#emp-emergency-body');
      await expect(body).toContainText(contact.name, { timeout: 15_000 });
      await expect(body).toContainText(contact.phone);
      await expect(body).toContainText(contact.name2);
      await expect(body).toContainText(contact.phone2);
      await expect(body).toContainText('Spouse');
      report.push('✓ HR Admin: 🚨 Emergency tab shows primary + backup contacts, relationship, phones');
      await snap(a, testInfo, '3_admin_emergency_tab');
    });

  } finally {
    // ── Restore baseline + verify ──────────────────────────────────────
    let cleanupLine;
    try {
      await patchEmployee(api, ttId, { emergency_contact: baseline || {} });
      const now = (await getEmployee(api, ttId)).emergency_contact || {};
      const wanted = baseline || {};
      const same = ['name', 'phone', 'name2', 'phone2'].every(k => (now[k] || '') === (wanted[k] || ''));
      const leftover = JSON.stringify(now).includes('ZZTEST');
      cleanupLine = same && !leftover
        ? 'CLEANUP VERIFIED [XEMC01]: Test Tester\'s emergency contacts restored to baseline'
        : `CLEANUP FAILED [XEMC01]: contacts not restored (${JSON.stringify(now).slice(0, 120)})`;
    } catch (e) { cleanupLine = `CLEANUP FAILED [XEMC01]: ${e.message}`; }

    const problems = [...(pP ? pP.list() : []), ...(aP ? aP.list() : [])];
    const summary = [...report, `Console errors / failed server calls: ${problems.length}`,
      ...problems.map(x => '  ✗ ' + x), cleanupLine].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await closeWindow(portal, testInfo);
    await closeWindow(admin, testInfo);
    await api.dispose();
    expect.soft(problems, 'Console errors or failed server calls').toEqual([]);
    expect(cleanupLine, 'Cleanup').toContain('CLEANUP VERIFIED');
  }
});
