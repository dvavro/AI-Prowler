// ADM-OFF-01/03/04/05 — Offboarding → terminate → Termination Records → 📁 Saved File → 🖨 Print.
// Uses ONLY a ZZTEST helper employee created by this test. Real employees are never touched.
//  1. Setup (API): create "ZZTEST Offboard <run>" with an emergency contact
//  2. HR Admin: Employees → helper → Offboarding tab → Initiate Termination → Voluntary, today → Confirm
//  3. Server: status terminated, type + last day + notes saved; the employee record still exists (nothing deleted)
//  4. Offboarding page lists the helper; 📋 Termination Records lists the helper
//  5. 📁 Saved File: all 6 sections, with the helper's details
//  6. 🖨 Print / Save as PDF: printable copy opens (no buttons in it)
// Cleanup: delete the helper via the API, verify gone.
const { test, expect } = require('@playwright/test');
const { addClickMarker, watchForProblems } = require('../helpers/common');
const { loginAdmin, openAdminPage } = require('../helpers/admin');
const { adminApi, testTag, postJson, deleteEmployee, allEmployees, getEmployee } = require('../helpers/api');

const isHelper = (e) => String(e.first_name || '').startsWith('ZZTEST');
const today = () => { const d = new Date(); d.setHours(12); return d.toISOString().slice(0, 10); };

test('ADM-OFF-01…05 · Offboard a helper: terminate → records → Saved File → Print', async ({ page }, testInfo) => {
  const tag = testTag('OFF');
  const last = `Offboard ${tag.slice(-10)}`;
  const api = await adminApi();
  const report = [];
  let id = null;
  await addClickMarker(page);
  // Never open a real print dialog during tests — record that printing was asked for instead
  await page.context().addInitScript(() => { window.print = () => { window.__printRequested = true; }; });
  const problems = watchForProblems(page, 'admin');

  try {
    await test.step('Setup (API): create the ZZTEST helper', async () => {
      for (const e of (await allEmployees(api)).filter(isHelper)) await deleteEmployee(api, e.id);
      const start = new Date(); start.setDate(start.getDate() - 60);
      const r = await postJson(api, '/employees', {
        personal: { first_name: 'ZZTEST', last_name: last, personal_email: 'jamievavroaiprowler+zz-off@gmail.com', phone: '(480) 555-0160' },
        employment: { title: 'QA Warehouse Helper', department: 'Operations', start_date: start.toISOString().slice(0, 10) },
        compensation: {},
      });
      expect(r.status, 'could not create helper').toBeLessThan(300);
      id = (r.data.employee || r.data).id;
      await api.patch(`/hr-api/employees/${id}`, { data: { emergency_contact: { name: 'ZZTEST Pat Offboard', relationship: 'Sibling', phone: '(480) 555-0161' } } });
      report.push(`• Setup: helper ${id} created (started 60 days ago, with an emergency contact)`);
    });

    await test.step('Sign in → helper → Offboarding tab → Initiate Termination', async () => {
      await loginAdmin(page);
      problems.at('Employees → helper → Offboarding');
      await openAdminPage(page, 'employees');
      await page.locator('.chip[data-filter="all"]').click();
      await page.locator('.emp-name', { hasText: `ZZTEST ${last}` }).first().click();
      await page.locator('.emp-sheet-tab', { hasText: 'Offboarding' }).click();
      await page.locator(`button[onclick="openInitiateTermination('${id}')"]`).first().click();
      await expect(page.locator('#term-type')).toBeVisible();
      await page.locator('#term-type').selectOption('voluntary');
      await page.locator('#term-date').fill(today());
      await page.locator('#term-notes').fill(`${tag} Moving out of state — automated test`);
      await page.getByRole('button', { name: 'Confirm Termination' }).click();
      await expect(page.locator('#term-type')).toBeHidden({ timeout: 10_000 });
      report.push('✓ Initiate Termination → Voluntary Resignation, last day today → Confirmed');
    });

    await test.step('ADM-OFF-03: server — terminated, details saved, nothing deleted', async () => {
      await expect.poll(async () => (await getEmployee(api, id))?.status, { timeout: 10_000 }).toBe('terminated');
      const e = await getEmployee(api, id);
      expect(e.termination_type).toBe('voluntary');
      expect(e.end_date).toBe(today());
      expect(e.termination_notes).toContain(tag);
      expect(e.emergency_contact && e.emergency_contact.name, 'emergency contact was lost').toBe('ZZTEST Pat Offboard');
      report.push('✓ Server: status terminated, type voluntary, last day + notes saved; record and emergency contact kept');
    });

    await test.step('ADM-OFF-01: Offboarding page lists the helper', async () => {
      problems.at('Offboarding');
      // The employee record is still open full-screen — close it with ← Back first, like a person would
      const back = page.locator('#emp-sheet').getByText(/Back/).first();
      if (await back.isVisible().catch(() => false)) await back.click();
      await expect(page.locator('#emp-sheet .emp-sheet-header')).toBeHidden({ timeout: 5_000 }).catch(() => {});
      await openAdminPage(page, 'offboarding');
      await expect(page.locator(`[onclick="openOffboardingForEmp('${id}')"]`)).toBeVisible({ timeout: 10_000 });
      report.push('✓ Offboarding page lists the helper');
    });

    await test.step('ADM-OFF-03: 📋 Termination Records lists the helper', async () => {
      problems.at('Termination Records');
      await openAdminPage(page, 'terminations');
      await expect(page.locator(`button[onclick="openEmployeeFile('${id}')"]`)).toBeVisible({ timeout: 10_000 });
      report.push('✓ Termination Records lists the helper with a 📁 Saved File button');
    });

    await test.step('ADM-OFF-04: 📁 Saved File shows all 6 sections', async () => {
      problems.at('Saved File');
      await page.locator(`button[onclick="openEmployeeFile('${id}')"]`).click();
      const body = page.locator('#ef-body');
      await expect(body).toBeVisible({ timeout: 15_000 });
      for (const s of ['Personal', 'Employment', 'Termination', 'Emergency Contact', 'Documents', 'Time Off History']) {
        await expect(body, `section "${s}"`).toContainText(s);
      }
      await expect(body).toContainText(`ZZTEST ${last}`);
      await expect(body).toContainText('Voluntary Resignation');
      await expect(body).toContainText('ZZTEST Pat Offboard');
      await expect(body).toContainText('QA Warehouse Helper');
      report.push('✓ Saved File: Personal, Employment, Termination, Emergency Contact, Documents, Time Off — with the helper\'s real details');
    });

    await test.step('ADM-OFF-05: 🖨 Print / Save as PDF opens a clean copy', async () => {
      const [popup] = await Promise.all([
        page.waitForEvent('popup'),
        page.locator('[onclick="printEmployeeFile()"]').click(),
      ]);
      await popup.waitForLoadState();
      await expect(popup.locator('body')).toContainText('Employee File');
      await expect(popup.locator('body')).toContainText(`ZZTEST ${last}`);
      expect(await popup.locator('button').count(), 'buttons in the printed copy').toBe(0);
      await expect.poll(() => popup.evaluate(() => !!window.__printRequested), { timeout: 5_000 }).toBe(true);
      report.push('✓ Print: a clean printable copy opened (title, name, no buttons) and asked to print');
      await popup.close();
    });

  } finally {
    let cleanupLine;
    try {
      for (const e of (await allEmployees(api)).filter(isHelper)) await deleteEmployee(api, e.id);
      const left = (await allEmployees(api)).filter(isHelper).length;
      cleanupLine = left === 0 ? 'CLEANUP VERIFIED [OFF]: helper deleted, 0 ZZTEST employees left'
                               : `CLEANUP FAILED [OFF]: ${left} ZZTEST employee(s) left`;
    } catch (e) { cleanupLine = `CLEANUP FAILED [OFF]: ${e.message}`; }
    const probs = problems.list();
    const summary = [...report, `Console errors / failed server calls: ${probs.length}`, ...probs.map(x => '  ✗ ' + x), cleanupLine].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await api.dispose();
    expect.soft(probs, 'Console errors or failed server calls').toEqual([]);
    expect(cleanupLine).toContain('CLEANUP VERIFIED');
  }
});
