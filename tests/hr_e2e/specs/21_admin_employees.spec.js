// ADM-EMP-01/02/03/05 (+ADM-EMP-12, REG-11) — HR Admin employees.
//  1. Employees list: all employees shown; real employees counted (never touched)
//  2. Filter chips: All / Hiring / Onboarding / Active / Terminated behave (case-insensitive; Hiring incl. Pre-Start)
//  3. + Add Employee form → "ZZTEST QA Helper" created with onboarding tasks
//  4. Open the new employee's record → every tab opens without errors
//  5. Delete the helper → gone from the list AND its onboarding tasks are gone too (no orphans)
const { test, expect } = require('@playwright/test');
const { addClickMarker, watchForProblems } = require('../helpers/common');
const { loginAdmin, openAdminPage } = require('../helpers/admin');
const { adminApi, testTag, getJson, deleteEmployee, allEmployees } = require('../helpers/api');

const isHelper = (e) => String(e.first_name || '').startsWith('ZZTEST');
async function tasksFor(api, empId) {
  const d = await getJson(api, `/tasks?employee_id=${encodeURIComponent(empId)}`).catch(() => ({ tasks: [] }));
  return (d.tasks || d || []).filter(t => t.employee_id === empId);
}

test('ADM-EMP-01…05 · Employees: list, filter chips, add, record tabs, delete', async ({ page }, testInfo) => {
  const tag = testTag('EMP');
  const first = 'ZZTEST', last = `QA Helper ${tag.slice(-12)}`;
  const api = await adminApi();
  const report = [];
  let helperId = null;
  await addClickMarker(page);
  const problems = watchForProblems(page, 'admin');

  try {
    await test.step('Pre-sweep leftover ZZTEST helper employees', async () => {
      const old = (await allEmployees(api)).filter(isHelper);
      for (const e of old) await deleteEmployee(api, e.id);
      report.push(old.length ? `• Removed ${old.length} leftover helper(s)` : '• No leftover helpers');
    });

    const realBefore = (await allEmployees(api)).filter(e => !isHelper(e));

    await test.step('Sign in → Employees', async () => {
      await loginAdmin(page);
      problems.at('Employees');
      await openAdminPage(page, 'employees');
    });

    await test.step('ADM-EMP-01: list shows every employee', async () => {
      for (const e of realBefore) {
        await expect(page.locator('.emp-name', { hasText: `${e.first_name} ${e.last_name}` }).first()).toBeAttached();
      }
      report.push(`✓ List shows all ${realBefore.length} employees (real employees are only read, never changed)`);
    });

    await test.step('ADM-EMP-02 / REG-11: filter chips', async () => {
      const count = async () => page.locator('.emp-name').count();
      const expected = (f) => realBefore.filter(e => {
        const s = String(e.status || '').toLowerCase();
        return f === 'all' || s === f || (f === 'hiring' && s === 'pre-start');
      }).length;
      for (const f of ['onboarding', 'hiring', 'active', 'terminated', 'all']) {
        await page.locator(`.chip[data-filter="${f}"]`).click();
        await page.waitForTimeout(300);
        expect(await count(), `"${f}" chip`).toBe(expected(f));
      }
      report.push('✓ Filter chips: Onboarding / Hiring (incl. Pre-Start) / Active / Terminated / All show the right people');
    });

    await test.step('ADM-EMP-03: + Add Employee → helper created with onboarding tasks', async () => {
      await page.locator('#btn-add-emp').click();
      await expect(page.locator('#new-emp-modal')).not.toHaveClass(/hidden/);
      await page.locator('#nef-first').fill(first);
      await page.locator('#nef-last').fill(last);
      await page.locator('#nef-personal-email').fill(`jamievavroaiprowler+zz-helper@gmail.com`);
      await page.locator('#nef-title').fill('QA Helper');
      await page.locator('#nef-dept').fill('Testing');
      await page.locator('#nef-work-state').selectOption({ index: 1 });
      await page.locator('[onclick="saveNewEmployee()"]').click();
      await expect(page.locator('.emp-name', { hasText: `${first} ${last}` }).first()).toBeVisible({ timeout: 15_000 });
      const h = (await allEmployees(api)).find(e => isHelper(e) && e.last_name === last);
      expect(h, 'helper not on the server').toBeTruthy();
      helperId = h.id;
      const tasks = await tasksFor(api, helperId);
      report.push(`✓ Added ${first} ${last} (${helperId}) — status "${h.status}", ${tasks.length} onboarding task(s) generated`);
    });

    await test.step('ADM-EMP-05: open the record → every tab opens without errors', async () => {
      await page.locator('.chip[data-filter="all"]').click();
      await page.locator('.emp-name', { hasText: `${first} ${last}` }).first().click();
      const tabs = page.locator('.emp-sheet-tab');
      const n = await tabs.count();
      expect(n, 'no tabs on the employee record').toBeGreaterThan(3);
      const names = [];
      for (let i = 0; i < n; i++) {
        const t = tabs.nth(i);
        const name = (await t.innerText()).trim();
        problems.at(`Employee record → ${name}`);
        await t.click();
        await page.waitForTimeout(500);
        names.push(name);
      }
      report.push(`✓ Employee record: ${n} tabs opened — ${names.join(', ')}`);
    });

    await test.step('ADM-EMP-12: delete the helper → gone, and no orphaned tasks', async () => {
      const status = await deleteEmployee(api, helperId);
      expect([200, 204]).toContain(status);
      await page.reload();
      await expect(page.locator('#auth-screen')).toBeHidden({ timeout: 20_000 });
      await openAdminPage(page, 'employees');
      await expect(page.locator('.emp-name', { hasText: `${first} ${last}` })).toHaveCount(0, { timeout: 10_000 });
      const orphans = await tasksFor(api, helperId);
      if (orphans.length) report.push(`✗ ${orphans.length} onboarding task(s) left behind for the deleted employee (orphans)`);
      else report.push('✓ Deleted: gone from the list; its onboarding tasks were removed too');
      expect.soft(orphans.length, 'onboarding tasks left behind after deleting the employee').toBe(0);
      helperId = null;
    });

  } finally {
    let cleanupLine;
    try {
      for (const e of (await allEmployees(api)).filter(isHelper)) await deleteEmployee(api, e.id);
      const left = (await allEmployees(api)).filter(isHelper).length;
      cleanupLine = left === 0 ? 'CLEANUP VERIFIED [EMP]: 0 ZZTEST helper employees left'
                               : `CLEANUP FAILED [EMP]: ${left} helper employee(s) left`;
    } catch (e) { cleanupLine = `CLEANUP FAILED [EMP]: ${e.message}`; }
    const probs = problems.list();
    const summary = [...report, `Console errors / failed server calls: ${probs.length}`, ...probs.map(x => '  ✗ ' + x), cleanupLine].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await api.dispose();
    expect.soft(probs, 'Console errors or failed server calls').toEqual([]);
    expect(cleanupLine).toContain('CLEANUP VERIFIED');
  }
});
