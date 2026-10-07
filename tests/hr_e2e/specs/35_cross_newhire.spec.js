// E2E-03 — New hire to first login (gap #24, approved by Jamie Oct 1).
//  1. Setup (API): ZZTEST position + candidate + PENDING offer
//  2. HR Admin → Recruiting → Offers → ✓ accept → "Create an employee record?" opens, pre-filled
//  3. Create Employee → "open their record to set a PIN?" → record opens → 🔑 Portal Sign-in → Set PIN
//  4. Server: employee with title/department/start date, onboarding tasks, linked to offer + candidate
//  5. Offers tab shows "✓ Employee EMP-…" (no second Create button)
//  6. The new hire signs into the Portal with email + PIN and sees their own name and title
// Cleanup: employee (and its tasks) + ZZTEST recruiting items removed, verified.
const { test, expect } = require('@playwright/test');
const { addClickMarker, watchForProblems, closeGettingStarted } = require('../helpers/common');
const { loginAdmin, openAdminPage } = require('../helpers/admin');
const { adminApi, testTag, getJson, postJson, deleteEmployee, allEmployees } = require('../helpers/api');

const isZZ = (x) => JSON.stringify(x).includes('ZZTEST');
async function bundle(api) { const d = await getJson(api, '/recruiting'); const b = d.recruiting || {}; b.version = d.version; return b; }
async function removeZZRec(api) {
  const b = await bundle(api); const clean = { version: b.version };
  for (const k of ['positions', 'candidates', 'interviews', 'offers']) clean[k] = (b[k] || []).filter(x => !isZZ(x));
  await postJson(api, '/recruiting', clean);
}

test('E2E-03 · New hire: accept offer → create employee → set PIN → first Portal sign-in', async ({ page, browser }, testInfo) => {
  const tag = testTag('E2E03');
  const ids = { pos: `POS-${tag}`, cand: `CAND-${tag}`, off: `OFF-${tag}` };
  const last = `Ellis ${tag.slice(-6)}`;
  const email = 'jamievavroaiprowler+zz-newhire@gmail.com';
  const start = new Date(); start.setDate(start.getDate() + 14);
  const startYmd = `${start.getFullYear()}-${String(start.getMonth() + 1).padStart(2, '0')}-${String(start.getDate()).padStart(2, '0')}`;
  const pin = String(Math.floor(10000000 + Math.random() * 89999999));
  const api = await adminApi();
  const lines = [];
  let empId = null;
  await addClickMarker(page);
  const problems = watchForProblems(page, 'admin');

  try {
    // 1. Setup
    for (const e of (await allEmployees(api)).filter(e => String(e.first_name).startsWith('ZZTEST'))) await deleteEmployee(api, e.id);
    await removeZZRec(api);
    const b = await bundle(api);
    b.positions.push({ id: ids.pos, title: 'Warehouse Associate', department: 'ZZTEST Operations', status: 'open' });
    b.candidates.push({ id: ids.cand, name: `ZZTEST ${last}`, email, phone: '(480) 555-0170', position_id: ids.pos, stage: 'offer' });
    b.offers.push({ id: ids.off, candidate_id: ids.cand, title: 'Warehouse Associate', salary: '$19/hr', start_date: startYmd, status: 'pending' });
    expect((await postJson(api, '/recruiting', b)).status).toBeLessThan(300);
    lines.push(`• Setup: pending offer for "ZZTEST ${last}", start ${startYmd}`);

    // 2. Accept the offer
    await loginAdmin(page);
    problems.at('Recruiting → Offers');
    await openAdminPage(page, 'recruiting');
    await page.locator('#rsnav-offers').click();
    await page.locator(`[onclick="updateOfferStatus('${ids.off}','accepted')"]`).click();
    await expect(page.locator('#hire-first')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('#hire-first')).toHaveValue('ZZTEST');
    await expect(page.locator('#hire-last')).toHaveValue(last);
    await expect(page.locator('#hire-email')).toHaveValue(email);
    await expect(page.locator('#hire-title')).toHaveValue('Warehouse Associate');
    await expect(page.locator('#hire-dept')).toHaveValue('ZZTEST Operations');
    await expect(page.locator('#hire-start')).toHaveValue(startYmd);
    lines.push('✓ ✓ Accept → "Create an employee record?" opened, pre-filled from recruiting (name, email, title, department, start date)');

    // 3. Create Employee → their record opens on 🔑 Portal Sign-in showing their new AI-Prowler token
    await page.locator('#hire-create-btn').click();
    await expect(page.locator('#dr-token-box')).toBeVisible({ timeout: 15_000 });
    await expect(page.locator('#emp-pane-directreports')).toContainText(email);
    const token = (await page.locator('#dr-token-value').innerText()).trim();
    expect(token.length, 'no AI-Prowler token shown for the new hire').toBeGreaterThan(20);
    lines.push('✓ Create Employee → record opened on 🔑 Portal Sign-in with their own AI-Prowler token, ready to copy');

    // 4. Server
    const emp = (await allEmployees(api)).find(e => e.last_name === last);
    expect(emp, 'employee not created').toBeTruthy();
    empId = emp.id;
    expect(emp.title).toBe('Warehouse Associate');
    expect(emp.department).toBe('ZZTEST Operations');
    expect(emp.start_date).toBe(startYmd);
    const tasks = ((await getJson(api, `/tasks?employee_id=${empId}`)).tasks || []).filter(t => t.employee_id === empId);
    expect(tasks.length, 'no onboarding tasks').toBeGreaterThan(0);
    const after = await bundle(api);
    expect(after.offers.find(o => o.id === ids.off)?.employee_id, 'offer not linked to the employee').toBe(empId);
    expect(after.candidates.find(c => c.id === ids.cand)?.stage).toBe('hired');
    lines.push(`✓ Server: ${empId} — Warehouse Associate, ZZTEST Operations, starts ${startYmd}; ${tasks.length} onboarding tasks; linked to offer + candidate (Hired)`);

    // 5. Offers tab: no duplicate Create button
    await openAdminPage(page, 'recruiting');
    await page.locator('#rsnav-offers').click();
    // Note: HR Admin has two elements with id "rec-view-offers" (the real list + an empty leftover copy) — use the real one
    await expect(page.locator('#rec-view-offers').first()).toContainText(`Employee ${empId}`, { timeout: 10_000 });
    await expect(page.locator(`[onclick="openCreateEmployeeFromOffer('${ids.off}')"]`)).toHaveCount(0);
    lines.push(`✓ Offers tab shows "✓ Employee ${empId}" — no way to create a duplicate`);

    // 6. First Portal sign-in
    const ctx = await browser.newContext({ baseURL: process.env.HR_E2E_BASE_URL, serviceWorkers: 'block' });
    const p = await ctx.newPage();
    await p.goto('/hr_portal/');
    await p.locator('#login-email').fill(email);
    await p.locator('#login-pass').fill(token);          // their own AI-Prowler token
    await p.locator('#login-btn').click();
    await expect(p.locator('#app')).toHaveClass(/visible/, { timeout: 20_000 });
    await closeGettingStarted(p, 5_000);
    await expect(p.locator('#sidebar-name')).toContainText('ZZTEST', { timeout: 10_000 });
    await expect(p.locator('#app')).toContainText('Warehouse Associate', { timeout: 10_000 });
    lines.push('✓ The new hire signed into the Portal with email + their AI-Prowler token and sees their own name and job title');
    await ctx.close();
  } finally {
    let cleanupLine;
    try {
      for (const e of (await allEmployees(api)).filter(e => String(e.first_name).startsWith('ZZTEST'))) await deleteEmployee(api, e.id);
      await removeZZRec(api);
      const leftEmp = (await allEmployees(api)).filter(e => String(e.first_name).startsWith('ZZTEST')).length;
      const leftTasks = empId ? ((await getJson(api, `/tasks?employee_id=${empId}`)).tasks || []).filter(t => t.employee_id === empId).length : 0;
      const b2 = await bundle(api);
      const leftRec = ['positions', 'candidates', 'offers'].reduce((n, k) => n + (b2[k] || []).filter(isZZ).length, 0);
      cleanupLine = (leftEmp + leftTasks + leftRec) === 0
        ? 'CLEANUP VERIFIED [E2E03]: new employee, their onboarding tasks, and test recruiting items removed'
        : `CLEANUP FAILED [E2E03]: employees ${leftEmp}, tasks ${leftTasks}, recruiting ${leftRec}`;
    } catch (e) { cleanupLine = `CLEANUP FAILED [E2E03]: ${e.message}`; }
    const probs = problems.list();
    const summary = [...lines, `Console errors / failed server calls: ${probs.length}`, ...probs.map(x => '  ✗ ' + x), cleanupLine].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await api.dispose();
    expect.soft(probs).toEqual([]);
    expect(cleanupLine).toContain('CLEANUP VERIFIED');
  }
});
