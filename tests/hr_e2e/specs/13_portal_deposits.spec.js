// PRT-DEP-01/02 — Deposits: bank details privacy (only the LAST 4 digits may ever leave the page).
// Uses standard test numbers: routing 110000000, account 000123456789 → only "6789" / "0000" allowed.
//  1. Portal → Deposits → Update Bank Account → save
//  2. Network: no request the page sends contains the full account or routing number
//  3. Server: record has account_last4 "6789", routing_last4 "0000", and the full numbers nowhere
//  4. Browser: full numbers not left in localStorage/sessionStorage; screen shows only the last 4
//  5. Server safety net: a tampered request sending a FULL number as "last 4" must not be stored as-is
// Cleanup: Test Tester's bank fields restored to their original values, verified.
const { test, expect } = require('@playwright/test');
const { addClickMarker, watchForProblems, loginPortal } = require('../helpers/common');
const { adminApi, employeeApi, getEmployee, patchEmployee } = require('../helpers/api');

const ACCOUNT = '000123456789', ROUTING = '110000000';
const BANK_FIELDS = ['bank_name', 'account_type', 'account_last4', 'routing_last4'];

test('PRT-DEP-01/02 · Deposits: only the last 4 digits are ever sent, stored, or shown', async ({ page }, testInfo) => {
  const ttId = process.env.HR_E2E_TT_ID;
  const api = await adminApi();
  const lines = [], problems = [];
  let baseline = null;
  await addClickMarker(page);
  const watch = watchForProblems(page, 'portal');

  // Record every request body the page sends, so we can prove the full numbers never leave it
  const sent = [];
  page.on('request', req => { const b = req.postData(); if (b) sent.push({ url: req.url(), body: b }); });

  try {
    const emp0 = await getEmployee(api, ttId);
    baseline = {};
    for (const f of BANK_FIELDS) baseline[f] = emp0[f] ?? '';

    await loginPortal(page);
    watch.at('Deposits');
    const nav = page.locator('.sidebar .nav-item[data-page="deposits"]').first();
    await nav.scrollIntoViewIfNeeded(); await nav.click();
    await page.getByRole('button', { name: /Update Bank Account/i }).first().click();
    await expect(page.locator('#bank-account-number')).toBeVisible();
    await page.locator('#bank-name').fill('ZZTEST Credit Union');
    await page.locator('#bank-account-type').selectOption('Checking');
    await page.locator('#bank-account-number').fill(ACCOUNT);
    await page.locator('#bank-routing-number').fill(ROUTING);
    await page.locator('[onclick="saveBankAccount()"]').click();
    await expect(page.locator('#bank-saved')).toBeVisible({ timeout: 10_000 });
    lines.push('✓ Deposits → Update Bank Account → saved');

    // 2. Network
    const leaked = sent.filter(s => s.body.includes(ACCOUNT) || s.body.includes(ROUTING));
    if (leaked.length) problems.push(`full bank number sent over the network (${leaked.map(l => l.url.replace(/^https?:\/\/[^/]+/, '')).join(', ')})`);
    else lines.push(`✓ Network: ${sent.length} request(s) checked — full account/routing numbers never sent`);

    // 3. Server
    const emp = await getEmployee(api, ttId);
    expect(emp.account_last4).toBe('6789');
    expect(emp.routing_last4).toBe('0000');
    const recText = JSON.stringify(emp);
    if (recText.includes(ACCOUNT) || recText.includes(ROUTING)) problems.push('full bank number stored on the server');
    else lines.push('✓ Server: stores only last 4 (account 6789, routing 0000); full numbers appear nowhere');

    // 4. Browser + screen
    const storage = await page.evaluate(() => JSON.stringify({ ...localStorage }) + JSON.stringify({ ...sessionStorage }));
    if (storage.includes(ACCOUNT) || storage.includes(ROUTING)) problems.push('full bank number left in browser storage');
    await page.locator('#bank-overlay').waitFor({ state: 'hidden', timeout: 5_000 }).catch(() => {});
    const screen = await page.locator('#page-deposits').innerText();
    if (screen.includes(ACCOUNT) || screen.includes(ROUTING)) problems.push('full bank number shown on screen');
    if (!screen.includes('6789')) problems.push('last 4 digits (6789) not shown on the Deposits page');
    if (!problems.some(p => /storage|screen|6789/.test(p))) lines.push('✓ Browser storage clean; screen shows only •••• 6789');

    // 5. Server safety net: tampered request
    const emp2 = await employeeApi();
    await emp2.patch('/hr-api/portal/me', { data: { account_last4: ACCOUNT, routing_last4: ROUTING } });
    const after = await getEmployee(api, ttId);
    if (String(after.account_last4) === ACCOUNT || String(after.routing_last4) === ROUTING) {
      problems.push('server accepted a FULL number as "last 4" from a tampered request (stores whatever it is sent)');
      lines.push('✗ Server safety net: a tampered request stored the FULL account number as "last 4"');
    } else {
      lines.push(`✓ Server safety net: tampered full number not stored as-is (now "${after.account_last4}")`);
    }
    await emp2.dispose();
  } finally {
    let cleanupLine;
    try {
      if (baseline) await patchEmployee(api, ttId, baseline);
      const now = await getEmployee(api, ttId);
      const ok = baseline && BANK_FIELDS.every(f => String(now[f] ?? '') === String(baseline[f] ?? ''));
      cleanupLine = ok ? 'CLEANUP VERIFIED [DEP]: Test Tester\'s bank fields restored' : 'CLEANUP FAILED [DEP]: bank fields not restored';
    } catch (e) { cleanupLine = `CLEANUP FAILED [DEP]: ${e.message}`; }
    const probs = watch.list();
    const summary = [...lines, ...problems.map(p => '  ✗ ' + p), `Console errors / failed server calls: ${probs.length}`, ...probs.map(x => '  ✗ ' + x), cleanupLine].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await api.dispose();
    expect.soft(probs).toEqual([]);
    expect(problems, 'Bank details privacy problems').toEqual([]);
    expect(cleanupLine).toContain('CLEANUP VERIFIED');
  }
});
