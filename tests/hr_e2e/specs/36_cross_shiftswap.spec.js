// X-SWP-01 — Coworker-to-coworker shift swaps (Jamie, Oct 1). Two Portal windows side by side:
// Test Tester (left) and a ZZTEST coworker (right).
//  1. Privacy: Test Tester's coworker list has the test coworker and NO real employees
//  2. Test Tester → Schedule → 🔁 Swap a Shift → click the coworker's name → short message → Send
//  3. Coworker: Schedule badge + request in 🔁 Shift Swaps → ✓ Approve → Test Tester sees "✓ Approved"
//  4. Second request → ✗ Deny → Test Tester sees "✗ Declined" (closed)
//  5. Security: an answered swap can't be answered again; the sender can't answer their own
// Cleanup: swaps removed (/test/cleanup) + ZZTEST coworker deleted, verified.
const { test, expect, request } = require('@playwright/test');
const { settings, watchForProblems, loginPortal, closeGettingStarted } = require('../helpers/common');
const { adminApi, employeeApi, testTag, getJson, postJson, deleteEmployee, allEmployees } = require('../helpers/api');
const { openPortalWindow, openAdminWindow, closeWindow, snap, clickAndConfirm } = require('../helpers/windows');

const isZZ = (e) => String(e.first_name || '').startsWith('ZZTEST');

async function openSchedule(p) {
  const nav = p.locator('.sidebar .nav-item[data-page="schedule"]').first();
  await nav.scrollIntoViewIfNeeded(); await nav.click();
  await expect(p.locator('#page-schedule')).toHaveClass(/active/);
}

test('X-SWP-01 · Shift swap: click a coworker → message → they Approve or Deny', async ({}, testInfo) => {
  const s = settings();
  const tag = testTag('SWP');
  const api = await adminApi();
  const lines = [];
  const coPin = String(Math.floor(10000000 + Math.random() * 89999999));
  const coEmail = 'jamievavroaiprowler+zz-swap@gmail.com';
  let left, right, pL, pR, coId = null, coName = '';

  try {
    // Setup: a ZZTEST coworker who can sign in
    for (const e of (await allEmployees(api)).filter(isZZ)) await deleteEmployee(api, e.id);
    await postJson(api, '/test/cleanup', {});
    const cr = await postJson(api, '/employees', {
      personal: { first_name: 'ZZTEST', last_name: `Casey ${tag.slice(-6)}`, personal_email: coEmail },
      employment: { title: 'Shift Lead', department: 'ZZTEST Operations', start_date: '2026-01-05' }, compensation: {},
    });
    coId = (cr.data.employee || cr.data).id;
    coName = `ZZTEST Casey ${tag.slice(-6)}`;
    expect((await postJson(api, '/portal/set-pin', { employee_id: coId, pin: coPin })).status).toBe(200);
    lines.push(`• Setup: test coworker "${coName}" (${coId})`);

    left = await openPortalWindow(testInfo);
    right = await openAdminWindow(testInfo);   // right-hand window, used as the coworker's Portal
    pL = watchForProblems(left.page, 'Test Tester'); pR = watchForProblems(right.page, 'coworker');
    const A = left.page, B = right.page;
    await loginPortal(A);
    await B.goto('/hr_portal/');
    await B.locator('#login-email').fill(coEmail);
    await B.locator('#login-pass').fill(coPin);
    await B.locator('#login-btn').click();
    await expect(B.locator('#app')).toHaveClass(/visible/, { timeout: 20_000 });
    await closeGettingStarted(B, 5_000);

    // 1. Coworker list + privacy
    pL.at('Schedule → Swap a Shift');
    await openSchedule(A);
    await A.getByRole('button', { name: /Swap a Shift/ }).click();
    const person = A.locator('.swap-person', { hasText: coName });
    await expect(person).toBeVisible({ timeout: 10_000 });
    const names = await A.locator('.swap-person').allInnerTexts();
    const realNames = (await allEmployees(api)).filter(e => !isZZ(e) && !/\+hrtest@/.test(e.personal_email || '')).map(e => `${e.first_name} ${e.last_name}`);
    const leaked = realNames.filter(n => names.some(t => t.includes(n)));
    expect(leaked, 'real employees appeared in the test account\'s coworker list').toEqual([]);
    lines.push(`✓ Coworker list shows the test coworker and no real employees (${names.length} name(s))`);

    // 2. Send a swap
    await person.click();
    await A.locator('#swap-msg').fill(`${tag} Can you take my Wed 8am–4pm? I'll take your Fri shift.`);
    await A.locator('#swap-send-btn').click();
    await expect(A.locator('#swap-status')).toContainText('Sent to', { timeout: 10_000 });
    await expect(A.locator('#swap-inbox')).toContainText('Waiting');
    lines.push('✓ Test Tester clicked the coworker\'s name, wrote a short message, and sent it');
    await snap(A, testInfo, '1_sent');

    // 3. Coworker approves
    pR.at('Coworker → Schedule');
    await B.evaluate(() => loadSwaps());
    await expect(B.locator('.sidebar .nav-item[data-page="schedule"] .swap-badge')).toHaveText('1', { timeout: 10_000 });
    await openSchedule(B);
    const item = B.locator('#swap-inbox .swap-item', { hasText: tag }).first();
    await expect(item).toContainText('From');
    await expect(item).toContainText("I'll take your Fri shift");
    await snap(B, testInfo, '2_coworker_inbox');
    await item.getByRole('button', { name: /Approve/ }).click();
    await expect(item).toContainText('You approved', { timeout: 10_000 });
    await A.evaluate(() => loadSwaps());
    await expect(A.locator('#swap-inbox')).toContainText('✓ Approved', { timeout: 10_000 });
    lines.push('✓ Coworker saw a badge + the request → ✓ Approve → Test Tester sees "✓ Approved"');

    // 3b. HR is notified in HR Admin → Messages (approved swaps only)
    const swapNotices = async () => ((await getJson(api, '/messages')).messages || [])
      .filter(m => m.message_type === 'shift_swap' && String(m.body || '').includes(tag));
    await expect.poll(async () => (await swapNotices()).length, { timeout: 10_000, message: 'HR was not notified of the approved swap' }).toBe(1);
    const notice = (await swapNotices())[0];
    expect(notice.subject).toContain('Shift swap approved');
    expect(notice.subject).toContain(coName);
    expect(notice.body).toContain("I'll take your Fri shift");
    expect(notice.read).toBe(false);
    const adm = await (await require('@playwright/test').chromium.launch({ headless: true })).newContext({ baseURL: process.env.HR_E2E_BASE_URL, serviceWorkers: 'block' });
    const ap = await adm.newPage();
    const { loginAdmin, openAdminPage } = require('../helpers/admin');
    await loginAdmin(ap);
    await openAdminPage(ap, 'messages');
    const card = ap.locator('#msg-list > div', { hasText: 'Shift swap approved' }).filter({ hasText: coName }).first();
    await expect(card).toBeVisible({ timeout: 15_000 });
    await expect(card).toContainText('NEW');
    await adm.browser().close();
    lines.push(`✓ HR notified: HR Admin → 💬 Messages shows NEW "${notice.subject.replace(/^ZZTEST /, '')}"`);

    // 4. Second request → Deny
    await A.getByRole('button', { name: /Swap a Shift/ }).click();   // close
    await A.getByRole('button', { name: /Swap a Shift/ }).click();   // reopen (reloads list)
    await A.locator('.swap-person', { hasText: coName }).click();
    await A.locator('#swap-msg').fill(`${tag} Could you cover my Sat morning?`);
    await A.locator('#swap-send-btn').click();
    await expect(A.locator('#swap-status')).toContainText('Sent to', { timeout: 10_000 });
    await B.evaluate(() => loadSwaps());
    const item2 = B.locator('#swap-inbox .swap-item', { hasText: 'Sat morning' }).first();
    await clickAndConfirm(B, item2.getByRole('button', { name: /Deny/ }));
    await expect(item2).toContainText('You declined', { timeout: 10_000 });
    await A.evaluate(() => loadSwaps());
    await expect(A.locator('#swap-inbox .swap-item', { hasText: 'Sat morning' })).toContainText('✗ Declined', { timeout: 10_000 });
    lines.push('✓ Second request → ✗ Deny → Test Tester sees "✗ Declined" (closed)');
    expect((await swapNotices()).length, 'a DENIED swap notified HR (it should not)').toBe(1);
    lines.push('✓ Denied swap did not notify HR (still just the 1 notice for the approved swap)');
    await snap(A, testInfo, '3_declined');

    // 5. Security
    const tt = await employeeApi();
    const sent = (await (await tt.get('/hr-api/swaps/mine')).json()).sent || [];
    const first = sent.find(x => String(x.message).includes("Fri shift"));
    const own = await tt.post(`/hr-api/swaps/${first.id}/respond`, { data: { decision: 'approved' } });
    expect(own.status(), 'the sender answered their own swap').toBe(403);
    const anon = await request.newContext({ baseURL: process.env.HR_E2E_BASE_URL, extraHTTPHeaders: { 'User-Agent': 'Mozilla/5.0 AI-Prowler-HR-E2E' } });
    const co = await anon.post('/hr-api/auth/employee', { data: { email: coEmail, pin: coPin } });
    const coSession = (await co.json()).session;
    const again = await anon.post(`/hr-api/swaps/${first.id}/respond`, { data: { decision: 'denied' }, headers: { 'X-Employee-Session': JSON.stringify(coSession) } });
    expect(again.status(), 'an answered swap was answered again').toBe(409);
    await anon.dispose(); await tt.dispose();
    lines.push('✓ Security: sender can\'t answer their own swap (403); an answered swap can\'t be answered again (409)');
  } finally {
    let cleanupLine;
    try {
      await postJson(api, '/test/cleanup', {});
      // HR swap notices from this test run (tagged ZZTEST by the server)
      const notices = ((await getJson(api, '/messages')).messages || []).filter(m => m.message_type === 'shift_swap' && String(m.subject || '').startsWith('ZZTEST'));
      for (const m of notices) await postJson(api, '/messages/delete', { id: m.id, box: 'inbox' });
      const noticesLeft = ((await getJson(api, '/messages')).messages || []).filter(m => m.message_type === 'shift_swap' && String(m.subject || '').startsWith('ZZTEST')).length;
      for (const e of (await allEmployees(api)).filter(isZZ)) await deleteEmployee(api, e.id);
      const lo = (await getJson(api, '/test/leftovers')).leftovers || {};
      const leftEmp = (await allEmployees(api)).filter(isZZ).length;
      cleanupLine = (!lo.shift_swaps && leftEmp === 0 && noticesLeft === 0) ? 'CLEANUP VERIFIED [SWP]: swaps + HR notices removed, test coworker deleted'
                                                     : `CLEANUP FAILED [SWP]: swaps ${lo.shift_swaps}, notices ${noticesLeft}, employees ${leftEmp}`;
    } catch (e) { cleanupLine = `CLEANUP FAILED [SWP]: ${e.message}`; }
    const probs = [...(pL ? pL.list() : []), ...(pR ? pR.list() : [])];
    const summary = [...lines, `Console errors / failed server calls: ${probs.length}`, ...probs.map(x => '  ✗ ' + x), cleanupLine].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await closeWindow(left, testInfo); await closeWindow(right, testInfo);
    await api.dispose();
    expect.soft(probs).toEqual([]);
    expect(cleanupLine).toContain('CLEANUP VERIFIED');
  }
});
