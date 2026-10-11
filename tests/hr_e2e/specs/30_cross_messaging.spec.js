// X-MSG-01 — Messaging between the Employee Portal and HR Admin.
//
// Two Chrome windows side by side: Portal (left, Test Tester) and HR Admin (right).
//   1. Portal: Test Tester sends a message to HR
//   2. Server: message saved and tied to Test Tester
//   3. HR Admin: message shows in the inbox as NEW → open it → text matches → reply
//   4. Server: reply saved on the message, marked read
//   5. Portal: ↻ Refresh → "Re: <subject>" and the reply appear under Messages from HR
//   6. HR Admin: delete the message with 🗑 (answers the "are you sure" box)
//   7. Cleanup verified: server has no ZZTEST messages left; Portal no longer shows the reply
//
// The HR broadcast outbox is NOT tested here — broadcasts are visible to every employee.
const { test, expect, chromium } = require('@playwright/test');
const { settings, addClickMarker, watchForProblems, loginPortal } = require('../helpers/common');
const { loginAdmin, openAdminPage } = require('../helpers/admin');
const { adminApi, testTag, findMessage, Cleanup } = require('../helpers/api');

const WATCH   = process.env.HR_E2E_WATCH !== '0';
const SLOW_MO = WATCH ? parseInt(process.env.HR_E2E_SLOW_MO || '400', 10) : 0;
const WIN_W = 960, WIN_H = 1000;

// Open one browser window at a screen position, recording video + trace.
async function openWindow(name, x, testInfo) {
  const browser = await chromium.launch({
    headless: !WATCH, slowMo: SLOW_MO,
    args: [`--window-position=${x},0`, `--window-size=${WIN_W},${WIN_H}`],
  });
  const context = await browser.newContext({
    baseURL: process.env.HR_E2E_BASE_URL,
    viewport: { width: WIN_W - 20, height: WIN_H - 140 },
    serviceWorkers: 'block',
    recordVideo: { dir: testInfo.outputPath(`video-${name}`), size: { width: WIN_W - 20, height: WIN_H - 140 } },
  });
  // Step-by-step traces are recorded automatically for every window (trace: 'on' in playwright.config.js)
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

test('X-MSG-01 · Portal ↔ HR Admin messaging (send, reply, delete)', async ({}, testInfo) => {
  const s = settings();
  const TEST_ID = 'XMSG01';
  const tag = testTag(TEST_ID);
  const subject = `${tag} Schedule question`;
  const body = `Hi HR, this is an automated test message (${tag}). Can I switch my Friday shift to 9:00 AM? Thank you!`;
  const replyText = `${tag} Reply from HR: Yes, Friday at 9:00 AM is approved.`;

  const api = await adminApi();
  const cleanup = new Cleanup(api, TEST_ID);
  const report = [];
  let portal, admin, pProblems, aProblems, msgId = null;

  try {
    // ── Setup ───────────────────────────────────────────────────────────
    await test.step('Pre-sweep leftover test messages', async () => {
      await cleanup.sweepOldTestMessages();
    });

    portal = await openWindow('portal', 0, testInfo);
    admin  = await openWindow('admin', WIN_W, testInfo);
    pProblems = watchForProblems(portal.page, 'portal');
    aProblems = watchForProblems(admin.page, 'admin');

    await test.step('Portal: sign in as Test Tester', async () => { await loginPortal(portal.page); });
    await test.step('HR Admin: sign in', async () => { await loginAdmin(admin.page); });

    // ── 1. Portal sends ─────────────────────────────────────────────────
    await test.step('Portal: send a message to HR', async () => {
      const p = portal.page;
      const nav = p.locator('.sidebar .nav-item[data-page="messages"]').first();   // 💬 Messages (has a hidden "!" badge, so match by page, not text)
      await nav.scrollIntoViewIfNeeded();
      await nav.click();
      const subj = p.locator('#portal-msg-subject');
      await expect(subj).toBeVisible();
      await subj.click();
      await subj.pressSequentially(subject, { delay: 15 });
      const bodyBox = p.locator('#portal-msg-body');
      await bodyBox.click();
      await bodyBox.pressSequentially(body, { delay: 8 });
      await p.locator('#portal-msg-btn').click();
      const fb = p.locator('#portal-msg-feedback');
      await expect(fb).toContainText('Sent! Reference:', { timeout: 15_000 });
      const m = (await fb.innerText()).match(/MSG-[A-Z0-9]+/);
      expect(m, 'Portal did not show a message reference number').toBeTruthy();
      msgId = m[0];
      cleanup.trackMessage(msgId);
      report.push(`✓ Portal sent message ${msgId}`);
      await snap(p, testInfo, '1_portal_sent');
    });

    // ── 2. Server has it ────────────────────────────────────────────────
    await test.step('Server: message saved and tied to Test Tester', async () => {
      const m = await findMessage(api, msgId);
      expect(m, `Message ${msgId} not found on the server`).toBeTruthy();
      expect(m.subject).toBe(subject);
      expect(m.body).toBe(body);
      expect(m.employee_id, 'Message is not tied to Test Tester').toBe(process.env.HR_E2E_TT_ID);
      expect(m.read).toBe(false);
      report.push(`✓ Server: saved, from ${m.sender_name} (${m.employee_id}), unread`);
    });

    // ── 3. HR Admin reads + replies ─────────────────────────────────────
    const a = admin.page;
    const card = a.locator('#msg-list > div', { hasText: subject });
    await test.step('HR Admin: message appears in inbox as NEW', async () => {
      await openAdminPage(a, 'messages');
      await expect(card).toBeVisible({ timeout: 20_000 });
      await expect(card).toContainText('NEW');
      await expect(card).toContainText(s.ttName);
      report.push('✓ HR Admin: message in inbox, marked NEW, from Test Tester');
      await snap(a, testInfo, '2_admin_inbox');
    });

    await test.step('HR Admin: open message — text matches', async () => {
      await card.getByText(subject).click();
      await expect(a.locator('#msg-detail-overlay')).toBeVisible();
      await expect(a.locator('#msg-detail-body')).toHaveText(body);
      await expect(a.locator('#msg-detail-meta')).toContainText(subject);
      report.push('✓ HR Admin: opened message, subject and text match');
    });

    await test.step('HR Admin: send a reply', async () => {
      const box = a.locator('#msg-reply-box');
      await box.click();
      await box.pressSequentially(replyText, { delay: 10 });
      await snap(a, testInfo, '3_admin_reply_typed');
      await a.locator('#msg-reply-btn').click();
      await expect(a.locator('#msg-detail-overlay')).toBeHidden({ timeout: 15_000 });
      await expect(card).toContainText('↩ Replied', { timeout: 15_000 });
      await expect(card).not.toContainText('NEW');
      report.push('✓ HR Admin: reply sent; card shows "↩ Replied", no longer NEW');
    });

    // ── 4. Server has the reply ─────────────────────────────────────────
    await test.step('Server: reply saved, message marked read', async () => {
      const m = await findMessage(api, msgId);
      expect(m.reply).toBe(replyText);
      expect(m.read).toBe(true);
      expect(m.replied_at, 'reply has no time stamp').toBeTruthy();
      report.push('✓ Server: reply stored on the message, marked read');
    });

    // ── 5. Portal sees the reply ────────────────────────────────────────
    const p = portal.page;
    const inbox = p.locator('#portal-inbox-list');
    const refreshBtn = p.locator('button:visible', { hasText: 'Refresh' }).first();   // ↻ Refresh on Messages from HR
    await test.step('Portal: ↻ Refresh shows the HR reply', async () => {
      await refreshBtn.click();
      await expect(inbox).toContainText(`Re: ${subject}`, { timeout: 15_000 });
      await expect(inbox).toContainText(replyText);
      report.push('✓ Portal: "Re: <subject>" and the reply text appear under Messages from HR');
      await snap(p, testInfo, '4_portal_reply');
    });

    // ── 6. HR Admin deletes (tests the 🗑 button + confirm box) ─────────
    await test.step('HR Admin: delete the message with 🗑', async () => {
      a.once('dialog', d => d.accept());       // "Delete this message? This cannot be undone." → OK
      await card.locator('button[title="Delete"]').click();
      await expect(card).toHaveCount(0, { timeout: 15_000 });
      report.push('✓ HR Admin: 🗑 delete removed the message from the inbox');
    });

    // ── 7. Gone everywhere ──────────────────────────────────────────────
    await test.step('Deleted everywhere (server + Portal)', async () => {
      expect(await findMessage(api, msgId), 'Message still on the server after delete').toBeNull();
      await refreshBtn.click();
      await expect(inbox).not.toContainText(subject, { timeout: 15_000 });
      report.push('✓ Gone from the server and from the Portal');
      await snap(p, testInfo, '5_portal_after_delete');
    });

  } finally {
    // ── Cleanup (runs even if the test failed) — delete + verify ─────────
    const leftovers = await cleanup.run().catch(e => [`cleanup error: ${e.message}`]);
    const problems = [...(pProblems ? pProblems.list() : []), ...(aProblems ? aProblems.list() : [])];
    const summary = [
      `Message: ${msgId || '(not created)'} · subject "${subject}"`,
      ...report,
      `Console errors / failed server calls: ${problems.length}`,
      ...problems.map(x => '  ✗ ' + x),
      ...cleanup.lines,
    ].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await closeWindow(portal, testInfo);
    await closeWindow(admin, testInfo);
    await api.dispose();

    expect.soft(problems, 'Console errors or failed server calls were found').toEqual([]);
    expect(leftovers, 'Test data was left behind on the server').toEqual([]);
  }
});
