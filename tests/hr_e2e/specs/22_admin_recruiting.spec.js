// ADM-REC-04…08 — Recruiting interview sheet.
// Setup (API): a ZZTEST position, candidate, and interview are added to the recruiting bundle.
// Tested through the screen:
//   1. Recruiting → Interviews: the interview is listed
//   2. Open its 📝 interview sheet → 15 questions in 4 groups
//   3. Notes on 2 questions, star ratings, overall ★★★★, 👍 Hire, overall notes, + own question → 💾 Save
//   4. Server: answers, ratings, recommendation, custom question all saved on the interview
//   5. Card shows the summary ("📝 3/16 answered … 👍 Hire")
//   6. Reload → reopen: everything still there
// Cleanup: ZZTEST items removed from the bundle (read-modify-write of the LATEST bundle), verified.
const { test, expect } = require('@playwright/test');
const { addClickMarker, watchForProblems } = require('../helpers/common');
const { loginAdmin, openAdminPage } = require('../helpers/admin');
const { adminApi, testTag, getJson, postJson } = require('../helpers/api');

const isZZ = (x) => JSON.stringify(x).includes('ZZTEST');
async function bundle(api) {
  const d = await getJson(api, '/recruiting');
  const b = d.recruiting || { positions: [], candidates: [], interviews: [], offers: [] };
  if (typeof d.version === 'number') b.version = d.version;   // send back with saves → never overwrite newer data
  return b;
}
async function removeZZ(api) {
  const b = await bundle(api);                         // always the LATEST bundle, so real edits aren't lost
  const clean = {};
  if (b.version !== undefined) clean.version = b.version;
  for (const k of ['positions', 'candidates', 'interviews', 'offers']) clean[k] = (b[k] || []).filter(x => !isZZ(x));
  const removed = ['positions', 'candidates', 'interviews', 'offers'].reduce((n, k) => n + (b[k] || []).length - clean[k].length, 0);
  if (removed) await postJson(api, '/recruiting', clean);
  return removed;
}

test('ADM-REC-04…08 · Interview sheet: questions, notes, stars, Hire, own question, save, persist', async ({ page }, testInfo) => {
  const tag = testTag('REC');
  const ids = { pos: `POS-${tag}`, cand: `CAND-${tag}`, int: `INT-${tag}` };
  const api = await adminApi();
  const report = [];
  await addClickMarker(page);
  const problems = watchForProblems(page, 'admin');

  try {
    await test.step('Setup (API): ZZTEST position + candidate + interview', async () => {
      const old = await removeZZ(api);
      const b = await bundle(api);
      const tomorrow = new Date(); tomorrow.setDate(tomorrow.getDate() + 1); tomorrow.setHours(10, 0, 0, 0);
      b.positions.push({ id: ids.pos, title: `${tag} Warehouse Associate`, department: 'Operations', status: 'open' });
      b.candidates.push({ id: ids.cand, name: `ZZTEST Jordan Ellis ${tag.slice(-6)}`, email: 'jordan.ellis.zztest@example.com', phone: '(480) 555-0150', position_id: ids.pos, stage: 'interview' });
      b.interviews.push({ id: ids.int, candidate_id: ids.cand, position_id: ids.pos, date_time: tomorrow.toISOString(), type: 'In-person', interviewers: 'ZZTEST Kevin Park', notes: `${tag} setup` });
      const r = await postJson(api, '/recruiting', b);
      expect(r.status, 'could not save the recruiting setup').toBeLessThan(300);
      report.push(`• Setup: position, candidate, interview added (${old} old test item(s) cleared first)`);
    });

    await test.step('Sign in → Recruiting → Interviews', async () => {
      await loginAdmin(page);
      problems.at('Recruiting');
      await openAdminPage(page, 'recruiting');
      await page.locator('#rsnav-interviews').click();   // the Interviews TAB (a counter box is also labeled "Interviews")
      // REG-19 (bug #10): clicking a tab while Recruiting is still loading used to bounce back to Positions
      await page.waitForTimeout(2000);
      await expect(page.locator('#rsnav-interviews'), 'bounced away from the Interviews tab after loading').toHaveClass(/active/);
      await expect(page.locator(`button[onclick="openInterviewSheet('${ids.int}')"]`)).toBeVisible({ timeout: 15_000 });
      report.push('✓ Interviews tab stays selected after loading (REG-19) and lists the test interview');
    });

    await test.step('ADM-REC-05: open the interview sheet → 15 questions in 4 groups', async () => {
      await page.locator(`button[onclick="openInterviewSheet('${ids.int}')"]`).click();   // the card's 📝 Questions button
      await expect(page.locator('#iq-n-0')).toBeVisible();
      const qCount = await page.locator('textarea[id^="iq-n-"]').count();
      expect(qCount, 'number of questions').toBe(15);
      for (const g of ['Getting to Know You', 'Experience & Skills', 'Teamwork & Behavior', 'Fit & Logistics']) {
        await expect(page.getByText(g, { exact: false }).first()).toBeVisible();
      }
      report.push('✓ Sheet opens with 15 questions in 4 groups');
    });

    await test.step('ADM-REC-06/08: answer, rate, recommend, add own question → Save', async () => {
      await page.locator('#iq-n-0').fill(`${tag} Five years in warehouse operations, forklift certified.`);
      await page.locator('[onclick="_iqRateQ.bind(null,0)(4)"]').click();
      await page.locator('#iq-n-3').fill(`${tag} Led inventory audit that cut shrinkage 12%.`);
      await page.locator('[onclick="_iqRateQ.bind(null,3)(5)"]').click();
      await page.locator('[onclick="_iqAddQ()"]').click();
      await page.locator('#iq-q-15').fill(`${tag} Are you comfortable lifting 50 lb?`);
      await page.locator('#iq-n-15').fill('Yes, daily in current role.');
      await page.locator('[onclick="_iqRateOverall(4)"]').click();
      await page.locator(`[onclick="_iqSetRec('hire')"]`).click();
      await page.locator('#iq-overall-notes').fill(`${tag} Strong, reliable — recommend hire.`);
      await page.locator('[onclick="_iqSave()"]').click();
      await expect(page.locator('#iq-n-0')).toBeHidden({ timeout: 10_000 });   // sheet closed (pop-ups are hidden, not removed)
      report.push('✓ Typed 3 answers, star ratings, overall ★★★★, 👍 Hire, own question → saved');
    });

    await test.step('Server: everything saved on the interview', async () => {
      // HR Admin saves in the background — wait for it to land
      await expect.poll(async () => ((await bundle(api)).interviews.find(x => x.id === ids.int)?.qa || []).length,
        { timeout: 15_000, message: 'interview answers never reached the server' }).toBe(16);
      const i = (await bundle(api)).interviews.find(x => x.id === ids.int);
      expect(i, 'interview missing').toBeTruthy();
      expect((i.qa || []).length, 'questions saved').toBe(16);
      expect(i.qa[0].notes).toContain('forklift'); expect(i.qa[0].rating).toBe(4);
      expect(i.qa[3].rating).toBe(5);
      expect(i.qa[15].q).toContain('50 lb'); expect(i.qa[15].group).toBe('My Questions');
      expect(i.overall_rating).toBe(4); expect(i.recommendation).toBe('hire');
      expect(i.overall_notes).toContain('recommend hire');
      report.push('✓ Server: 16 questions (15 + own), notes, ratings 4 and 5, overall 4, "hire", overall notes');
    });

    await test.step('ADM-REC-06: card shows the summary', async () => {
      const card = page.locator(`button[onclick="openInterviewSheet('${ids.int}')"]`).locator('xpath=ancestor::div[contains(@class,"list-item")][1]');
      await expect(card).toContainText('3/16 answered');
      await expect(card).toContainText('Hire');
      report.push('✓ Interview card shows "📝 3/16 answered … 👍 Hire"');
    });

    await test.step('ADM-REC-07: reload → reopen → still there', async () => {
      await page.reload();
      await expect(page.locator('#auth-screen')).toBeHidden({ timeout: 20_000 });
      await openAdminPage(page, 'recruiting');
      await page.locator('#rsnav-interviews').click();
      await page.locator(`button[onclick="openInterviewSheet('${ids.int}')"]`).click();
      await expect(page.locator('#iq-n-0')).toHaveValue(/forklift/);
      await expect(page.locator('#iq-q-15')).toHaveValue(/50 lb/);
      await expect(page.locator('#iq-overall-notes')).toHaveValue(/recommend hire/);
      report.push('✓ After reload the sheet reopens with the answers, own question, and overall notes');
      await page.getByRole('button', { name: /Close without saving/ }).click();
    });

  } finally {
    let cleanupLine;
    try {
      await removeZZ(api);
      const b = await bundle(api);
      const leftCount = ['positions', 'candidates', 'interviews', 'offers'].reduce((n, k) => n + (b[k] || []).filter(isZZ).length, 0);
      cleanupLine = leftCount === 0 ? 'CLEANUP VERIFIED [REC]: 0 ZZTEST recruiting items left (real recruiting data untouched)'
                                    : `CLEANUP FAILED [REC]: ${leftCount} ZZTEST recruiting item(s) left`;
    } catch (e) { cleanupLine = `CLEANUP FAILED [REC]: ${e.message}`; }
    const probs = problems.list();
    const summary = [...report, `Console errors / failed server calls: ${probs.length}`, ...probs.map(x => '  ✗ ' + x), cleanupLine].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await api.dispose();
    expect.soft(probs, 'Console errors or failed server calls').toEqual([]);
    expect(cleanupLine).toContain('CLEANUP VERIFIED');
  }
});

// ADM-REC-13 — Two HR people editing recruiting at once must NOT overwrite each other.
test('ADM-REC-13 · Recruiting: an out-of-date save is refused, the newer change survives', async ({}, testInfo) => {
  const tag = testTag('REC13');
  const api = await adminApi();
  const lines = [];
  let cleanupLine;
  try {
    await removeZZ(api);
    const A = await bundle(api);                           // person A loads
    const B = JSON.parse(JSON.stringify(A));               // person B loads the same version
    expect(typeof A.version, 'server did not send a recruiting version — deploy ai_prowler_mcp.py and restart').toBe('number');

    A.positions.push({ id: `POS-${tag}-A`, title: `${tag} Saved by person A`, status: 'open' });
    const ra = await postJson(api, '/recruiting', A);
    expect(ra.status, 'person A\'s save').toBe(200);
    lines.push(`✓ Person A saved first (version ${A.version} → ${ra.data.version})`);

    B.positions.push({ id: `POS-${tag}-B`, title: `${tag} Saved by person B (out of date)`, status: 'open' });
    const rb = await postJson(api, '/recruiting', B);
    expect(rb.status, 'person B\'s out-of-date save should be refused').toBe(409);
    lines.push(`✓ Person B saved from an out-of-date copy → refused (409 "${rb.data.message}")`);

    const now = await bundle(api);
    expect(now.positions.some(p => p.id === `POS-${tag}-A`), 'person A\'s change was lost').toBe(true);
    expect(now.positions.some(p => p.id === `POS-${tag}-B`), 'the out-of-date save got through').toBe(false);
    lines.push('✓ Person A\'s change is still there; nothing was overwritten');
  } finally {
    try {
      await removeZZ(api);
      const b = await bundle(api);
      const left = b.positions.filter(isZZ).length;
      cleanupLine = left === 0 ? 'CLEANUP VERIFIED [REC13]: 0 ZZTEST positions left' : `CLEANUP FAILED [REC13]: ${left} left`;
    } catch (e) { cleanupLine = `CLEANUP FAILED [REC13]: ${e.message}`; }
    const summary = [...lines, cleanupLine].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await api.dispose();
    expect(cleanupLine).toContain('CLEANUP VERIFIED');
  }
});
