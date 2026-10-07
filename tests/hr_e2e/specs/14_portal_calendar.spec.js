// PRT-CCAL-01 / PRT-CAL-03 — Company Calendar: birthdays and time off land on the RIGHT day.
// (Bugs #14 and #20 showed dates can slip a day in Arizona — this checks the calendar doesn't.)
//  Setup: Test Tester's birthday = Oct 16; one approved day off = Wed Oct 21 (2026)
//  1. Oct 16 shows 🎂 Test — Oct 15 and Oct 17 do not
//  2. Oct 21 shows Test as off — Oct 20 and Oct 22 do not
// Cleanup: birthday restored, time off removed — both verified.
const { test, expect } = require('@playwright/test');
const { addClickMarker, watchForProblems, loginPortal } = require('../helpers/common');
const { adminApi, testTag, getJson, postJson, getEmployee, patchEmployee } = require('../helpers/api');

const BDAY = '1990-10-16', OFF = '2026-10-21';

test('PRT-CCAL-01 · Company Calendar: birthday and time off on the right day (no one-day slip)', async ({ page }, testInfo) => {
  const ttId = process.env.HR_E2E_TT_ID;
  const tag = testTag('CAL');
  const api = await adminApi();
  const lines = [];
  let dobBefore, reqId;
  await addClickMarker(page);
  const problems = watchForProblems(page, 'portal');
  const cell = (k) => page.locator(`#ccscroll [data-key="${k}"]`).first();

  try {
    dobBefore = (await getEmployee(api, ttId)).date_of_birth || '';
    await patchEmployee(api, ttId, { date_of_birth: BDAY });
    const r = await postJson(api, '/pto/request', { employee_id: ttId, type: 'PTO (Vacation)', start_date: OFF, end_date: OFF, notes: `${tag} calendar check` });
    expect(r.status, 'could not create the setup time off').toBeLessThan(300);
    reqId = r.data.request.id;
    await postJson(api, `/pto/${reqId}/approve`, {});
    lines.push(`• Setup: Test Tester birthday Oct 16; approved day off Wed ${OFF} (${reqId})`);

    await loginPortal(page);
    problems.at('Company Calendar');
    const navId = await page.evaluate(() => {
      const el = [...document.querySelectorAll('.sidebar .nav-item[data-page]')].find(n => /Company Calendar/i.test(n.innerText));
      return el ? el.getAttribute('data-page') : null;
    });
    expect(navId, 'no "Company Calendar" in the sidebar').toBeTruthy();
    const nav = page.locator(`.sidebar .nav-item[data-page="${navId}"]`).first();
    await nav.scrollIntoViewIfNeeded(); await nav.click();
    await expect(cell('2026-10-16')).toBeAttached({ timeout: 15_000 });

    // 1. Birthday on Oct 16 only
    await expect(cell('2026-10-16'), 'birthday missing from Oct 16').toContainText('Test', { timeout: 15_000 });
    await expect(cell('2026-10-16')).toContainText('🎂');
    for (const k of ['2026-10-15', '2026-10-17']) {
      const t = await cell(k).innerText();
      expect(/🎂[^\n]*Test/.test(t), `birthday slipped onto ${k}`).toBe(false);
    }
    lines.push('✓ 🎂 Test on Oct 16 — not on Oct 15 or Oct 17 (no one-day slip)');

    // 2. Day off on Oct 21 only
    await expect(cell(OFF), 'time off missing from Oct 21').toContainText('Test', { timeout: 15_000 });
    for (const k of ['2026-10-20', '2026-10-22']) {
      const t = (await cell(k).innerText()).replace(/🎂.*$/m, '');
      expect(t.includes('Test'), `time off slipped onto ${k}`).toBe(false);
    }
    lines.push(`✓ Test shown off on Wed ${OFF} — not on Tue Oct 20 or Thu Oct 22`);

    const shot = testInfo.outputPath('company_calendar_oct.png');
    await cell('2026-10-16').scrollIntoViewIfNeeded();
    await page.screenshot({ path: shot });
    await testInfo.attach('Company Calendar — October', { path: shot, contentType: 'image/png' });
  } finally {
    let cleanupLine;
    try {
      if (reqId) await postJson(api, `/pto/${reqId}/delete`, {});
      await patchEmployee(api, ttId, { date_of_birth: dobBefore });
      const now = await getEmployee(api, ttId);
      const left = ((await getJson(api, '/pto')).requests || []).filter(x => String(x.notes || '').includes(tag)).length;
      cleanupLine = (left === 0 && (now.date_of_birth || '') === dobBefore)
        ? 'CLEANUP VERIFIED [CAL]: time off removed, birthday restored'
        : `CLEANUP FAILED [CAL]: requests left ${left}, birthday "${now.date_of_birth}"`;
    } catch (e) { cleanupLine = `CLEANUP FAILED [CAL]: ${e.message}`; }
    const probs = problems.list();
    const summary = [...lines, `Console errors / failed server calls: ${probs.length}`, ...probs.map(x => '  ✗ ' + x), cleanupLine].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await api.dispose();
    expect.soft(probs).toEqual([]);
    expect(cleanupLine).toContain('CLEANUP VERIFIED');
  }
});
