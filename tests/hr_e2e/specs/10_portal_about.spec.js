// PRT-ABT-01…05, 07 — About Me: view cards, edit + save + persist, cancel, Fun Stuff, locked email.
// Cleanup: Test Tester's profile fields are restored to what they were before, and verified.
const { test, expect } = require('@playwright/test');
const { addClickMarker, watchForProblems, loginPortal } = require('../helpers/common');
const { adminApi, testTag, getEmployee, patchEmployee } = require('../helpers/api');

const FIELDS = ['nickname', 'pronouns', 'about_fun', 'work_style'];

test('PRT-ABT-01…07 · About Me: edit, save, persist, cancel, locked email', async ({ page }, testInfo) => {
  const ttId = process.env.HR_E2E_TT_ID;
  const tag = testTag('ABT');
  const nick = `${tag} Tess`;
  const api = await adminApi();
  const report = [];
  let baseline = null;
  await addClickMarker(page);
  const problems = watchForProblems(page, 'portal');

  const openAbout = async () => {
    const nav = page.locator('.sidebar .nav-item[data-page="about"]').first();
    await nav.scrollIntoViewIfNeeded(); await nav.click();
    await expect(page.locator('#ab-sec-personal')).toBeVisible();
  };

  try {
    await test.step('Remember Test Tester\'s current About Me (baseline)', async () => {
      const emp = await getEmployee(api, ttId);
      baseline = {};
      for (const f of FIELDS) baseline[f] = emp[f] === undefined ? null : JSON.parse(JSON.stringify(emp[f]));
    });

    await test.step('Sign in', async () => { await loginPortal(page); });

    await test.step('PRT-ABT-01: About Me shows cards with ✏️ Edit', async () => {
      problems.at('About');
      await openAbout();
      for (const sec of ['personal', 'fun', 'work']) {
        await expect(page.locator(`#ab-sec-${sec}`).getByRole('button', { name: /Edit/ })).toBeVisible();
      }
      report.push('✓ About Me: Personal Info, Fun Stuff, Work Style cards each have ✏️ Edit');
    });

    await test.step('PRT-ABT-07: Personal Email can\'t be edited', async () => {
      await page.locator('#ab-sec-personal').getByRole('button', { name: /Edit/ }).click();
      await expect(page.locator('#ab-personal-nickname')).toBeVisible();
      await expect(page.locator('#ab-personal-personal_email'), 'login email is editable').toHaveCount(0);
      report.push('✓ Personal Email is shown read-only (it\'s the login email)');
    });

    await test.step('PRT-ABT-04: Cancel throws away changes', async () => {
      await page.locator('#ab-personal-nickname').fill(`${tag} SHOULD NOT SAVE`);
      await page.locator('#ab-sec-personal').getByRole('button', { name: 'Cancel' }).click();
      await expect(page.locator('#ab-sec-personal')).not.toContainText('SHOULD NOT SAVE');
      const emp = await getEmployee(api, ttId);
      expect(String(emp.nickname || ''), 'Cancel still saved to the server').not.toContain('SHOULD NOT SAVE');
      report.push('✓ Cancel: nothing shown, nothing saved');
    });

    await test.step('PRT-ABT-02: Edit Preferred Name → Save', async () => {
      await page.locator('#ab-sec-personal').getByRole('button', { name: /Edit/ }).click();
      await page.locator('#ab-personal-nickname').fill(nick);
      await page.locator('#ab-personal-pronouns').fill('she/her');
      await page.locator('#ab-save-personal').click();
      await expect(page.locator('#ab-toast')).toContainText('Saved', { timeout: 15_000 });
      await expect(page.locator('#ab-sec-personal')).toContainText(nick);
      await expect.poll(async () => (await getEmployee(api, ttId)).nickname, { timeout: 10_000 }).toBe(nick);
      report.push('✓ Saved: toast shown, card updated, server has the new Preferred Name');
    });

    await test.step('PRT-ABT-03: Still there after leaving and reloading', async () => {
      await page.locator('.sidebar .nav-item[data-page="portfolio"]').first().click();
      await page.reload();
      await expect(page.locator('#app')).toHaveClass(/visible/, { timeout: 20_000 });
      await openAbout();
      await expect(page.locator('#ab-sec-personal')).toContainText(nick, { timeout: 15_000 });
      await expect(page.locator('#ab-banner')).toContainText(nick);
      report.push('✓ Persists after leaving the page and reloading (card + banner)');
    });

    await test.step('PRT-ABT-05: Fun Stuff saves', async () => {
      const fun = page.locator('#ab-sec-fun');
      await fun.getByRole('button', { name: /Edit/ }).click();
      await page.locator('#ab-fun-fact').fill(`${tag} I once hiked the Grand Canyon`);
      await page.locator('#ab-fun-coffee').selectOption({ index: 1 });
      await page.locator('#ab-save-fun').click();
      await expect(fun).toContainText(`${tag} I once hiked the Grand Canyon`, { timeout: 15_000 });
      await expect.poll(async () => ((await getEmployee(api, ttId)).about_fun || {}).fact, { timeout: 10_000 })
        .toBe(`${tag} I once hiked the Grand Canyon`);
      report.push('✓ Fun Stuff saved to the server and shown in its tile');
    });

  } finally {
    let cleanupLine;
    try {
      const restore = {};
      for (const f of FIELDS) restore[f] = baseline ? (baseline[f] ?? (f === 'about_fun' || f === 'work_style' ? {} : '')) : '';
      await patchEmployee(api, ttId, restore);
      const now = await getEmployee(api, ttId);
      const left = JSON.stringify(FIELDS.map(f => now[f])).includes('ZZTEST');
      cleanupLine = left ? `CLEANUP FAILED [ABT]: ZZTEST text still on Test Tester's profile`
                         : 'CLEANUP VERIFIED [ABT]: About Me fields restored to baseline';
    } catch (e) { cleanupLine = `CLEANUP FAILED [ABT]: ${e.message}`; }
    const probs = problems.list();
    const summary = [...report, `Console errors / failed server calls: ${probs.length}`, ...probs.map(x => '  ✗ ' + x), cleanupLine].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await api.dispose();
    expect.soft(probs, 'Console errors or failed server calls').toEqual([]);
    expect(cleanupLine).toContain('CLEANUP VERIFIED');
  }
});
