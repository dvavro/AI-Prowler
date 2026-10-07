// ADM-LAY-01 — Every HR Admin menu page opens and looks right.
// ADM-LAY-02 — Main (btn-primary) buttons are styled, not plain white browser defaults.
// Views only — creates no data.
const { test, expect } = require('@playwright/test');
const { addClickMarker, watchForProblems, badTextIn } = require('../helpers/common');
const { loginAdmin, openAdminPage } = require('../helpers/admin');

const UNSTYLED = ['rgb(255, 255, 255)', 'rgb(239, 239, 239)', 'rgb(240, 240, 240)', 'rgba(0, 0, 0, 0)', 'transparent'];

test('ADM-LAY-01 · Every HR Admin page opens (and ADM-LAY-02 buttons styled)', async ({ page }, testInfo) => {
  const issues = [];
  const unstyled = new Set();
  await addClickMarker(page);
  const problems = watchForProblems(page, 'admin');

  await test.step('Sign in', async () => { await loginAdmin(page); });

  const tabs = await page.evaluate(() =>
    Array.from(document.querySelectorAll('#sidebar-nav .sidebar-item[data-tab]'))
      .filter(el => getComputedStyle(el).display !== 'none')
      .map(el => ({ tab: el.dataset.tab, label: el.innerText.trim().replace(/\s+/g, ' ') }))
      .filter((v, i, a) => a.findIndex(x => x.tab === v.tab) === i));
  testInfo.annotations.push({ type: 'pages found', description: `${tabs.length}: ${tabs.map(t => t.label).join(', ')}` });
  expect(tabs.length, 'no HR Admin menu pages found').toBeGreaterThan(5);

  for (const t of tabs) {
    await test.step(`Open "${t.label}"`, async () => {
      problems.at(t.label);                       // label any error with this page's name
      try { await openAdminPage(page, t.tab); }
      catch (e) { issues.push(`${t.label}: could not click menu item (${e.message.split('\n')[0]})`); return; }
      await page.waitForTimeout(900);
      const r = await page.evaluate((tab) => {
        // Recruiting shows its content in its own containers (#rec-fixed-header + #rec-scroll-body)
        // and hides the normal page area, so measure those instead.
        const ALT = { recruiting: 'rec-scroll-body' };
        const pane = document.getElementById(ALT[tab] || ('tab-' + tab)) || document.getElementById('tab-' + tab);
        if (!pane) return { missing: true };
        const rect = pane.getBoundingClientRect();
        const btns = Array.from(pane.querySelectorAll('.btn-primary'))
          .filter(b => b.offsetParent !== null)
          .map(b => ({ text: (b.innerText || '').trim().slice(0, 30), bg: getComputedStyle(b).backgroundColor }));
        return {
          shown: getComputedStyle(pane).display !== 'none',
          height: Math.round(rect.height),
          sideScroll: document.documentElement.scrollWidth > window.innerWidth + 2,
          text: (pane.innerText || '').slice(0, 30000),
          btns,
        };
      }, t.tab);

      const shot = testInfo.outputPath(`admin_${t.tab}.png`);
      await page.screenshot({ path: shot });
      await testInfo.attach(`page: ${t.label}`, { path: shot, contentType: 'image/png' });

      if (r.missing) { issues.push(`${t.label}: no page panel "#tab-${t.tab}" exists`); return; }
      if (!r.shown) issues.push(`${t.label}: page panel did not show`);
      if (r.height < 60) issues.push(`${t.label}: page looks blank (${r.height}px tall)`);
      if (r.sideScroll) issues.push(`${t.label}: whole window scrolls sideways`);
      for (const why of badTextIn(r.text)) issues.push(`${t.label}: shows ${why}`);
      for (const b of r.btns) if (UNSTYLED.includes(b.bg)) unstyled.add(`${t.label}: "${b.text}" (${b.bg})`);
    });
  }

  const consoleIssues = problems.list();
  const report = [
    `Pages checked: ${tabs.length}`,
    `Layout / text problems: ${issues.length}`, ...issues.map(i => '  ✗ ' + i),
    `Unstyled main buttons (ADM-LAY-02): ${unstyled.size}`, ...[...unstyled].map(i => '  ✗ ' + i),
    `Console errors / failed server calls: ${consoleIssues.length}`, ...consoleIssues.map(i => '  ✗ ' + i),
  ].join('\n');
  await testInfo.attach('summary', { body: report, contentType: 'text/plain' });
  console.log('\n' + report + '\n');

  expect.soft([...unstyled], 'ADM-LAY-02: unstyled main buttons').toEqual([]);
  expect.soft(consoleIssues, 'Console errors or failed server calls').toEqual([]);
  expect(issues, 'Layout or text problems').toEqual([]);
});
