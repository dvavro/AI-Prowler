// MOB-LAY-02 — HR Admin on a phone (iPhone 14, emulated in Chrome).
// Opens every menu page through ☰ Menu and checks:
//   • the top bar fits the phone (bug #17 was the Portal's top bar forcing a zoom-out)
//   • nothing scrolls sideways, pages aren't blank, no "undefined"/"NaN"/"DEBUG" text
//   • small tap targets (< 36 px) listed as WARNINGS, not failures
// Views only — creates no data.
const { test, expect, devices } = require('@playwright/test');
const { addClickMarker, watchForProblems, badTextIn } = require('../helpers/common');
const { loginAdmin, openAdminPage } = require('../helpers/admin');

const { defaultBrowserType, ...iphone } = devices['iPhone 14'];
test.use({ ...iphone });

test('MOB-LAY-02 · HR Admin on iPhone 14: every menu page fits the phone', async ({ page }, testInfo) => {
  const issues = [], warnings = [], lines = [];
  await addClickMarker(page);
  const problems = watchForProblems(page, 'admin · iPhone 14');
  await loginAdmin(page);
  const win = page.viewportSize().width;

  const top = await page.evaluate(() => {
    const h = document.getElementById('top-bar') || document.querySelector('#top-bar-title')?.parentElement;
    return h ? { needs: h.scrollWidth, has: h.clientWidth } : null;
  });
  if (top && top.needs > top.has + 2) issues.push(`Top bar needs ${top.needs}px but the phone is ${win}px wide`);
  else if (top) lines.push(`✓ Top bar fits the phone (${top.needs}px of ${win}px)`);

  const tabs = await page.evaluate(() =>
    Array.from(document.querySelectorAll('#sidebar-nav .sidebar-item[data-tab]'))
      .filter(el => getComputedStyle(el).display !== 'none')
      .map(el => ({ tab: el.dataset.tab, label: el.innerText.trim().replace(/\s+/g, ' ') }))
      .filter((v, i, a) => a.findIndex(x => x.tab === v.tab) === i));
  expect(tabs.length, 'no HR Admin menu pages found').toBeGreaterThan(5);

  for (const t of tabs) {
    await test.step(`☰ → ${t.label}`, async () => {
      problems.at(t.label);
      try { await openAdminPage(page, t.tab); }
      catch (e) { issues.push(`${t.label}: couldn't open from the menu (${e.message.split('\n')[0]})`); return; }
      await page.waitForTimeout(700);
      const r = await page.evaluate((tab) => {
        const ALT = { recruiting: 'rec-scroll-body' };
        const pane = document.getElementById(ALT[tab] || ('tab-' + tab)) || document.getElementById('tab-' + tab);
        if (!pane) return { missing: true };
        const small = [...pane.querySelectorAll('button, [onclick]')].filter(b => b.offsetParent !== null)
          .map(b => ({ t: (b.innerText || b.title || '').trim().slice(0, 22), w: b.getBoundingClientRect().width, h: b.getBoundingClientRect().height }))
          .filter(b => b.h > 0 && (b.h < 36 || b.w < 36) && b.t);
        const tiny = [...pane.querySelectorAll('button, .chip')].filter(b => b.offsetParent !== null)
          .map(b => ({ t: (b.innerText || b.title || '').trim().slice(0, 22), w: b.getBoundingClientRect().width, h: b.getBoundingClientRect().height }))
          .filter(b => b.h > 0 && (b.h < 28 || b.w < 28));
        const wide = [...pane.querySelectorAll('*')].filter(el => el.getBoundingClientRect().right > window.innerWidth + 2 && getComputedStyle(el).position !== 'fixed')
          .slice(0, 3).map(el => (el.id ? '#' + el.id : el.tagName.toLowerCase()) + ' ' + Math.round(el.getBoundingClientRect().right) + 'px');
        return {
          sideScroll: document.documentElement.scrollWidth > window.innerWidth + 2,
          height: Math.round(pane.getBoundingClientRect().height),
          text: (pane.innerText || '').slice(0, 30000), small: small.slice(0, 5), smallCount: small.length, wide,
          tiny: tiny.slice(0, 4), tinyCount: tiny.length,
        };
      }, t.tab);
      const shot = testInfo.outputPath(`admin_phone_${t.tab}.png`);
      await page.screenshot({ path: shot });
      await testInfo.attach(`iPhone 14: ${t.label}`, { path: shot, contentType: 'image/png' });
      if (r.missing) { issues.push(`${t.label}: no page panel`); return; }
      if (r.sideScroll) issues.push(`${t.label}: scrolls sideways${r.wide.length ? ' — too wide: ' + r.wide.join(', ') : ''}`);
      if (r.height < 60) issues.push(`${t.label}: looks blank`);
      for (const why of badTextIn(r.text)) issues.push(`${t.label}: shows ${why}`);
      if (r.smallCount) warnings.push(`${t.label}: ${r.smallCount} small tap target(s), e.g. ${r.small.map(s => `"${s.t}" ${Math.round(s.w)}×${Math.round(s.h)}`).join(', ')}`);
      if (r.tinyCount) issues.push(`${t.label}: ${r.tinyCount} button(s)/chip(s) under 28 px — too small to tap, e.g. ${r.tiny.map(s => `"${s.t}" ${Math.round(s.w)}×${Math.round(s.h)}`).join(', ')}`);
    });
  }

  const probs = problems.list();
  const summary = [
    `• Screen: ${win}px wide (iPhone 14)`, ...lines,
    `Pages opened: ${tabs.length}`,
    `Problems: ${issues.length}`, ...issues.map(i => '  ✗ ' + i),
    `Small tap targets (warnings, not failures): ${warnings.length} page(s)`, ...warnings.map(w => '  ⚠ ' + w),
    `Console errors / failed server calls: ${probs.length}`, ...probs.map(x => '  ✗ ' + x),
  ].join('\n');
  await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
  console.log('\n' + summary + '\n');
  expect.soft(probs, 'Console errors or failed server calls').toEqual([]);
  expect(issues, 'HR Admin phone layout problems').toEqual([]);
});
