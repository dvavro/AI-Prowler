// MOB-LAY-01 — Employee Portal on phones (iPhone 14 + Pixel 7, emulated in Chrome).
// Guards bug #15: on phones the sidebar was hidden with no way to open it.
// For each phone:
//   1. Sign in; ☰ Menu button is visible and at least 44 px (Apple's minimum tap size)
//   2. Open EVERY page through ☰ → drawer closes → page shows
//   3. No sideways scrolling, not blank, no "undefined"/"NaN"/"DEBUG" text
//   4. Buttons smaller than 36 px are listed as WARNINGS (hard to tap) — not failures
// Views only — creates no data.
const { test, expect, devices } = require('@playwright/test');
const { addClickMarker, watchForProblems, loginPortal, closeGettingStarted, badTextIn } = require('../helpers/common');

const strip = (d) => { const { defaultBrowserType, ...rest } = d; return rest; };   // run in Chrome (Safari engine not installed yet)
const PHONES = [
  ['iPhone 14', strip(devices['iPhone 14'])],
  ['Pixel 7',   strip(devices['Pixel 7'])],
];

for (const [phoneName, phone] of PHONES) {
  test.describe(`on ${phoneName}`, () => {
    test.use({ ...phone });

    test(`MOB-LAY-01 · Portal on ${phoneName}: ☰ menu reaches every page, no sideways scroll`, async ({ page }, testInfo) => {
      const issues = [], warnings = [], lines = [];
      await addClickMarker(page);
      const problems = watchForProblems(page, `portal · ${phoneName}`);

      await loginPortal(page);
      const vw = page.viewportSize().width;
      lines.push(`• Screen: ${vw}×${page.viewportSize().height} (${phoneName})`);

      // Bug #17 guard: the top bar must fit the phone (it used to force the whole page wider → zoomed out)
      const fit = await page.evaluate(() => {
        const h = document.querySelector('.header');
        return { headerNeeds: h ? h.scrollWidth : 0, headerHas: h ? h.clientWidth : 0, win: window.innerWidth };
      });
      if (fit.headerNeeds > fit.headerHas + 2) issues.push(`Top bar needs ${fit.headerNeeds}px but the phone is ${fit.win}px wide (bug #17)`);
      else lines.push(`✓ Top bar fits the phone (${fit.headerNeeds}px of ${fit.win}px)`);

      const menuBtn = page.locator('#mobile-menu-btn');
      await expect(menuBtn, '☰ Menu button missing on a phone (bug #15)').toBeVisible();
      const mb = await menuBtn.boundingBox();
      if (mb.width < 44 || mb.height < 44) issues.push(`☰ button is ${Math.round(mb.width)}×${Math.round(mb.height)} px — under the 44 px tap minimum`);
      lines.push(`✓ ☰ Menu button visible (${Math.round(mb.width)}×${Math.round(mb.height)} px)`);

      const pages = await page.evaluate(() => {
        // Skip items hidden themselves OR inside a hidden section (e.g. manager-only "My Team")
        const hiddenInMenu = (el) => {
          for (let n = el; n && !n.classList.contains('sidebar'); n = n.parentElement) {
            if (getComputedStyle(n).display === 'none') return true;
          }
          return false;
        };
        return Array.from(document.querySelectorAll('.sidebar .nav-item[data-page]'))
          .filter(el => !hiddenInMenu(el))
          .map(el => ({ id: el.getAttribute('data-page'), label: el.innerText.trim().replace(/\s+/g, ' ') }))
          .filter((v, i, a) => a.findIndex(x => x.id === v.id) === i);
      });
      expect(pages.length, 'no pages in the menu').toBeGreaterThan(10);

      for (const p of pages) {
        await test.step(`☰ → ${p.label}`, async () => {
          problems.at(p.label);
          await closeGettingStarted(page);
          await menuBtn.click();
          const item = page.locator(`.sidebar.mobile-open .nav-item[data-page="${p.id}"]`).first();
          try { await expect(item).toBeVisible({ timeout: 5_000 }); }
          catch { issues.push(`${p.label}: menu drawer didn't open`); return; }
          await item.scrollIntoViewIfNeeded();
          await item.click();
          await expect(page.locator('.sidebar')).not.toHaveClass(/mobile-open/, { timeout: 5_000 }).catch(() => issues.push(`${p.label}: drawer stayed open after picking a page`));
          const pg = page.locator(`[id="page-${p.id}"]`).first();
          try { await expect(pg).toHaveClass(/active/, { timeout: 8_000 }); }
          catch { issues.push(`${p.label}: page didn't open`); return; }
          await page.waitForTimeout(500);
          const r = await page.evaluate((id) => {
            const el = document.getElementById('page-' + id);
            const small = [...el.querySelectorAll('button, [onclick]')]
              .filter(b => b.offsetParent !== null)
              .map(b => ({ t: (b.innerText || b.title || b.getAttribute('aria-label') || '').trim().slice(0, 24), h: b.getBoundingClientRect().height, w: b.getBoundingClientRect().width }))
              .filter(b => b.h > 0 && (b.h < 36 || b.w < 36) && b.t);
            // Hard floor (approved Sept 30): real buttons must be at least 28 px — anything smaller fails
            const tiny = [...el.querySelectorAll('button')].filter(b => b.offsetParent !== null)
              .map(b => ({ t: (b.innerText || b.title || b.getAttribute('aria-label') || '').trim().slice(0, 24), h: b.getBoundingClientRect().height, w: b.getBoundingClientRect().width }))
              .filter(b => b.h > 0 && (b.h < 28 || b.w < 28));
            return {
              sideScroll: document.documentElement.scrollWidth > window.innerWidth + 2,
              scrollW: document.documentElement.scrollWidth, winW: window.innerWidth,
              height: Math.round(el.getBoundingClientRect().height),
              text: (el.innerText || '').slice(0, 30000),
              small: small.slice(0, 6), smallCount: small.length,
              tiny: tiny.slice(0, 4), tinyCount: tiny.length,
            };
          }, p.id);
          const shot = testInfo.outputPath(`phone_${phoneName.replace(/\s/g, '')}_${p.id}.png`);
          await page.screenshot({ path: shot, fullPage: false });
          await testInfo.attach(`${phoneName}: ${p.label}`, { path: shot, contentType: 'image/png' });
          if (r.sideScroll) issues.push(`${p.label}: scrolls sideways (page ${r.scrollW}px wide on a ${r.winW}px screen)`);
          if (r.height < 60) issues.push(`${p.label}: looks blank`);
          for (const why of badTextIn(r.text)) issues.push(`${p.label}: shows ${why}`);
          if (r.smallCount) warnings.push(`${p.label}: ${r.smallCount} small tap target(s), e.g. ${r.small.map(s => `"${s.t}" ${Math.round(s.w)}×${Math.round(s.h)}`).join(', ')}`);
          if (r.tinyCount) issues.push(`${p.label}: ${r.tinyCount} button(s) under 28 px — too small to tap, e.g. ${r.tiny.map(s => `"${s.t}" ${Math.round(s.w)}×${Math.round(s.h)}`).join(', ')}`);
        });
      }

      const probs = problems.list();
      const summary = [
        ...lines,
        `Pages opened through ☰: ${pages.length}`,
        `Problems: ${issues.length}`, ...issues.map(i => '  ✗ ' + i),
        `Small tap targets (warnings, not failures): ${warnings.length} page(s)`, ...warnings.map(w => '  ⚠ ' + w),
        `Console errors / failed server calls: ${probs.length}`, ...probs.map(x => '  ✗ ' + x),
      ].join('\n');
      await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
      console.log('\n' + summary + '\n');
      expect.soft(probs, 'Console errors or failed server calls').toEqual([]);
      expect(issues, 'Phone layout problems').toEqual([]);
    });
  });
}
