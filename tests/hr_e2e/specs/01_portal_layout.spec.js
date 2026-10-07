// PRT-LAY-01 — Every Employee Portal page opens inside the layout.
// Also covers AUTH-03 (Test Tester can sign in), REG-01/REG-02 (stray </div>
// pushed pages below the layout), REG-03 (sidebar name / Portfolio details
// fill in), REG-05 (no leftover "DEBUG:" text) and REG-16 (no "undefined").
//
// This test only LOOKS and CLICKS — it creates no data, so there is nothing to clean up.
const { test, expect } = require('@playwright/test');
const { settings, addClickMarker, watchForProblems, loginPortal, closeGettingStarted, badTextIn } = require('../helpers/common');

test('PRT-LAY-01 · Every Portal page opens inside the layout', async ({ page }, testInfo) => {
  const s = settings();
  const issues = [];                       // every problem found, reported together at the end
  await addClickMarker(page);
  const problems = watchForProblems(page, 'portal');

  // ── Sign in (AUTH-03) ──────────────────────────────────────────────────
  await test.step('Sign in as Test Tester', async () => {
    await loginPortal(page);
  });

  // ── REG-03: sidebar shows the real name, not the "Employee" placeholder ──
  await test.step('Sidebar shows Test Tester (not "Employee")', async () => {
    await expect.poll(async () => (await page.locator('#sidebar-name').innerText()).trim(),
      { timeout: 15_000, message: 'sidebar name never filled in' }).not.toBe('Employee');
    const name = (await page.locator('#sidebar-name').innerText()).trim();
    if (!/test/i.test(name)) issues.push(`Sidebar name is "${name}" — expected "${s.ttName}"`);
  });

  // ── Find every visible sidebar page ────────────────────────────────────
  const navPages = await page.evaluate(() =>
    Array.from(document.querySelectorAll('.sidebar .nav-item[data-page]'))
      .filter(el => el.offsetParent !== null)                       // skip hidden items (e.g. My Team for non-managers)
      .map(el => ({ id: el.getAttribute('data-page'), label: el.innerText.trim().replace(/\s+/g, ' ') }))
      .filter((v, i, a) => a.findIndex(x => x.id === v.id) === i)   // no duplicates
  );
  testInfo.annotations.push({ type: 'pages found', description: `${navPages.length}: ${navPages.map(p => p.label).join(', ')}` });
  expect(navPages.length, 'no sidebar pages were found').toBeGreaterThan(10);

  // ── Visit each page ────────────────────────────────────────────────────
  for (const nav of navPages) {
    await test.step(`Open "${nav.label}"`, async () => {
      const item = page.locator(`.sidebar .nav-item[data-page="${nav.id}"]`).first();
      await closeGettingStarted(page);          // in case the pop-up came back
      await item.scrollIntoViewIfNeeded();
      await item.click();
      await closeGettingStarted(page);          // Welcome page can re-open it

      const pgAll = page.locator(`[id="page-${nav.id}"]`);
      const copies = await pgAll.count();
      if (copies === 0) { issues.push(`${nav.label}: page "#page-${nav.id}" does not exist`); return; }
      if (copies > 1) issues.push(`${nav.label}: page "#page-${nav.id}" exists ${copies} times in the HTML (duplicate — remove the extra copy)`);
      const pg = pgAll.first();              // the browser uses the first copy
      try { await expect(pg).toHaveClass(/active/, { timeout: 10_000 }); }
      catch { issues.push(`${nav.label}: page did not open (never became active)`); return; }
      await page.waitForTimeout(800);   // let the page load its data

      const r = await page.evaluate((id) => {
        const pg = document.getElementById('page-' + id);
        const main = document.querySelector('main.main');
        const sb = document.querySelector('.sidebar');
        const pr = pg.getBoundingClientRect(), sr = sb.getBoundingClientRect();
        return {
          inMain: !!main && main.contains(pg),
          pageLeft: Math.round(pr.left), sidebarRight: Math.round(sr.right),
          sidebarHeight: Math.round(sr.height), winHeight: window.innerHeight,
          pageHeight: Math.round(pr.height),
          sideScroll: document.documentElement.scrollWidth > window.innerWidth + 2,
          text: (pg.innerText || '').slice(0, 30000),
        };
      }, nav.id);

      const shot = testInfo.outputPath(`page_${nav.id}.png`);
      await page.screenshot({ path: shot });
      await testInfo.attach(`page: ${nav.label}`, { path: shot, contentType: 'image/png' });

      const where = `${nav.label}`;
      if (!r.inMain) issues.push(`${where}: page is OUTSIDE the main content area (stray </div>?)`);
      if (r.pageLeft < r.sidebarRight - 4) issues.push(`${where}: page starts at x=${r.pageLeft}, under/left of the sidebar edge x=${r.sidebarRight}`);
      if (r.sidebarHeight < r.winHeight * 0.6) issues.push(`${where}: sidebar is squished (${r.sidebarHeight}px tall, window ${r.winHeight}px)`);
      if (r.pageHeight < 60) issues.push(`${where}: page looks blank (${r.pageHeight}px tall)`);
      if (r.sideScroll) issues.push(`${where}: whole window scrolls sideways`);
      for (const why of badTextIn(r.text)) issues.push(`${where}: shows ${why}`);
    });
  }

  // ── REG-03: Portfolio details actually filled in (not dashes) ──────────
  await test.step('Portfolio details are filled in', async () => {
    const item = page.locator('.sidebar .nav-item[data-page="portfolio"]').first();
    if (await item.count() === 0) { issues.push('Portfolio: no sidebar item'); return; }
    await item.scrollIntoViewIfNeeded();
    await item.click();
    for (const id of ['emp-id', 'emp-department', 'emp-start-date']) {
      const el = page.locator(`#${id}`);
      if (await el.count() === 0) continue;
      const ok = await expect.poll(async () => (await el.innerText()).trim(), { timeout: 15_000 })
        .not.toBe('—').then(() => true, () => false);
      if (!ok) issues.push(`Portfolio: "${id}" still shows a dash — profile details did not load`);
    }
    const shot = testInfo.outputPath('portfolio_details.png');
    await page.screenshot({ path: shot, fullPage: true });
    await testInfo.attach('portfolio details', { path: shot, contentType: 'image/png' });
  });

  // ── Report ─────────────────────────────────────────────────────────────
  const consoleIssues = problems.list();
  const report = [
    `Pages checked: ${navPages.length}`,
    `Layout / text problems: ${issues.length}`,
    ...issues.map(i => '  ✗ ' + i),
    `Console errors / failed server calls: ${consoleIssues.length}`,
    ...consoleIssues.map(i => '  ✗ ' + i),
  ].join('\n');
  await testInfo.attach('summary', { body: report, contentType: 'text/plain' });
  console.log('\n' + report + '\n');

  expect.soft(consoleIssues, 'Console errors or failed server calls were found').toEqual([]);
  expect(issues, 'Layout or text problems were found').toEqual([]);
});
