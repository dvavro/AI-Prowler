// PRT-LINK-01 — No broken document / training / handbook links anywhere in the Portal.
// PRT-TRN-02  — The training viewer opens a training, shows it, and closes with ✕.
// Scans the whole Portal for links to files on this server (/hr_portal/docs/…, PDFs, trainings,
// handbook pages) — in href, src, and onclick (openTraining('…'), window.open('…')) — and checks
// every one actually loads. Views only — creates no data.
const { test, expect } = require('@playwright/test');
const { addClickMarker, watchForProblems, loginPortal } = require('../helpers/common');

test('PRT-LINK-01 · Every document, training, and handbook link in the Portal opens', async ({ page }, testInfo) => {
  const lines = [], broken = [];
  await addClickMarker(page);
  const problems = watchForProblems(page, 'portal');
  await loginPortal(page);

  // Collect every same-site file link in the whole Portal (all pages are in the DOM)
  const links = await page.evaluate(() => {
    const out = new Map();
    const add = (u, where) => {
      if (!u || /^(#|javascript:|mailto:|tel:|data:|blob:)/i.test(u)) return;
      let abs; try { abs = new URL(u, location.href); } catch { return; }
      if (abs.origin !== location.origin) return;
      if (!/\/hr_portal\/(docs|files|training|handbook)\b|\.(pdf|html?|docx?)$/i.test(abs.pathname)) return;
      if (abs.pathname === '/hr_portal/' || abs.pathname.endsWith('/index.html')) return;
      if (!out.has(abs.pathname)) out.set(abs.pathname, where);
    };
    document.querySelectorAll('[href]').forEach(el => add(el.getAttribute('href'), (el.closest('.page') || {}).id || 'page'));
    document.querySelectorAll('[src]').forEach(el => add(el.getAttribute('src'), (el.closest('.page') || {}).id || 'page'));
    document.querySelectorAll('[onclick]').forEach(el => {
      const m = el.getAttribute('onclick').match(/(?:openTraining|window\.open|openDoc|openPolicy|openHandbook)\w*\(\s*['"]([^'"]+)['"]/);
      if (m) add(m[1], (el.closest('.page') || {}).id || 'page');
    });
    return [...out.entries()].map(([path, where]) => ({ path, where }));
  });
  expect(links.length, 'found no document/training links at all').toBeGreaterThan(0);

  for (const l of links) {
    const res = await page.request.get(l.path);
    const ct = res.headers()['content-type'] || '';
    const body = res.status() === 200 ? await res.text().catch(() => '') : '';
    const looksLikeAppShell = /<title>[^<]*AI-Prowler HR[^<]*<\/title>/i.test(body) && body.includes('id="page-');
    if (res.status() !== 200) broken.push(`${l.path} → ${res.status()} (linked from ${l.where})`);
    else if (looksLikeAppShell) broken.push(`${l.path} → returned the Portal itself, not the document (linked from ${l.where})`);
    else if (/html/.test(ct) && body.length < 200) broken.push(`${l.path} → nearly empty page (${body.length} bytes)`);
  }
  lines.push(`Links checked: ${links.length} (trainings, handbook, documents)`);
  lines.push(broken.length ? `Broken: ${broken.length}` : '✓ Every link opens');
  for (const b of broken) lines.push('  ✗ ' + b);

  // PRT-TRN-02: open the first training in the viewer, then close it with ✕
  const nav = page.locator('.sidebar .nav-item[data-page="trainings"]').first();
  if (await nav.count()) {
    problems.at('Trainings');
    await nav.scrollIntoViewIfNeeded(); await nav.click();
    const first = page.locator('#page-trainings [onclick*="openTraining("]').first();
    if (await first.count()) {
      await first.click();
      await expect(page.locator('#training-modal')).toBeVisible();
      const src = await page.locator('#training-iframe').getAttribute('src');
      const frame = page.frameLocator('#training-iframe');
      await expect(frame.locator('body')).not.toBeEmpty({ timeout: 10_000 });
      await page.locator('#training-modal button', { hasText: '✕' }).click();
      await expect(page.locator('#training-modal')).toBeHidden();
      lines.push(`✓ Training viewer opened "${src}", showed it, and closed with ✕`);
    }
  }

  const probs = problems.list();
  const summary = [...lines, `Console errors / failed server calls: ${probs.length}`, ...probs.map(x => '  ✗ ' + x)].join('\n');
  await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
  console.log('\n' + summary + '\n');
  expect.soft(probs).toEqual([]);
  expect(broken, 'broken links in the Portal').toEqual([]);
});
