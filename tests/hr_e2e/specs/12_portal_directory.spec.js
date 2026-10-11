// PRT-DIR-01…03 — Portal Directory: search, add, edit, delete (shared company directory).
// Adds a ZZTEST contact through the screen, searches for it, edits it, deletes it with 🗑.
// Real contacts are only read. Cleanup: any ZZTEST contact deleted via the admin API, verified.
const { test, expect } = require('@playwright/test');
const { addClickMarker, watchForProblems, loginPortal } = require('../helpers/common');
const { adminApi, testTag, getJson } = require('../helpers/api');

async function contacts(api) { return (await getJson(api, '/directory')).contacts || []; }
const isZZ = (c) => String(c.name || '').startsWith('ZZTEST');

test('PRT-DIR-01…03 · Directory: search, add, edit, delete', async ({ page }, testInfo) => {
  const tag = testTag('DIR');
  const name = `ZZTEST Morgan Lee ${tag.slice(-6)}`;
  const api = await adminApi();
  const lines = [];
  await addClickMarker(page);
  const problems = watchForProblems(page, 'portal');
  const row = () => page.locator('#page-directory .dir-name', { hasText: name }).first();

  try {
    for (const c of (await contacts(api)).filter(isZZ)) await api.delete(`/hr-api/directory/${c.id}`);
    const real = (await contacts(api)).filter(c => !isZZ(c));

    await loginPortal(page);
    problems.at('Directory');
    const nav = page.locator('.sidebar .nav-item[data-page="directory"]').first();
    await nav.scrollIntoViewIfNeeded(); await nav.click();
    await expect(page.locator('#page-directory')).toHaveClass(/active/);
    for (const c of real) await expect(page.locator('#page-directory .dir-name', { hasText: c.name }).first()).toBeAttached();
    lines.push(`✓ Directory lists all ${real.length} real contacts (read only)`);

    // PRT-DIR-02: + Add Contact
    await page.getByRole('button', { name: /Add Contact/ }).click();
    await expect(page.locator('#dir-form-name')).toBeVisible();
    await page.locator('#dir-form-name').fill(name);
    await page.locator('#dir-form-role').fill('Facilities');
    await page.locator('#dir-form-ext').fill('4417');
    await page.locator('#dir-form-email').fill('morgan.lee.zztest@example.com');
    await page.locator('[onclick="saveDirContact()"]').click();
    await expect(row()).toBeVisible({ timeout: 10_000 });
    const added = (await contacts(api)).find(c => c.name === name);
    expect(added, 'contact not saved on the server').toBeTruthy();
    expect(added.role).toBe('Facilities');
    lines.push(`✓ + Add Contact → "${name}" saved on the server (${added.id})`);

    // PRT-DIR-01: search
    const search = page.locator('#dir-search');
    await search.fill('Morgan Lee');
    await expect(row()).toBeVisible();
    if (real[0]) await expect(page.locator('#page-directory .dir-name', { hasText: real[0].name })).toBeHidden();
    await search.fill('');
    lines.push('✓ Search "Morgan Lee" shows the new contact and hides the others');

    // PRT-DIR-03: edit
    await page.locator(`[onclick="openDirContactForm('${added.id}')"]`).click();
    await expect(page.locator('#dir-form-name')).toHaveValue(name);
    await page.locator('#dir-form-role').fill('Facilities Manager');
    await page.locator('[onclick="saveDirContact()"]').click();
    await expect.poll(async () => (await contacts(api)).find(c => c.id === added.id)?.role, { timeout: 10_000 }).toBe('Facilities Manager');
    await expect(page.locator('#page-directory')).toContainText('Facilities Manager');
    lines.push('✓ ✎ Edit → role changed to "Facilities Manager" on screen and on the server');

    // PRT-DIR-03: delete with 🗑 (answers "Remove this contact?")
    page.once('dialog', d => d.accept());
    await page.locator(`[onclick="deleteDirContact('${added.id}')"]`).click();
    await expect(row()).toHaveCount(0, { timeout: 10_000 });
    expect((await contacts(api)).some(c => c.id === added.id), 'contact still on the server').toBe(false);
    lines.push('✓ 🗑 Remove → gone from the screen and the server');

    const after = (await contacts(api)).filter(c => !isZZ(c));
    expect(after.length, 'a real contact was changed or removed').toBe(real.length);
    lines.push(`✓ All ${real.length} real contacts untouched`);
  } finally {
    for (const c of (await contacts(api)).filter(isZZ)) await api.delete(`/hr-api/directory/${c.id}`);
    const left = (await contacts(api)).filter(isZZ).length;
    const cleanupLine = left === 0 ? 'CLEANUP VERIFIED [DIR]: 0 ZZTEST contacts left' : `CLEANUP FAILED [DIR]: ${left} left`;
    const probs = problems.list();
    const summary = [...lines, `Console errors / failed server calls: ${probs.length}`, ...probs.map(x => '  ✗ ' + x), cleanupLine].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await api.dispose();
    expect.soft(probs).toEqual([]);
    expect(left).toBe(0);
  }
});
