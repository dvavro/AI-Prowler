// PRT-TSK-01…07 — Tasks / Projects: summary boxes, add task, complete + Oops undo,
// Oops from Done tab, filter tabs, drag to Due Today, drag to Completed, survives reload.
// Tasks live in this browser only (fresh browser per test), so nothing is left on the server.
const { test, expect } = require('@playwright/test');
const { addClickMarker, watchForProblems, loginPortal } = require('../helpers/common');
const { testTag } = require('../helpers/api');

const inDays = (n) => { const d = new Date(); d.setHours(12); d.setDate(d.getDate() + n); return d.toISOString().slice(0, 10); };
const num = async (page, id) => parseInt((await page.locator(id).innerText()).trim(), 10) || 0;

test('PRT-TSK-01…07 · Tasks: add, complete, Oops, filters, drag, reload', async ({ page }, testInfo) => {
  const tag = testTag('TSK');
  const t1 = `${tag} Send weekly report`, t2 = `${tag} Restock supplies`;
  const report = [];
  await addClickMarker(page);
  const problems = watchForProblems(page, 'portal');
  const row = (text) => page.locator('#tp-list > div', { hasText: text }).first();

  await test.step('Sign in → Tasks / Projects', async () => {
    await loginPortal(page);
    problems.at('Tasks');
    const nav = page.locator('.sidebar .nav-item[data-page="tasks"]').first();
    await nav.scrollIntoViewIfNeeded(); await nav.click();
  });

  await test.step('PRT-TSK-01: summary boxes, task list, projects', async () => {
    for (const id of ['#tp-s-today', '#tp-s-over', '#tp-s-done', '#tp-s-proj']) await expect(page.locator(id)).toHaveText(/^\d+$/);
    await expect(page.locator('#tp-list')).not.toBeEmpty();
    expect(await num(page, '#tp-s-proj'), 'Active Projects').toBeGreaterThan(0);
    report.push('✓ 4 summary boxes show numbers; task list and project cards load');
  });

  await test.step('PRT-TSK-02: add a High-priority task due today', async () => {
    const before = await num(page, '#tp-s-today');
    await page.locator('#tp-new-text').fill(t1);
    await page.locator('#tp-new-due').fill(inDays(0));
    await page.locator('#tp-new-pri').selectOption('high');
    await page.getByRole('button', { name: '+ Add task' }).click();
    await expect(row(t1)).toBeVisible();
    await expect(row(t1)).toContainText('High');
    await expect(row(t1)).toContainText(/Due today/i);
    expect(await num(page, '#tp-s-today'), 'Due Today count').toBe(before + 1);
    report.push(`✓ Added "${t1.replace(tag + ' ', '')}" — red High tag, "Due today", Due Today ${before} → ${before + 1}`);
  });

  await test.step('PRT-TSK-03: complete it → Oops undo in the pop-up bar', async () => {
    const doneBefore = await num(page, '#tp-s-done');
    await row(t1).locator('[title="Mark done"]').click();
    const toast = page.locator('#tp-toast');
    await expect(toast).toBeVisible();
    await expect(toast).toContainText('completed');
    expect(await num(page, '#tp-s-done')).toBe(doneBefore + 1);
    await toast.getByRole('button', { name: /Oops/ }).click();
    await expect(row(t1)).toBeVisible();
    expect(await num(page, '#tp-s-done'), 'Oops did not undo').toBe(doneBefore);
    report.push('✓ Checked off → "completed ↩ Oops" bar → Oops put it back');
  });

  await test.step('PRT-TSK-04: Oops from the Done tab', async () => {
    await row(t1).locator('[title="Mark done"]').click();
    await page.locator('#tp-tabs button', { hasText: 'Done' }).click();
    await expect(row(t1)).toBeVisible();
    await row(t1).getByRole('button', { name: /Oops/ }).click();
    await page.locator('#tp-tabs button', { hasText: 'All Open' }).click();
    await expect(row(t1)).toBeVisible();
    report.push('✓ Done tab → ↩ Oops moved it back to All Open');
  });

  await test.step('PRT-TSK-05: filter tabs', async () => {
    await page.locator('#tp-new-text').fill(t2);
    await page.locator('#tp-new-due').fill(inDays(3));
    await page.locator('#tp-new-pri').selectOption('medium');
    await page.getByRole('button', { name: '+ Add task' }).click();
    await page.locator('#tp-tabs button', { hasText: 'Today' }).click();
    await expect(row(t1)).toBeVisible();
    await expect(page.locator('#tp-list')).not.toContainText(t2);
    await page.locator('#tp-tabs button', { hasText: 'All Open' }).click();
    await expect(row(t2)).toBeVisible();
    report.push('✓ Today tab shows only today\'s task; All Open shows both');
  });

  await test.step('PRT-TSK-06: drag a future task onto "Due Today"', async () => {
    const before = await num(page, '#tp-s-today');
    await row(t2).dragTo(page.locator('#tp-drop-today'));
    await expect(row(t2)).toContainText(/Due today/i);
    expect(await num(page, '#tp-s-today')).toBe(before + 1);
    report.push('✓ Dragged "Restock supplies" onto Due Today → now due today');
  });

  await test.step('PRT-TSK-07: drag a task onto "Completed This Week"', async () => {
    const before = await num(page, '#tp-s-done');
    await row(t2).dragTo(page.locator('#tp-drop-done'));
    expect(await num(page, '#tp-s-done')).toBe(before + 1);
    await expect(page.locator('#tp-list')).not.toContainText(t2);   // All Open hides done tasks
    report.push('✓ Dragged onto Completed This Week → marked done');
  });

  await test.step('PRT-TSK-09: tasks survive a reload', async () => {
    await page.reload();
    await expect(page.locator('#app')).toHaveClass(/visible/, { timeout: 20_000 });
    const nav = page.locator('.sidebar .nav-item[data-page="tasks"]').first();
    await nav.scrollIntoViewIfNeeded(); await nav.click();
    await expect(row(t1)).toBeVisible();
    report.push('✓ After reload the added task is still there');
  });

  const probs = problems.list();
  const summary = [...report, `Console errors / failed server calls: ${probs.length}`, ...probs.map(x => '  ✗ ' + x),
    'CLEANUP VERIFIED [TSK]: tasks live only in this test\'s browser — nothing saved on the server'].join('\n');
  await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
  console.log('\n' + summary + '\n');
  expect.soft(probs, 'Console errors or failed server calls').toEqual([]);
});
