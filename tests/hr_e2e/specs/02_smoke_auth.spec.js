// SMK-01…03 and AUTH-01, 02, 04, 05, 06 — both apps load; sign-in / sign-out work.
// (AUTH-03, Portal sign-in, is covered inside PRT-LAY-01 and X-MSG-01.)
const { test, expect } = require('@playwright/test');
const { settings, addClickMarker, watchForProblems, loginPortal, closeGettingStarted } = require('../helpers/common');
const { loginAdmin } = require('../helpers/admin');
const { adminApi } = require('../helpers/api');

test('SMK-01 · HR Admin loads', async ({ page }) => {
  const problems = watchForProblems(page, 'admin');
  await page.goto('/hr_admin/');
  await expect(page.locator('#auth-token')).toBeVisible();
  await page.waitForTimeout(800);
  expect(problems.list(), 'console errors on HR Admin load').toEqual([]);
});

test('SMK-02 · Employee Portal loads', async ({ page }) => {
  const problems = watchForProblems(page, 'portal');
  await page.goto('/hr_portal/');
  await expect(page.locator('#login-email')).toBeVisible();
  await page.waitForTimeout(800);
  expect(problems.list(), 'console errors on Portal load').toEqual([]);
});

test('SMK-03 · HR API answers within 5 seconds', async () => {
  const api = await adminApi();
  const t0 = Date.now();
  const res = await api.get('/hr-api/employees');
  const ms = Date.now() - t0;
  await api.dispose();
  expect(res.status(), 'HR API did not answer 200').toBe(200);
  expect(ms, `HR API took ${ms} ms`).toBeLessThan(5000);
});

test('AUTH-01 · HR Admin signs in with the AI-Prowler token', async ({ page }) => {
  await addClickMarker(page);
  const problems = watchForProblems(page, 'admin');
  await loginAdmin(page);
  await expect(page.locator('#auth-screen')).toBeHidden();
  await page.waitForTimeout(1000);
  expect(problems.list(), 'console errors after admin sign-in').toEqual([]);
});

test('AUTH-02 · HR Admin refuses a wrong token', async ({ page }) => {
  await addClickMarker(page);
  await page.goto('/hr_admin/');
  await page.locator('#auth-token').fill('ZZTEST-wrong-token-' + Date.now());
  await page.getByRole('button', { name: 'Sign In as HR Admin' }).click();
  await page.waitForTimeout(2500);
  await expect(page.locator('#auth-screen'), 'wrong token got past the sign-in screen').toBeVisible();
});

test('AUTH-04 · Portal refuses a wrong PIN', async ({ page }) => {
  const s = settings();
  await addClickMarker(page);
  await page.goto('/hr_portal/');
  await page.locator('#login-email').fill(s.ttEmail);
  await page.locator('#login-pass').fill('00000000');           // wrong on purpose
  await page.locator('#login-btn').click();
  await page.waitForTimeout(2500);
  await expect(page.locator('#app'), 'wrong PIN opened the Portal').not.toHaveClass(/visible/);
  await expect(page.locator('#login-email')).toBeVisible();
});

test('AUTH-05 · Portal stays signed in after a reload', async ({ page }) => {
  await addClickMarker(page);
  const problems = watchForProblems(page, 'portal');
  await loginPortal(page);
  await page.reload();
  await expect(page.locator('#app')).toHaveClass(/visible/, { timeout: 20_000 });
  await closeGettingStarted(page, 3_000);
  await expect.poll(async () => (await page.locator('#sidebar-name').innerText()).trim(), { timeout: 15_000 })
    .toMatch(/test/i);
  expect(problems.list(), 'console errors after reload').toEqual([]);
});

test('AUTH-06 · Portal signs out cleanly', async ({ page }) => {
  await addClickMarker(page);
  const problems = watchForProblems(page, 'portal');
  await loginPortal(page);
  await page.getByRole('button', { name: /sign out/i }).first().click();
  await expect(page.locator('#login-email')).toBeVisible({ timeout: 10_000 });
  await expect(page.locator('#app')).not.toHaveClass(/visible/);
  // After a reload we must still be signed out
  await page.reload();
  await expect(page.locator('#login-email')).toBeVisible({ timeout: 10_000 });
  expect(problems.list(), 'console errors during sign-out').toEqual([]);
});
