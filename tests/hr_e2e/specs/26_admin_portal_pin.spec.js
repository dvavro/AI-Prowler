// ADM-TOK-01 — Option B (Jamie, Oct 1): each employee signs in with THEIR OWN AI-Prowler token.
//  1. HR Admin → Test Tester → 🔑 Portal Sign-in → Make a new AI-Prowler token → shown once, with Copy
//  2. Portal sign-in screen says "AI-Prowler Access Token"; email + that token signs in
//  3. Make another new token → the previous one is refused (lost tokens can be shut off)
//  4. The shared HR Admin bearer token is refused for employees (nobody signs in as someone else)
//  5. The optional short PIN still works
// Afterwards Test Tester's PIN is put back to this run's PIN so other tests keep working.
const { test, expect, request } = require('@playwright/test');
const { settings, addClickMarker, watchForProblems, closeGettingStarted } = require('../helpers/common');
const { loginAdmin, openAdminPage, adminToken } = require('../helpers/admin');
const { adminApi, postJson } = require('../helpers/api');

async function tryLogin(email, secret) {
  const anon = await request.newContext({ baseURL: process.env.HR_E2E_BASE_URL, extraHTTPHeaders: { 'User-Agent': 'Mozilla/5.0 AI-Prowler-HR-E2E' } });
  const r = await anon.post('/hr-api/auth/employee', { data: { email, pin: secret } });
  const s = r.status(); await anon.dispose(); return s;
}

test('ADM-TOK-01 · Each employee has their own AI-Prowler token; old tokens and the shared token are refused', async ({ page, browser }, testInfo) => {
  const s = settings();
  const api = await adminApi();
  const lines = [];
  const pin = String(Math.floor(10000000 + Math.random() * 89999999));
  await addClickMarker(page);
  const problems = watchForProblems(page, 'admin');
  // When the token box is already showing a previous token, length>20 is already true.
  // Wait until the displayed value actually changes (backend always generates a new one).
  const newToken = async (previous = '') => {
    page.once('dialog', d => d.accept());   // "Their old token will stop working right away."
    await page.locator('#dr-token-btn').click();
    await expect(page.locator('#dr-token-box')).toBeVisible({ timeout: 10_000 });
    await expect.poll(async () => {
      const t = (await page.locator('#dr-token-value').innerText()).trim();
      return t.length > 20 && t !== previous;
    }, { timeout: 10_000 }).toBe(true);
    return (await page.locator('#dr-token-value').innerText()).trim();
  };

  try {
    // 1. HR makes a token
    await loginAdmin(page);
    problems.at('Employee → Direct Reports → Portal Sign-in');
    await openAdminPage(page, 'employees');
    await page.locator('.chip[data-filter="all"]').click();
    await page.locator('.emp-name', { hasText: s.ttName }).first().click();
    await page.locator('.emp-sheet-tab', { hasText: 'Direct Reports' }).click();
    await expect(page.locator('#emp-pane-directreports')).toContainText('their own AI-Prowler token');
    await expect(page.locator('#emp-pane-directreports')).toContainText(s.ttEmail);
    const tok1 = await newToken();
    await expect(page.locator('#dr-token-box').getByRole('button', { name: /Copy/ })).toBeVisible();
    lines.push(`✓ HR made a new AI-Prowler token for Test Tester — shown once with 📋 Copy (${tok1.length} characters)`);

    // 2. Employee signs in with it through the real sign-in screen
    const ctx = await browser.newContext({ baseURL: process.env.HR_E2E_BASE_URL, serviceWorkers: 'block' });
    const p = await ctx.newPage();
    await p.goto('/hr_portal/');
    await expect(p.getByText('AI-Prowler Access Token', { exact: true })).toBeVisible();
    await p.locator('#login-email').fill(s.ttEmail);
    await p.locator('#login-pass').fill(tok1);
    await p.locator('#login-btn').click();
    await expect(p.locator('#app')).toHaveClass(/visible/, { timeout: 20_000 });
    await closeGettingStarted(p, 4_000);
    await expect(p.locator('#sidebar-name')).toContainText(/test/i, { timeout: 10_000 });
    await ctx.close();
    lines.push('✓ Portal sign-in screen asks for the "AI-Prowler Access Token"; email + that token signed in');

    // 3. A newer token replaces it
    const tok2 = await newToken(tok1);
    expect(tok2).not.toBe(tok1);
    expect(await tryLogin(s.ttEmail, tok1), 'the old token still works after making a new one').toBe(401);
    expect(await tryLogin(s.ttEmail, tok2), 'the new token does not work').toBe(200);
    lines.push('✓ Made another token → the previous one is refused (401), the new one works');

    // 4. Shared HR Admin token refused for employees
    expect(await tryLogin(s.ttEmail, adminToken()), 'the shared HR Admin token let an employee sign in').toBe(401);
    lines.push('✓ The shared HR Admin bearer token is refused for employees (401) — nobody can sign in as someone else');

    // 5. Optional PIN still works
    await page.locator('#emp-pane-directreports summary', { hasText: 'PIN' }).click();
    await page.locator('#dr-pin-input').fill(pin);
    await page.getByRole('button', { name: 'Set PIN' }).click();
    await expect(page.locator('#dr-pin-status')).toContainText('PIN set', { timeout: 10_000 });
    expect(await tryLogin(s.ttEmail, pin), 'the optional PIN does not work').toBe(200);
    lines.push('✓ Optional short PIN also works');
  } finally {
    const back = await postJson(api, '/portal/set-pin', { employee_id: process.env.HR_E2E_TT_ID, pin: s.ttPin });
    lines.push(back.status === 200 ? 'CLEANUP VERIFIED [TOK]: Test Tester\'s PIN restored for the rest of this run' : `CLEANUP FAILED [TOK]: could not restore PIN (${back.status})`);
    const probs = problems.list();
    const summary = [...lines, `Console errors / failed server calls: ${probs.length}`, ...probs.map(x => '  ✗ ' + x)].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await api.dispose();
    expect.soft(probs).toEqual([]);
    expect(back.status).toBe(200);
  }
});
