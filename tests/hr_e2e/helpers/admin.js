// HR Admin helpers — sign in and open menu pages, like a person would.
const { expect } = require('@playwright/test');

function adminToken() {
  const t = process.env.HR_E2E_ADMIN_TOKEN;
  if (!t) throw new Error('Missing admin token. Start the tests with run_tests_hr_e2e.py, not directly.');
  return t;
}

// Sign in on the HR Admin login screen with the AI-Prowler bearer token.
async function loginAdmin(page) {
  await page.goto('/hr_admin/');
  const tokenBox = page.locator('#auth-token');
  await expect(tokenBox).toBeVisible();
  await tokenBox.click();
  await tokenBox.fill(adminToken());               // token is long — fill instead of typing each character
  await page.getByRole('button', { name: 'Sign In as HR Admin' }).click();
  await expect(page.locator('#auth-screen')).toBeHidden({ timeout: 30_000 });
}

// Open a page from the HR Admin menu (e.g. 'messages', 'employees', 'timeoff').
// Opens the ☰ Menu first if the sidebar is tucked away.
async function openAdminPage(page, tab) {
  // If an employee's record is open full-screen, close it with ← Back first (like a person would)
  const sheetBack = page.locator('#emp-sheet:not(.hidden)').getByText(/Back/).first();
  if (await sheetBack.isVisible().catch(() => false)) { await sheetBack.click(); await page.waitForTimeout(300); }
  const item = page.locator(`#sidebar-nav .sidebar-item[data-tab="${tab}"]`).first();
  // The sidebar slides in from off-screen. "Visible" isn't enough — it must be ON screen.
  const onScreen = async () => {
    const box = await item.boundingBox();
    const vw = page.viewportSize().width;
    return !!box && box.x >= 0 && box.x + box.width <= vw;
  };
  if (!(await onScreen())) {
    await page.locator('#btn-hamburger').click();          // ☰ Menu
    await page.waitForTimeout(350);                          // let the slide-in animation finish
    await item.scrollIntoViewIfNeeded();                     // long menus: scroll down to the item
    await expect(item).toBeInViewport({ timeout: 5_000 });
  }
  await item.click();
}

module.exports = { loginAdmin, openAdminPage, adminToken };
