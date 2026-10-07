// ADM-DOC-01 (+ bug #21) — HR uploads a document from inside an employee's record; it's saved,
// shows in the record right away, and downloads back byte-for-byte. Uses a tiny ZZTEST PDF only.
const { test, expect } = require('@playwright/test');
const { addClickMarker, watchForProblems } = require('../helpers/common');
const { loginAdmin, openAdminPage } = require('../helpers/admin');
const { adminApi, testTag, getJson } = require('../helpers/api');

// Minimal valid one-page PDF (text "ZZTEST offer letter"). Like real PDFs it has a binary marker
// line (bytes above 127) and ends with "\r\n" — so any text-mangling or trimming fails the check (bug #23).
function tinyPdf(tag) {
  const body = `%PDF-1.4\n%\xE2\xE3\xCF\xD3\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n` +
    `3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 300 100]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>endobj\n` +
    `4 0 obj<</Length 60>>stream\nBT /F1 12 Tf 10 50 Td (ZZTEST offer letter ${tag}) Tj ET\nendstream endobj\n` +
    `5 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\r\n`;
  return Buffer.from(body, 'latin1');
}
async function ttDocs(api) {
  const d = await getJson(api, `/documents?employee_id=${encodeURIComponent(process.env.HR_E2E_TT_ID)}`);
  return (d.documents || d || []).filter(x => String(x.name || x.filename || '').startsWith('ZZTEST'));
}

test('ADM-DOC-01 · Upload from the employee record: pre-selected, saved, shown, downloads intact', async ({ page }, testInfo) => {
  const tag = testTag('DOC');
  const fileName = `ZZTEST_offer_letter_${tag.slice(-6)}.pdf`;
  const pdf = tinyPdf(tag);
  const api = await adminApi();
  const lines = [];
  await addClickMarker(page);
  const problems = watchForProblems(page, 'admin');

  try {
    for (const d of await ttDocs(api)) await api.delete(`/hr-api/documents/${d.id}`);

    await loginAdmin(page);
    problems.at('Employee → Documents → Upload');
    await openAdminPage(page, 'employees');
    await page.locator('.chip[data-filter="all"]').click();
    await page.locator('.emp-name', { hasText: process.env.HR_E2E_TT_NAME || 'Test Tester' }).first().click();
    await page.locator('.emp-sheet-tab', { hasText: 'Documents' }).click();
    await page.locator('#emp-pane-documents .upload-btn').click();
    await expect(page.locator('#up-emp')).toBeVisible();
    await expect(page.locator('#up-emp'), 'employee not pre-selected (bug #21)').toHaveValue(process.env.HR_E2E_TT_ID);
    lines.push('✓ Upload box opened from Test Tester\'s record with Test Tester already selected (bug #21)');

    await page.locator('#up-cat').selectOption({ index: 0 });
    await page.locator('#up-file').setInputFiles({ name: fileName, mimeType: 'application/pdf', buffer: pdf });
    await page.locator('#up-notes').fill(`${tag} automated test`);
    await page.locator('#up-submit-btn').click();
    await expect(page.locator('#up-emp')).toBeHidden({ timeout: 15_000 });

    await expect.poll(async () => (await ttDocs(api)).length, { timeout: 10_000, message: 'document never reached the server' }).toBe(1);
    const doc = (await ttDocs(api))[0];
    lines.push(`✓ Server: "${doc.name || doc.filename}" saved under Test Tester (${doc.id})`);

    await expect(page.locator('#emp-doc-list'), 'record\'s Documents tab not refreshed after upload (bug #21)').toContainText(fileName, { timeout: 10_000 });
    lines.push('✓ The new file shows in the record\'s Documents tab right away (bug #21)');

    const card = page.locator('#emp-doc-list .doc-card', { hasText: fileName }).first();
    const dl = card.getByRole('button', { name: /Download/ });
    await expect(dl, 'no ⬇ Download button on the document in the employee record (bug #22)').toBeVisible();
    const [download] = await Promise.all([page.waitForEvent('download', { timeout: 15_000 }), dl.click()]);
    const saved = testInfo.outputPath('downloaded.pdf');
    await download.saveAs(saved);
    const got = require('fs').readFileSync(saved);
    expect(Buffer.compare(got, pdf), 'downloaded file differs from what was uploaded').toBe(0);
    lines.push(`✓ ⬇ Download: ${got.length} bytes, identical to the uploaded file`);
  } finally {
    for (const d of await ttDocs(api)) await api.delete(`/hr-api/documents/${d.id}`);
    const left = (await ttDocs(api)).length;
    const cleanupLine = left === 0 ? 'CLEANUP VERIFIED [DOC]: test document deleted' : `CLEANUP FAILED [DOC]: ${left} test document(s) left`;
    const probs = problems.list();
    const summary = [...lines, `Console errors / failed server calls: ${probs.length}`, ...probs.map(x => '  ✗ ' + x), cleanupLine].join('\n');
    await testInfo.attach('summary', { body: summary, contentType: 'text/plain' });
    console.log('\n' + summary + '\n');
    await api.dispose();
    expect.soft(probs).toEqual([]);
    expect(left).toBe(0);
  }
});
