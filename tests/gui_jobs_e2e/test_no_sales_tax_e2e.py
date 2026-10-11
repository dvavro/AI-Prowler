"""NST-01..NST-03 — per-job No Sales Tax (built 2026-10-08).

The job edit popup carries a "No Sales Tax" checkbox (id jfNoTax, after
Payment Status); the Database Jobs listing shows the flag under a friendlier
"Tax Disabled" header, positioned immediately after the "Tax (Tax%)" column.

These are live-browser Playwright tests — they CANNOT run from a dev
machine. They need David's Windows machine with the Jobs PWA up.
Run: run_tests_gui_jobs_e2e.bat --human -k test_no_sales_tax_e2e
"""

from playwright.sync_api import expect


def _open_sheet(app, page):
    app.goto("sheet")
    expect(page.locator("#sheetContent .spinner")).to_have_count(0, timeout=30_000)
    app.log("NO-TAX open the Jobs_Schedule tab")
    page.locator("#sheetTabs .sheet-tab-btn[data-sheet='Jobs_Schedule']").click()
    expect(page.locator("#sheetContent .spinner")).to_have_count(0, timeout=30_000)


def _open_edit(app, page, row_id):
    """Database → Jobs_Schedule tab → Edit on the row → the job edit popup."""
    _open_sheet(app, page)
    app.log(f"NO-TAX tap Edit on {row_id}")
    btn = page.locator(f".sheet-row-edit-btn[data-rowid='{row_id}']")
    btn.scroll_into_view_if_needed()
    btn.click()
    expect(page.locator("#jobFormModal")).to_be_visible()
    expect(page.locator("#jfGenericInputs .spinner")).to_have_count(0, timeout=20_000)


def _close_form(page):
    page.keyboard.press("Escape")
    if page.locator("#jobFormModal").is_visible():
        page.locator("#jobFormModal").click(position={"x": 5, "y": 5})
    if page.locator("#jobFormModal").is_visible():
        page.evaluate("closeJobFormModal()")


def _headers(page):
    return [t.strip() for t in page.locator("#sheetContent th").all_inner_texts()]


# ── NST-01: the checkbox in the job edit popup ──────────────────────────────
def test_NST_01_edit_popup_has_the_no_sales_tax_checkbox(clean_slate, app, page, data):
    jid = data.job("NST01")
    _open_edit(app, page, jid)
    try:
        box = page.locator("#jfNoTax")
        expect(box).to_have_count(1)
        expect(box).to_have_attribute("type", "checkbox")
        expect(page.locator("#jobFormModal")).to_contain_text("No Sales Tax")
        app.log("NO-TAX #jfNoTax checkbox present in the edit popup")
    finally:
        _close_form(page)          # read-only check — never saved


# ── NST-02: the "Tax Disabled" column header in the listing ─────────────────
def test_NST_02_database_jobs_listing_has_tax_disabled_header(clean_slate, app, page, data):
    data.job("NST02")
    _open_sheet(app, page)
    headers = _headers(page)
    app.log(f"NO-TAX listing headers: {headers}")
    assert "Tax Disabled" in headers, \
        f"no 'Tax Disabled' header in the Database Jobs listing (headers: {headers})"


# ── NST-03: "Tax Disabled" sits immediately after "Tax (Tax%)" ──────────────
def test_NST_03_tax_disabled_sits_right_after_tax(clean_slate, app, page, data):
    data.job("NST03")
    _open_sheet(app, page)
    headers = _headers(page)
    lowered = [h.lower() for h in headers]
    assert "tax disabled" in lowered, f"no 'Tax Disabled' header (headers: {headers})"
    tax_idx = next((i for i, h in enumerate(lowered) if h == "tax (tax%)"), None)
    assert tax_idx is not None, f"no 'Tax (Tax%)' header to sit after (headers: {headers})"
    disabled_idx = lowered.index("tax disabled")
    app.log(f"NO-TAX 'Tax (Tax%)' at {tax_idx}, 'Tax Disabled' at {disabled_idx}")
    assert disabled_idx == tax_idx + 1, \
        f"'Tax Disabled' should sit immediately after 'Tax (Tax%)' " \
        f"(headers around it: {headers[max(0, tax_idx - 1):disabled_idx + 2]})"
