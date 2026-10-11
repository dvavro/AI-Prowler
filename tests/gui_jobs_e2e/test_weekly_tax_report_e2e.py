"""WTR-01..WTR-02 — the Weekly Tax Collected card (built 2026-10-08).

Reports shows a "🧾 Weekly Tax Collected" card (actual vs projected tax chart),
and the Weekly Detail table carries Actual/Proj/Total Tax columns between the
revenue and hours groups. Tax collected is proportional: tax x paid/total.

These are live-browser Playwright tests — they CANNOT run from a dev
machine. They need David's Windows machine with the Jobs PWA up.
Run: run_tests_gui_jobs_e2e.bat --human -k test_weekly_tax_report_e2e
"""

from playwright.sync_api import expect


def _open(app, page):
    app.goto("reports")
    expect(page.locator("#reportsContent table tbody tr").first).to_be_visible(timeout=30_000)


def _card(page):
    return page.locator("#reportsContent .card", has_text="Weekly Tax Collected")


# ── WTR-01: the card itself ─────────────────────────────────────────────────
def test_WTR_01_weekly_tax_collected_card_exists(app, page):
    _open(app, page)
    card = _card(page)
    expect(card).to_have_count(1)
    expect(card.locator(".card-title")).to_contain_text("🧾")
    expect(card.locator("svg")).to_have_count(1)      # actual/projected tax chart
    app.log("WTR 🧾 Weekly Tax Collected card with its chart is on Reports")


# ── WTR-02: Actual/Proj/Total Tax columns in the Weekly Detail table ─────────
def test_WTR_02_detail_table_has_actual_proj_total_tax_columns(app, page):
    _open(app, page)
    headers = [t.strip() for t in
               page.locator("#reportsContent table thead th").all_inner_texts()]
    app.log(f"WTR detail headers: {headers}")
    for want in ("Actual Tax", "Proj Tax", "Total Tax"):
        assert want in headers, f"missing {want!r} column (headers: {headers})"
    # the tax group sits between revenue and hours, in Actual/Proj/Total order
    rev = headers.index("Total Rev")
    hrs = headers.index("Actual Hrs")
    tax = [headers.index(h) for h in ("Actual Tax", "Proj Tax", "Total Tax")]
    assert tax == sorted(tax) == list(range(tax[0], tax[0] + 3)), \
        f"tax columns not contiguous in Actual/Proj/Total order: {headers}"
    assert rev < tax[0] and tax[2] < hrs, \
        f"tax columns should sit between revenue and hours: {headers}"
