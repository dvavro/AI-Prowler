"""QBO-01..QBO-02 — QuickBooks import entry point in the onboarding wizard (2026-10-08).

Step 1 of the Getting-started wizard (🧙 on the Jobs screen) lists
"Import from QuickBooks (fastest start)" as its first bullet — the
conversational-import path (David's Path B decision): connect the QuickBooks
MCP in Claude.ai and ask to import customers, invoices, and payments, instead
of entering everything by hand.

These are live-browser Playwright tests — they CANNOT run from a dev
machine. They need David's Windows machine with the Jobs PWA up.
Run: run_tests_gui_jobs_e2e.bat --human -k test_qb_onboarding_e2e
"""
import pytest
from playwright.sync_api import expect

from app_wizard import Wizard


@pytest.fixture
def wiz(app, page):
    app.goto("jobs")
    return Wizard(page, app.log)


def _step_1_items(wiz):
    wiz.open()                                            # the wizard always starts at step 1
    return [t.strip() for t in wiz.body.locator(".wiz-list li").all_inner_texts()]


# ── QBO-01: Step 1 leads with the QuickBooks import ─────────────────────────
def test_QBO_01_step_1_lists_import_from_quickbooks_first(wiz):
    items = _step_1_items(wiz)
    wiz.log(f"QB-ONBOARDING step 1 bullets: {items}")
    assert any("Import from QuickBooks" in t for t in items), \
        f"Step 1 lost its QuickBooks import entry: {items}"
    assert items[0].startswith("Import from QuickBooks"), \
        f"'Import from QuickBooks' should be the first bullet of Step 1: {items}"


# ── QBO-02: Step 1 explains the Claude.ai import path ────────────────────────
def test_QBO_02_step_1_text_describes_the_quickbooks_import(wiz):
    wiz.open()
    expect(wiz.body).to_contain_text("QuickBooks")
    expect(wiz.body).to_contain_text("import your customers")
    wiz.log("QB-ONBOARDING step 1 explains the Claude.ai QuickBooks import")
