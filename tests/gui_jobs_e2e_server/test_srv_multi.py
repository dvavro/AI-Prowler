"""Server mode — two people at once, and owner-vs-manager screens
(spec §6.11.5 SRV-MULTI / SRV-SCR). David = owner, Vicki = manager.

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_multi
"""
import re

import pytest
from playwright.sync_api import expect

# price-list screen helpers from the personal suite (underscore names only, so
# none of that file's tests are pulled into this one)
from test_price_list import _close_form, _error, _fill, _open_edit, _price, _save

SHEET = "Services_Pricing"


def _signed_in(w):
    expect(w.page.locator("#app")).to_be_visible(timeout=30_000)
    expect(w.page.locator("#authScreen")).to_be_hidden()


def _pricing_tab(w):
    w.app.goto("sheet")
    w.app.step("open the Pricing tab")
    w.page.locator("#sheetTabs").get_by_role("button", name=re.compile("pric", re.I)).first.click()
    expect(w.page.locator("#sheetAddBtn")).to_be_visible()
    w.page.wait_for_timeout(600)


# ── SRV-MULTI-03: same price, two people, second save must not overwrite ─────
def test_SRV_MULTI_03_second_save_is_refused_not_overwritten(windows, owner_api, clean_slate):
    owner_api.call("create_service_pricing", {"updates": {
        "Service Code": "ZTEST-SHARED", "Name": "shared price", "Base Price ($)": "100",
        "Notes": "original"}})
    david, vicki = windows("U1", "U2")
    david.log_in()
    vicki.log_in()
    _signed_in(david)
    _signed_in(vicki)
    _pricing_tab(david)
    _pricing_tab(vicki)

    # both open the same row
    _open_edit(david.app, david.page, "ZTEST-SHARED")
    _open_edit(vicki.app, vicki.page, "ZTEST-SHARED")

    # David changes the notes and saves first
    _fill(david.app, david.page, "Notes", "David's change")
    _save(david.app, david.page, "update_job_spreadsheet")
    expect(david.page.locator("#jobFormModal")).to_be_hidden(timeout=20_000)
    assert _price(owner_api, "ZTEST-SHARED")["Notes"] == "David's change"

    # Vicki, whose form still shows the old row, changes the price and saves
    _fill(vicki.app, vicki.page, "Base Price ($)", "125")
    _save(vicki.app, vicki.page, "update_job_spreadsheet")
    vicki.page.wait_for_timeout(1500)
    row = _price(owner_api, "ZTEST-SHARED")
    assert row["Notes"] == "David's change", \
        f"Vicki's save silently wiped David's change: Notes={row['Notes']!r}"
    expect(_error(vicki.page)).to_be_visible()
    expect(_error(vicki.page)).to_contain_text(re.compile(r"reload|try again", re.I))
    expect(_error(vicki.page)).to_contain_text("David")          # names who changed it
    _close_form(vicki.page)


# ── SRV-SCR-01: Reports tab — owner and manager (R-068/R-069, David 2026-09-29) ─
def test_SRV_SCR_01_reports_tab_owner_and_manager(windows):
    david, vicki = windows("U1", "U2")
    david.log_in()
    vicki.log_in()
    _signed_in(david)
    _signed_in(vicki)
    expect(david.page.get_by_test_id("nav-reports")).to_be_visible()
    expect(vicki.page.get_by_test_id("nav-reports")).to_be_visible()
    # every other tab is there for both
    for w in (david, vicki):
        for tab in ("jobs", "board", "route", "calendar", "clock", "photos", "messages", "sheet", "profile"):
            expect(w.page.get_by_test_id(f"nav-{tab}")).to_be_visible()


# ── SRV-SCR-02: what each one sees on Reports ────────────────────────────────
# Owner: AR Aging + Customer Reminders (with the send controls) + the revenue /
# hours charts. Manager: AR Aging + Customer Reminders (list only) — the charts
# stay owner-only (David 2026-09-23) and so does SENDING a reminder (the server
# refuses it: SRV-API-05). Read-only: no search is run, nothing is sent.
def test_SRV_SCR_02_manager_sees_ar_and_reminders_not_the_owner_parts(windows):
    david, vicki = windows("U1", "U2")
    david.log_in()
    vicki.log_in()
    _signed_in(david)
    _signed_in(vicki)
    for w, is_owner in ((david, True), (vicki, False)):
        w.app.goto("reports")
        expect(w.page.locator("#arAgingCard")).to_be_visible()
        expect(w.page.locator("#arAgingReport")).not_to_have_text("Loading…", timeout=30_000)
        expect(w.page.locator("#arAgingReport")).not_to_contain_text("❌")
        expect(w.page.locator("#customerRemindersCard")).to_be_visible()
        if is_owner:
            expect(w.page.locator("#reportsOwnerOnly")).to_be_visible()
            expect(w.page.locator("#staleCustomerMessageBox")).to_be_visible()
        else:
            expect(w.page.locator("#reportsOwnerOnly")).to_be_hidden()
            expect(w.page.locator("#staleCustomerMessageBox")).to_be_hidden()
    # the data behind the two cards comes back for the manager too
    for w in (david, vicki):
        for tool, args in (("find_stale_customers", {"days_threshold": 0}), ("get_ar_aging_report", {})):
            out = w.app.mcp(tool, args)
            assert isinstance(out, str) and not out.lstrip().startswith("❌"), \
                f"{tool} refused for {w.user.name}: {str(out)[:160]!r}"
