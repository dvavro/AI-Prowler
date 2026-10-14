"""YRP-01..YRP-02 — yearly recurring-job projections on the calendar (built 2026-10-08).

For each ACTIVE customer with a Frequency + Last Service Date, the calendar
renders view-only projected visits across the next 12 months (Weekly +7d,
Bi-Monthly +14d, Monthly +1mo) with a 🔮 and dashed styling, in the 12-month
overview below the 2-week agenda. They are never database rows: tapping one
shows an info note, never the job modal.

These are live-browser Playwright tests — they CANNOT run from a dev
machine. They need David's Windows machine with the Jobs PWA up.
Run: run_tests_gui_jobs_e2e.bat --human -k test_yearly_projections_e2e
"""
import datetime as _dt
import re

import pytest
from playwright.sync_api import expect

from safety import SANDBOX_DATE, ZTEST_PREFIX

CUST_NAME = f"{ZTEST_PREFIX} Projections Weekly"


@pytest.fixture
def recurring_customer(clean_slate, api, data):
    """A weekly recurring customer whose next visits are projections, not jobs.

    2026-10-13: "Last Service Date" is never a stored value (Case D / David's
    2026-10-05 rule) — the server computes it from the customer's COMPLETED
    jobs on past dates, and ignores what create_customer is given. So the
    customer gets a real Complete job a week ago, which is what makes it a
    recurring customer with a last service the calendar can project from."""
    last_svc = (_dt.date.fromisoformat(SANDBOX_DATE) - _dt.timedelta(days=7)).isoformat()
    out = api.call("create_customer", {"updates": {
        "Company Name": CUST_NAME,
        "City": "New Smyrna Beach", "State": "FL", "ZIP": "32168",
        "Status Active/Inactive": "Active",
        "Frequency": "Weekly"}})
    cid = out.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    data.job("YRP last weekly visit", date=last_svc, CustomerID=cid,
             **{"Customer Name / Company": CUST_NAME, "Job Status": "Complete"})
    return cid


def _overview_projections(app, page):
    """The 🔮 entries for our customer inside the 12-month overview grid."""
    app.goto("calendar")
    expect(page.locator("#calendarContent .cal-week-row")).to_have_count(14, timeout=30_000)
    label = page.locator("#calendarContent .cal-section-label", has_text="12-Month Overview")
    expect(label).to_have_count(1, timeout=30_000)
    app.log("YEARLY scroll to the 12-Month Overview")
    label.scroll_into_view_if_needed()
    app.log("YEARLY diag: " + str(page.evaluate("""async () => { try {
        const raw = await mcpCall('read_job_spreadsheet', {sheet_name: 'Customers', max_rows: 500});
        const rows = _routeParseSheetText(raw || '');
        const r = rows.find(x => (x['Company Name'] || '').indexOf('Projections') !== -1) || {};
        const p = _calRecurringProjections(rows);
        const cal = Object.values(window._calLastByDate || {}).flat().filter(x => x && x.projected).length;
        return JSON.stringify({rows: rows.length, status: r['Status Active/Inactive'], freq: r['Frequency'],
                               last: r['Last Service Date'], proj: p.length, onCalendar: cal,
                               devents: document.querySelectorAll('#calendarContent .devent').length});
      } catch (e) { return 'ERR ' + e; } }""")))
    return page.locator(f'#calendarContent .devent[data-customer="{CUST_NAME}"]')


# ── YRP-01: 🔮 entries render for the recurring customer ─────────────────────
def test_YRP_01_projections_visible_in_the_12_month_overview(app, page, recurring_customer):
    projs = _overview_projections(app, page)
    expect(projs.first).to_be_attached(timeout=30_000)
    n = projs.count()
    app.log(f"YEARLY {n} 🔮 projection entries for {CUST_NAME}")
    assert n >= 1, "no 🔮 projection entries rendered for the weekly recurring customer"
    first = projs.first
    expect(first).to_contain_text("🔮")
    expect(first).to_contain_text(CUST_NAME)
    style = first.get_attribute("style") or ""
    assert "dashed" in style, f"projection entry lost its dashed styling: {style!r}"


# ── YRP-02: tapping one shows the info note, never the job modal ─────────────
def test_YRP_02_tapping_a_projection_shows_an_info_note(app, page, recurring_customer):
    projs = _overview_projections(app, page)
    expect(projs.first).to_be_attached(timeout=30_000)
    app.log("YEARLY tap the first 🔮 projection")
    projs.first.click()
    note = page.locator("#_projInfoNote")
    expect(note).to_be_visible(timeout=10_000)
    expect(note).to_contain_text("Projected visit")
    expect(page.locator("#jobModal")).not_to_have_class(re.compile(r"\bopen\b"))
    app.log("YEARLY info note shown; the job modal stayed closed")
