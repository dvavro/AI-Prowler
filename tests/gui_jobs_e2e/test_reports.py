"""Reports screen (spec §6.8) — weekly revenue / hours, and Customer Reminders.
Personal mode (Reports is owner-only in server mode — §6.11).

Numbers are checked as a CHANGE: the current week's row is read, jobs with
known amounts and hours are added this week, ↻ is tapped, and the row must
move by exactly that much — so any other jobs already in the database don't
matter. Revenue: actual = money already collected (invoice Amount Paid),
projected = still owed (Scheduled, In Progress and unpaid Completed work).
Hours: actual = Complete jobs, projected = Scheduled / In Progress.
Cancelled jobs never count.

Customer Reminders: send_customer_reminders is OUTBOUND — the write guard
records it (with the exact customer ids / channel / message) and nothing is
emailed or texted.

Run: run_tests_gui_jobs_e2e.bat --human -k test_reports
"""
import re

import pytest
from playwright.sync_api import expect

from app import type_text

MONEY = re.compile(r"-?\$?([\d,]+(?:\.\d+)?)")


def _sandbox_label() -> str:
    """Weekly Detail label (its Monday, 'M/D') of the week the test jobs land in —
    the sandbox date's week, which is 'this week' only when no E2E_SANDBOX_DATE
    is set. (2026-10-09: with a sandbox date the jobs were in another week and
    REP-02 read an unchanged row.)"""
    import datetime as _dt
    from safety import SANDBOX_DATE
    d = _dt.date.fromisoformat(SANDBOX_DATE)
    mon = d - _dt.timedelta(days=d.weekday())
    return f"{mon.month}/{mon.day}"


def _open(app, page, *, wide=False):
    app.goto("reports")
    expect(page.locator("#reportsContent table tbody tr").first).to_be_visible(timeout=30_000)
    if wide:
        # 26 weeks each way, so a sandbox date up to ~6 months off today is on screen
        app.log("REPORTS weeks each direction → 26 (the sandbox week must be in range)")
        page.locator("#reportsWeeksSelect").select_option("26")
        expect(page.locator("#reportsContent table tbody tr")).to_have_count(53, timeout=30_000)


def _refresh(app, page):
    app.log("REPORTS tap ↻")
    with page.expect_response(lambda r: "/pwa-api" in r.url and "read_job_spreadsheet" in (r.request.post_data or "")):
        page.locator("#refreshReportsBtn").click()
    expect(page.locator("#reportsContent table tbody tr").first).to_be_visible(timeout=30_000)


def _this_week(page) -> dict:
    """The sandbox week's Weekly Detail row (= this week without a sandbox date)."""
    label = _sandbox_label()
    row = page.locator("#reportsContent table tbody tr").filter(
        has_text=re.compile(rf"^\s*{re.escape(label)}(?!\d)"))
    expect(row).to_have_count(1)
    cells = [c.strip() for c in row.locator("td").all_inner_texts()]
    num = lambda s: float(MONEY.search(s).group(1).replace(",", ""))
    # Weekly Detail table column order (2026-10-08: the Actual/Proj/Total
    # Tax columns were added between Rev and Hrs):
    #   Week of | Actual Rev | Proj Rev | Total Rev | Actual Tax | Proj Tax |
    #   Total Tax | Actual Hrs | Proj Hrs | Total Hrs
    keys = ["actual_rev", "proj_rev", "total_rev",
            "actual_tax", "proj_tax", "total_tax",
            "actual_hrs", "proj_hrs", "total_hrs"]
    return {k: num(v) for k, v in zip(keys, cells[1:10])}


# ── REP-01: the screen and the weeks selector ────────────────────────────────
def test_REP_01_charts_table_and_weeks_selector(app, page):
    _open(app, page)
    expect(page.locator("#reportsContent")).to_contain_text("Weekly Revenue")
    expect(page.locator("#reportsContent")).to_contain_text("Weekly Scheduled Hours")
    # yearly net revenue (2026-10-21) + weekly revenue + tax + hours
    expect(page.locator("#reportsContent svg")).to_have_count(4)
    expect(page.locator("#reportsContent")).to_contain_text("Weekly Tax Collected")
    rows = page.locator("#reportsContent table tbody tr")
    # 2026-10-23 (David): default 52 weeks each way
    expect(page.locator("#reportsWeeksSelect")).to_have_value("52")
    expect(rows).to_have_count(105)                      # 52 back + this week + 52 ahead
    expect(rows.filter(has_text="(this week)")).to_have_count(1)
    app.log("REPORTS weeks each direction → 4")
    page.locator("#reportsWeeksSelect").select_option("4")
    expect(rows).to_have_count(9)


# ── REP-07: every chart covers the whole range and scrolls sideways ─────────
def test_REP_07_every_chart_spans_the_range_and_scrolls(app, page):
    """David 2026-10-23: the Net Revenue chart stopped at December with no
    scroll bar. All four charts now cover 52 weeks back and ahead, sit in a
    sideways-scrolling box, and open scrolled to this week / this month."""
    _open(app, page)
    boxes = page.locator("#reportsContent .reports-chart-scroll")
    expect(boxes).to_have_count(4)
    page.wait_for_timeout(500)
    info = page.evaluate("""() => [...document.querySelectorAll('#reportsContent .reports-chart-scroll')]
        .map(b => ({sw: b.scrollWidth, cw: b.clientWidth, sl: b.scrollLeft,
                    bars: b.querySelectorAll('svg > text').length}))""")
    app.log(f"REPORTS chart boxes: {info}")
    # weekly charts (105 weeks) are always wider than the screen: they scroll and
    # open on this week. The monthly chart (25 months) may fit a wide PC screen
    # — then it needs no scroll; on a phone it scrolls and opens on this month.
    for b in info[1:]:
        assert b["sw"] > b["cw"], f"a weekly chart doesn't scroll sideways: {info}"
        assert b["sl"] > 0, f"a weekly chart didn't open scrolled to this week: {info}"
    if info[0]["sw"] > info[0]["cw"]:
        assert info[0]["sl"] > 0, f"the monthly chart didn't open scrolled to this month: {info}"
    for b in info:
        assert b["sw"] - b["sl"] >= b["cw"] - 1, f"a chart is cut off: {info}"
    # the monthly chart: about 25 months (a year back to a year ahead), with years on its labels
    net = page.get_by_test_id("reports-year-net")
    expect(net).to_contain_text("'2")                    # e.g. "Oct '25", "Jan '27"
    expect(page.get_by_test_id("reports-range-net-total")).to_be_visible()


# ── REP-08: a 🔮 visit for a customer with no price uses their last job ─────
def test_REP_08_recurring_visit_without_customer_price_uses_last_job(clean_slate, app, page, data, api):
    """David 2026-10-23: imported customers have no Net Price / Standard Quote,
    so every 🔮 visit counted $0. A visit is now valued at the customer's most
    recent priced job (Quote less Discount) — here $180, +7% projected tax."""
    import datetime as _dt
    today = _dt.date.fromisoformat(page.evaluate(
        "() => { const t = new Date(); return t.getFullYear() + '-' + String(t.getMonth() + 1).padStart(2, '0')"
        " + '-' + String(t.getDate()).padStart(2, '0'); }"))
    last = today - _dt.timedelta(days=21)                 # Monthly -> next visit in ~10 days
    last = last.replace(day=min(last.day, 28))            # so "+1 month" is the same day
    visit = last.replace(month=last.month % 12 + 1, year=last.year + (last.month == 12))
    out = api.call("create_customer", {"updates": {
        "Company Name": "ZTEST E2E Recurring NoPrice", "City": "New Smyrna Beach", "State": "FL",
        "ZIP": "32168", "Status Active/Inactive": "Active", "Frequency": "Monthly",
        "Last Service Date": last.isoformat(), "Avg Job Duration (min)": 60}})
    cid = out.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    mon = visit - _dt.timedelta(days=visit.weekday())
    label = f"{mon.month}/{mon.day}"
    _open(app, page)

    def _week():
        row = page.locator("#reportsContent table tbody tr").filter(has_text=re.compile(rf"^\s*{re.escape(label)}(?!\d)"))
        expect(row).to_have_count(1)
        cells = [c.strip() for c in row.locator("td").all_inner_texts()]
        return float(MONEY.search(cells[2]).group(1).replace(",", "")), float(MONEY.search(cells[5]).group(1).replace(",", ""))

    before = _week()
    app.log(f"REPORTS customer {cid} has no price; adding its last job at $200 − $20 on {last}")
    data.job("REP08 last visit", date=last.isoformat(), **{
        "CustomerID": cid, "Customer Name / Company": "ZTEST E2E Recurring NoPrice",
        "Job Status": "Complete", "Quote Amount ($)": 200, "Discount Applied ($)": 20})
    _refresh(app, page)
    after = _week()
    app.log(f"REPORTS week of {label} (🔮 visit {visit}): proj rev/tax {before} → {after}")
    assert round(after[0] - before[0], 2) == 180, (before, after)
    assert abs((after[1] - before[1]) - 12.6) <= 1, (before, after)    # 7% (the table rounds to $)


# ── REP-02: this week's numbers move by exactly what was added ───────────────
def test_REP_02_this_weeks_revenue_and_hours(clean_slate, app, page, data, api):
    """Revenue per the owner's definitions (2026-09-26):
         actual    = money already collected (the invoice's Amount Paid)
         projected = everything still owed (Scheduled, In Progress, AND
                     completed-but-unpaid work alike)
       Hours are unchanged: actual = Completed, projected = Scheduled/In Progress."""
    _open(app, page, wide=True)
    before = _this_week(page)
    # Completed, never invoiced -> nothing collected: $0 actual, $150 still owed.
    data.job("REP02 done unpaid", **{"Job Status": "Complete", "Quote Amount ($)": 150,
                                     "Est. Duration": 60, "Est. Duration Unit": "min",
                                     "Actual Duration": 90, "Actual Duration Unit": "min"})
    # Completed, invoiced $100 (no tax, to keep the math plain), $40 paid so far:
    # $40 actual, $60 still owed.
    paid_job = data.job("REP02 done partly paid", "flagler",
                        **{"Job Status": "Complete", "Quote Amount ($)": 100,
                           "Est. Duration": 60, "Est. Duration Unit": "min",
                           "Actual Duration": 60, "Actual Duration Unit": "min"})
    out = api.call("create_invoice", {"job_identifier": paid_job, "quote_amount": 100,
                                      "discount": 0, "tax_rate": 0})
    inv_id = re.search(r"INV-\d+", out).group(0)
    app.log(f"REPORTS invoiced {paid_job} as {inv_id}; recording a $40 partial payment")
    api.call("update_job_spreadsheet", {"sheet_name": "Invoices", "job_identifier": inv_id,
                                        "id_column": "InvoiceID (INV-####)",
                                        "updates": {"Amount Paid ($)": 40,
                                                    "Payment Status": "Partial"}})
    # Scheduled, not done: $200 still owed, 30 min projected.
    data.job("REP02 upcoming", "brannon", **{"Quote Amount ($)": 200,
                                             "Est. Duration": 30, "Est. Duration Unit": "min"})
    # Cancelled: never counted anywhere.
    data.job("REP02 cancelled", "library", **{"Job Status": "Cancelled", "Quote Amount ($)": 999,
                                              "Est. Duration": 2, "Est. Duration Unit": "hr"})
    _refresh(app, page)
    after = _this_week(page)
    delta = {k: round(after[k] - before[k], 2) for k in before}
    app.log(f"REPORTS this-week change: {delta}")
    assert delta["actual_rev"] == 40, f"only the $40 actually paid should be actual revenue: {delta}"
    assert delta["proj_rev"] == 410, f"still owed should be 150 + 60 + 200 = 410: {delta}"
    assert delta["actual_hrs"] == 2.5, f"completed jobs' 90 + 60 min not counted: {delta}"
    assert delta["proj_hrs"] == 0.5, f"scheduled job's 30 min estimate not counted: {delta}"
    assert delta["total_rev"] == 450 and delta["total_hrs"] == 3.0, f"cancelled job counted? {delta}"
    # REP02 jobs are invoiced at tax_rate=0 or not invoiced at all, so the
    # new Weekly Tax Collected columns must not move.
    assert delta["actual_tax"] == 0 and delta["proj_tax"] == 0 \
        and delta["total_tax"] == 0, f"tax columns moved on tax-free jobs: {delta}"


# ── REP-06: invoice tax reaches Weekly Tax Collected (R-084) ─────────────────
def test_REP_06_taxed_invoice_moves_the_tax_columns(clean_slate, app, page, data, api):
    """R-084 (2026-10-09): Reports read the invoice tax under the wrong column
    name, so every invoice counted $0 tax. A Complete $100 job invoiced at 7%:
    unpaid -> $107 projected revenue, $7 projected tax; paid -> $107 / $7 actual."""
    _open(app, page, wide=True)
    before = _this_week(page)
    jid = data.job("REP06 taxed", **{"Job Status": "Complete", "Quote Amount ($)": 100,
                                     "Est. Duration": 60, "Est. Duration Unit": "min",
                                     "Actual Duration": 60, "Actual Duration Unit": "min"})
    out = api.call("create_invoice", {"job_identifier": jid, "quote_amount": 100,
                                      "discount": 0, "tax_rate": 0.07})
    inv_id = re.search(r"INV-[\d-]*\d", out).group(0)
    app.log(f"REPORTS invoiced {jid} as {inv_id} at 7% — unpaid")
    _refresh(app, page)
    mid = _this_week(page)
    d1 = {k: round(mid[k] - before[k], 2) for k in before}
    app.log(f"REPORTS this-week change (unpaid): {d1}")
    assert (d1["actual_rev"], d1["proj_rev"], d1["actual_tax"], d1["proj_tax"]) == (0, 107, 0, 7), \
        f"an unpaid $107 invoice should show $107 / $7 tax projected: {d1}"
    app.log(f"REPORTS recording {inv_id} as Paid")
    api.call("update_job_spreadsheet", {"sheet_name": "Invoices", "job_identifier": inv_id,
                                        "id_column": "InvoiceID (INV-####)",
                                        "updates": {"Payment Status": "Paid"}})
    _refresh(app, page)
    after = _this_week(page)
    d2 = {k: round(after[k] - before[k], 2) for k in before}
    app.log(f"REPORTS this-week change (paid): {d2}")
    assert (d2["actual_rev"], d2["proj_rev"], d2["actual_tax"], d2["proj_tax"]) == (107, 0, 7, 0), \
        f"a paid $107 invoice should show $107 / $7 tax actual: {d2}"
    assert d2["actual_hrs"] == 1.0, d2


# ── Customer Reminders ───────────────────────────────────────────────────────
@pytest.fixture
def stale_customer(clean_slate, api):
    out = api.call("create_customer", {"updates": {
        "Company Name": "ZTEST E2E Reminder <b>Co</b>", "First Name": "Pat",
        "Email": "ztest-e2e@example.invalid", "City": "New Smyrna Beach", "State": "FL",
        "ZIP": "32168", "Status Active/Inactive": "Active"}})
    return out.split("NEW_CUST_ID=")[1].splitlines()[0].strip()


def _reminder_settings(value):
    """Answer ONLY the Settings read (the app's check of the two
    'Customer Reminder … Enabled' switches) in the browser; every other read
    goes to the real server. Nothing in Settings is changed."""
    text = (f"📋 Settings (E2E fake)\n\n  Setting: Customer Reminder Email Enabled\n  Value: {value}\n\n"
            f"  Setting: Customer Reminder SMS Enabled\n  Value: {value}\n")
    return lambda args: text if args.get("sheet_name") == "Settings" else None


def _find(app, page, days="0"):
    page.locator("#staleCustomerDays").fill(days)
    app.log(f"REPORTS 🔍 Find Customers (not serviced in {days} days)")
    with page.expect_response(lambda r: "/pwa-api" in r.url and "find_stale_customers" in (r.request.post_data or "")):
        page.get_by_role("button", name=re.compile("Find Customers")).click()
    expect(page.locator("#staleCustomersResult .loader")).to_have_count(0, timeout=20_000)


def _only_check(page, cust_name_part):
    for lab in page.locator("#staleCustomersResult label").all():
        box = lab.locator("input.stale-cust-check")
        if cust_name_part in lab.inner_text():
            box.check()
        else:
            box.uncheck()


def test_REP_03_find_and_email_selected_reminder(app, page, guard, stale_customer):
    page.e2e_fakes["read_job_spreadsheet"] = _reminder_settings("Enabled")
    _open(app, page)
    _find(app, page)
    mine = page.locator("#staleCustomersResult label").filter(has_text="ZTEST E2E Reminder")
    expect(mine).to_have_count(1)
    expect(mine).to_contain_text("ZTEST E2E Reminder <b>Co</b>")      # markup shown as text
    expect(mine).to_contain_text("ztest-e2e@example.invalid")
    email_btn = page.locator("#staleCustomersResult button", has_text=re.compile("Email Selected"))
    expect(email_btn).to_be_enabled()
    _only_check(page, "ZTEST E2E Reminder")
    type_text(page, page.locator("#staleCustomerMessage"), "Hi {name}, time for your next service!")
    before = len(guard.recorded_calls("send_customer_reminders"))
    app.log("REPORTS ✉️ Email Selected (recorded by the guard — nothing is emailed)")
    email_btn.click()
    expect(page.locator("#staleCustomersSendStatus")).not_to_contain_text("Sending", timeout=20_000)
    calls = guard.recorded_calls("send_customer_reminders")
    assert len(calls) == before + 1
    args = calls[-1]["args"]
    assert args["customer_ids"] == stale_customer, args
    assert args["channel"] == "email"
    assert args["message"] == "Hi {name}, time for your next service!"


def test_REP_04_send_with_nobody_selected(app, page, guard, stale_customer):
    page.e2e_fakes["read_job_spreadsheet"] = _reminder_settings("Enabled")
    _open(app, page)
    _find(app, page)
    for box in page.locator("#staleCustomersResult input.stale-cust-check").all():
        box.uncheck()
    before = len(guard.recorded_calls("send_customer_reminders"))
    page.locator("#staleCustomersResult button", has_text=re.compile("Text Selected")).click()
    expect(page.locator("#toast")).to_contain_text("Select at least one customer first")
    assert len(guard.recorded_calls("send_customer_reminders")) == before


def test_REP_05_channels_turned_off_in_settings_grey_out(app, page, guard, stale_customer):
    page.e2e_fakes["read_job_spreadsheet"] = _reminder_settings("Disabled")
    _open(app, page)
    _find(app, page)
    res = page.locator("#staleCustomersResult")
    expect(res.locator("button", has_text="Email Disabled")).to_be_disabled()
    expect(res.locator("button", has_text="Text Disabled")).to_be_disabled()
    expect(res.locator("button", has_text=re.compile("Selected"))).to_have_count(0)
