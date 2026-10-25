"""
tests/mcp_tests/test_reports_board_oct23.py
===========================================
David 2026-10-23 — Jobs app Board + Reports changes, checked by running
jobs/index.html's REAL JavaScript in node with "today" frozen:

Board
  * a Complete job opens after another one was saved (fallback to the
    Board's own row) — source check
  * Complete column: newest date first; route/time order within one day
  * paid Complete jobs age from the JOB's date, not the last edit
  * age markers: "⏰ N days late" (Scheduled / In Progress past their date),
    "💳 Unpaid · N days" on unpaid Complete jobs

Reports
  * "Weeks each direction" defaults to 52 (and offers 52)
  * a 🔮 visit for a customer with no Net Price / Standard Quote is valued at
    that customer's most recent priced job (Quote less Discount)
  * 🔮 visits reach the end of the chosen range (52 weeks ahead > 12 months)
  * the monthly Net Revenue chart spans the same range as the weekly charts
  * every chart sits in a sideways-scrolling box

Run: run_tests.bat tests\\mcp_tests\\test_reports_board_oct23.py -v
"""
import json
import pathlib
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC = (ROOT / "jobs" / "index.html").read_text(encoding="utf-8")
TODAY = (2026, 10, 23)          # a Friday


def _js_function(src: str, name: str) -> str:
    start = src.index(f"function {name}(")
    i = src.index("{", start)
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[start:j + 1]
    raise AssertionError(f"unbalanced braces in {name}")


_FUNCS = [
    "parseJobDate", "_dkey", "_toDateInputValue", "_timeToMinutes", "_hhmmToMin",
    "_prefDaySet", "_snapToPreferredDay", "_custPreferredDaysText", "_calRecurringProjections",
    "_reportsNum", "_durationToHours", "_noSalesTaxIsSet",
    "_reportsCustomerVisitValue", "_reportsLastJobByCustomer", "_reportsLastJobFor",
    "_reportsCustomersById", "_reportsIsUnpricedAutoJob", "_reportsRecurringProjections",
    "_reportsYearNet",
    "_boardJobId", "_derivedJobStatus", "_boardStatus", "_boardTimeKey", "_boardApprovedArrMin",
    "_boardSorted", "_boardAgeMs", "_boardIsStale", "_boardJobDateIsOld", "_boardDaysSinceJob",
    "_boardIsPaid", "_boardVisibleInColumn",
]


def _run(body: str):
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    y, m, d = TODAY
    script = "\n".join([
        "const _RD = Date; class FD extends _RD { constructor(...a) {"
        f" if (a.length) super(...a); else super({y}, {m - 1}, {d}, 12, 0, 0); }} }}"
        " FD.now = () => new FD().getTime(); globalThis.Date = FD;",
        "globalThis.window = {};",
        "var REPORTS_PROJECTED_TAX_RATE = 0.07;",
        "var _REPORTS_MONTHS = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];",
        "const BOARD_STALE_MS = 7 * 24 * 60 * 60 * 1000;",
        *[_js_function(SRC, n) for n in _FUNCS],
        body,
    ])
    out = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr[-2000:]
    return json.loads(out.stdout)


def _job(jid, date, status="Scheduled", pay="", quote="", start="", cust="CUST-1", name="ZTEST A", **kw):
    r = {"JobID (JOB-####)": jid, "Service Date": date, "Job Status": status, "Payment Status": pay,
         "Quote Amount ($)": quote, "Start Time": start, "CustomerID": cust,
         "Customer Name / Company": name, "Est. Duration": "60", "Est. Duration Unit": "min"}
    r.update(kw)
    return r


# ── Board ────────────────────────────────────────────────────────────────────
def test_board_card_tap_falls_back_to_the_board_row():
    body = _js_function(SRC, "openEditJobModal")
    assert "state.boardJobs" in body and "_mergeIntoSheetJobsCache([br])" in body
    assert "tap ↻ to refresh" in body          # never silent any more


def test_complete_column_is_newest_date_first_and_time_order_within_a_day():
    jobs = [_job("J1", "2026-10-06", "Complete", start="9:00 AM"),
            _job("J2", "2026-10-22", "Complete", start="2:00 PM"),
            _job("J3", "2026-10-22", "Complete", start="8:00 AM"),
            _job("J4", "2026-10-15", "Complete"),
            _job("J5", "", "Complete")]
    order = _run(f"process.stdout.write(JSON.stringify(_boardSorted({json.dumps(jobs)}, 'Complete').map(_boardJobId)));")
    assert order == ["J3", "J2", "J4", "J1", "J5"]


def test_scheduled_column_stays_oldest_first():
    jobs = [_job("S1", "2026-10-30"), _job("S2", "2026-10-20"), _job("S3", "2026-10-25")]
    order = _run(f"process.stdout.write(JSON.stringify(_boardSorted({json.dumps(jobs)}, 'Scheduled').map(_boardJobId)));")
    assert order == ["S2", "S3", "S1"]


def test_paid_complete_job_ages_from_its_own_date_not_the_last_edit():
    edited_now = "2026-10-23T12:00:00"
    rows = {
        "old_paid": _job("A", "2026-10-06", "Complete", pay="Paid", _last_edited_at=edited_now),
        "old_unpaid": _job("B", "2026-10-06", "Complete", pay="Unpaid", _last_edited_at=edited_now),
        "old_partial": _job("C", "2026-10-06", "Complete", pay="Partial", _last_edited_at=edited_now),
        "recent_paid": _job("D", "2026-10-20", "Complete", pay="Paid", _last_edited_at=edited_now),
    }
    vis = _run("const R = " + json.dumps(rows) + ";"
               "process.stdout.write(JSON.stringify(Object.fromEntries(Object.entries(R)"
               ".map(([k, r]) => [k, _boardVisibleInColumn(r, 'Complete')]))));")
    assert vis == {"old_paid": False, "old_unpaid": True, "old_partial": True, "recent_paid": True}


def test_days_since_job():
    got = _run("process.stdout.write(JSON.stringify(["
               "_boardDaysSinceJob({'Service Date': '2026-10-20'}),"
               "_boardDaysSinceJob({'Service Date': '2026-10-23'}),"
               "_boardDaysSinceJob({'Service Date': '2026-10-01', 'End Date (blank = single-day job)': '2026-10-21'}),"
               "_boardDaysSinceJob({'Service Date': ''})]));")
    assert got == [3, 0, 2, None]


def test_card_shows_late_and_unpaid_age_markers():
    body = _js_function(SRC, "boardCardHTML")
    assert "day${_bdAge === 1 ? '' : 's'} late" in body and "${lateLine}" in body
    assert "_bdOwedAge" in body and "💳 Not paid" in body


# ── Reports ──────────────────────────────────────────────────────────────────
def test_weeks_each_direction_defaults_to_52():
    assert '<option value="52" selected>52</option>' in SRC
    assert "var REPORTS_DEFAULT_WEEKS = 52;" in SRC


def test_visit_value_falls_back_to_the_customers_latest_priced_job():
    cust = {"CustomerID (CUST-####)": "CUST-1", "Company Name": "ZTEST A"}
    jobs = [_job("J1", "2026-09-01", "Complete", quote="100"),
            _job("J2", "2026-10-06", "Complete", quote="150", **{"Discount Applied ($)": "10"}),
            _job("J3", "2026-10-30", "Scheduled", quote=""),          # unpriced: ignored
            _job("J4", "2026-10-29", "Cancelled", quote="999")]       # cancelled: ignored
    got = _run(f"const lj = _reportsLastJobByCustomer({json.dumps(jobs)});"
               f"process.stdout.write(JSON.stringify([_reportsCustomerVisitValue({json.dumps(cust)}, lj),"
               f" _reportsCustomerVisitValue({json.dumps(dict(cust, **{'Net Price ($)': '80'}))}, lj),"
               f" _reportsCustomerVisitValue({json.dumps(cust)})]));")
    assert got == [140, 80, 0]      # fallback; own Net Price wins; no jobs -> 0 as before


def test_visits_reach_the_end_of_a_52_week_range_and_are_valued():
    cust = {"CustomerID (CUST-####)": "CUST-1", "Company Name": "ZTEST A", "Frequency": "Weekly",
            "Last Service Date": "2026-10-19", "Avg Job Duration (min)": "45"}
    jobs = [_job("J1", "2026-10-19", "Complete", quote="200")]
    got = _run(f"const p = _reportsRecurringProjections([{json.dumps(cust)}], {json.dumps(jobs)}, new Date(2027, 9, 24));"
               "process.stdout.write(JSON.stringify({n: p.length, last: p[p.length - 1].date,"
               " rev: p[0].revenue, tax: p[0].tax, hrs: p[0].hours}));")
    assert got["n"] == 52 and got["last"] == "2027-10-18"
    assert got["rev"] == 200 and got["tax"] == 14 and got["hrs"] == 0.75


def test_monthly_net_chart_spans_the_weekly_range():
    cust = {"CustomerID (CUST-####)": "CUST-1", "Company Name": "ZTEST A", "Frequency": "Monthly",
            "Last Service Date": "2026-10-06"}
    jobs = [_job("J1", "2025-11-10", "Complete", quote="300"),
            _job("J2", "2026-10-06", "Complete", quote="250")]
    got = _run(f"const m = _reportsYearNet({json.dumps(jobs)}, {{}}, {{}}, [{json.dumps(cust)}],"
               " new Date(2026, 9, 23), new Date(2025, 9, 20), new Date(2027, 9, 24));"
               "process.stdout.write(JSON.stringify(m.map(x => [x.label, x.year, x.monthIndex + 1, Math.round(x.projNet), x.isCurrent])));")
    labels = [x[0] for x in got]
    assert len(got) == 25 and (got[0][1], got[0][2]) == (2025, 10) and (got[-1][1], got[-1][2]) == (2027, 10)
    assert labels[0] == "Oct '25" and "Jan '26" in labels and "Jan '27" in labels
    by = {(x[1], x[2]): x for x in got}
    assert by[(2025, 11)][3] == 300       # a past job, outside the calendar year, now on the chart
    assert by[(2026, 10)][4] is True      # this month is marked
    assert by[(2027, 9)][3] == 250        # 🔮 visit in Sep 2027, valued from the last job
    assert sum(1 for x in got if x[3] == 250) == 13   # the Oct 6 job + 🔮 Nov '26 .. Oct '27


def test_year_net_without_a_range_is_still_the_calendar_year():
    got = _run("process.stdout.write(JSON.stringify(_reportsYearNet([], {}, {}, [], new Date(2026, 6, 1)).map(x => x.label)));")
    assert got == ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def test_every_chart_scrolls_and_centres_on_today():
    chart = _js_function(SRC, "_reportsChartSvg")
    assert 'class="reports-chart-scroll"' in chart and "overflow-x:auto" in chart
    assert 'data-current="1"' in chart
    assert "_reportsCenterCharts();" in _js_function(SRC, "loadReports")
    assert "max_rows: REPORTS_ROW_CAP" in _js_function(SRC, "loadReports")
