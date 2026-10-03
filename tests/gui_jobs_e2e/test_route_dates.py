"""RD-01 (spec §6.5, open question 2026-09-25): the Route screen's date
dropdown lists the days that have work, with a job count. What happens on a
day whose jobs are all Cancelled, and does a cancelled job count toward
"N jobs" on a normal day?

Expected: a cancelled job is not work — an all-cancelled day isn't offered
(routing it can only produce an empty route), and counts leave cancelled jobs
out.

Run: run_tests_gui_jobs_e2e.bat --human -k test_route_dates
"""
from playwright.sync_api import expect

from safety import sandbox_day


def _options(page):
    page.evaluate("async () => { await loadJobs(); _populateRouteDateOptions(); }")
    return dict(page.eval_on_selector_all("#routeDatePicker option",
                                          "os => os.map(o => [o.value, o.textContent])"))


def test_RD_01_route_dates_ignore_cancelled_jobs(clean_slate, route, page, data, app):
    all_cancelled, mixed = sandbox_day(3), sandbox_day(4)
    data.job("RD01 a", date=all_cancelled, **{"Job Status": "Cancelled"})
    data.job("RD01 b", "library", date=all_cancelled, **{"Job Status": "Cancelled"})
    data.job("RD01 c", date=mixed)
    data.job("RD01 d", "library", date=mixed, **{"Job Status": "Cancelled"})
    opts = _options(page)
    app.log(f"ROUTE date options: {opts}")
    assert mixed in opts, f"{mixed} (1 live job) missing: {opts}"
    assert opts[mixed].rstrip().endswith("1 job"), f"cancelled job counted: {opts[mixed]!r}"
    assert all_cancelled not in opts, \
        f"a day whose jobs are all cancelled is offered for routing: {opts[all_cancelled]!r}"
    expect(page.locator("#routeDatePicker")).to_be_visible()
