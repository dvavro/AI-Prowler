"""Calendar (spec §6.6) — the "Next 2 Weeks" agenda and the 12-month grid,
used the way a person uses them: look at today, tap a day to see its jobs,
tap a job to open it, tap an empty day to schedule a new job on it.

The agenda's first row is always TODAY (= the sandbox date), row N is today+N.
Chips are identified by the job number they open (the text on a chip is the
customer RECORD's name, which every test job shares).

Run: run_tests_gui_jobs_e2e.bat --human -k calendar
"""
import re

import pytest
from playwright.sync_api import expect

from safety import SANDBOX_DATE, ZTEST_PREFIX, sandbox_day

OPEN = re.compile(r"\bopen\b")


# ── helpers ──────────────────────────────────────────────────────────────────
def _open_calendar(app, page):
    app.goto("calendar")
    expect(page.locator("#calendarContent .cal-week-row")).to_have_count(14, timeout=30_000)


def _row(page, offset):
    """Agenda row for today+offset."""
    return page.locator("#calendarContent .cal-week-row").nth(offset)


def _chip(scope, jid):
    return scope.locator(f".cal-job-chip[onclick*=\"'{jid}'\"]")


# ── CAL-01: today's jobs on today's row ──────────────────────────────────────
def test_CAL_01_todays_job_is_on_the_today_row(clean_slate, app, page, data):
    hard = data.job("CAL01 hard", **{"Schedule Type (Hard/Soft)": "Hard",
                                     "Start Time": "09:00", "End Time": "10:00"})
    soft = data.job("CAL01 soft", "brannon", **{"Start Time": "13:00", "End Time": "15:00"})
    _open_calendar(app, page)
    today = _row(page, 0)
    expect(today).to_have_class(re.compile(r"\btoday\b"))
    expect(today.locator(".dow")).to_have_text("Today")
    expect(_chip(today, hard)).to_contain_text("9:00 AM")
    expect(_chip(today, hard)).to_contain_text("🔒")
    expect(_chip(today, soft)).to_contain_text("1:00 PM")
    expect(_chip(today, soft)).to_contain_text("☁️")
    # 9 AM is listed before 1 PM
    chips = today.locator(".cal-job-chip")
    expect(chips.nth(0)).to_contain_text("9:00 AM")
    # both jobs have a block on the day's time bar
    expect(today.locator(".cal-occ-bar .seg:not(.occ-lunch)")).to_have_count(2)
    # not on tomorrow
    expect(_chip(_row(page, 1), hard)).to_have_count(0)


# ── CAL-02: tap the day → day list → tap the job → job detail ────────────────
def test_CAL_02_tap_day_then_job_opens_it(clean_slate, app, page, data):
    jid = data.job("CAL02", **{"Start Time": "10:30", "End Time": "11:30"})
    _open_calendar(app, page)
    app.log("CAL tap today's row")
    _row(page, 0).locator(".cal-week-date").click()
    expect(page.locator("#calDayModal")).to_have_class(OPEN)
    row = page.locator("#calDayModalList .cal-day-list-row").filter(
        has=page.locator(".id", has_text=re.compile(rf"^{re.escape(jid)}$")))
    expect(row).to_have_count(1)
    expect(row.locator(".time")).to_have_text("10:30 AM")
    app.log(f"CAL tap {jid} in the day list")
    row.click()
    expect(page.locator("#calDayModal")).not_to_have_class(OPEN)
    expect(page.locator("#jobModal")).to_have_class(OPEN)
    expect(page.locator("#jobModal")).to_contain_text(jid)


# ── CAL-03: Cancelled jobs are left off; Complete ones are shown as done ─────
def test_CAL_03_cancelled_hidden_complete_marked(clean_slate, app, page, data):
    done = data.job("CAL03 done", **{"Start Time": "08:00", "Job Status": "Complete"})
    gone = data.job("CAL03 cancelled", "brannon", **{"Start Time": "09:00", "Job Status": "Cancelled"})
    _open_calendar(app, page)
    today = _row(page, 0)
    expect(_chip(today, done)).to_have_class(re.compile(r"\bstatus-complete\b"))
    expect(_chip(today, gone)).to_have_count(0)


# ── CAL-04: a multi-day job shows on every WORKING day it covers ─────────────
# R-058 (2026-09-28): only working days inside the span; the start day always
# counts. 2026-10-02: the working days come from Settings → Working Days
# (default Mon–Fri), so the expected rows are worked out from the days the app
# itself is using — this test used to assume every day, and failed whenever the
# 3-day span crossed a weekend (e.g. a run on a Friday).
def _app_working_days(page) -> set:
    """JS getDay() numbers (Sun=0) the Calendar is using right now."""
    return set(page.evaluate("() => Array.from(window._workingDays || [])"))


def _wait_app_working_days(page, want: set, timeout=30_000) -> set:
    """Wait until the app has loaded `want` (JS getDay() numbers), then return
    what it holds. Re-opening the Calendar shows the previous 14 rows straight
    away while get_working_days is still in flight, so reading
    window._workingDays at once raced the reply (CAL-06, 2026-10-02: the
    server had already answered Mon–Fri, the app hadn't applied it yet)."""
    try:
        page.wait_for_function(
            "want => { const s = window._workingDays; if (!s) return false;"
            " const a = Array.from(s).sort().join(','); return a === want; }",
            arg=",".join(str(d) for d in sorted(want)), timeout=timeout)
    except Exception:
        pass                                  # the assert below says what it holds
    return _app_working_days(page)


def _js_weekday(iso: str) -> int:
    import datetime as _dt
    return (_dt.date.fromisoformat(iso).weekday() + 1) % 7     # Mon=1 … Sun=0


def test_CAL_04_multi_day_job_on_every_day(clean_slate, app, page, data):
    jid = data.job("CAL04 3-day", date=sandbox_day(1),
                   **{"End Date (blank = single-day job)": sandbox_day(3), "Start Time": "08:00"})
    _open_calendar(app, page)
    working = _app_working_days(page)
    assert working, "the Calendar has no working days loaded"
    expected = {0: 0, 1: 1, 4: 0}                                # before / start day / after
    for offset in (2, 3):
        expected[offset] = 1 if _js_weekday(sandbox_day(offset)) in working else 0
    app.log(f"CAL-04 working days (JS getDay) {sorted(working)} → expected per row {expected}")
    for offset, want in sorted(expected.items()):
        expect(_chip(_row(page, offset), jid)).to_have_count(want)


# ── CAL-06: Settings → Working Days — weekends on, then back off ─────────────
# Vicki 2026-10-02: a contractor running late can work Saturday and Sunday.
# A 4-day job spanning a weekend: with Mon–Fri its weekend days are empty
# (the start day always shows); with every day all four show; back to
# Mon–Fri, the weekend is empty again.
WORKING_DAYS = "Working Days"
EVERY_DAY = "Mon,Tue,Wed,Thu,Fri,Sat,Sun"


def _real_open_day_jobs(api) -> dict:
    """JobID -> End Date of every NON-test open job measured in days. Changing
    Working Days re-counts their End Date, so the test must not run if any exist."""
    out = {}
    for r in api.read("Jobs_Schedule"):
        name = str(r.get("Customer Name / Company") or "")
        unit = str(r.get("Est. Duration Unit") or "").strip().lower()
        status = str(r.get("Job Status") or "").strip().lower()
        if name.startswith(ZTEST_PREFIX) or unit != "day":
            continue
        if status in ("complete", "completed", "cancelled", "canceled"):
            continue
        jid = str(r.get("JobID (JOB-####)") or r.get("JobID") or "")
        out[jid] = str(r.get("End Date (blank = single-day job)") or "")
    return out


def test_CAL_06_working_days_setting_adds_the_weekend(clean_slate, app, page, data, api, toggles, guard):
    if WORKING_DAYS not in toggles.saved:
        pytest.skip("this AI-Prowler has no 'Working Days' setting yet — deploy the 2026-10-02 update")
    real = _real_open_day_jobs(api)
    if real:
        pytest.skip(f"{len(real)} real open job(s) measured in days — changing Working Days would "
                    f"re-count their End Date, so this test leaves the setting alone")
    original = toggles.saved[WORKING_DAYS]["Value"]
    if original != "Mon,Tue,Wed,Thu,Fri":
        pytest.skip(f"Working Days is {original!r} on this install, not the Mon–Fri default")

    # A 4-day job inside the sandbox window (+1 … +7): start somewhere in +1 … +4
    # and pick the start whose span has the most weekend days AFTER its start
    # day (the start day always shows). Any 4-day span here includes at least
    # one. (2026-10-02: first version hunted for "the next Friday, then Monday",
    # which could fall outside the -3..+7 window.)
    def _weekend_days_after_start(s):
        return sum(1 for o in (s + 1, s + 2, s + 3) if _js_weekday(sandbox_day(o)) in (0, 6))
    k = max(range(1, 5), key=_weekend_days_after_start)
    span = [k, k + 1, k + 2, k + 3]
    weekend = [o for o in span[1:] if _js_weekday(sandbox_day(o)) in (0, 6)]
    assert weekend, "no weekend day inside the test span"
    jid = data.job("CAL06 4-day", date=sandbox_day(k),
                   **{"End Date (blank = single-day job)": sandbox_day(k + 3), "Start Time": "08:00"})

    def _mon_fri_expected(o):
        return 1 if o == k or _js_weekday(sandbox_day(o)) not in (0, 6) else 0

    app.log(f"CAL-06 job days {[sandbox_day(o) for o in span]}, weekend inside: "
            f"{[sandbox_day(o) for o in weekend]}")
    _open_calendar(app, page)
    assert _wait_app_working_days(page, {1, 2, 3, 4, 5}) == {1, 2, 3, 4, 5}
    for offset in span:
        expect(_chip(_row(page, offset), jid)).to_have_count(_mon_fri_expected(offset))

    try:
        # Through the Settings screen, the way a person does it — and the save
        # itself applies it: no reload, no separate "Apply" step (Vicki 2026-10-02).
        from test_database import _tab, _wait
        from test_settings_toggles import _flip_in_app
        app.log("CAL-06 Settings → Working Days = every day (in the app)")
        app.goto("sheet")
        _wait(page)
        _tab(app, page, "Settings")
        guard.observe_setting(WORKING_DAYS, EVERY_DAY, pending=True)
        _flip_in_app(app, page, WORKING_DAYS, EVERY_DAY)
        expect(page.locator("#toast")).to_contain_text("Working Days applied: Mon, Tue, Wed, Thu, Fri, Sat, Sun")
        assert toggles.value(WORKING_DAYS) == EVERY_DAY
        guard.observe_setting(WORKING_DAYS, EVERY_DAY)
        assert _wait_app_working_days(page, {0, 1, 2, 3, 4, 5, 6}) == {0, 1, 2, 3, 4, 5, 6}, \
            "the app didn't pick up the new days on save"
        assert "WORKING_DAYS: " + EVERY_DAY in str(api.call("get_working_days", {}))
        app.goto("calendar")                           # same page — no reload
        expect(page.locator("#calendarContent .cal-week-row")).to_have_count(14, timeout=30_000)
        for offset in span:
            expect(_chip(_row(page, offset), jid)).to_have_count(1)
        # the server's day filter agrees (Jobs list / Calendar data)
        assert jid in str(api.call("read_job_spreadsheet", {"filter_date": sandbox_day(weekend[0])}))
    finally:
        app.log("CAL-06 Settings → Working Days back to Mon–Fri")
        toggles.set(WORKING_DAYS, original)

    _open_calendar(app, page)
    assert _wait_app_working_days(page, {1, 2, 3, 4, 5}) == {1, 2, 3, 4, 5}
    for offset in span:
        expect(_chip(_row(page, offset), jid)).to_have_count(_mon_fri_expected(offset))
    assert _real_open_day_jobs(api) == real, "a real job changed while Working Days was switched"


# ── CAL-05: an empty day opens Add Job with that date filled in ──────────────
def test_CAL_05_empty_day_opens_add_job_for_that_day(clean_slate, app, page, data):
    data.job("CAL05 other day")                       # something on today, nothing on +5
    _open_calendar(app, page)
    empty = _row(page, 5)
    expect(empty.locator(".cal-week-empty")).to_have_text("No jobs scheduled")
    app.log("CAL tap the empty day (+5)")
    empty.locator(".cal-week-date").click()
    expect(page.locator("#jobFormModal")).to_be_visible()
    expect(page.locator("#jobFormTitle")).to_have_text("Add New Job")
    expect(page.locator("#jfDate")).to_have_value(sandbox_day(5))


# ── CAL-06: month grid — today's cell, names, "+N more" ──────────────────────
def test_CAL_06_month_grid_today_cell(clean_slate, app, page, data):
    for i, t in enumerate(["08:00", "09:00", "10:00", "11:00"]):
        data.job(f"CAL06 {i}", **{"Start Time": t})
    _open_calendar(app, page)
    cell = page.locator("#calendarContent .cal-day.today")
    expect(cell).to_have_count(1)
    expect(cell).to_have_class(re.compile(r"\bhas-jobs\b"))
    expect(cell.locator(".devent")).to_have_count(3)
    expect(cell.locator(".devent").first).to_contain_text("8:00 AM")
    expect(cell.locator(".dmore")).to_have_text("+1 more")
    app.log("CAL tap today's cell in the month grid")
    cell.click()
    expect(page.locator("#calDayModal")).to_have_class(OPEN)
    expect(page.locator("#calDayModalList .cal-day-list-row")).to_have_count(4)


# ── CAL-07: a routed day shows the 📍 route link ─────────────────────────────
def test_CAL_07_routed_day_shows_route_link(clean_slate, app, page, data):
    from app import RouteScreen
    ids = [data.job("CAL07 A", "city_hall"), data.job("CAL07 B", "brannon")]
    app.goto("route")
    route = RouteScreen(page, app.log)
    route.pick_date(SANDBOX_DATE)
    route.press_route_selected_date(accept_errors=True)
    route.wait_quiet()
    route.expect_stops_include(ids)
    _open_calendar(app, page)
    link = _row(page, 0).locator("a[title^='Route built for this day']")
    expect(link).to_have_count(1)
    expect(link).to_have_attribute("href", re.compile(r"^https://www\.google\.com/maps/"))
    expect(_row(page, 1).locator("a[title^='Route built for this day']")).to_have_count(0)
    _row(page, 0).locator(".cal-week-date .dow").click()
    expect(page.locator("#calDayModalRoute")).to_contain_text("Route for this day")


# ── CAL-08: ↻ picks up a job added elsewhere ────────────────────────────────
def test_CAL_08_refresh_shows_a_new_job(clean_slate, app, page, data):
    data.customer_id()
    _open_calendar(app, page)
    jid = data.job("CAL08 new", date=sandbox_day(2), **{"Start Time": "14:00"})
    expect(_chip(_row(page, 2), jid)).to_have_count(0)
    app.log("CAL tap ↻ refresh")
    page.locator("#refreshCalBtn").click()
    expect(_chip(_row(page, 2), jid)).to_contain_text("2:00 PM", timeout=20_000)
