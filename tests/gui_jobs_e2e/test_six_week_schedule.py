"""Personal mode — a realistic 6-week window-cleaning schedule, plus customer
reminders (spec §6.14, PSCHED-01..05, REM-01..04). Requested by David 2026-09-28.

  • David Vavro (the owner — personal mode is one person) creates 15 customers:
    8 in New Smyrna Beach, 7 in Daytona Beach, real public addresses; 8 Weekly
    and 7 Biweekly, three per weekday, each with its own start time; and
    schedules 6 weeks of Window-cleaning jobs from them (8×6 + 7×3 = 69 jobs).
  • He works day 1 (clock in/out, complete), routes every in-window workday,
    and sees the schedule on the Calendar and Jobs screens.
  • Customer reminders: "who hasn't been serviced lately" (Reports → Customer
    Reminders) and the send step — lapsed / recently-serviced / inactive /
    never-serviced customers, the threshold boundary, the "no email on file"
    skip, and (tier email/full only) ONE real reminder to David's own address.

Safety: everything is named "ZTEST E2E …" and swept before and after; routes
only on sandbox-window days; schedule customers have no email/phone, so no
reminder can reach them. The only customer with an email is the reminder test
customer, and only in tier email/full, with David's address from
AIPROWLER_E2E_COMMS_TO — the guard lets exactly one reminder through, to him.

Run: run_tests_gui_jobs_e2e.bat --human -k test_six_week_schedule
     (add --tier email for the one real reminder email to David)
"""
from __future__ import annotations

import datetime as dt
import logging
import re

import pytest
from playwright.sync_api import expect

from api import iso_date
from safety import SANDBOX_DATE, SANDBOX_DATES, ZTEST_PREFIX

log = logging.getLogger("e2e")

DAVID = "David Vavro"
WEEKS = 6
TIMES = ["09:00", "11:00", "13:30"]            # the three customers on each weekday

# name, street, city, zip, lat, lon  (frequency and weekday slot follow the index)
CUSTOMERS = [
    ("Riverside Cafe",        "105 S Riverside Dr",    "New Smyrna Beach", "32168", 29.0263, -80.9216),
    ("City Hall Offices",     "210 Sams Ave",          "New Smyrna Beach", "32168", 29.0258, -80.9270),
    ("Library Annex",         "1001 S Dixie Fwy",      "New Smyrna Beach", "32168", 29.0122, -80.9303),
    ("Flagler Ave Shops",     "1 Flagler Ave",         "New Smyrna Beach", "32169", 29.0413, -80.8965),
    ("Sports Complex",        "201 Sports Complex Dr", "New Smyrna Beach", "32168", 29.0060, -80.9458),
    ("Canal Street Gallery",  "300 Canal St",          "New Smyrna Beach", "32168", 29.0271, -80.9244),
    ("Chamber Office",        "115 Canal St",          "New Smyrna Beach", "32168", 29.0269, -80.9225),
    ("Beachside Condos",      "3500 S Atlantic Ave",   "New Smyrna Beach", "32169", 28.9981, -80.8836),
    ("Main Street Pier Shop", "1200 Main St",          "Daytona Beach",    "32118", 29.2278, -81.0059),
    ("Daytona City Hall",     "301 S Ridgewood Ave",   "Daytona Beach",    "32114", 29.2097, -81.0232),
    ("Museum Offices",        "352 S Nova Rd",         "Daytona Beach",    "32114", 29.2013, -81.0415),
    ("Speedway Suites",       "1801 W International Speedway Blvd", "Daytona Beach", "32114", 29.1852, -81.0705),
    ("City Island Library",   "105 E Magnolia Ave",    "Daytona Beach",    "32114", 29.2140, -81.0165),
    ("Beach Street Shops",    "100 N Beach St",        "Daytona Beach",    "32114", 29.2105, -81.0170),
    ("Oceanfront Suites",     "250 N Atlantic Ave",    "Daytona Beach",    "32118", 29.2296, -81.0069),
]
FREQ = ["Weekly" if i % 2 == 0 else "Biweekly" for i in range(len(CUSTOMERS))]    # 8 weekly, 7 biweekly
SLOT = [i % 5 for i in range(len(CUSTOMERS))]                                        # 3 per weekday
PRICE = [95, 180, 140, 120, 160, 110, 90, 220, 110, 200, 175, 250, 130, 115, 240]
DAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
BASE = dt.date.fromisoformat(SANDBOX_DATE)
TODAY = BASE.isoformat()


def workday(week: int, slot: int) -> str:
    """The slot-th weekday (0-4) on or after SANDBOX_DATE + 7*week — the same
    slot is always the same weekday, so Weekly jobs land 7 days apart and
    Biweekly 14."""
    d, n = BASE + dt.timedelta(days=7 * week), -1
    while True:
        if d.weekday() < 5:
            n += 1
            if n == slot:
                return d.isoformat()
        d += dt.timedelta(days=1)


def _ago(days: int) -> str:
    return (BASE - dt.timedelta(days=days)).isoformat()


def _refused(text) -> bool:
    return str(text).lstrip().startswith(("❌", "⛔"))


def _new_id(out, key):
    return str(out).split(f"{key}=")[1].splitlines()[0].strip()


def _ztest_jobs(api) -> list[dict]:
    return [j for j in api.read("Jobs_Schedule") if j.get("Customer Name / Company", "").startswith(ZTEST_PREFIX)]


def _customer(api, full, street, city, zp, lat, lon, **extra) -> str:
    fields = {"Company Name": full, "Customer Type Comm/Res": "Commercial", "Street Address": street,
              "City": city, "State": "FL", "ZIP": zp, "Latitude (AI Geocode)": lat,
              "Longitude (AI Geocode)": lon, "Service Type(s) Win/Press/Both": "Win",
              "Status Active/Inactive": "Active"}
    fields.update(extra)
    return _new_id(api.call("create_customer", {"updates": fields}), "NEW_CUST_ID")


def _job(api, cid, full, day, street, city, zp, lat, lon, **extra) -> str:
    fields = {"CustomerID": cid, "Customer Name / Company": full, "Service Date": day,
              "Street Address": street, "City": city, "State": "FL", "ZIP": zp,
              "Latitude (AI Geocode)": lat, "Longitude (AI Geocode)": lon,
              "Service Type": "Window", "Job Status": "Scheduled", "Crew / Technician": DAVID,
              "Schedule Type (Hard/Soft)": "Soft", "Est. Duration": 60, "Est. Duration Unit": "min"}
    fields.update(extra)
    return _new_id(api.call("create_job", {"updates": fields}), "NEW_JOB_ID")


# ── the schedule (created once for the module, swept before and after) ────────
@pytest.fixture(scope="module")
def schedule(data, api):
    data.sweep("6-week schedule start")
    cust, jobs = {}, []
    for i, (name, street, city, zp, lat, lon) in enumerate(CUSTOMERS):
        full = f"{ZTEST_PREFIX} {name}"
        cid = _customer(api, full, street, city, zp, lat, lon, **{
            "Frequency": FREQ[i], "Preferred Day(s)": DAY_NAMES[dt.date.fromisoformat(workday(0, SLOT[i])).weekday()],
            "Avg Job Duration (min)": 60, "Standard Quote ($)": PRICE[i]})
        cust[full] = cid
        weeks = range(WEEKS) if FREQ[i] == "Weekly" else range(0, WEEKS, 2)
        start = TIMES[i // 5]
        for w in weeks:
            day = workday(w, SLOT[i])
            jid = _job(api, cid, full, day, street, city, zp, lat, lon, **{
                "Start Time": start, "Quote Amount ($)": PRICE[i]})
            jobs.append({"id": jid, "customer": full, "cid": cid, "date": day, "freq": FREQ[i],
                         "week": w, "start": start, "street": street})
    log.info(f"[PSCHED] created {len(cust)} customers, {len(jobs)} jobs "
             f"({workday(0, 0)} .. {max(j['date'] for j in jobs)})")
    yield {"customers": cust, "jobs": jobs}
    data.sweep("6-week schedule end")


def _in_window_days(schedule) -> list[str]:
    return sorted({j["date"] for j in schedule["jobs"] if j["date"] in SANDBOX_DATES})


# ── PSCHED-01: David's 6-week schedule is exactly as planned ──────────────────
def test_PSCHED_01_owner_builds_six_week_schedule(schedule, api):
    rows = {j["JobID (JOB-####)"]: j for j in _ztest_jobs(api)}
    assert len(schedule["customers"]) == 15
    assert len(schedule["jobs"]) == 8 * WEEKS + 7 * (WEEKS // 2) == 69
    for j in schedule["jobs"]:
        r = rows.get(j["id"])
        assert r, f"{j['id']} ({j['customer']}) is missing"
        assert iso_date(r.get("Service Date", "")) == j["date"], f"{j['id']} date {r.get('Service Date')} != {j['date']}"
        assert r.get("Service Type", "").lower().startswith("window"), f"{j['id']} service {r.get('Service Type')!r}"
        assert r.get("Crew / Technician") == DAVID, f"{j['id']} crew {r.get('Crew / Technician')!r}"
    # repeat pattern: Weekly = every 7 days ×6, Biweekly = every 14 days ×3, always the same weekday
    by_cust = {}
    for j in schedule["jobs"]:
        by_cust.setdefault(j["customer"], []).append(dt.date.fromisoformat(j["date"]))
    for i, (name, *_r) in enumerate(CUSTOMERS):
        dates = sorted(by_cust[f"{ZTEST_PREFIX} {name}"])
        gaps = {(b - a).days for a, b in zip(dates, dates[1:])}
        assert (len(dates), gaps) == ((6, {7}) if FREQ[i] == "Weekly" else (3, {14})), f"{name} ({FREQ[i]}): {dates}"
        assert len({d.weekday() for d in dates}) == 1 and dates[0].weekday() < 5, f"{name} not on one weekday: {dates}"
    # never more than 3 jobs on a day; no weekend work
    per_day = {}
    for j in schedule["jobs"]:
        per_day[j["date"]] = per_day.get(j["date"], 0) + 1
    assert max(per_day.values()) <= 3 and all(dt.date.fromisoformat(d).weekday() < 5 for d in per_day)
    # customers: frequency, real NSB / Daytona address, no contact details (nothing can be sent)
    seen = 0
    for c in api.read("Customers"):
        if c.get("Company Name") in schedule["customers"]:
            seen += 1
            assert c.get("Frequency") in ("Weekly", "Biweekly")
            assert c.get("City") in ("New Smyrna Beach", "Daytona Beach") and c.get("Street Address")
            assert not c.get("Email") and not c.get("Phone"), "schedule customers must have no contact details"
    assert seen == 15
    assert sum(1 for c in CUSTOMERS if c[2] == "New Smyrna Beach") == 8
    assert sum(1 for c in CUSTOMERS if c[2] == "Daytona Beach") == 7


# ── PSCHED-02: the next 2 weeks on the Calendar (visible in --human) ─────────
def test_PSCHED_02_calendar_shows_the_next_two_weeks(schedule, app, page):
    app.goto("calendar")
    expect(page.locator("#calendarContent .cal-week-row")).to_have_count(14, timeout=30_000)
    rows = page.locator("#calendarContent .cal-week-row")
    shown = 0
    for offset in range(14):
        day = (BASE + dt.timedelta(days=offset)).isoformat()
        for j in (j for j in schedule["jobs"] if j["date"] == day):
            expect(rows.nth(offset).locator(f".cal-job-chip[onclick*=\"'{j['id']}'\"]")).to_have_count(1)
            shown += 1
    app.log(f"Calendar: all {shown} schedule jobs in the next 14 days are on their day")
    assert shown >= 20, f"expected ~23 jobs in the next two weeks, saw {shown}"


# ── PSCHED-03: work day 1 — clock in/out, complete, note ─────────────────────
def test_PSCHED_03_owner_works_day_one(schedule, api):
    todays = [j for j in schedule["jobs"] if j["date"] == TODAY]
    if not todays:
        pytest.skip(f"no schedule work on {TODAY} (a weekend?)")
    for j in todays:
        start = api.call("log_time_entry", {"job_identifier": j["id"], "action": "start"}, expect_ok=False)
        assert not _refused(start), f"couldn't clock in on {j['id']}: {str(start)[:200]!r}"
        stop = api.call("log_time_entry", {"job_identifier": j["id"], "action": "stop"}, expect_ok=False)
        assert not _refused(stop), f"couldn't clock out on {j['id']}: {str(stop)[:200]!r}"
        done = api.call("update_job_spreadsheet", {
            "sheet_name": "Jobs_Schedule", "id_column": "JobID (JOB-####)", "job_identifier": j["id"],
            "updates": {"Job Status": "Complete", "Service Details / Notes": "all windows done, screens wiped"}},
            expect_ok=False)
        assert not _refused(done), f"couldn't complete {j['id']}: {str(done)[:200]!r}"
    rows = {r["JobID (JOB-####)"]: r for r in _ztest_jobs(api)}
    for j in todays:
        assert rows[j["id"]].get("Job Status") == "Complete", f"{j['id']}: {rows[j['id']].get('Job Status')}"
    tl = [r for r in api.read("TimeLog") if any(j["id"] in r.values() for j in todays)]
    assert len(tl) >= len(todays), f"expected a time entry per job, got {len(tl)}"
    for j in todays:
        j["completed"] = True


# ── PSCHED-04: route every in-window workday (one route per day) ─────────────
def test_PSCHED_04_owner_routes_each_workday(schedule, api):
    days = _in_window_days(schedule)
    assert len(days) >= 5, f"too few schedule days inside the sandbox window: {days}"
    ids = {j["id"] for j in schedule["jobs"]}
    for day in days:
        want = {j["id"] for j in schedule["jobs"] if j["date"] == day}
        out = api.call("build_daily_route", {"route_date": day, "email_link": False, "accept_reorder": True},
                       expect_ok=False)
        log.info(f"[PSCHED-04] {day} -> {str(out).splitlines()[0][:140]}")
        assert not _refused(out), f"couldn't route {day}: {str(out)[:200]!r}"
        got = {s.get("JobID (JOB-####)", "") for s in api.read("Route_Planner")
               if iso_date(s.get("Route Date", "")) == day and s.get("JobID (JOB-####)")}
        assert want <= got, f"route on {day} is missing {want - got}"
        extra = {g for g in got if g not in ids}
        assert not extra, f"route on {day} has jobs that aren't in the schedule: {extra}"


# ── PSCHED-05: the Jobs screen and the Route tab (visible in --human) ────────
def test_PSCHED_05_jobs_and_route_screens(schedule, app, page, api):
    # This harness runs browser tests before API-only ones, so PSCHED-04 may not
    # have routed yet — build this test's own day (same call PSCHED-04 makes).
    day = _in_window_days(schedule)[1]
    out = api.call("build_daily_route", {"route_date": day, "email_link": False, "accept_reorder": True},
                   expect_ok=False)
    assert not _refused(out), f"couldn't route {day}: {str(out)[:200]!r}"
    app.goto("jobs")
    page.evaluate("async () => { await loadJobs(); }")
    page.wait_for_timeout(1000)
    shown = set(page.evaluate("() => (state.jobs || []).map(j => String(j.id))"))
    mine = {j["id"] for j in schedule["jobs"]}
    app.log(f"Jobs screen shows {len(shown & mine)} of the schedule's jobs")
    assert shown & mine, "the Jobs screen shows none of the schedule"
    # the route built for the 2nd workday is on the Route tab, with exactly that day's 3 stops
    from app import RouteScreen
    want = sorted(j["id"] for j in schedule["jobs"] if j["date"] == day)
    app.goto("route")
    rs = RouteScreen(page, app.log).pick_date(day)
    rs.expect_stops_include(want)
    app.log(f"Route tab {day}: stops {want}")


# ── PSCHED-06/07: Settings → "Email Route On Build" (R-059, David 2026-09-29) ──
# A test gap until today: the pre-flight used to stop the whole run when the
# setting was Enabled. Now the guard lets every route build through but switches
# its automatic email off per call (email_route / email_link = False) — except
# the ONE real route email per run, in tier email/full, to David's own address.
# R-060: the tests set the toggle themselves (and it's put back afterwards).
ROUTE_EMAIL = "Email Route On Build"


def test_PSCHED_06_email_route_on_build_api(schedule, api, guard, toggles):
    toggles.set(ROUTE_EMAIL, "Enabled")
    from safety import ROUTE_EMAILED_MARK
    days = _in_window_days(schedule)
    day = days[-1]
    # 1) this call opts out itself — the server must NOT email, in any tier
    out = api.call("suggest_route_schedule", {"route_date": day, "email_route": False}, expect_ok=False)
    assert not _refused(out), f"Route Today on {day} failed: {str(out)[:200]!r}"
    assert ROUTE_EMAILED_MARK not in out, f"email_route=False still emailed the route: {out[-300:]!r}"
    # 2) a plain call (follows the setting) — the guard decides
    before = guard.real_route_emails
    out = api.call("suggest_route_schedule", {"route_date": day}, expect_ok=False)
    assert not _refused(out), f"Route Today on {day} failed: {str(out)[:200]!r}"
    if guard.real_route_emails > before:           # the ONE real route email (tier email/full)
        assert f"{ROUTE_EMAILED_MARK} {guard.route_email_to}" in out, \
            f"expected the route emailed to {guard.route_email_to}: {out[-300:]!r}"
        log.info(f"[PSCHED-06] REAL route email sent to {guard.route_email_to} for {day}")
    else:
        assert ROUTE_EMAILED_MARK not in out, f"guard switched the email off but it went out: {out[-300:]!r}"
        log.info(f"[PSCHED-06] auto route email switched off by the guard (tier {guard.tier}) for {day}")
    assert guard.route_emails_seen == guard.real_route_emails, "a route email went out that the guard didn't allow"


def test_PSCHED_07_route_today_button_with_email_on(schedule, app, page, api, guard, toggles):
    toggles.set(ROUTE_EMAIL, "Enabled")
    from app import RouteScreen
    day = _in_window_days(schedule)[0]
    want = sorted(j["id"] for j in schedule["jobs"] if j["date"] == day)
    before = guard.route_emails_suppressed + guard.real_route_emails
    app.goto("route")
    rs = RouteScreen(page, app.log).pick_date(day)
    rs.press_route_selected_date()
    rs.wait_quiet()
    assert guard.route_emails_suppressed + guard.real_route_emails > before, \
        "the Route button's build never reached the guard's route-email check"
    rs.expect_stops_include(want)
    assert guard.route_emails_seen == guard.real_route_emails, "a route email went out that the guard didn't allow"
    app.log(f"Route button on {day}: {len(want)} stops, auto-email handled by the guard")


def test_PSCHED_08_email_route_off_sends_nothing(schedule, api, guard, toggles):
    """With the setting Disabled the guard leaves the build alone (no switch
    rewritten) — the SERVER itself must then send no route email."""
    toggles.set(ROUTE_EMAIL, "Disabled")
    from safety import ROUTE_EMAILED_MARK
    assert not guard.route_email_on
    day = _in_window_days(schedule)[-2]
    before = guard.route_emails_suppressed
    out = api.call("suggest_route_schedule", {"route_date": day}, expect_ok=False)
    assert not _refused(out), f"Route Today on {day} failed: {str(out)[:200]!r}"
    assert guard.route_emails_suppressed == before, "the guard rewrote a build although the setting is off"
    assert ROUTE_EMAILED_MARK not in out, f"setting Disabled but the route was emailed: {out[-300:]!r}"
    assert guard.route_emails_seen == guard.real_route_emails


# ── customer reminders ───────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def reminders(schedule, api, guard):
    """Four customers whose service history makes them (not) due for a check-in.
    Only 'Reminder To David' gets an email address — David's own, from
    AIPROWLER_E2E_COMMS_TO. Whether a reminder to it is really sent is the
    guard's call: recorded (not sent) in tier safe, exactly one real email in
    tier email/full."""
    street, city, zp, lat, lon = CUSTOMERS[0][1:]
    targets = sorted(t for t in guard._comms_targets() if "@" in t)
    david_email = next((t for t in targets if "david" in t), "") or (targets[0] if targets else "")
    made = {}
    for key, name, last_done, extra in [
        ("lapsed",   "Lapsed Customer",   90,  {}),
        ("recent",   "Recent Customer",   10,  {}),
        ("inactive", "Inactive Customer", 120, {"Status Active/Inactive": "Inactive"}),
        ("david",    "Reminder To David", 75,  {"First Name": "David", **({"Email": david_email} if david_email else {})}),
    ]:
        full = f"{ZTEST_PREFIX} {name}"
        cid = _customer(api, full, street, city, zp, lat, lon, **extra)
        _job(api, cid, full, _ago(last_done), street, city, zp, lat, lon, **{"Job Status": "Complete"})
        made[key] = cid
    made["david_email"] = david_email
    log.info(f"[REM] customers {made}")
    return made


def _stale(api, days) -> dict:
    out = api.call("find_stale_customers", {"days_threshold": days})
    rows = {}
    for ln in str(out).splitlines()[1:]:
        m = re.match(r"^\s*•\s*(\S+)\s*—\s*(.+?)\s*—\s*last serviced\s*(.+?)\s*—\s*(.+)$", ln)
        if m:
            rows[m.group(1)] = {"name": m.group(2), "when": m.group(3), "contact": m.group(4)}
    return rows


# ── REM-01: who is due — lapsed yes, recent no, inactive never ───────────────
def test_REM_01_find_stale_customers(schedule, reminders, api):
    due = _stale(api, 60)
    assert reminders["lapsed"] in due and due[reminders["lapsed"]]["when"] == "90 days ago", due.get(reminders["lapsed"])
    assert reminders["david"] in due and due[reminders["david"]]["when"] == "75 days ago"
    assert reminders["recent"] not in due, "serviced 10 days ago is not due at 60 days"
    assert reminders["inactive"] not in due, "an Inactive customer must never be listed"
    # day-1 schedule customers were just serviced; the rest were never serviced
    done_today = {j["cid"] for j in schedule["jobs"] if j.get("completed")}
    for cid in done_today:
        assert cid not in due, f"{cid} was serviced today but is listed as due"
    for cid in set(schedule["customers"].values()) - done_today:
        assert cid in due and due[cid]["when"] == "never serviced", f"{cid}: {due.get(cid)}"
        assert due[cid]["contact"] == "no contact on file"
    # most-overdue first: lapsed (90) before David (75)
    order = [c for c in due if c in (reminders["lapsed"], reminders["david"])]
    assert order == [reminders["lapsed"], reminders["david"]], order


# ── REM-02: the threshold is a real boundary ────────────────────────────────
def test_REM_02_threshold_boundary(reminders, api):
    assert reminders["recent"] in _stale(api, 10), "10 days since service must be due at a 10-day threshold"
    assert reminders["recent"] not in _stale(api, 11)
    assert reminders["lapsed"] in _stale(api, 90) and reminders["lapsed"] not in _stale(api, 91)
    assert reminders["inactive"] not in _stale(api, 0)


# ── REM-03: Reports → Customer Reminders — no email on file is skipped ───────
def _find_in_app(app, page, days: int):
    app.goto("reports")
    box = page.locator("#staleCustomerDays")
    expect(box).to_be_visible(timeout=30_000)
    box.fill(str(days))
    app.step(f"REPORTS Customer Reminders: not serviced in {days}+ days → 🔍 Find Customers")
    page.locator("#screen-reports").get_by_role("button", name=re.compile("Find Customers")).click()
    res = page.locator("#staleCustomersResult")
    expect(res.locator(".stale-cust-check").first).to_be_attached(timeout=30_000)
    return res


def _email_button(app, res):
    """The ✉️ Email Selected button. If 'Customer Reminder Email Enabled' is off
    the app shows a grayed-out '✉️ Email Disabled' instead — that is a setting,
    not a bug, so the test says so and skips (it never changes Settings)."""
    btn = res.locator("button[onclick*=\"sendStaleCustomerReminders('email')\"]")
    if btn.count() == 0:
        buttons = [b.inner_text().strip() for b in res.locator("button").all()]
        app.log(f"reminder buttons shown: {buttons}")
        if any("Email Disabled" in b for b in buttons):
            pytest.skip("Settings → 'Customer Reminder Email Enabled' is Disabled on this database — "
                        "turn it on to test sending reminders")
        raise AssertionError(f"no Email Selected button; buttons shown: {buttons}")
    return btn


def _tick_only(page, cid: str):
    """Untick every row, then tick the row for `cid` (rows are matched by index)."""
    idx = page.evaluate(f"() => (window._staleCustomerRows || []).findIndex(r => r.id === '{cid}')")
    assert idx >= 0, f"{cid} is not in the reminder list"
    page.evaluate("() => document.querySelectorAll('.stale-cust-check').forEach(c => { c.checked = false; })")
    page.locator(f".stale-cust-check[data-idx='{idx}']").check()


REM_EMAIL, REM_SMS = "Customer Reminder Email Enabled", "Customer Reminder SMS Enabled"


def test_REM_03_reminder_to_customer_without_email_is_skipped(reminders, app, page, toggles):
    toggles.set(REM_EMAIL, "Enabled")                 # R-060: put back after the test
    res = _find_in_app(app, page, 60)
    expect(res).to_contain_text(f"{ZTEST_PREFIX} Lapsed Customer")
    expect(res).not_to_contain_text(f"{ZTEST_PREFIX} Recent Customer")
    expect(res).not_to_contain_text(f"{ZTEST_PREFIX} Inactive Customer")
    btn = _email_button(app, res)
    _tick_only(page, reminders["lapsed"])
    app.step("REPORTS tick only 'Lapsed Customer' → ✉️ Email Selected")
    btn.click()
    status = page.locator("#staleCustomersSendStatus")
    expect(status).not_to_contain_text("Sending…", timeout=30_000)
    # the guard let this through (nothing can be sent); the SERVER answers
    expect(status).to_contain_text("Reminder emailed to 0 customer(s)")
    expect(status).to_contain_text("no email on file")
    app.log(f"REM-03 server reply: {status.inner_text()[:200]!r}")


# ── REM-04: a custom reminder to David (real only in tier email/full) ────────
def test_REM_04_custom_reminder_to_david(reminders, app, page, guard, toggles):
    if not reminders["david_email"]:
        pytest.skip("no email address in AIPROWLER_E2E_COMMS_TO — nowhere safe to aim a reminder")
    toggles.set(REM_EMAIL, "Enabled")                 # R-060: put back after the test
    res = _find_in_app(app, page, 60)
    expect(res).to_contain_text(f"{ZTEST_PREFIX} Reminder To David")
    btn = _email_button(app, res)
    _tick_only(page, reminders["david"])
    msg = "ZTEST E2E reminder test — Hi {name}, your last window cleaning was {date}. Want us back this week?"
    page.locator("#staleCustomerMessage").fill(msg)
    app.step("REPORTS tick only 'Reminder To David', custom message → ✉️ Email Selected")
    btn.click()
    status = page.locator("#staleCustomersSendStatus")
    expect(status).not_to_contain_text("Sending…", timeout=60_000)
    text = status.inner_text()
    app.log(f"REM-04 reply: {text[:240]!r}")
    if guard.tier in ("email", "full"):
        # the ONE real reminder of this run, to David's own address
        assert "Reminder emailed to 1 customer(s)" in text, text
        assert guard.real_reminders_sent == 1
    else:
        # safe tier: recorded, not sent — the app still shows a success-shaped reply
        assert "not sent" in text, text
        calls = guard.recorded_calls("send_customer_reminders")
        assert calls, "the reminder call wasn't recorded"
        a = calls[-1]["args"]
        assert a.get("customer_ids") == reminders["david"] and a.get("channel") == "email"
        assert a.get("message") == msg, "the custom message ({name}/{date} placeholders) didn't reach the server call"


# ── REM-05/06: the Email / SMS reminder switches really switch (R-060) ───────
def _reminder_buttons(app, page) -> list[str]:
    res = _find_in_app(app, page, 60)
    names = [b.inner_text().strip() for b in res.locator("button").all()]
    app.log(f"reminder buttons shown: {names}")
    return names


@pytest.mark.parametrize("key,channel,on_label,off_label", [
    (REM_EMAIL, "email", "Email Selected", "Email Disabled"),
    (REM_SMS, "sms", "Text Selected", "Text Disabled"),
], ids=["email", "sms"])
def test_REM_05_reminder_switch_on_and_off(reminders, app, page, api, toggles, key, channel, on_label, off_label):
    """Turned off: the app shows the grayed-out '… Disabled' button AND the
    server refuses the send. Turned on: the real button is back. The send used
    here is to the 'Lapsed Customer', who has no email or phone on file — so
    even the 'on' state can't reach anyone."""
    toggles.set(key, "Disabled")
    names = _reminder_buttons(app, page)
    assert any(off_label in n for n in names), f"{key} Disabled but buttons are {names}"
    assert not any(on_label in n for n in names)
    off_btn = page.locator("#staleCustomersResult button", has_text=off_label)
    assert off_btn.is_disabled(), f"'{off_label}' is clickable"
    out = api.call("send_customer_reminders", {"customer_ids": reminders["lapsed"], "channel": channel},
                   expect_ok=False)
    app.log(f"{key}=Disabled, server reply: {str(out)[:200]!r}")
    assert _refused(out) or "disabled" in str(out).lower(), f"{key} is Disabled but the send wasn't refused: {out!r}"
    toggles.set(key, "Enabled")
    names = _reminder_buttons(app, page)
    assert any(on_label in n for n in names), f"{key} Enabled but buttons are {names}"
    assert not any(off_label in n for n in names)
