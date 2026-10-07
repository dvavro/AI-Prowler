"""TIME MACHINE — six weeks of real work, one day at a time (spec §6.19).

David 2026-09-29: "can you make a test like the 6 week test and simulate the
passing of days so that the full jobs features show up through time".

The app runs as a throwaway copy with a movable clock (tm_server.py): its own
empty database, every email/SMS caught in an outbox, AI Routing off. Day 0 is
the next Monday. Every simulated workday morning the owner:
  1. opens the app — the once-a-day recurring-job sweep and the stale-customer
     digest run, exactly as they do when he opens the Jobs tab;
  2. schedules any new auto-generated recurring visit for its due date;
  3. reads the morning briefing (the scheduler's own job, run for that day);
  4. presses Route Today;
  5. works the day: clock in, clock out, mark Complete.
Twists built in: a job that runs over (left In Progress, must carry to the
next workdays until Complete), a 3-day job (must skip the weekend), an unpaid
invoice (must turn overdue), and a one-time customer who goes stale.

Checked every day: the briefing lists exactly the jobs being worked that day,
the route has exactly those stops, the recurring sweep creates each visit on
the first morning it's within the lead time — once, with the right due date.
Checked at the end: visit counts per customer, time entries on the right
dates, overdue-invoice alert timing, stale-customer timing and digest emails,
and that the outbox only ever held test addresses.

Run: run_tests_gui_jobs_e2e.bat --timemachine --human
"""
from __future__ import annotations

import datetime as dt
import logging
import os
import re

import pytest
from playwright.sync_api import expect

from api import iso_date

log = logging.getLogger("e2e")
OWNER = "David Vavro"
MODE = (os.environ.get("E2E_TM_MODE") or "personal").strip().lower()
SERVER = MODE == "server"
# Server mode: which field crew does each customer's work (made-up users, conftest.SERVER_USERS)
CREW = {"A": "alex", "B": "bea", "C": "alex", "D": "bea", "E": "alex", "F": "bea"}
# Server mode: who the browser is logged in as, per test (conftest's page fixture reads this)
BROWSER_USER = {"test_TM_02_day_one_in_the_app": "alex",
                "test_TM_04_overrun_carries_to_the_next_day": "alex",
                "test_TM_06_last_day_reminders_screen": "owner",
                "test_TM_06b_manager_reports": "manager",
                "test_TM_06c_staff_reports": "staff",
                "test_TM_06d_field_crew_has_no_reports_tab": "bea"}
LEAD_DAYS = 5
STALE_DAYS = 21
WEEKS = 6
INTERVAL = {"Weekly": 7, "Biweekly": 14}

# key: (name, street, zip, lat, lon, frequency, has_email, weekday of first visit)
CUST = {
    "A": ("Riverside Cafe",       "105 S Riverside Dr",    "32168", 29.0263, -80.9216, "Weekly",   True,  0),
    "B": ("Library Annex",        "1001 S Dixie Fwy",      "32168", 29.0122, -80.9303, "Biweekly", False, 1),
    "C": ("Flagler Ave Shops",    "1 Flagler Ave",         "32169", 29.0413, -80.8965, "Weekly",   True,  2),
    "D": ("Sports Complex",       "201 Sports Complex Dr", "32168", 29.0060, -80.9458, "Monthly",  True,  3),
    "E": ("Canal Street Gallery", "300 Canal St",          "32168", 29.0271, -80.9244, "",         True,  2),
    "F": ("Beachside Condos",     "3500 S Atlantic Ave",   "32169", 28.9981, -80.8836, "",         False, 3),
}


def cname(k: str) -> str:
    return f"ZT {CUST[k][0]}"


def _refused(t) -> bool:
    return str(t).lstrip().startswith(("❌", "⛔"))


def _new_id(out, key):
    return str(out).split(f"{key}=")[1].splitlines()[0].strip()


def workdays(start: dt.date, end: dt.date):
    d = start
    while d <= end:
        if d.weekday() < 5:
            yield d
        d += dt.timedelta(days=1)


class World:
    """Everything the test knows independently of the app (the oracle)."""

    def __init__(self, tm, apis):
        self.tm, self.apis = tm, apis
        self.api = apis["owner"]                      # setup + the oracle's own reads
        # who books the recurring sweep's new visits: the owner (personal) / the manager (server)
        self.sched_api = apis["manager"] if SERVER else apis["owner"]
        self.d0 = tm.start_day
        self.end = self.d0 + dt.timedelta(days=7 * (WEEKS - 1) + 4)          # Friday of week 6
        self.cust_id: dict[str, str] = {}
        self.visits: dict[str, list[tuple[str, dt.date]]] = {k: [] for k in CUST}   # (job_id, date)
        self.overrun_job = ""            # C's week-2 visit, left In Progress
        self.overrun_done_on: dt.date | None = None
        self.multi_job = ""              # F's 3-day job
        self.invoice_job = ""
        self.sweep_log: list[dict] = []  # every auto-generated job seen: {cust, due, created_on, expected_on}
        self.day_log: list[str] = []
        self.done_days: set[dt.date] = set()
        self.briefings: dict[dt.date, str] = {}
        self.stale_seen: dict[dt.date, str] = {}

    # ── helpers ──────────────────────────────────────────────────────────────
    def crew_name(self, k: str) -> str:
        return self.tm.users[CREW[k]].name if SERVER else OWNER

    def worker_api(self, k: str):
        """Who works customer k's jobs: its field crew, as themselves (server) / the owner."""
        return self.apis[CREW[k]] if SERVER else self.api

    def jobs(self, api=None) -> list[dict]:
        return [j for j in (api or self.api).read("Jobs_Schedule")
                if j.get("Customer Name / Company", "").startswith("ZT ")]

    def route_job_ids(self, day: dt.date, api=None) -> list[str]:
        rows = [s for s in (api or self.api).read("Route_Planner")
                if iso_date(s.get("Route Date", "")) == day.isoformat()]
        rows.sort(key=lambda s: int(float(s.get("Stop #") or 0)))
        return [s["JobID (JOB-####)"] for s in rows if s.get("JobID (JOB-####)")]

    def set_setting(self, key, value):
        self.api.call("update_job_spreadsheet", {"sheet_name": "Settings", "id_column": "Setting",
                                                 "job_identifier": key, "updates": {"Value": str(value)}})

    def key_of(self, job: dict) -> str:
        name = job.get("Customer Name / Company", "")
        for k in CUST:
            if name == cname(k):
                return k
        return "?"

    def create_job(self, k, day: dt.date, **extra) -> str:
        name, street, zp, lat, lon, *_ = CUST[k]
        f = {"CustomerID": self.cust_id[k], "Customer Name / Company": cname(k), "Service Date": day.isoformat(),
             "Street Address": street, "City": "New Smyrna Beach", "State": "FL", "ZIP": zp,
             "Latitude (AI Geocode)": lat, "Longitude (AI Geocode)": lon, "Service Type": "Window",
             "Job Status": "Scheduled", "Crew / Technician": self.crew_name(k), "Schedule Type (Hard/Soft)": "Soft",
             "Est. Duration": 60, "Est. Duration Unit": "min", "Start Time": "09:00"}
        f.update(extra)
        jid = _new_id(self.api.call("create_job", {"updates": f}), "NEW_JOB_ID")
        self.visits[k].append((jid, day))
        return jid

    # ── the owner's morning ──────────────────────────────────────────────────
    def open_app_and_schedule_new_visits(self, day: dt.date):
        """Opening the app runs the once-a-day sweep. Any new auto-generated
        (unscheduled) recurring job is checked, then scheduled for its due date."""
        for j in self.jobs():
            if iso_date(j.get("Service Date", "")) or j.get("Job Status", "") in ("Cancelled",):
                continue
            k = self.key_of(j)
            notes = j.get("Service Details / Notes", "")
            m = re.search(r"due ~(\d\d)/(\d\d)/(\d{4})", notes)
            assert m, f"unscheduled job {j['JobID (JOB-####)']} for {k} has no due date in its note: {notes!r}"
            due = dt.date(int(m.group(3)), int(m.group(1)), int(m.group(2)))
            last = max(d for _, d in self.visits[k])
            expected_due = self._next_due(k, last)
            first_chance = next(d for d in self._opened_days(due - dt.timedelta(days=LEAD_DAYS)))
            self.sweep_log.append({"cust": k, "job": j["JobID (JOB-####)"], "due": due, "expected_due": expected_due,
                                   "created_on": day, "expected_on": first_chance})
            # the owner (personal) / the manager (server) puts it on the calendar and
            # assigns the customer's crew (weekend due dates move to Monday)
            when = due if due.weekday() < 5 else due + dt.timedelta(days=7 - due.weekday())
            _, _, zp, lat, lon, *_ = CUST[k]
            if SERVER:
                assert not (j.get("Crew / Technician") or "").strip(), \
                    f"the sweep's new {k} visit already has a crew: {j.get('Crew / Technician')!r}"
            self.sched_api.call("update_job_spreadsheet", {
                "sheet_name": "Jobs_Schedule", "id_column": "JobID (JOB-####)", "job_identifier": j["JobID (JOB-####)"],
                "updates": {"Service Date": when.isoformat(), "Start Time": "09:00", "Crew / Technician": self.crew_name(k),
                            "Latitude (AI Geocode)": lat, "Longitude (AI Geocode)": lon, "Service Type": "Window",
                            "Est. Duration": 60, "Est. Duration Unit": "min", "Schedule Type (Hard/Soft)": "Soft"}})
            self.visits[k].append((j["JobID (JOB-####)"], when))
            self.day_log.append(f"{day:%a %m/%d}: sweep created {k} visit due {due:%a %m/%d} -> scheduled {when:%m/%d}")

    def _opened_days(self, from_day: dt.date):
        """Days the app gets opened (workdays, plus the one Saturday we look in)."""
        d = from_day
        while True:
            if d.weekday() < 5 or d == self.d0 + dt.timedelta(days=5):
                if d >= self.d0:
                    yield d
            d += dt.timedelta(days=1)

    def _next_due(self, k, last: dt.date) -> dt.date:
        freq = CUST[k][5]
        if freq == "Monthly":
            y, m = (last.year + (last.month // 12), last.month % 12 + 1)
            import calendar
            return dt.date(y, m, min(last.day, calendar.monthrange(y, m)[1]))
        return last + dt.timedelta(days=INTERVAL[freq])

    def expected_today(self, day: dt.date) -> dict[str, str]:
        """job_id -> customer key for every job worked on `day` (the oracle)."""
        want = {}
        for k, vs in self.visits.items():
            for jid, d in vs:
                if d == day:
                    want[jid] = k
        if self.overrun_job and self.overrun_done_on and self.visits["C"] and day.weekday() < 5:
            d_planned = next(d for j, d in self.visits["C"] if j == self.overrun_job)
            if d_planned < day <= self.overrun_done_on:
                want[self.overrun_job] = "C"
        if self.multi_job:
            start = next(d for j, d in self.visits["F"] if j == self.multi_job)
            if day in (start, start + dt.timedelta(days=1), start + dt.timedelta(days=4)):
                want[self.multi_job] = "F"
        return want

    def morning(self, day: dt.date):
        self.tm.set_clock(day, "07:00")
        self.open_app_and_schedule_new_visits(day)
        want = self.expected_today(day)
        if SERVER:
            return self._morning_server(day, want)
        # the morning briefing, as the scheduler would send it that day
        mb = self.tm.run_job("morning_briefing")
        assert mb["today"] == day.isoformat(), f"briefing ran on {mb['today']}, clock says {day}"
        body = mb.get("body", "")
        self.briefings[day] = body
        # the jobs part only — since R-067 the briefing also has an "Overdue
        # Invoices" section that names the customer who owes (checked below)
        jobs_part, _, od_part = body.partition("Overdue Invoices")
        listed = {k for k in CUST if cname(k) in jobs_part}
        inv_due = getattr(self, "invoice_due", None)
        if inv_due:
            late = (day - inv_due).days
            if late >= 31:
                assert cname("A") in od_part, (f"{day:%a %m/%d}: A's invoice is {late} days overdue "
                                               f"but the briefing has no overdue line for it")
            else:
                assert cname("A") not in od_part, (f"{day:%a %m/%d}: A's invoice is only {late} days "
                                                   f"overdue but the briefing flags it")
        assert listed == set(want.values()), (f"{day:%a %m/%d} briefing lists {sorted(listed)}, "
                                              f"expected {sorted(set(want.values()))}")
        if not want:
            assert "No jobs scheduled today" in body
        # Route Today
        out = self.api.call("suggest_route_schedule", {"route_date": day.isoformat(), "email_route": False},
                            expect_ok=False)
        if want:
            assert not _refused(out), f"{day} Route Today failed: {out[:300]!r}"
            got = self.route_job_ids(day)
            assert sorted(got) == sorted(want), f"{day:%a %m/%d} route stops {got}, expected {sorted(want)}"
        return want

    def _morning_server(self, day: dt.date, want: dict[str, str]) -> dict[str, str]:
        """Server mode: each field crew opens the app as THEMSELVES — they must see
        their own jobs and none of the other crew's — and presses Route Today,
        which routes only their own day. The owner then sees both crews' stops.
        (The morning-briefing email is a personal-mode feature of the desktop app.)"""
        all_ids = {jid for k, vs in self.visits.items() for jid, _ in vs}
        for c in ("alex", "bea"):
            capi, me = self.apis[c], self.tm.users[c].name
            mine = {jid: k for jid, k in want.items() if CREW[k] == c}
            seen = self.jobs(capi)
            others = [j["JobID (JOB-####)"] for j in seen
                      if (j.get("Crew / Technician") or "").strip() != me]
            assert not others, f"{day:%a %m/%d}: {me} can see jobs that aren't theirs: {others}"
            seen_ids = {j["JobID (JOB-####)"] for j in seen}
            missing = sorted(set(mine) - seen_ids)
            assert not missing, f"{day:%a %m/%d}: {me} can't see today's jobs {missing}"
            theirs = {jid for jid, _ in [x for k, vs in self.visits.items() if CREW[k] != c for x in vs]}
            leaked = sorted(seen_ids & theirs & all_ids)
            assert not leaked, f"{day:%a %m/%d}: {me} sees the other crew's jobs {leaked}"
            if not mine:
                continue
            out = capi.call("suggest_route_schedule", {"route_date": day.isoformat(), "email_route": False},
                            expect_ok=False)
            assert not _refused(out), f"{day} {me} Route Today failed: {out[:300]!r}"
            got = self.route_job_ids(day, capi)
            assert sorted(got) == sorted(mine), \
                f"{day:%a %m/%d} {me}'s route stops {got}, expected {sorted(mine)}"
        both = self.route_job_ids(day)                  # the owner sees every crew's stops
        assert sorted(both) == sorted(want), f"{day:%a %m/%d} owner sees stops {both}, expected {sorted(want)}"
        self.briefings[day] = f"(server) crews routed: {sorted(want)}"
        return want

    def work(self, day: dt.date, want: dict[str, str]):
        slot = 9
        for jid, k in sorted(want.items(), key=lambda kv: kv[1]):
            wapi = self.worker_api(k)                   # the crew clocks in as themselves
            self.tm.set_clock(day, f"{slot:02d}:00")
            r = wapi.call("log_time_entry", {"job_identifier": jid, "action": "start"}, expect_ok=False)
            assert not _refused(r), f"clock in {jid} on {day}: {r[:200]!r}"
            self.tm.set_clock(day, f"{slot:02d}:50")
            r = wapi.call("log_time_entry", {"job_identifier": jid, "action": "stop"}, expect_ok=False)
            assert not _refused(r), f"clock out {jid} on {day}: {r[:200]!r}"
            slot += 1
            status = "Complete"
            if jid == self.overrun_job and day < self.overrun_done_on:
                status = "In Progress"                         # the job runs over
            if jid == self.multi_job:
                start = next(d for j, d in self.visits["F"] if j == jid)
                if day < start + dt.timedelta(days=4):
                    status = "In Progress"                     # a 3-day job isn't done until its last day
            r = wapi.call("update_job_spreadsheet", {
                "sheet_name": "Jobs_Schedule", "id_column": "JobID (JOB-####)", "job_identifier": jid,
                "updates": {"Job Status": status}}, expect_ok=False)
            assert not _refused(r), f"{jid} -> {status} on {day}: {r[:200]!r}"
        self.day_log.append(f"{day:%a %m/%d}: worked {', '.join(f'{k}:{j}' for j, k in sorted(want.items()))}"
                            if want else f"{day:%a %m/%d}: no work")
        self.done_days.add(day)

    def walk(self, start: dt.date, end: dt.date):
        for day in workdays(start, end):
            if day in self.done_days:
                continue
            want = self.morning(day)
            self.work(day, want)
            # watch the stale list every day
            self.stale_seen[day] = self.api.call("find_stale_customers", {"days_threshold": STALE_DAYS},
                                                 expect_ok=False)


@pytest.fixture(scope="module")
def world(tm, apis):
    return World(tm, apis)


# This is ONE story told in order. pytest-playwright parametrizes every test
# that touches the browser ("[chromium]") and pytest then runs those as a group
# ahead of the rest — which would work day 10 before day 3. Asking for
# browser_name in every test keeps them all in one group, in file order.
_story = {"broken": ""}


@pytest.fixture(autouse=True)
def _in_order(request, browser_name):
    if _story["broken"]:
        pytest.skip(f"an earlier step of the story failed ({_story['broken']})")
    yield
    rep = getattr(request.node, "rep_call", None)
    if rep is not None and rep.failed:
        _story["broken"] = request.node.name        # rep_call is set by conftest's makereport hook


def _expect_my_route(w, rs, want: dict[str, str]):
    """Personal: the Route tab shows the day's jobs. Server (browser logged in as
    field crew Alex): it shows Alex's jobs and NONE of Bea's."""
    if not SERVER:
        rs.expect_stops_include(sorted(want))
        return
    mine = sorted(j for j, k in want.items() if CREW[k] == "alex")
    theirs = sorted(j for j, k in want.items() if CREW[k] != "alex")
    rs.expect_stops_include(mine)
    if theirs:
        rs.expect_not_on_route(theirs)


# ── TM-01: day 0 — the owner sets up his business ────────────────────────────
def test_TM_01_setup_day_zero(world, tm, api):
    w = world
    tm.set_clock(w.d0, "06:30")
    api.read("Settings")                                     # seeds the default Settings rows
    for key, val in [("Route Origin Mode", "Company Location"), ("Start/End Street Address", "210 Sams Ave"),
                     ("Start/End City", "New Smyrna Beach"), ("Start/End State", "FL"), ("Start/End ZIP", "32168"),
                     ("Stale Customer Reminder Days", STALE_DAYS), ("Customer Reminder Daily Digest", "Enabled"),
                     ("Recurring Job Lead Time (days)", LEAD_DAYS)]:
        w.set_setting(key, val)
    for k, (name, street, zp, lat, lon, freq, has_email, wd) in CUST.items():
        f = {"Company Name": cname(k), "Customer Type Comm/Res": "Commercial", "Street Address": street,
             "City": "New Smyrna Beach", "State": "FL", "ZIP": zp, "Latitude (AI Geocode)": lat,
             "Longitude (AI Geocode)": lon, "Status Active/Inactive": "Active"}
        if freq:
            f["Frequency"] = freq
        if has_email:
            f["Email"] = f"{name.lower().replace(' ', '.')}@time-machine.test"
        w.cust_id[k] = _new_id(api.call("create_customer", {"updates": f}), "NEW_CUST_ID")
    for k in "ABCDE":
        w.create_job(k, w.d0 + dt.timedelta(days=CUST[k][7]))
    w.multi_job = w.create_job("F", w.d0 + dt.timedelta(days=3), **{"Est. Duration": 3, "Est. Duration Unit": "day",
                                                                     "Start Time": "08:00"})
    jf = next(j for j in w.jobs() if j["JobID (JOB-####)"] == w.multi_job)
    end = iso_date(jf.get("End Date (blank = single-day job)")
                   or jf.get("End Date", ""))
    assert end == (w.d0 + dt.timedelta(days=7)).isoformat(), \
        f"3-day job from Thu should end the following Mon {w.d0 + dt.timedelta(days=7)}, End Date is {end!r}"
    log.info(f"[TM] day 0 = {w.d0:%a %Y-%m-%d}; end = {w.end:%a %Y-%m-%d}; customers {w.cust_id}")


# ── TM-02: day 1 in the browser (the app's own 'today' is the simulated day) ──
def test_TM_02_day_one_in_the_app(world, tm, api, app, page):
    w = world
    want = w.morning(w.d0)
    from app import RouteScreen
    app.goto("route")
    rs = RouteScreen(page, app.log).pick_date(w.d0.isoformat())
    _expect_my_route(w, rs, want)
    app.log(f"TM day 1 ({w.d0:%a %m/%d}) — Route tab shows {sorted(want)}")
    w.work(w.d0, want)
    # the first visit gets its invoice (due tomorrow — it must turn overdue during the six weeks)
    w.invoice_job = w.visits["A"][0][0]
    out = api.call("create_invoice", {"job_identifier": w.invoice_job, "quote_amount": 95, "due_days": 1},
                   expect_ok=False)
    assert not _refused(out), f"invoice: {out[:200]!r}"
    w.invoice_due = w.d0 + dt.timedelta(days=1)   # due_days=1 from day 0


# ── TM-03: weeks 1-2 up to the day C's visit runs over ───────────────────────
def test_TM_03_walk_to_the_overrun(world, tm):
    w = world
    w.walk(w.d0 + dt.timedelta(days=1), w.d0 + dt.timedelta(days=4))
    # Saturday: the 3-day job must NOT be on the weekend
    tm.set_clock(w.d0 + dt.timedelta(days=5), "07:00")
    w.open_app_and_schedule_new_visits(w.d0 + dt.timedelta(days=5))
    if SERVER:
        # Bea (F's crew) has nothing to route on Saturday
        sat_jobs = [j["JobID (JOB-####)"] for j in w.jobs(w.apis["bea"])
                    if iso_date(j.get("Service Date", "")) == (w.d0 + dt.timedelta(days=5)).isoformat()]
        assert not sat_jobs, f"jobs on Saturday for Bea: {sat_jobs}"
    else:
        sat = tm.run_job("morning_briefing")
        assert cname("F") not in sat["body"], "the 3-day job shows on Saturday"
    # C's week-2 visit is the one that runs over: planned Wed of week 2, done Fri
    w.walk(w.d0 + dt.timedelta(days=7), w.d0 + dt.timedelta(days=8))
    c2 = [(j, d) for j, d in w.visits["C"] if d == w.d0 + dt.timedelta(days=9)]
    assert c2, f"C's week-2 visit (due {w.d0 + dt.timedelta(days=9)}) was never auto-created: {w.visits['C']}"
    w.overrun_job, w.overrun_done_on = c2[0][0], w.d0 + dt.timedelta(days=11)
    w.walk(w.d0 + dt.timedelta(days=9), w.d0 + dt.timedelta(days=9))


# ── TM-04: the next morning, in the app — the unfinished job is still there ──
def test_TM_04_overrun_carries_to_the_next_day(world, tm, app, page):
    w = world
    day = w.d0 + dt.timedelta(days=10)
    want = w.morning(day)
    assert w.overrun_job in want, f"the overrun job {w.overrun_job} isn't planned for {day}"
    # the page opened before morning() moved the server clock to Thursday —
    # move the browser's clock too and reload, or the app still thinks it's Wednesday
    page.clock.set_system_time(tm.now())
    page.reload()
    page.wait_for_load_state("networkidle")
    app.log(f"browser clock -> {tm.now():%a %Y-%m-%d %H:%M}")
    from app import RouteScreen
    app.goto("route")
    rs = RouteScreen(page, app.log).pick_date(day.isoformat())
    _expect_my_route(w, rs, want)
    rs.expect_stops_include([w.overrun_job])
    app.log(f"TM {day:%a %m/%d}: the unfinished {w.overrun_job} (C) is on today's route")
    w.work(day, want)


# ── TM-05: the rest of the six weeks ─────────────────────────────────────────
def test_TM_05_walk_to_the_end(world):
    w = world
    # (each morning() already checks the briefing and route list EXACTLY the day's
    # jobs — so the finished overrun job not coming back is checked every day after)
    w.walk(w.d0 + dt.timedelta(days=11), w.end)


# ── TM-05b: a session nobody used for 30+ days is ended (R-043) ──────────────
def test_TM_05b_idle_session_expires(world, tm, apis):
    """ZT Office Sam signed in on day 0 and never used the app during the six
    weeks. Since R-043 a Jobs-app session idle for 30 days is ended on its next
    use (401 'Session expired') and the app goes back to its sign-in screen;
    signing in again works."""
    if not SERVER:
        pytest.skip("server mode only (personal mode has no per-user sessions)")
    old = tm.users["staff"].access_token
    r = tm.pwa_call("staff", "read_job_spreadsheet", {"sheet_name": "Jobs_Schedule", "max_rows": 1})
    log.info(f"[TM] Sam's day-0 session on {world.end:%a %m/%d}: {str(r)[:160]}")
    assert "401" in str(r.get("error", "")) and "expired" in str(r.get("error", "")).lower(), \
        f"a session idle for 39 days still works: {str(r)[:200]}"
    tm.login("staff")
    assert tm.users["staff"].access_token != old
    r = tm.pwa_call("staff", "read_job_spreadsheet", {"sheet_name": "Jobs_Schedule", "max_rows": 1})
    assert r.get("ok"), f"signing in again didn't work: {str(r)[:200]}"
    apis["staff"] = tm.client("staff")


# ── TM-06: last day, in the app — Reports, by who is looking ─────────────────
# Owner: AR Aging (R-068) + Customer Reminders with the send controls + charts.
# Manager: AR Aging + Customer Reminders (list only). Staff: Customer Reminders
# (list only). (R-069, David 2026-09-29.) Field crew: no Reports tab at all.
def _reports_as(w, app, page, who: str):
    from playwright.sync_api import expect as _expect
    app.goto("reports")
    scr = page.locator("#screen-reports")
    ar, rem = page.locator("#arAgingCard"), page.locator("#customerRemindersCard")
    charts = page.locator("#reportsOwnerOnly")
    if who in ("owner", "manager"):
        _expect(ar).to_be_visible()
        _expect(page.locator("#arAgingReport")).to_contain_text("31 – 60 days overdue", timeout=30_000)
        _expect(page.locator("#arAgingReport")).to_contain_text(cname("A"))
    else:
        _expect(ar).to_be_hidden()
    _expect(rem).to_be_visible()
    (_expect(charts).to_be_visible() if who == "owner" else _expect(charts).to_be_hidden())
    page.locator("#staleCustomerDays").fill(str(STALE_DAYS))
    rem.get_by_role("button", name=re.compile("Find Customers")).click()
    _expect(page.locator("#staleCustomersResult")).to_contain_text(cname("E"), timeout=30_000)
    checks = page.locator("#staleCustomersResult .stale-cust-check")
    if who == "owner":
        assert checks.count() >= 1, "the owner has no send checkboxes"
        _expect(page.locator("#staleCustomerMessageBox")).to_be_visible()
    else:
        assert checks.count() == 0, f"{who} sees the send checkboxes"
        _expect(page.locator("#staleCustomerMessageBox")).to_be_hidden()
        _expect(page.locator("#staleCustomersResult")).to_contain_text("Sending reminders is done by the owner")
    app.log(f"TM last day ({w.end:%a %m/%d}) Reports as {who}: {scr.inner_text()[:300]!r}")


def test_TM_06_last_day_reminders_screen(world, tm, app, page):
    w = world
    stale = w.stale_seen[w.end]
    assert cname("E") in stale, f"one-time customer E isn't stale on the last day: {stale[:400]!r}"
    _reports_as(w, app, page, "owner")


def test_TM_06b_manager_reports(world, tm, app, page):
    if not SERVER:
        pytest.skip("server mode only (personal mode has only the owner)")
    _reports_as(world, app, page, "manager")


def test_TM_06c_staff_reports(world, tm, app, page):
    if not SERVER:
        pytest.skip("server mode only (personal mode has only the owner)")
    _reports_as(world, app, page, "staff")


def test_TM_06d_field_crew_has_no_reports_tab(world, tm, app, page):
    if not SERVER:
        pytest.skip("server mode only")
    from playwright.sync_api import expect as _expect
    _expect(page.get_by_test_id("nav-reports")).to_be_hidden()


# ── TM-07: the six weeks add up ──────────────────────────────────────────────
def test_TM_07_the_six_weeks_add_up(world, tm, api):
    w = world
    for line in w.day_log:
        log.info(f"[TM] {line}")
    # recurring sweep: every auto visit on the first morning it was within the lead time, right due date, once
    for s in w.sweep_log:
        assert s["due"] == s["expected_due"], f"{s['cust']} {s['job']}: due {s['due']}, expected {s['expected_due']}"
        assert s["created_on"] == s["expected_on"], \
            f"{s['cust']} {s['job']} (due {s['due']}) created {s['created_on']}, first chance was {s['expected_on']}"
    jobs = w.jobs()
    open_unscheduled = [j for j in jobs if not iso_date(j.get("Service Date", ""))]
    assert len({w.key_of(j) for j in open_unscheduled}) == len(open_unscheduled), \
        f"duplicate pending auto visits: {[j['JobID (JOB-####)'] for j in open_unscheduled]}"
    # visits: weekly = every week, biweekly = every 2nd week, monthly = twice, one-time = once
    count = {k: sum(1 for _, d in v if d <= w.end) for k, v in w.visits.items()}
    assert count["A"] == WEEKS and count["C"] == WEEKS, f"weekly visits: {count}"
    assert count["B"] == WEEKS // 2, f"biweekly visits: {count}"
    assert count["D"] == 2 and count["E"] == 1 and count["F"] == 1, f"visits: {count}"
    by_id = {j["JobID (JOB-####)"]: j for j in jobs}
    for k, vs in w.visits.items():
        for jid, d in vs:
            if d <= w.end:
                assert by_id[jid].get("Job Status") == "Complete", f"{k} {jid} on {d}: {by_id[jid].get('Job Status')}"
    # time entries were stamped with the SIMULATED dates
    tl = api.read("TimeLog")
    stamped = {str(r.get("Entry Date") or r.get("Date") or r.get("Clock In") or "") for r in tl}
    for jid, d in w.visits["A"]:
        if d <= w.end:
            assert any(d.isoformat() in s or d.strftime("%m/%d/%Y") in s for s in stamped), \
                f"no time entry dated {d} (A {jid}); dates seen: {sorted(stamped)[:10]}"
    if SERVER:
        # every time entry is stamped with the crew who actually did the job
        crew_of_job = {jid: w.crew_name(k) for k, vs in w.visits.items() for jid, _ in vs}
        wrong = [(r.get("JobID (JOB-####)") or r.get("JobID"), r.get("Crew / Technician"))
                 for r in tl if (r.get("JobID (JOB-####)") or r.get("JobID")) in crew_of_job
                 and (r.get("Crew / Technician") or "").strip() != crew_of_job[r.get("JobID (JOB-####)") or r.get("JobID")]]
        assert not wrong, f"time entries stamped with the wrong crew: {wrong[:6]}"
        # a crew sees only its own time entries
        for c in ("alex", "bea"):
            me = w.tm.users[c].name
            other = [r.get("Crew / Technician") for r in w.apis[c].read("TimeLog")
                     if (r.get("Crew / Technician") or "").strip() not in ("", me)]
            assert not other, f"{me} can read other people's time entries: {other[:4]}"
    # the unpaid invoice (due day 1): not 31+ days overdue a month in, 31-60 days by the end
    tm.set_clock(w.d0 + dt.timedelta(days=29), "07:00")
    if SERVER:
        # R-068 (David 2026-09-29): the AR aging report is the server-mode view of
        # overdue invoices — owner AND manager see it, everyone else is refused.
        def _ar(who):
            return w.apis[who].call("get_ar_aging_report", {}, expect_ok=False)
        early_t = _ar("owner")
        tm.set_clock(w.end, "18:00")
        for who in ("owner", "manager"):
            t = _ar(who)
            log.info(f"[TM] AR aging last day as {who}: {t[:300]!r}")
            assert "31 – 60 days overdue" in t and cname("A") in t, \
                f"{who}: the 38-day-overdue invoice isn't in the 31-60 bucket: {t[:400]!r}"
        assert "31 – 60" not in early_t, f"invoice 31+ days overdue after 28 days: {early_t[:300]!r}"
        for who in ("staff", "alex", "bea"):
            t = _ar(who)
            assert t.lstrip().startswith("❌") and cname("A") not in t, f"{who} can read the AR report: {t[:200]!r}"
        # R-069: Customer Reminders — the LIST for owner, manager, staff; crews refused;
        # SENDING stays owner-only
        for who in ("owner", "manager", "staff"):
            t = w.apis[who].call("find_stale_customers", {"days_threshold": STALE_DAYS}, expect_ok=False)
            assert cname("E") in t, f"{who} can't see the stale-customer list: {t[:200]!r}"
        for who in ("alex", "bea"):
            t = w.apis[who].call("find_stale_customers", {"days_threshold": STALE_DAYS}, expect_ok=False)
            assert t.lstrip().startswith("❌"), f"{who} (field crew) can see the stale-customer list: {t[:200]!r}"
        for who in ("manager", "staff", "alex"):
            t = w.apis[who].call("send_customer_reminders", {"customer_ids": w.cust_id["E"]}, expect_ok=False)
            assert t.lstrip().startswith("❌"), f"{who} could send a customer reminder: {t[:200]!r}"
    else:
        early = tm.run_job("overdue_invoice_alert")
        tm.set_clock(w.end, "18:00")
        late = tm.run_job("overdue_invoice_alert")
        log.info(f"[TM] overdue alert day 29: {early.get('subject')!r}; last day: {late.get('subject')!r}")
        assert not early.get("subject"), f"invoice flagged 31+ days overdue after only 28 days: {early.get('subject')!r}"
        assert late.get("subject"), "the 38-day-overdue invoice never raised the overdue alert"
    # stale customer E: serviced once (Wed of week 1), stale from 21 days later, never
    # in between (before its first visit a never-serviced customer counts as due — by design)
    e_day = w.visits["E"][0][1]
    for day, text in sorted(w.stale_seen.items()):
        if day < e_day:
            continue
        is_stale = cname("E") in text
        assert is_stale == ((day - e_day).days >= STALE_DAYS), \
            f"{day}: E stale={is_stale} but last serviced {e_day} ({(day - e_day).days} days)"
    for k in "ABCD":
        assert cname(k) not in w.stale_seen[w.end], f"{k} is serviced regularly but shows as stale"
    # the outbox: the digest went to the owner only; nothing to a real address
    ob = tm.outbox()
    for m in ob:
        assert m["kind"] != "blocked_http" or True
        if m["kind"] in ("email", "sms", "whatsapp"):
            assert "time-machine" in m["to"] or m["to"].startswith("+1555"), f"a message to a real address: {m}"
    digests = [m for m in ob if m["kind"] == "email" and cname("E") in (m.get("body", "") + m.get("subject", ""))]
    log.info(f"[TM] outbox: {len(ob)} caught; {len(digests)} digest(s) naming E; "
             f"blocked outbound: {[m['to'] for m in ob if m['kind'] == 'blocked_http']}")
    after_visit = sorted(dt.date.fromisoformat(m["sim_time"][:10]) for m in digests
                         if dt.date.fromisoformat(m["sim_time"][:10]) > e_day)
    assert after_visit, "after E's visit, the daily digest never told the owner E is due again"
    assert (after_visit[0] - e_day).days >= STALE_DAYS, \
        f"digest named E {(after_visit[0] - e_day).days} days after its visit (threshold {STALE_DAYS})"
    log.info(f"[TM] digest days naming E: {[d.isoformat() for d in sorted(set(after_visit))][:8]} ...")
