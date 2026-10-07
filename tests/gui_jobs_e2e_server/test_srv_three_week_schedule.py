"""Server mode — a realistic 3-week window-cleaning schedule (spec §6.11.7,
SRV-SCHED-01..06). Requested by David 2026-09-28.

  • David Vavro (U1, owner) creates 10 customers — 5 in New Smyrna Beach, 5 in
    Daytona Beach, real public addresses — half Weekly, half Biweekly, and
    schedules 3 weeks of window-cleaning jobs from them (25 jobs).
  • Vicki Vavro (U2) is a MANAGER but works as field crew; Samual Cronin (U3)
    is field crew. Jobs are split between them.
  • Both crew members work their first day through their OWN sessions: build
    their route, clock in/out, complete the job, add a note, add a job. Vicki
    must be able to do everything Samual can (David's requirement).

Safety: every customer and job is named "ZTEST E2E …" (the guard only lets
this run touch records it created); no customer has an email or phone, so
nothing can ever be sent; routes are only built on days inside the sandbox
window; the module sweeps all test data before and after. Jobs past the
sandbox window are still ZTEST-named, so the sweep removes them too (it
deletes ZTEST customers, which cascades their jobs, and any ZTEST job on any
date). With --keep-data the customers keep their Frequency, so the server's
once-a-day recurring sweep may add ZTEST follow-up jobs — the next run's sweep
removes those as well.

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_three_week_schedule
"""
from __future__ import annotations

import datetime as dt
import json
import logging

import pytest
from playwright.sync_api import expect

from api import iso_date, parse_records
from safety import SANDBOX_DATE, SANDBOX_DATES, ZTEST_PREFIX

log = logging.getLogger("e2e_srv")

SAMUAL = "Samual Cronin"
VICKI = "Vicki Vavro"
DAVID = "David Vavro"
CREW_KEY = {SAMUAL: "U3", VICKI: "U2"}
WEEKS = 3

# name, street, city, zip, lat, lon, frequency, weekday slot (0-4), crew, price
CUSTOMERS = [
    ("Riverside Cafe",       "105 S Riverside Dr",   "New Smyrna Beach", "32168", 29.0263, -80.9216, "Weekly",   0, SAMUAL, 95),
    ("City Hall Offices",    "210 Sams Ave",         "New Smyrna Beach", "32168", 29.0258, -80.9270, "Biweekly", 1, SAMUAL, 180),
    ("Library Annex",        "1001 S Dixie Fwy",     "New Smyrna Beach", "32168", 29.0122, -80.9303, "Weekly",   2, SAMUAL, 140),
    ("Flagler Ave Shops",    "1 Flagler Ave",        "New Smyrna Beach", "32169", 29.0413, -80.8965, "Biweekly", 3, VICKI,  120),
    ("Sports Complex",       "201 Sports Complex Dr", "New Smyrna Beach", "32168", 29.0060, -80.9458, "Weekly",  4, SAMUAL, 160),
    ("Main Street Pier Shop", "1200 Main St",        "Daytona Beach",    "32118", 29.2278, -81.0059, "Weekly",   0, VICKI,  110),
    ("Daytona City Hall",    "301 S Ridgewood Ave",  "Daytona Beach",    "32114", 29.2097, -81.0232, "Biweekly", 1, VICKI,  200),
    ("Museum Offices",       "352 S Nova Rd",        "Daytona Beach",    "32114", 29.2013, -81.0415, "Weekly",   2, VICKI,  175),
    ("Speedway Suites",      "1801 W International Speedway Blvd", "Daytona Beach", "32114", 29.1852, -81.0705,
                                                                                    "Biweekly", 3, SAMUAL, 250),
    ("City Island Library",  "105 E Magnolia Ave",   "Daytona Beach",    "32114", 29.2140, -81.0165, "Biweekly", 4, VICKI,  130),
]
DAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
BASE = dt.date.fromisoformat(SANDBOX_DATE)


def workday(week: int, slot: int) -> str:
    """The slot-th weekday (0-4) on or after SANDBOX_DATE + 7*week. The same
    slot is always the same weekday, so Weekly jobs land 7 days apart and
    Biweekly jobs 14 days apart."""
    d, n = BASE + dt.timedelta(days=7 * week), -1
    while True:
        if d.weekday() < 5:
            n += 1
            if n == slot:
                return d.isoformat()
        d += dt.timedelta(days=1)


def _refused(text) -> bool:
    return str(text).lstrip().startswith(("❌", "⛔"))


def _new_id(out, key):
    return str(out).split(f"{key}=")[1].splitlines()[0].strip()


def _jobs(api) -> list[dict]:
    return [j for j in api.read("Jobs_Schedule")
            if j.get("Customer Name / Company", "").startswith(ZTEST_PREFIX)]


# ── the schedule (created once for the module, swept before and after) ────────
@pytest.fixture(scope="module")
def schedule(data, owner_api):
    data.sweep("3-week schedule start")
    cust, jobs = {}, []          # name -> CUST id ; list of dicts
    for (name, street, city, zp, lat, lon, freq, slot, crew, price) in CUSTOMERS:
        full = f"{ZTEST_PREFIX} {name}"
        out = owner_api.call("create_customer", {"updates": {
            "Company Name": full, "Customer Type Comm/Res": "Commercial",
            "Street Address": street, "City": city, "State": "FL", "ZIP": zp,
            "Latitude (AI Geocode)": lat, "Longitude (AI Geocode)": lon,
            "Service Type(s) Win/Press/Both": "Win", "Frequency": freq,
            "Preferred Day(s)": DAY_NAMES[dt.date.fromisoformat(workday(0, slot)).weekday()],
            "Avg Job Duration (min)": 60, "Standard Quote ($)": price,
            "Status Active/Inactive": "Active"}})
        cid = _new_id(out, "NEW_CUST_ID")
        cust[full] = cid
        weeks = range(WEEKS) if freq == "Weekly" else range(0, WEEKS, 2)
        for w in weeks:
            day = workday(w, slot)
            out = owner_api.call("create_job", {"updates": {
                "CustomerID": cid, "Customer Name / Company": full,
                "Service Date": day, "Street Address": street, "City": city, "State": "FL", "ZIP": zp,
                "Latitude (AI Geocode)": lat, "Longitude (AI Geocode)": lon,
                "Service Type": "Window", "Job Status": "Scheduled", "Crew / Technician": crew,
                "Schedule Type (Hard/Soft)": "Soft", "Est. Duration": 60, "Est. Duration Unit": "min",
                "Quote Amount ($)": price}})
            jobs.append({"id": _new_id(out, "NEW_JOB_ID"), "customer": full, "cid": cid,
                         "date": day, "crew": crew, "freq": freq, "week": w})
    log.info(f"[SRV-SCHED] created {len(cust)} customers, {len(jobs)} jobs "
             f"({workday(0, 0)} .. {max(j['date'] for j in jobs)})")
    yield {"customers": cust, "jobs": jobs}
    data.sweep("3-week schedule end")


def _mine(schedule, crew):
    return [j for j in schedule["jobs"] if j["crew"] == crew]


def _day1(schedule, crew):
    first = workday(0, 0)
    return [j for j in schedule["jobs"] if j["crew"] == crew and j["date"] == first]


# ── SRV-SCHED-01: the owner's 3-week schedule is exactly as planned ───────────
def test_SRV_SCHED_01_owner_builds_three_week_schedule(schedule, owner_api):
    rows = {j["JobID (JOB-####)"]: j for j in _jobs(owner_api)}
    assert len(schedule["customers"]) == 10
    assert len(schedule["jobs"]) == 25 and len(_mine(schedule, SAMUAL)) == 13 and len(_mine(schedule, VICKI)) == 12
    for j in schedule["jobs"]:
        r = rows.get(j["id"])
        assert r, f"{j['id']} ({j['customer']}) is missing"
        assert iso_date(r.get("Service Date", "")) == j["date"], f"{j['id']} date {r.get('Service Date')} != {j['date']}"
        assert r.get("Crew / Technician") == j["crew"], f"{j['id']} crew {r.get('Crew / Technician')!r}"
        assert r.get("Service Type", "").lower().startswith("window"), f"{j['id']} service {r.get('Service Type')!r}"
    # repeat pattern: Weekly = every 7 days x3, Biweekly = every 14 days x2
    by_cust = {}
    for j in schedule["jobs"]:
        by_cust.setdefault(j["customer"], []).append(dt.date.fromisoformat(j["date"]))
    for (name, *_rest) in CUSTOMERS:
        freq = _rest[5]
        dates = sorted(by_cust[f"{ZTEST_PREFIX} {name}"])
        gaps = {(b - a).days for a, b in zip(dates, dates[1:])}
        assert (len(dates), gaps) == ((3, {7}) if freq == "Weekly" else (2, {14})), \
            f"{name} ({freq}): {dates}"
    # customers carry their frequency and a real NSB / Daytona address
    for c in owner_api.read("Customers"):
        if c.get("Company Name") in schedule["customers"]:
            assert c.get("Frequency") in ("Weekly", "Biweekly")
            assert c.get("City") in ("New Smyrna Beach", "Daytona Beach") and c.get("Street Address")
            assert not c.get("Email") and not c.get("Phone"), "test customers must have no contact details"


# ── SRV-SCHED-02: each crew member sees their share ───────────────────────────
def test_SRV_SCHED_02_each_crew_member_sees_their_share(schedule, api_as):
    sam_ids = {j["JobID (JOB-####)"] for j in _jobs(api_as("U3"))}
    assert sam_ids == {j["id"] for j in _mine(schedule, SAMUAL)}, \
        f"Samual should see exactly his 13 jobs; extra={sam_ids - {j['id'] for j in _mine(schedule, SAMUAL)}}"
    vicki_ids = {j["JobID (JOB-####)"] for j in _jobs(api_as("U2"))}
    missing = {j["id"] for j in _mine(schedule, VICKI)} - vicki_ids
    assert not missing, f"Vicki can't see her own jobs: {missing}"
    # both need the customer record (gate codes, address) to do the work
    for key in ("U2", "U3"):
        names = {c.get("Company Name") for c in api_as(key).read("Customers")}
        assert set(schedule["customers"]) <= names, f"{key} can't read every schedule customer"


# ── SRV-SCHED-03: first day — each crew member works their own jobs ──────────
@pytest.mark.parametrize("crew", [SAMUAL, VICKI])
def test_SRV_SCHED_03_crew_works_first_day(crew, schedule, api_as, owner_api):
    me = api_as(CREW_KEY[crew])
    day = workday(0, 0)
    assert day in SANDBOX_DATES
    todays = _day1(schedule, crew)
    assert todays, f"{crew} has no job on {day}"
    # build my own route (field crew: blank = mine; a manager names herself)
    out = me.call("build_daily_route", {"route_date": day, "crew": "" if crew == SAMUAL else crew,
                                        "email_link": False}, expect_ok=False)
    log.info(f"[SRV-SCHED-03] {crew} builds own route {day} -> {str(out).splitlines()[0][:160]}")
    assert not _refused(out), f"{crew} couldn't build their own route: {str(out)[:200]!r}"
    stops = [s for s in parse_records(me.call("read_job_spreadsheet", {"sheet_name": "Route_Planner",
                                                                        "max_rows": 500}, expect_ok=False))
             if iso_date(s.get("Route Date", "")) == day]
    stop_jobs = {s.get("JobID (JOB-####)", "") for s in stops}
    others = {s.get("JobID (JOB-####)") for s in stops if s.get("Crew / Technician") != crew}
    if crew == SAMUAL:   # field crew sees only their own route's stops
        assert not others, f"Samual can see other crews' stops on {day}: {others}"
    for j in todays:
        assert j["id"] in stop_jobs, f"{j['id']} isn't on {crew}'s route: {stop_jobs}"
    # clock in, clock out, note, complete — on each of today's jobs
    for j in todays:
        start = me.call("log_time_entry", {"job_identifier": j["id"], "action": "start"}, expect_ok=False)
        assert not _refused(start), f"{crew} couldn't clock in on {j['id']}: {str(start)[:200]!r}"
        stop = me.call("log_time_entry", {"job_identifier": j["id"], "action": "stop"}, expect_ok=False)
        assert not _refused(stop), f"{crew} couldn't clock out on {j['id']}: {str(stop)[:200]!r}"
        done = me.call("update_job_spreadsheet", {
            "sheet_name": "Jobs_Schedule", "id_column": "JobID (JOB-####)", "job_identifier": j["id"],
            # "Complete" is the app's value (R-057: "Completed" is now stored as "Complete" too)
            "updates": {"Job Status": "Complete", "Service Details / Notes": f"windows done by {crew}"}},
            expect_ok=False)
        assert not _refused(done), f"{crew} couldn't complete {j['id']}: {str(done)[:200]!r}"
    rows = {r["JobID (JOB-####)"]: r for r in _jobs(owner_api)}
    for j in todays:
        assert rows[j["id"]].get("Job Status") == "Complete", f"{j['id']} not Complete: {rows[j['id']].get('Job Status')}"
    tl = [r for r in owner_api.read("TimeLog") if any(j["id"] in r.values() for j in todays)]
    assert tl and all(crew in r.values() for r in tl), f"time entries for {crew}'s jobs aren't under {crew}: {tl}"


# ── SRV-SCHED-04: Vicki (manager doing crew work) can do everything Samual can ─
@pytest.mark.parametrize("crew", [SAMUAL, VICKI])
def test_SRV_SCHED_04_crew_can_add_and_edit_their_own_jobs(crew, schedule, api_as, owner_api):
    me = api_as(CREW_KEY[crew])
    mine = _mine(schedule, crew)
    # add a job (an extra visit for one of my customers in week 2)
    c = mine[0]
    out = me.call("create_job", {"updates": {
        "CustomerID": c["cid"], "Customer Name / Company": f"{c['customer']} extra visit",
        "Service Date": workday(1, 0), "Service Type": "Window", "Job Status": "Scheduled",
        "Crew / Technician": crew, "Est. Duration": 30, "Est. Duration Unit": "min"}}, expect_ok=False)
    log.info(f"[SRV-SCHED-04] {crew} create_job -> {str(out).splitlines()[0][:160]}")
    assert not _refused(out), f"{crew} couldn't add a job: {str(out)[:200]!r}"
    new_id = _new_id(out, "NEW_JOB_ID")
    assert new_id in {j["JobID (JOB-####)"] for j in _jobs(me)}, f"{crew} can't see the job they just added"
    # edit a later job of mine
    later = next(j for j in mine if j["week"] > 0)
    ok = me.call("update_job_spreadsheet", {"sheet_name": "Jobs_Schedule", "id_column": "JobID (JOB-####)",
                                           "job_identifier": later["id"],
                                           "updates": {"Service Details / Notes": f"{crew}: bring extension pole"}},
                 expect_ok=False)
    assert not _refused(ok), f"{crew} couldn't edit their own job {later['id']}: {str(ok)[:200]!r}"
    # control: field crew still can't edit someone else's job (Vicki is a manager, so she can)
    other = next(j for j in schedule["jobs"] if j["crew"] != crew and j["week"] > 0)
    res = me.call("update_job_spreadsheet", {"sheet_name": "Jobs_Schedule", "id_column": "JobID (JOB-####)",
                                            "job_identifier": other["id"],
                                            "updates": {"Service Details / Notes": "E2E cross-edit check"}},
                  expect_ok=False)
    if crew == SAMUAL:
        assert _refused(res), f"Samual changed Vicki's job {other['id']}: {str(res)[:200]!r}"
    else:
        assert not _refused(res), f"Vicki (manager) couldn't edit Samual's job: {str(res)[:200]!r}"


# ── SRV-SCHED-05: the owner routes every in-window workday for both crews ────
def test_SRV_SCHED_05_owner_routes_each_workday_per_crew(schedule, owner_api):
    # Day 1 is skipped: SRV-SCHED-03 already routed it and completed its jobs.
    days = sorted({j["date"] for j in schedule["jobs"]
                   if j["date"] in SANDBOX_DATES and j["week"] == 0 and j["date"] != workday(0, 0)})
    assert len(days) >= 3, f"too few schedule days inside the sandbox window: {days}"
    crew_of = {j["id"]: j["crew"] for j in schedule["jobs"]}
    for day in days:
        for crew in (SAMUAL, VICKI):
            want = {j["id"] for j in schedule["jobs"] if j["date"] == day and j["crew"] == crew}
            if not want:
                continue
            out = owner_api.call("build_daily_route", {"route_date": day, "crew": crew, "email_link": False},
                                 expect_ok=False)
            log.info(f"[SRV-SCHED-05] {crew} {day} -> {str(out).splitlines()[0][:140]}")
            assert not _refused(out), f"owner couldn't route {crew} on {day}: {str(out)[:200]!r}"
            got = {s.get("JobID (JOB-####)", "") for s in owner_api.read("Route_Planner")
                   if iso_date(s.get("Route Date", "")) == day and s.get("Crew / Technician") == crew}
            assert want <= got, f"{crew}'s route on {day} is missing {want - got}"
            wrong = {jid for jid in got if crew_of.get(jid, crew) != crew}
            assert not wrong, f"{crew}'s route on {day} has another crew's jobs: {wrong}"


# ── SRV-SCHED-07 (R-055): Vicki's "no crew picked" route is only her jobs ────
def test_SRV_SCHED_07_manager_blank_route_is_only_her_jobs(schedule, api_as, owner_api):
    """David 2026-09-28: Vicki (manager) may see every job, but Route Today /
    AI Route / the Route tab's default must route only the jobs assigned to
    her. Before R-055 a manager's blank crew meant every crew."""
    day = workday(0, 1)                    # both crews have work on this day
    assert day in SANDBOX_DATES
    hers = {j["id"] for j in schedule["jobs"] if j["date"] == day and j["crew"] == VICKI}
    his = {j["id"] for j in schedule["jobs"] if j["date"] == day and j["crew"] == SAMUAL}
    assert hers and his, f"test data: need both crews on {day}"
    owner_api.call("delete_route", {"route_date": day, "confirm": True}, expect_ok=False)   # clean day
    out = api_as("U2").call("build_daily_route", {"route_date": day, "crew": "", "email_link": False},
                            expect_ok=False)
    log.info(f"[SRV-SCHED-07] Vicki Route Today (no crew) {day} -> {str(out).splitlines()[0][:160]}")
    assert not _refused(out), f"Vicki couldn't route her day: {str(out)[:200]!r}"
    stops = [s for s in owner_api.read("Route_Planner") if iso_date(s.get("Route Date", "")) == day]
    ids = {s.get("JobID (JOB-####)") for s in stops}
    assert hers <= ids, f"Vicki's route is missing her jobs {hers - ids}"
    assert not (his & ids), f"Vicki's blank-crew route pulled in Samual's jobs {his & ids} (R-055)"
    assert {s.get("Crew / Technician") for s in stops if s.get("JobID (JOB-####)")} == {VICKI}, \
        f"stops created under other crews: {[(s.get('JobID (JOB-####)'), s.get('Crew / Technician')) for s in stops]}"


# ── SRV-SCHED-08 (R-055 all roles + R-056): shared job, everyone self-routes ──
def test_SRV_SCHED_08_shared_job_on_each_self_served_route(schedule, api_as, owner_api):
    """David 2026-09-28: a job may be assigned to several people; each person
    who routes their own day (blank crew = "my jobs", ANY role — the owner too)
    gets it on their route. Nobody routes for anyone else."""
    day = workday(0, 2)
    if day not in SANDBOX_DATES:
        pytest.skip(f"{day} is outside the sandbox window")
    team = {m["name"]: m["role"] for m in json.loads(str(api_as("U3").call("list_team_members", {})))["members"]}
    log.info(f"[SRV-SCHED-08] list_team_members (as Samual) -> {team}")
    assert {SAMUAL, VICKI, DAVID} <= set(team), f"team list is missing people: {team}"
    assert team[VICKI] == "manager" and team[SAMUAL] == "field_crew"
    c = schedule["jobs"][0]
    shared_crew = f"{SAMUAL}, {VICKI}"
    made = {}
    for label, crew in (("shared visit", shared_crew), ("owner's own visit", DAVID)):
        out = owner_api.call("create_job", {"updates": {
            "CustomerID": c["cid"], "Customer Name / Company": f"{c['customer']} {label}",
            "Service Date": day, "Street Address": CUSTOMERS[0][1], "City": CUSTOMERS[0][2], "State": "FL",
            "ZIP": CUSTOMERS[0][3], "Latitude (AI Geocode)": CUSTOMERS[0][4], "Longitude (AI Geocode)": CUSTOMERS[0][5],
            "Service Type": "Window", "Job Status": "Scheduled", "Crew / Technician": crew,
            "Schedule Type (Hard/Soft)": "Soft", "Est. Duration": 30, "Est. Duration Unit": "min"}})
        made[crew] = _new_id(out, "NEW_JOB_ID")
    shared, davids = made[shared_crew], made[DAVID]
    owner_api.call("delete_route", {"route_date": day, "confirm": True}, expect_ok=False)   # clean day
    want = {
        VICKI: {j["id"] for j in schedule["jobs"] if j["date"] == day and j["crew"] == VICKI} | {shared},
        SAMUAL: {j["id"] for j in schedule["jobs"] if j["date"] == day and j["crew"] == SAMUAL} | {shared},
        DAVID: {davids},
    }
    for who, key in ((VICKI, "U2"), (SAMUAL, "U3"), (DAVID, "U1")):
        me = owner_api if key == "U1" else api_as(key)
        # accept_reorder: when a faster visit order exists the first build only
        # reports "ROUTE SAVINGS AVAILABLE" and saves nothing (found live
        # 19:23 on Vicki's day) — the app's user confirms; so does the test.
        out = me.call("build_daily_route", {"route_date": day, "crew": "", "email_link": False,
                                            "accept_reorder": True}, expect_ok=False)
        log.info(f"[SRV-SCHED-08] {who} Route Today (no crew) {day} -> {str(out).splitlines()[0][:160]}")
        assert not _refused(out), f"{who} couldn't route their own day: {str(out)[:200]!r}"
    stops = [s for s in owner_api.read("Route_Planner")
             if iso_date(s.get("Route Date", "")) == day and s.get("JobID (JOB-####)")]
    by = {}
    for s in stops:
        by.setdefault(s.get("Crew / Technician"), set()).add(s.get("JobID (JOB-####)"))
    log.info(f"[SRV-SCHED-08] routes on {day}: { {k: sorted(v) for k, v in by.items()} }")
    assert set(by) == {VICKI, SAMUAL, DAVID}, f"routes should be one per person, got {sorted(by)}"
    for who, ids in want.items():
        assert by[who] == ids, f"{who}'s route: extra {by[who] - ids}, missing {ids - by[who]}"
    # both people on the shared job can clock it
    for key in ("U2", "U3"):
        out = api_as(key).call("log_time_entry", {"job_identifier": shared, "action": "start"}, expect_ok=False)
        assert not _refused(out), f"{key} couldn't clock in on the shared job: {str(out)[:200]!r}"
        api_as(key).call("log_time_entry", {"job_identifier": shared, "action": "stop"}, expect_ok=False)


# ── SRV-SCHED-09 (R-056): the Crew / Technician picker in the app ────────────
def test_SRV_SCHED_09_crew_picker_lists_the_team(windows, schedule):
    owner, = windows("U1")
    owner.log_in()
    expect(owner.page.locator("#app")).to_be_visible(timeout=30_000)
    owner.page.evaluate("() => openAddJobModal()")
    picker = owner.page.locator("#jfCrewPicker")
    expect(picker).to_be_visible(timeout=15_000)
    expect(owner.page.locator("#jfCrew")).to_be_hidden()
    for name in (DAVID, VICKI, SAMUAL):
        expect(picker.locator(f"input[type=checkbox][value='{name}']")).to_have_count(1)
    picker.locator(f"input[type=checkbox][value='{SAMUAL}']").check()
    picker.locator(f"input[type=checkbox][value='{VICKI}']").check()
    val = owner.page.evaluate("() => document.getElementById('jfCrew').value")
    owner.app.log(f"Crew picker value with two people ticked: {val!r}")
    assert sorted(v.strip() for v in val.split(",")) == sorted([SAMUAL, VICKI])
    own = owner.page.evaluate("() => _routeOwnDefaultName()")
    assert own == DAVID, f"owner's route default isn't his own jobs (got {own!r}) — R-055 extension not deployed?"
    owner.page.evaluate("() => closeJobFormModal()")        # nothing saved


# ── SRV-SCHED-06: what each person sees in the app (visible in --human) ──────
def test_SRV_SCHED_06_jobs_screen_per_person(windows, schedule):
    sam, vicki = windows("U3", "U2")
    for w in (sam, vicki):
        w.log_in()
        expect(w.page.locator("#app")).to_be_visible(timeout=30_000)
        w.app.goto("jobs")
        w.page.evaluate("async () => { await loadJobs(); }")
        w.page.wait_for_timeout(1000)
    ids = lambda w: set(w.page.evaluate("() => (state.jobs || []).map(j => String(j.id))"))
    sam_ids, vicki_ids = ids(sam), ids(vicki)
    sam.app.log(f"Samual's Jobs screen has {len(sam_ids)} jobs; Vicki's {len(vicki_ids)}")
    vicki_jobs = {j["id"] for j in _mine(schedule, VICKI)}
    sam_jobs = {j["id"] for j in _mine(schedule, SAMUAL)}
    assert not (sam_ids & vicki_jobs), f"Samual's screen shows Vicki's jobs: {sam_ids & vicki_jobs}"
    # the Jobs screen may hide completed / far-future jobs — check what it shows is his,
    # and that each person sees at least one of their own upcoming jobs
    assert sam_ids & sam_jobs, "Samual's Jobs screen shows none of his schedule"
    assert vicki_ids & vicki_jobs, "Vicki's Jobs screen shows none of her schedule"
    # R-055: Vicki's Route tab default is "My jobs (Vicki Vavro)", not "All crews"
    own = vicki.page.evaluate("() => (typeof _routeOwnDefaultName === 'function') ? _routeOwnDefaultName() : null")
    assert own == VICKI, f"Vicki's route default isn't her own jobs (got {own!r}) — R-055 not deployed?"
