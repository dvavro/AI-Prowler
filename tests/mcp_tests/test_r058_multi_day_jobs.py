"""
R-058 (2026-09-28, David): a job with Est. Duration in DAYS runs that many
WORKING days (Mon–Fri) from its Service Date, and is on its assignee's route
every one of those days. Before: "day" was offered by the Jobs app's dropdown
but understood nowhere — a 10-day job was routed once, on its first day, and
timed as 10 minutes; days 2–10 never appeared on anyone's route. Jobs with an
explicit End Date had the same first-day-only routing.

  * a day-unit duration sets End Date = Nth working day (create and edit)
  * every route engine / prescreen / unapprove sees the job on each working
    day of its span (weekends inside the span skipped; the Service Date always
    counts), timed as that day's full workday (a final part-day as a share)
  * the Calendar / date filter / Route tab date list skip those weekends too
  * multi-person (R-056): each assignee gets it on their route every day

Run: run_tests.bat tests\\mcp\\test_r058_multi_day_jobs.py -v
"""
from __future__ import annotations

import datetime as dt
import sqlite3
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from db_access import init_db                         # noqa: E402
import db_write_ops as w                               # noqa: E402
import db_route_ops as ro                              # noqa: E402

MON = "2026-10-05"       # a Monday
SAM, VICKI = "Samual Cronin", "Vicki Vavro"


@pytest.fixture
def db(tmp_path, monkeypatch):
    p = str(tmp_path / "jobs.db")
    init_db(p)
    monkeypatch.setattr(w, "db_read_owner_home_address", lambda: "")
    return p


def _job(db, dur=None, unit=None, date=MON, crew=SAM, **extra):
    c = w.db_create_customer(db, {"Company Name": "Acme"}, actor="t")
    cid = c.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    f = {"CustomerID": cid, "Customer Name / Company": "Acme", "Service Date": date,
         "Street Address": "1 Flagler Ave", "City": "New Smyrna Beach", "State": "FL",
         "Latitude (AI Geocode)": 29.04, "Longitude (AI Geocode)": -80.89, "Crew / Technician": crew}
    if dur is not None:
        f["Est. Duration"] = dur
    if unit is not None:
        f["Est. Duration Unit"] = unit
    f.update(extra)
    out = w.db_create_job(db, f, actor="t")
    assert out.startswith("✅"), out
    return out.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _end(db, jid):
    c = sqlite3.connect(db)
    v = c.execute("SELECT end_date FROM jobs WHERE job_id = ?", (jid,)).fetchone()[0]
    c.close()
    return v or ""


def _day(offset):
    return (dt.date.fromisoformat(MON) + dt.timedelta(days=offset)).isoformat()


# ── the calendar arithmetic ─────────────────────────────────────────────────
def test_working_day_helpers():
    m = dt.date.fromisoformat(MON)
    assert w.add_workdays(m, 0) == m
    assert w.add_workdays(m, 4).isoformat() == _day(4)          # Fri
    assert w.add_workdays(m, 5).isoformat() == _day(7)          # next Mon (weekend skipped)
    assert w.day_unit_end_date(MON, 10) == _day(11)             # 10 working days = Mon .. Fri next week
    assert w.day_unit_end_date(MON, 1) == "" and w.day_unit_end_date(MON, 0.5) == ""
    assert w.day_unit_end_date(MON, 2.5) == _day(2)             # 3 working days
    assert w.job_day_number(MON, _day(11), _day(0)) == 1
    assert w.job_day_number(MON, _day(11), _day(5)) is None     # Saturday inside the span
    assert w.job_day_number(MON, _day(11), _day(7)) == 6        # the next Monday is day 6
    assert w.job_day_number(MON, _day(11), _day(12)) is None    # after the end
    sat = _day(5)
    assert w.job_day_number(sat, "", sat) == 1                  # a job booked ON a Saturday counts


def test_per_day_minutes(db):
    w.db_seed_default_settings(db)                               # 07:00-17:00, 60 min lunch
    assert w.workday_job_minutes(db) == 540
    assert w.per_day_duration(db, 3, "day", 1) == (540, "min")
    assert w.per_day_duration(db, 2.5, "day", 3) == (270, "min")   # the half day
    assert w.per_day_duration(db, 2, "hour", 2) == (2, "hour")     # hours/minutes unchanged


# ── End Date follows a day-unit duration ────────────────────────────────────
def test_create_sets_end_date(db):
    jid = _job(db, 10, "days")                                   # R-057 turns "days" into "day"
    assert _end(db, jid) == _day(11)


def test_edit_keeps_end_date_in_step(db):
    jid = _job(db, 3, "day")
    assert _end(db, jid) == _day(2)
    w.db_update_job(db, jid, {"Est. Duration": 5}, actor="t")
    assert _end(db, jid) == _day(4)
    w.db_update_job(db, jid, {"Service Date": _day(2)}, actor="t")       # Wed + 5 working days
    assert _end(db, jid) == _day(8)
    w.db_update_job(db, jid, {"Est. Duration": 1}, actor="t")
    assert _end(db, jid) == ""


def test_hour_jobs_end_date_untouched(db):
    jid = _job(db, 3, "hour", **{"End Date (blank = single-day job)": _day(1)})
    assert _end(db, jid) == _day(1)
    w.db_update_job(db, jid, {"Est. Duration": 4}, actor="t")
    assert _end(db, jid) == _day(1)


# ── every working day is on the route ───────────────────────────────────────
def test_ten_day_job_is_routed_every_working_day(db):
    w.db_seed_default_settings(db)
    jid = _job(db, 10, "day")
    for off in range(14):
        day = _day(off)
        jobs = [j for j in ro.db_get_jobs_for_route(db, day, SAM) if j["job_id"] == jid]
        weekend = dt.date.fromisoformat(day).weekday() >= 5
        if off <= 11 and not weekend:
            assert jobs, f"{day} (day {off}) should have the job"
            assert jobs[0]["duration"] == 540 and jobs[0]["duration_unit"] == "min"
            assert jobs[0]["job_days"] == 10
        else:
            assert not jobs, f"{day} should not have the job"


def test_explicit_end_date_job_routed_each_day(db):
    jid = _job(db, 2, "hour", **{"End Date (blank = single-day job)": _day(2)})
    for off, want in [(0, True), (1, True), (2, True), (3, False)]:
        ids = {j["job_id"] for j in ro.db_get_jobs_for_route(db, _day(off), SAM)}
        assert (jid in ids) == want, off
    j = [x for x in ro.db_get_jobs_for_route(db, _day(1), SAM) if x["job_id"] == jid][0]
    assert (j["duration"], j["duration_unit"], j["day_no"]) == (2, "hour", 2)


def test_multi_day_shared_job_on_each_persons_route(db):
    jid = _job(db, 3, "day", crew=f"{SAM}, {VICKI}")
    for off in range(3):
        for who in (SAM, VICKI):
            assert jid in {j["job_id"] for j in ro.db_get_jobs_for_route(db, _day(off), who)}


def test_suggest_route_on_day_three_writes_the_stop(db, monkeypatch):
    import requests

    class _R:
        def json(self):
            return {"code": "Ok", "routes": [{"legs": [{"duration": 600}], "distance": 1000, "duration": 600}]}
    monkeypatch.setattr(requests, "get", lambda *a, **k: _R())
    w.db_seed_default_settings(db)
    jid = _job(db, 5, "day")
    ro.db_suggest_route_schedule(db, _day(2), SAM, actor="t")
    c = sqlite3.connect(db)
    got = [r[0] for r in c.execute("SELECT job_id FROM route_stops WHERE route_date = ? AND job_id IS NOT NULL",
                                   (_day(2),))]
    c.close()
    assert got == [jid]


def test_routing_day_two_keeps_day_one_route(db, monkeypatch):
    """The route follows the job — but a multi-day job belongs on EVERY day of its
    span, so building day 2's route must not delete day 1's stop."""
    import requests

    class _R:
        def json(self):
            return {"code": "Ok", "routes": [{"legs": [{"duration": 600}], "distance": 1000, "duration": 600}]}
    monkeypatch.setattr(requests, "get", lambda *a, **k: _R())
    jid = _job(db, 3, "day")
    ro.db_suggest_route_schedule(db, _day(0), SAM, actor="t")
    ro.db_suggest_route_schedule(db, _day(1), SAM, actor="t")
    c = sqlite3.connect(db)
    days = {r[0] for r in c.execute("SELECT route_date FROM route_stops WHERE job_id = ?", (jid,))}
    c.close()
    assert days == {_day(0), _day(1)}


def test_prescreen_and_unapprove_see_later_days(db):
    jid = _job(db, 3, "day", **{"Start Time": "10:15", "Original Start Time": "08:00"})
    assert all(i["code"] != "NO_ADDRESS" for i in ro.db_prescreen_route_jobs(db, _day(2), SAM))
    out = ro.db_unapprove_route_schedule(db, _day(2), SAM, actor="t")
    assert jid in out or "No jobs scheduled" not in out


# ── the date filter / app agree on weekends ─────────────────────────────────
def test_date_filter_skips_weekend_inside_span(db):
    from db_read_ops import db_read_job_spreadsheet
    jid = _job(db, 10, "day")
    sat, mon2 = _day(5), _day(7)
    assert jid not in db_read_job_spreadsheet(db, sheet_name="Jobs_Schedule", filter_date=sat)
    assert jid in db_read_job_spreadsheet(db, sheet_name="Jobs_Schedule", filter_date=mon2)


def test_app_calendar_skips_weekends_in_a_span():
    # 2026-10-02: the working days are now the Settings → Working Days value
    # (default Mon–Fri), asked through _isWorkingDay() — no hard-wired weekend.
    # Covered in depth by tests/mcp_tests/test_working_days_setting.py (WD-17).
    html = (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")
    i = html.index("function _calJobsByDate(jobs)")
    body = html[i:i + 2200]
    assert "_isWorkingDay(cur)" in body and "cur.getTime() === start.getTime()" in body
    assert "const _WD_DEFAULT = [1, 2, 3, 4, 5];" in html        # default still Mon–Fri


# ── overrun: an open job keeps being worked until it is marked Complete ─────
# David 2026-09-28: "if the job is not completed on the 10th day and still
# marked as in progress, then it should continue to ... be routed on the 11th
# day ... until the job is marked complete" — and the same for one-day and
# part-day jobs. Forward it reaches the next working day after today.
@pytest.fixture
def horizon_fri(monkeypatch):
    """Pretend today is Thursday of week 2, so the horizon is that Friday (_day(11))."""
    monkeypatch.setattr(w, "overrun_today", lambda: dt.date.fromisoformat(_day(10)))


def _set_status(db, jid, status):
    out = w.db_update_job(db, jid, {"Job Status": status}, actor="t")
    assert out.startswith("✅"), out


def test_overrun_helper():
    thu, fri, mon3 = _day(10), _day(11), _day(14)
    end = _day(2)                                               # a 3-day job, Mon..Wed
    assert w.job_day_number(MON, end, _day(3)) is None           # no status: planned span only
    assert w.job_day_number(MON, end, _day(3), status="In Progress", today=thu) == 4
    assert w.job_day_number(MON, end, fri, status="Scheduled", today=thu) == 10
    assert w.job_day_number(MON, end, _day(5), status="In Progress", today=thu) is None   # Saturday
    assert w.job_day_number(MON, end, mon3, status="In Progress", today=thu) is None      # past the horizon
    assert w.job_day_number(MON, end, _day(3), status="Complete", today=thu) is None
    assert w.job_day_number(MON, end, _day(3), status="done", today=thu) is None          # R-057 variant
    assert w.job_day_number(MON, end, _day(3), status="Cancelled", today=thu) is None
    # one-day job rolls over too
    assert w.job_day_number(MON, "", _day(1), status="Scheduled", today=thu) == 2
    assert w.job_day_number(MON, "", _day(1), status="Complete", today=thu) is None
    # ... but only once its day has PASSED: today's open jobs are not late yet,
    # so they are not on tomorrow's plan (found by the E2E at 4 AM: today's
    # three jobs were showing up on tomorrow's route)
    assert w.job_day_number(thu, "", fri, status="Scheduled", today=thu) is None
    assert w.job_day_number(MON, thu, fri, status="In Progress", today=thu) is None


def test_ten_day_job_overruns_to_day_eleven_until_complete(db, horizon_fri):
    w.db_seed_default_settings(db)
    jid = _job(db, 3, "day", **{"Job Status": "In Progress"})    # planned Mon..Wed
    thu = [j for j in ro.db_get_jobs_for_route(db, _day(3), SAM) if j["job_id"] == jid]
    assert thu, "an unfinished job must still be on Thursday's route"
    assert (thu[0]["day_no"], thu[0]["job_days"], thu[0]["overrun"]) == (4, 3, True)
    assert (thu[0]["duration"], thu[0]["duration_unit"]) == (540, "min")   # another full day
    assert not [j for j in ro.db_get_jobs_for_route(db, _day(5), SAM) if j["job_id"] == jid]  # Sat
    assert [j for j in ro.db_get_jobs_for_route(db, _day(7), SAM) if j["job_id"] == jid]      # Mon
    _set_status(db, jid, "Complete")
    assert not [j for j in ro.db_get_jobs_for_route(db, _day(3), SAM) if j["job_id"] == jid]


def test_one_day_job_rolls_over_until_complete(db, horizon_fri):
    jid = _job(db, 2, "hour")                                    # blank status = open
    nxt = [j for j in ro.db_get_jobs_for_route(db, _day(1), SAM) if j["job_id"] == jid]
    assert nxt and nxt[0]["overrun"] and (nxt[0]["duration"], nxt[0]["duration_unit"]) == (2, "hour")
    _set_status(db, jid, "Complete")
    assert not [j for j in ro.db_get_jobs_for_route(db, _day(1), SAM) if j["job_id"] == jid]


def test_half_day_job_overrun_is_another_half_day(db, horizon_fri):
    w.db_seed_default_settings(db)
    jid = _job(db, 0.5, "day")
    j = [x for x in ro.db_get_jobs_for_route(db, _day(1), SAM) if x["job_id"] == jid][0]
    assert (j["duration"], j["duration_unit"]) == (270, "min")


def test_overrun_stop_kept_while_open_and_future_one_dropped_on_complete(db, horizon_fri, monkeypatch):
    import requests

    class _R:
        def json(self):
            return {"code": "Ok", "routes": [{"legs": [{"duration": 600}], "distance": 1000, "duration": 600}]}
    monkeypatch.setattr(requests, "get", lambda *a, **k: _R())
    jid = _job(db, 2, "day", **{"Job Status": "In Progress"})    # planned Mon..Tue
    ro.db_suggest_route_schedule(db, _day(2), SAM, actor="t")    # overrun day 3 (Wed)
    ro.db_suggest_route_schedule(db, _day(3), SAM, actor="t")    # overrun day 4 (Thu)

    def days():
        c = sqlite3.connect(db)
        d = {r[0] for r in c.execute("SELECT route_date FROM route_stops WHERE job_id = ?", (jid,))}
        c.close()
        return d
    assert days() == {_day(2), _day(3)}
    ro.db_drop_stale_job_stops(db, [jid])                         # the clean-up keeps them
    assert days() == {_day(2), _day(3)}
    # Marked Complete when "today" is Wednesday: Wed's worked stop stays as
    # history, Thursday's (not worked now) goes
    monkeypatch.setattr(w, "overrun_today", lambda: dt.date.fromisoformat(_day(2)))
    _set_status(db, jid, "Complete")
    assert days() == {_day(2)}


def test_date_filter_and_today_list_show_overrun(db, monkeypatch):
    from db_read_ops import db_read_job_spreadsheet
    today = dt.date.today()
    past = today - dt.timedelta(days=7)
    while past.weekday() >= 5:
        past -= dt.timedelta(days=1)
    jid = _job(db, 1, "hour", date=past.isoformat(), **{"Job Status": "Scheduled"})
    probe = today if today.weekday() < 5 else w.add_workdays(today, 1)
    assert jid in db_read_job_spreadsheet(db, sheet_name="Jobs_Schedule", filter_date=probe.isoformat())
    _set_status(db, jid, "Complete")
    assert jid not in db_read_job_spreadsheet(db, sheet_name="Jobs_Schedule", filter_date=probe.isoformat())


def test_app_calendar_carries_open_jobs_forward():
    html = (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")
    assert "function _overrunHorizon()" in html
    i = html.index("function _calJobsByDate(jobs)")
    body = html[i:i + 3500]
    assert "R-058 overrun" in body and "_overrunHorizon()" in body
    assert "end < today0" in body          # today's jobs don't pre-fill tomorrow
