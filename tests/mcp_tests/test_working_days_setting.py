"""
Working Days setting (Vicki, 2026-10-02).

R-058 treated a "working day" as Mon–Fri, hard-wired. A contractor running late
on a project may work Saturday and/or Sunday, so the days now come from the
Settings row "Working Days" (default Mon,Tue,Wed,Thu,Fri — no change for anyone
who never touches it). These tests cover:

  * reading the setting: names, ranges, groups, wrap-around, junk refused
  * the new row is seeded on every install with the Mon–Fri default
  * saving: an unreadable value is refused with a clear message (never a silent
    fall-back), a readable one is stored in one tidy form
  * every R-058 rule follows the setting: End Date of an N-day job, which days
    a multi-day job is worked, the overrun carry-over day, the day filter
    (Calendar / Jobs list), the route engines
  * changing the days re-counts the End Date of OPEN day-unit jobs only
  * get_working_days (the read-only tool the Jobs app uses — field crew can't
    read Settings) and both Jobs-app allowlists

Run: run_tests.bat tests\\mcp\\test_working_days_setting.py -v
"""
from __future__ import annotations

import datetime as dt
import re
import sqlite3
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from db_access import init_db                         # noqa: E402
import db_write_ops as w                               # noqa: E402
import db_read_ops as rd                               # noqa: E402
import db_route_ops as ro                              # noqa: E402

MON = "2026-10-05"            # a Monday
FRI = "2026-10-09"
SAT = "2026-10-10"
SUN = "2026-10-11"
NEXT_MON = "2026-10-12"
MON_FRI = frozenset(range(5))
ALL = frozenset(range(7))
MON_SAT = frozenset(range(6))


@pytest.fixture
def db(tmp_path, monkeypatch):
    p = str(tmp_path / "jobs.db")
    init_db(p)
    w.db_seed_default_settings(p)
    monkeypatch.setattr(w, "db_read_owner_home_address", lambda: "")
    return p


def _set_days(db, text):
    return w.db_update_settings(db, "Working Days", {"Value": text}, actor="t")


def _setting(db):
    c = sqlite3.connect(db)
    v = c.execute("SELECT value FROM settings WHERE key = 'Working Days'").fetchone()
    c.close()
    return v[0] if v else None


def _job(db, date=MON, dur=None, unit=None, status=None, **extra):
    c = w.db_create_customer(db, {"Company Name": "Acme"}, actor="t")
    cid = c.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    f = {"CustomerID": cid, "Customer Name / Company": "Acme", "Service Date": date,
         "Street Address": "1 Flagler Ave", "City": "New Smyrna Beach", "State": "FL",
         "Latitude (AI Geocode)": 29.04, "Longitude (AI Geocode)": -80.89,
         "Crew / Technician": "Samual Cronin"}
    if dur is not None:
        f["Est. Duration"] = dur
    if unit is not None:
        f["Est. Duration Unit"] = unit
    if status is not None:
        f["Job Status"] = status
    f.update(extra)
    out = w.db_create_job(db, f, actor="t")
    assert out.startswith("✅"), out
    return out.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _end(db, jid):
    c = sqlite3.connect(db)
    v = c.execute("SELECT end_date FROM jobs WHERE job_id = ?", (jid,)).fetchone()[0]
    c.close()
    return v or ""


# ── WD-01..04: reading the setting ──────────────────────────────────────────
@pytest.mark.parametrize("text, days", [
    ("Mon,Tue,Wed,Thu,Fri", MON_FRI),
    ("", MON_FRI),                                   # blank = default
    ("Mon-Sat", MON_SAT),
    ("mon - sat", MON_SAT),
    ("Monday to Saturday", MON_SAT),
    ("Mon,Tue,Wed,Thu,Fri,Sat,Sun", ALL),
    ("All", ALL),
    ("every day", ALL),
    ("Weekdays, Sat", MON_SAT),
    ("Weekdays and Weekends", ALL),
    ("Fri-Mon", frozenset({4, 5, 6, 0})),            # wraps past Sunday
    ("Monday Wednesday Friday", frozenset({0, 2, 4})),
    ("SAT; SUN", frozenset({5, 6})),
])
def test_WD_01_parse_accepts_friendly_forms(text, days):
    got, problem = w.parse_working_days(text)
    assert problem == "" and got == days, (text, got, problem)


@pytest.mark.parametrize("text", ["Mon,Tue,Wendsday", "funday", "Mon-Blursday", "8 days"])
def test_WD_02_parse_refuses_junk_and_says_why(text):
    got, problem = w.parse_working_days(text)
    assert problem and got == MON_FRI, (text, got)
    assert "Mon,Tue,Wed,Thu,Fri,Sat,Sun" in problem      # tells the person what to type


def test_WD_03_format_is_tidy_and_in_week_order():
    assert w.format_working_days({6, 0, 5, 2}) == "Mon,Wed,Sat,Sun"
    assert w.format_working_days(MON_FRI) == w.DEFAULT_WORKING_DAYS_TEXT


def test_WD_04_missing_or_unreadable_row_means_mon_fri(tmp_path):
    p = str(tmp_path / "bare.db")
    init_db(p)                                        # no Settings rows at all
    assert w.working_days(p) == MON_FRI
    assert w.working_days("") == MON_FRI
    assert w.working_days(str(tmp_path / "does_not_exist.db")) == MON_FRI


# ── WD-05: the row is seeded on every install ───────────────────────────────
def test_WD_05_seeded_with_the_mon_fri_default(db):
    assert _setting(db) == "Mon,Tue,Wed,Thu,Fri"
    keys = [k for k, _v, _n in w.DEFAULT_SETTINGS]
    # shown right after the workday hours it belongs with
    assert keys.index("Working Days") == keys.index("Workday End Time") + 1


# ── WD-06..07: saving ───────────────────────────────────────────────────────
def test_WD_06_saving_junk_is_refused_and_nothing_changes(db):
    out = _set_days(db, "Mon,Tue,Wendsday")
    assert out.startswith("❌") and "Working Days not saved" in out and "Wendsday".lower() in out.lower()
    assert _setting(db) == "Mon,Tue,Wed,Thu,Fri"


def test_WD_07_saving_stores_one_tidy_form(db):
    out = _set_days(db, "monday - saturday")
    assert out.startswith("✅"), out
    assert _setting(db) == "Mon,Tue,Wed,Thu,Fri,Sat"
    assert w.working_days(db) == MON_SAT


# ── WD-08..10: every R-058 rule follows the setting ─────────────────────────
def test_WD_08_end_date_of_an_n_day_job_counts_working_days():
    # 7 working days from Monday: Mon–Fri ends next Tuesday; Mon–Sat ends Monday;
    # every day ends Sunday.
    assert w.day_unit_end_date(MON, 7) == "2026-10-13"
    assert w.day_unit_end_date(MON, 7, MON_SAT) == NEXT_MON
    assert w.day_unit_end_date(MON, 7, ALL) == SUN


def test_WD_09_which_days_a_multi_day_job_is_worked():
    # A Friday–Monday job: default skips the weekend; with weekends on, every day counts.
    assert w.job_day_number(FRI, NEXT_MON, SAT) is None
    assert w.job_day_number(FRI, NEXT_MON, NEXT_MON) == 2
    assert w.job_day_number(FRI, NEXT_MON, SAT, days=ALL) == 2
    assert w.job_day_number(FRI, NEXT_MON, SUN, days=ALL) == 3
    assert w.job_day_number(FRI, NEXT_MON, NEXT_MON, days=ALL) == 4
    assert w.job_day_number(FRI, NEXT_MON, SUN, days=MON_SAT) is None
    # the day it was booked for always counts, even on a non-working day
    assert w.job_day_number(SUN, "", SUN) == 1


def test_WD_10_overrun_carries_to_the_next_working_day():
    # A job that should have finished Thursday is still open on Friday:
    assert w.overrun_horizon(FRI) == dt.date.fromisoformat(NEXT_MON)          # Mon–Fri
    assert w.overrun_horizon(FRI, MON_SAT) == dt.date.fromisoformat(SAT)
    assert w.job_day_number("2026-10-08", "", SAT, status="In Progress",
                            today=FRI, days=MON_SAT) is not None
    assert w.job_day_number("2026-10-08", "", SAT, status="In Progress", today=FRI) is None
    # an empty set never loops forever
    assert w.add_workdays(dt.date.fromisoformat(MON), 3, frozenset()) == dt.date.fromisoformat("2026-10-08")


# ── WD-11: the Calendar / Jobs-list day filter ──────────────────────────────
def test_WD_11_day_filter_follows_the_setting(db):
    jid = _job(db, date=FRI, **{"End Date (blank = single-day job)": NEXT_MON})
    sat_before = rd.db_read_job_spreadsheet(db, filter_date=SAT)
    assert jid not in sat_before, "default Mon–Fri: not on Saturday"
    assert _set_days(db, "All").startswith("✅")
    assert jid in rd.db_read_job_spreadsheet(db, filter_date=SAT)
    assert jid in rd.db_read_job_spreadsheet(db, filter_date=SUN)


# ── WD-12: the route engines ────────────────────────────────────────────────
def test_WD_12_route_engines_follow_the_setting(db):
    jid = _job(db, date=FRI, **{"End Date (blank = single-day job)": NEXT_MON})
    on = lambda day: [r["job_id"] for r in ro.db_get_jobs_for_route(db, day)]
    assert jid not in on(SAT) and jid in on(NEXT_MON)
    assert _set_days(db, "Mon-Sat").startswith("✅")
    assert jid in on(SAT) and jid not in on(SUN)
    # Saturday counts as day 2, so Monday is day 3 of the job
    worked = {r["job_id"]: n for r, n in ro._jobs_worked_on(db, NEXT_MON)}
    assert worked[jid] == 3


# ── WD-13: changing the days re-counts OPEN day-unit jobs only ──────────────
def test_WD_13_new_days_recount_open_jobs_and_leave_finished_ones(db):
    open_job = _job(db, date=MON, dur=7, unit="day")
    done_job = _job(db, date=MON, dur=7, unit="day", status="Complete")
    minutes_job = _job(db, date=MON, dur=90, unit="min",
                       **{"End Date (blank = single-day job)": FRI})
    assert _end(db, open_job) == _end(db, done_job) == "2026-10-13"   # Mon–Fri
    assert _set_days(db, "Mon-Sat").startswith("✅")
    assert _end(db, open_job) == NEXT_MON            # Saturday now counts
    assert _end(db, done_job) == "2026-10-13"        # finished work keeps its history
    assert _end(db, minutes_job) == FRI              # not a day-unit job: untouched


def test_WD_14_new_job_uses_the_current_days(db):
    assert _set_days(db, "All").startswith("✅")
    jid = _job(db, date=MON, dur=7, unit="day")
    assert _end(db, jid) == SUN


# ── WD-15..16: the tool the Jobs app reads, and its allowlists ──────────────
def test_WD_15_get_working_days_tool(db, monkeypatch):
    import ai_prowler_mcp as m
    monkeypatch.setattr(m, "_resolve_job_db_path", lambda ctx, filepath="": db)
    assert m.get_working_days(ctx=None) == "WORKING_DAYS: Mon,Tue,Wed,Thu,Fri"
    assert _set_days(db, "weekdays, sat").startswith("✅")
    assert m.get_working_days(ctx=None) == "WORKING_DAYS: Mon,Tue,Wed,Thu,Fri,Sat"


def test_WD_16_jobs_app_may_call_it_in_both_modes():
    """Field crew can't read Settings, so the Calendar reads Working Days
    through this tool — it must be on BOTH Jobs-app allowlists and in the
    tool catalog (MCP Tool Configuration panel)."""
    src = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    assert len(re.findall(r'^\s*"get_working_days",', src, re.M)) == 2, \
        "get_working_days must be on the server AND personal Jobs-app allowlists"
    cat_src = (_SRC / "mcp_tool_catalog.py").read_text(encoding="utf-8")
    assert "('get_working_days'," in cat_src


def test_WD_17_jobs_app_uses_the_setting_not_a_hard_wired_weekend():
    """The Calendar's R-058 loops must ask _isWorkingDay(), and load the days
    through get_working_days (never the Settings sheet, which field crew
    can't read)."""
    html = (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")
    start = html.index("function _overrunHorizon()")
    block = html[start:html.index("async function loadCalendar()")]
    assert "getDay() === 0 || d.getDay() === 6" not in block
    assert "wd !== 0 && wd !== 6" not in block
    assert block.count("_isWorkingDay(") >= 3
    assert "mcpCall('get_working_days'" in html
    assert "_getSettingValue('Working Days')" not in html


def test_WD_18_saving_the_setting_applies_it_without_a_reload():
    """Vicki 2026-10-02: a change must take effect at once. The server reads
    the setting fresh on every call (no restart); the Jobs app refreshes its
    own copy right after the Settings save, tells the person, and the Route
    tab's day list re-checks the days whenever it is built."""
    html = (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")
    i = html.index("// Working Days (2026-10-02): saving it APPLIES it right away")
    block = html[i:i + 1200]
    assert "await _loadWorkingDays();" in block
    assert "Working Days applied" in block
    assert block.index("_loadWorkingDays") < block.index("closeJobFormModal")
    j = html.index("function _populateRouteDateOptions()")
    assert "_loadWorkingDays().then(" in html[j:j + 1500]


def test_WD_19_server_never_caches_the_setting(db):
    """Two saves in a row, each read straight back — no restart in between."""
    assert _set_days(db, "Mon-Sat").startswith("✅")
    assert w.working_days(db) == MON_SAT
    assert _set_days(db, "Weekdays").startswith("✅")
    assert w.working_days(db) == MON_FRI
