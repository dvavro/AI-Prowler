"""
tests/mcp_tests/test_route_soft_window_and_replan.py
================================================
Two Route-tab changes:

1. (2026-10-05, David's rule) The yellow "outside window" check is for SOFT
   jobs only and is judged ONLY against the CUSTOMER's preferred time
   window (Pref. Time Start/End on the customer record) — never the job's
   Start/End Time, which is a scheduled slot, not a constraint. A customer
   with no preferred window set has no constraint: no warning can fire.
   Either end may be blank (a partial window like "before 10:00 AM"
   constrains only its set end).
   (Server: _soft_window_strs + the SOFT WINDOW VIOLATION warning. Client:
   jobs/index.html.)

2. Editing a job from a Route stop (✏️) re-plans the day IN ITS CURRENT ORDER
   (db_replan_current_order / the replan_route_day tool) so every stop's time reflects the
   edit — without changing the visit order, and dropping (not deleting) jobs the edit moved
   off that day/crew.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest
import requests

from db_access import init_db
from db_write_ops import db_create_customer, db_create_job
from db_route_ops import db_apply_route_order, db_replan_current_order, _soft_window_strs
import db_write_ops as write_ops

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

DATE = "2026-09-22"
NEXT_DAY = "2026-09-23"


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


@pytest.fixture(autouse=True)
def _no_real_home_address(monkeypatch):
    monkeypatch.setattr(write_ops, "db_read_owner_home_address", lambda: "")


class _FakeResponse:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


@pytest.fixture(autouse=True)
def _osrm(monkeypatch):
    """Every drive leg is 5 minutes."""
    def fake_get(url, *a, **k):
        assert "router.project-osrm.org/route" in url, url
        return _FakeResponse({"code": "Ok", "routes": [{"legs": [{"duration": 300}]}]})
    monkeypatch.setattr(requests, "get", fake_get)


def _job(db_path, name, start, duration, kind="soft", end=None, crew="", date=DATE,
         cust_pref_start="", cust_pref_end=""):
    # Job Board Architecture Spec §5.1 (2026-09-22): create_job now requires
    # a real, existing CustomerID.
    cust_fields = {"Company Name": name}
    if cust_pref_start:
        cust_fields["Pref. Time Start"] = cust_pref_start
    if cust_pref_end:
        cust_fields["Pref. Time End"] = cust_pref_end
    cust_result = db_create_customer(db_path, cust_fields, actor="dave")
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    fields = {
        "CustomerID (Customers!A)": cust_id,
        "Customer Name / Company": name, "Service Date": date,
        "Street Address": f"{name} St", "City": "NSB", "State": "FL",
        "Schedule Type (Hard/Soft)": kind, "Start Time": start,
        "Est. Duration": duration, "Est. Duration Unit": "min",
        "Latitude (AI Geocode)": 29.0, "Longitude (AI Geocode)": -80.9,
    }
    if end:
        fields["End Time"] = end
    if crew:
        fields["Crew / Technician"] = crew
    out = db_create_job(db_path, fields, actor="dave")
    return out.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _sql(db_path, sql, params=()):
    conn = sqlite3.connect(db_path)
    conn.execute(sql, params)
    conn.commit()
    conn.close()


def _set_workday_start(db_path, hhmm="07:00"):
    _sql(db_path,
         "INSERT INTO settings (key, value, last_edited_by, last_edited_at) VALUES ('Workday Start Time', ?, 'dave', '2026-01-01T00:00:00Z') "
         "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (hhmm,))


def _stops(db_path, date=DATE):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM route_stops WHERE route_date = ? ORDER BY stop_number", (date,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _order(db_path):
    return [r["job_id"] for r in _stops(db_path) if r["job_id"]]


def _etas(db_path):
    return {r["job_id"]: r["eta"] for r in _stops(db_path) if r["job_id"]}


def _mins(hhmm):
    h, m = hhmm.split(":")[:2]
    return int(h) * 60 + int(m)


# ── 1. the soft window is the CUSTOMER's preferred window (2026-10-05) ──


def test_window_comes_from_customer_preferred_window_not_job_times():
    job = {"start_time": "08:05", "end_time": "08:35",
           "cust_pref_start": "10:00 AM", "cust_pref_end": "10:30 AM"}
    assert _soft_window_strs(job) == ("10:00 AM", "10:30 AM")


def test_blank_customer_window_is_no_window_even_with_job_times():
    # David's rule: the job's Start/End is a scheduled slot, not a constraint.
    assert _soft_window_strs({"start_time": "09:00", "end_time": "09:30"}) is None
    assert _soft_window_strs({"start_time": "09:00", "end_time": "09:30",
                              "cust_pref_start": "", "cust_pref_end": ""}) is None
    assert _soft_window_strs({}) is None


def test_partial_customer_window_constrains_only_its_set_end():
    # "before 10:00 AM" — only the end constrains.
    assert _soft_window_strs({"cust_pref_start": "", "cust_pref_end": "10:00 AM"}) == ("", "10:00 AM")
    assert _soft_window_strs({"cust_pref_start": "7:00 AM", "cust_pref_end": ""}) == ("7:00 AM", "")


def test_arriving_inside_customer_window_is_fine(db_path):
    _set_workday_start(db_path, "07:00")
    j = _job(db_path, "Soft", "09:00", 30, "soft", end="09:30",
             cust_pref_start="7:00 AM", cust_pref_end="10:00 AM")
    res = db_apply_route_order(db_path, DATE, j, "", "dave", single_crew=True)
    assert res.startswith("✅ Applied route"), res
    assert "SOFT WINDOW VIOLATION" not in res


def test_arriving_outside_customer_window_is_flagged(db_path):
    _set_workday_start(db_path, "07:00")
    # Customer window 7:00-10:00 AM; the route cannot arrive before 07:00
    # (workday start), so force lateness by making the job's duration push
    # a second stop past the window — simpler: single job, workday starts
    # at 11:00 so arrival (11:00) is outside the 7:00-10:00 window.
    _set_workday_start(db_path, "11:00")
    j = _job(db_path, "Soft", "09:00", 30, "soft", end="09:30",
             cust_pref_start="7:00 AM", cust_pref_end="10:00 AM")
    res = db_apply_route_order(db_path, DATE, j, "", "dave", single_crew=True)
    assert "SOFT WINDOW VIOLATION" in res and "7:00 AM" in res


def test_job_times_alone_never_trigger_a_warning(db_path):
    # The reported bug: customer has NO preferred window, job has a scheduled
    # slot (09:00-09:30), arrival falls outside that slot — must NOT warn.
    _set_workday_start(db_path, "11:00")
    j = _job(db_path, "NoWin", "09:00", 30, "soft", end="09:30")
    res = db_apply_route_order(db_path, DATE, j, "", "dave", single_crew=True)
    assert res.startswith("✅ Applied route"), res
    assert "SOFT WINDOW VIOLATION" not in res


def test_partial_window_before_end_flags_late_arrival(db_path):
    _set_workday_start(db_path, "11:00")
    j = _job(db_path, "Before", "09:00", 30, "soft", end="09:30",
             cust_pref_end="10:00 AM")
    res = db_apply_route_order(db_path, DATE, j, "", "dave", single_crew=True)
    assert "SOFT WINDOW VIOLATION" in res


def test_hard_jobs_never_get_the_soft_warning(db_path):
    _set_workday_start(db_path, "07:00")
    j = _job(db_path, "Hard", "10:00", 30, "hard",
             cust_pref_start="7:00 AM", cust_pref_end="10:00 AM")
    res = db_apply_route_order(db_path, DATE, j, "", "dave", single_crew=True)
    assert "SOFT WINDOW VIOLATION" not in res


# ── 2. re-plan the day in its current order ───────────────────────────────

@pytest.fixture
def day(db_path):
    j1 = _job(db_path, "Riverside", "07:15", 45, "soft", end="08:00")
    j2 = _job(db_path, "Faulkner", "08:00", 60, "hard")
    j3 = _job(db_path, "StateRd", "09:15", 45, "hard")
    j4 = _job(db_path, "PineTree", "10:00", 30, "soft", end="10:30")
    assert db_apply_route_order(db_path, DATE, ",".join([j1, j2, j3, j4]), "", "dave",
                                single_crew=True).startswith("✅ Applied route")
    return j1, j2, j3, j4


def test_replan_keeps_the_order_and_repairs_stale_times(db_path, day):
    j1, j2, j3, j4 = day
    good = _etas(db_path)
    # the live bug: stops 3 and 4 saved with bad arrivals
    _sql(db_path, "UPDATE route_stops SET eta='08:05' WHERE job_id IN (?, ?)", (j3, j4))
    assert _etas(db_path) != good

    res = db_replan_current_order(db_path, DATE, "", "dave")
    assert res.startswith("✅ Re-planned the day"), res
    assert _order(db_path) == [j1, j2, j3, j4]          # order untouched
    assert _etas(db_path) == good                        # times recomputed correctly


def test_a_longer_job_shifts_everything_after_it(db_path, day):
    j1, j2, j3, j4 = day
    before = _etas(db_path)
    _sql(db_path, "UPDATE jobs SET est_duration = 120 WHERE job_id = ?", (j2,))   # Faulkner now takes 2 hours
    res = db_replan_current_order(db_path, DATE, "", "dave")
    after = _etas(db_path)
    assert _order(db_path) == [j1, j2, j3, j4]
    assert after[j1] == before[j1] and after[j2] == before[j2]                   # earlier stops unchanged
    assert _mins(after[j3]) >= _mins(before[j2]) + 120                           # StateRd can't start before Faulkner ends
    assert "HARD TIME VIOLATION" in res and j3 in res                            # and now it's late, and says so


def test_a_job_moved_to_another_day_is_dropped_not_deleted(db_path, day):
    j1, j2, j3, j4 = day
    _sql(db_path, "UPDATE jobs SET service_date = ? WHERE job_id = ?", (NEXT_DAY, j4))
    res = db_replan_current_order(db_path, DATE, "", "dave")
    assert res.startswith("✅ Re-planned the day"), res
    assert _order(db_path) == [j1, j2, j3]
    assert "No longer on this route" in res and j4 in res
    conn = sqlite3.connect(db_path)
    assert conn.execute("SELECT service_date FROM jobs WHERE job_id = ?", (j4,)).fetchone()[0] == NEXT_DAY   # job itself untouched
    conn.close()


def test_jobs_never_on_the_route_are_not_reported_or_added(db_path, day):
    _job(db_path, "LateAdd", "13:00", 30, "soft")
    res = db_replan_current_order(db_path, DATE, "", "dave")
    assert "NOT PLACED" not in res
    assert len(_order(db_path)) == 4


def test_no_stored_route_is_a_clear_no_op(db_path):
    assert db_replan_current_order(db_path, DATE, "", "dave").startswith("✅ No route is stored")


def test_server_mode_scopes_to_the_crew_and_field_crew_only_replan_their_own(db_path):
    a = _job(db_path, "A", "08:00", 30, crew="Jake")
    b = _job(db_path, "B", "09:00", 30, crew="Jake")
    db_apply_route_order(db_path, DATE, f"{a},{b}", "Jake", "dave", single_crew=False)
    denied = db_replan_current_order(db_path, DATE, "", "sam", is_server_mode=True, restrict=True, crew_name="sam")
    assert denied.startswith("❌") and "own route" in denied
    # same convention as reorder_route_stop: a matching caller passes crew_name pre-lowercased
    ok = db_replan_current_order(db_path, DATE, "", "jake", is_server_mode=True, restrict=True, crew_name="jake")
    assert ok.startswith("✅ Re-planned the day"), ok
    other = db_replan_current_order(db_path, DATE, "Nobody", "dave", is_server_mode=True)
    assert other.startswith("✅ No route") or other.strip() == ""


# ── 3. the tool + the phone app ───────────────────────────────────────────

@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


def test_the_tool_replans_without_publishing_the_phone_link(tmp_path, monkeypatch, mcp_mod):
    """2026-10-05: the tap-to-navigate link is NO LONGER published by routing
    tools — only an APPROVED route gets its link pinned (see
    approve_route_schedule). Re-plan recomputes the times but leaves link
    pinning to the approve step, so the 📍 note must NOT appear here."""

    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(tmp_path / "x.xlsx"))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    monkeypatch.setattr(mcp_mod, "_get_personal_owner_address", lambda: {})
    def make(name, street, start):
        cust_result = mcp_mod.create_customer({"Company Name": name}, filepath="", backup=False, ctx=None)
        cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
        out = mcp_mod.create_job({
            "CustomerID": cust_id, "Customer Name / Company": name, "Service Date": DATE, "Street Address": street, "City": "NSB", "State": "FL",
            "Start Time": start, "Est. Duration": 30, "Est. Duration Unit": "min",
            "Latitude (AI Geocode)": 29.0, "Longitude (AI Geocode)": -80.9,
        }, filepath="", backup=False, ctx=None)
        return out.split("NEW_JOB_ID=")[1].splitlines()[0].strip()
    a = make("Alpha", "1 Alpha St", "08:00")
    b = make("Bravo", "2 Bravo St", "09:00")
    assert "Applied route" in mcp_mod.apply_route_order(DATE, f"{a},{b}", ctx=None)
    out = mcp_mod.replan_route_day(DATE, ctx=None)
    assert out.startswith("✅ Re-planned the day"), out
    assert "07:00" in out and "07:35" in out   # times recomputed in current order
    assert "📍 Phone route link saved" not in out   # approve-only since 2026-10-05


def test_the_tool_is_registered_and_on_both_phone_allow_lists(mcp_mod):
    assert hasattr(mcp_mod, "replan_route_day")
    src = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    assert src.count('"replan_route_day"') >= 2          # personal-mode + server-mode allow-list


_HTML = (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")


def test_client_yellow_check_uses_the_agreed_window_and_only_for_soft_jobs():
    assert "s._softViolation = false;" in _HTML
    # 2026-10-06: refactored to the customer-window fields with partial-window
    # support — EITHER end set is enough (a "before X"/"after X" window
    # constrains only its set end).
    assert "if (!s._hard && s._jobId && (s._custWinStart || s._custWinEnd) && arrivalMin !== null)" in _HTML
    # the yellow window comes from the CUSTOMER's Pref. Time Start/End — never
    # the job's own (possibly approved) Start/End, never Original Start/End.
    assert "s._custWinStart = _cwS;" in _HTML
    assert "s._custWinEnd = _cwE;" in _HTML
    assert "_cust['Pref. Time Start']" in _HTML and "_cust['Pref. Time End']" in _HTML
    assert "? _cwS : s._committedStart" not in _HTML
    assert "? _cwS : s._winStart" not in _HTML
    # and the row says so instead of showing a made-up slot
    assert "'Any time'" in _HTML


def test_client_route_rows_have_an_edit_button_that_replans_after_save():
    assert "routeEditJob(" in _HTML and "class=\"route-stop-edit\"" in _HTML
    assert "mcpCall('replan_route_day'" in _HTML
    assert "if (returnToRoute)" in _HTML and "window._jfReturnTo = 'route';" in _HTML
    assert "_mergeIntoSheetJobsCache(jobRows);" in _HTML
