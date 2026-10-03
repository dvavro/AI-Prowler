"""
tests/mcp_tests/test_route_soft_window_and_replan.py
================================================
Two Route-tab changes (2026-09-21):

1. The yellow "outside window" check is for SOFT jobs only and is judged against the
   customer-AGREED window: Original Start/End Time (when both are set), and ONLY that. With no
   original window the job has a full-day window, so it can never be flagged — the current
   Start/End is NOT a fallback, because Approve overwrites it with the routed slot (after
   which "the window" would just be wherever the route had put the job).
   (Server: _soft_window_strs + the SOFT WINDOW VIOLATION warning. Client: jobs/index.html.)

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


def _job(db_path, name, start, duration, kind="soft", end=None, crew="", date=DATE):
    # Job Board Architecture Spec §5.1 (2026-09-22): create_job now requires
    # a real, existing CustomerID.
    cust_result = db_create_customer(db_path, {"Company Name": name}, actor="dave")
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


# ── 1. the soft window is the customer-agreed one ─────────────────────────

def test_window_is_the_original_when_both_originals_are_set():
    job = {"start_time": "08:05", "end_time": "08:35", "original_start_time": "10:00", "original_end_time": "10:30"}
    assert _soft_window_strs(job) == ("10:00", "10:30")


def test_no_original_window_is_no_window_never_the_current_start_end():
    # Current Start/End is deliberately NOT a fallback: Approve overwrites it with the routed slot.
    assert _soft_window_strs({"start_time": "09:00", "end_time": "09:30"}) is None
    assert _soft_window_strs({"start_time": "09:00", "end_time": "09:30",
                              "original_start_time": "10:00", "original_end_time": ""}) is None
    assert _soft_window_strs({"start_time": "09:00", "end_time": "09:30",
                              "original_start_time": "", "original_end_time": "10:30"}) is None
    assert _soft_window_strs({"original_start_time": None, "original_end_time": None}) is None
    assert _soft_window_strs({}) is None


def test_arriving_inside_the_original_window_is_fine_even_after_approve_moved_the_slot(db_path):
    _set_workday_start(db_path, "07:00")
    j = _job(db_path, "Soft", "07:00", 30, "soft", end="07:30")        # customer agreed 07:00-07:30
    _sql(db_path, "UPDATE jobs SET start_time='12:00', end_time='12:30' WHERE job_id = ?", (j,))   # Approve put it at noon
    res = db_apply_route_order(db_path, DATE, j, "", "dave", single_crew=True)
    assert res.startswith("✅ Applied route"), res
    assert _etas(db_path)[j] == "07:00"
    # Judged against the CURRENT (12:00-12:30) slot this would have been flagged, wrongly.
    assert "SOFT WINDOW VIOLATION" not in res


def test_arriving_outside_the_original_window_is_flagged_and_names_the_original(db_path):
    _set_workday_start(db_path, "07:00")
    j = _job(db_path, "Soft", "09:00", 30, "soft", end="09:30")        # customer agreed 09:00-09:30
    _sql(db_path, "UPDATE jobs SET start_time='07:00', end_time='07:30' WHERE job_id = ?", (j,))   # approved slot = arrival
    res = db_apply_route_order(db_path, DATE, j, "", "dave", single_crew=True)
    # Judged against the current slot (07:00-07:30) it would look perfect, wrongly hiding the miss.
    assert "SOFT WINDOW VIOLATION" in res and "09:00–09:30" in res


def test_no_original_window_means_a_full_day_window_so_no_warning_is_possible(db_path):
    """No Original Start/End -> no window at all. The job's CURRENT Start/End (09:00-09:30
    here, and arrival is 07:00 — outside it) must NOT be used as a fallback."""
    _set_workday_start(db_path, "07:00")
    j = _job(db_path, "Old", "09:00", 30, "soft", end="09:30")
    _sql(db_path, "UPDATE jobs SET original_start_time=NULL, original_end_time=NULL WHERE job_id = ?", (j,))
    res = db_apply_route_order(db_path, DATE, j, "", "dave", single_crew=True)
    assert res.startswith("✅ Applied route"), res
    assert _etas(db_path)[j] == "07:00"
    assert "SOFT WINDOW VIOLATION" not in res


def test_a_half_set_original_is_no_window_either(db_path):
    _set_workday_start(db_path, "07:00")
    j = _job(db_path, "Half", "09:00", 30, "soft", end="09:30")
    _sql(db_path, "UPDATE jobs SET original_start_time='09:00', original_end_time=NULL WHERE job_id = ?", (j,))
    res = db_apply_route_order(db_path, DATE, j, "", "dave", single_crew=True)
    assert "SOFT WINDOW VIOLATION" not in res


def test_hard_jobs_never_get_the_soft_warning(db_path):
    _set_workday_start(db_path, "07:00")
    j = _job(db_path, "Hard", "10:00", 30, "hard")
    _sql(db_path, "UPDATE jobs SET original_start_time='06:00', original_end_time='06:30' WHERE job_id = ?", (j,))
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


def test_the_tool_replans_and_refreshes_the_saved_phone_link(tmp_path, monkeypatch, mcp_mod):
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
    assert "📍 Phone route link saved" in out


def test_the_tool_is_registered_and_on_both_phone_allow_lists(mcp_mod):
    assert hasattr(mcp_mod, "replan_route_day")
    src = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    assert src.count('"replan_route_day"') >= 2          # personal-mode + server-mode allow-list


_HTML = (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")


def test_client_yellow_check_uses_the_agreed_window_and_only_for_soft_jobs():
    assert "s._softViolation = false;" in _HTML
    assert "if (!s._hard && s._jobId && s._winStart && s._winEnd && arrivalMin !== null)" in _HTML
    # the old check compared against the current (possibly approved) Start/End
    assert "!s._hard && s._jobId && s._committedStart && s._committedEnd" not in _HTML
    # no original window -> NO window (full-day), never a fallback to the current Start/End
    assert "s._winStart = (_oS && _oE) ? _oS : '';" in _HTML
    assert "s._winEnd   = (_oS && _oE) ? _oE : '';" in _HTML
    assert "? _oS : s._committedStart" not in _HTML
    # and the row says so instead of showing a made-up slot
    assert "'Any time'" in _HTML


def test_client_route_rows_have_an_edit_button_that_replans_after_save():
    assert "routeEditJob(" in _HTML and "class=\"route-stop-edit\"" in _HTML
    assert "mcpCall('replan_route_day'" in _HTML
    assert "if (returnToRoute)" in _HTML and "window._jfReturnTo = 'route';" in _HTML
    assert "_mergeIntoSheetJobsCache(jobRows);" in _HTML
