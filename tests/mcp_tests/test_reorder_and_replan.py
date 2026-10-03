"""
tests/mcp_tests/test_reorder_and_replan.py
=====================================
Route tab drag-and-drop / ▲▼ now RE-PLANS THE WHOLE DAY (db_reorder_and_replan),
instead of re-timing only the moved stops with drive time alone.

The live bug (2026-09-21): swapping stops 3 and 4 gave BOTH an 8:05 arrival — stop 2's
8:01 plus a 4-minute drive, ignoring stop 2's hour-long job — which lit up red/yellow
"off schedule" flags, and swapping them back did NOT clear the flags because they were
re-timed the same wrong way instead of restoring the original plan.

What these lock in:
  * after a move, every stop's time accounts for how long the jobs before it take;
  * MOVE AND MOVE BACK returns exactly the original times (order alone decides them);
  * jobs that aren't on the route are neither added nor reported as "NOT PLACED";
  * validation / no-op / crew scoping unchanged; falls back to the narrow nudge for a
    non-job stop or a day that can't be re-planned;
  * the MCP tool refreshes the saved phone link to follow the new order.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest
import requests

from db_access import init_db
from db_write_ops import db_create_customer, db_create_job
from db_route_ops import db_apply_route_order, db_reorder_and_replan
import db_write_ops as write_ops

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

DATE = "2026-09-22"


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


@pytest.fixture(autouse=True)
def _no_real_home_address(monkeypatch):
    # Same isolation guard as the other route tests: never read this machine's real config.
    monkeypatch.setattr(write_ops, "db_read_owner_home_address", lambda: "")


class _FakeResponse:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


@pytest.fixture(autouse=True)
def _osrm(monkeypatch):
    """Every drive leg is 5 minutes, whatever the coordinates."""
    def fake_get(url, *a, **k):
        assert "router.project-osrm.org/route" in url, url
        return _FakeResponse({"code": "Ok", "routes": [{"legs": [{"duration": 300}]}]})
    monkeypatch.setattr(requests, "get", fake_get)


def _job(db_path, name, start, duration, kind="soft", end=None, lat=29.0, lon=-80.9):
    cust_result = db_create_customer(db_path, {"Company Name": name}, actor="dave")
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    fields = {
        "CustomerID (Customers!A)": cust_id,
        "Customer Name / Company": name, "Service Date": DATE,
        "Street Address": f"{name} St", "City": "NSB", "State": "FL",
        "Schedule Type (Hard/Soft)": kind, "Start Time": start,
        "Est. Duration": duration, "Est. Duration Unit": "min",
        "Latitude (AI Geocode)": lat, "Longitude (AI Geocode)": lon,
    }
    if end:
        fields["End Time"] = end
    out = db_create_job(db_path, fields, actor="dave")
    return out.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _stops(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM route_stops WHERE route_date = ? ORDER BY stop_number",
                        (DATE,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _order(db_path):
    return [r["job_id"] for r in _stops(db_path) if r["job_id"]]


def _etas(db_path):
    return {r["job_id"]: r["eta"] for r in _stops(db_path) if r["job_id"]}


def _stop_id(db_path, job_id):
    return next(r["id"] for r in _stops(db_path) if r["job_id"] == job_id)


def _mins(hhmm):
    h, m = hhmm.split(":")[:2]
    return int(h) * 60 + int(m)


@pytest.fixture
def day(db_path):
    """The shape of the day in the screenshot: soft, hard, hard, soft-window, hard."""
    j1 = _job(db_path, "Riverside", "07:15", 45, "soft", end="08:00")
    j2 = _job(db_path, "Faulkner", "08:00", 60, "hard")
    j3 = _job(db_path, "StateRd", "09:15", 45, "hard")
    j4 = _job(db_path, "PineTree", "10:00", 30, "soft", end="10:30")
    j5 = _job(db_path, "Canal", "11:30", 90, "hard")
    res = db_apply_route_order(db_path, DATE, ",".join([j1, j2, j3, j4, j5]), "", "dave", single_crew=True)
    assert res.startswith("✅ Applied route"), res
    return j1, j2, j3, j4, j5


# ── the bug ───────────────────────────────────────────────────────────────

def test_swapping_two_stops_still_counts_how_long_each_job_takes(db_path, day):
    j1, j2, j3, j4, j5 = day
    res = db_reorder_and_replan(db_path, _stop_id(db_path, j4), 3, "dave")
    assert res.startswith("✅ Moved stop and re-planned"), res
    assert _order(db_path) == [j1, j2, j4, j3, j5]
    eta = _etas(db_path)
    # The old code gave stop 3 an arrival of (stop 2's arrival + drive) — under 10 minutes
    # later. Stop 2 is a 60-minute job, so the next stop can't start before it's done.
    assert _mins(eta[j4]) >= _mins(eta[j2]) + 60
    assert _mins(eta[j3]) >= _mins(eta[j4]) + 30


def test_move_then_move_back_restores_the_original_times(db_path, day):
    """The user's exact complaint: they swapped 3 and 4, swapped back, and the flags stayed."""
    j1, j2, j3, j4, j5 = day
    original_order, original_etas = _order(db_path), _etas(db_path)

    db_reorder_and_replan(db_path, _stop_id(db_path, j4), 3, "dave")           # swap 3 <-> 4
    assert _order(db_path) != original_order
    assert _etas(db_path) != original_etas

    db_reorder_and_replan(db_path, _stop_id(db_path, j3), 3, "dave")           # swap them back
    assert _order(db_path) == original_order
    assert _etas(db_path) == original_etas                                       # identical, not "drifted"


def test_moving_the_same_way_twice_is_stable(db_path, day):
    j1, j2, j3, j4, j5 = day
    db_reorder_and_replan(db_path, _stop_id(db_path, j4), 3, "dave")
    once = (_order(db_path), _etas(db_path))
    # dragging j3 to where it already is changes nothing
    res = db_reorder_and_replan(db_path, _stop_id(db_path, j3), 4, "dave")
    assert "already at position" in res
    assert (_order(db_path), _etas(db_path)) == once


def test_jobs_not_on_the_route_are_not_added_or_reported(db_path, day):
    j1, j2, j3, j4, j5 = day
    _job(db_path, "Late Add", "13:00", 30, "soft")           # exists that day, was never routed
    res = db_reorder_and_replan(db_path, _stop_id(db_path, j4), 3, "dave")
    assert "NOT PLACED" not in res
    assert len(_order(db_path)) == 5                          # still only the five routed jobs


# ── validation, scoping, fallbacks ────────────────────────────────────────

def test_unknown_stop_and_bad_position(db_path, day):
    assert db_reorder_and_replan(db_path, 99999, 1, "dave").startswith("❌ No route stop found")
    sid = _stop_id(db_path, day[0])
    assert db_reorder_and_replan(db_path, sid, "x", "dave").startswith("❌ new_position must be a whole number")
    assert db_reorder_and_replan(db_path, sid, 0, "dave").startswith("❌ new_position must be 1")


def test_position_past_the_end_is_clamped_to_last(db_path, day):
    j1, j2, j3, j4, j5 = day
    res = db_reorder_and_replan(db_path, _stop_id(db_path, j1), 99, "dave")
    assert res.startswith("✅ Moved stop"), res
    assert _order(db_path)[-1] == j1


def test_field_crew_cannot_move_a_coworkers_stop(db_path):
    a = _job(db_path, "A", "08:00", 30)
    b = _job(db_path, "B", "09:00", 30)
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE jobs SET crew = 'Jake' WHERE job_id IN (?, ?)", (a, b))
    conn.commit()
    conn.close()
    db_apply_route_order(db_path, DATE, f"{a},{b}", "Jake", "dave", single_crew=False)
    sid = _stop_id(db_path, a)
    res = db_reorder_and_replan(db_path, sid, 2, "sam", restrict=True, crew_name="Sam", is_server_mode=True)
    assert res.startswith("❌") and "own route" in res
    # (same convention as db_reorder_route_stop: a matching caller passes crew_name pre-lowercased)
    ok = db_reorder_and_replan(db_path, sid, 2, "jake", restrict=True, crew_name="jake", is_server_mode=True)
    assert ok.startswith("✅ Moved stop"), ok


def test_a_stop_with_no_job_falls_back_to_the_narrow_nudge(db_path):
    conn = sqlite3.connect(db_path)
    for n in (1, 2, 3):
        conn.execute(
            "INSERT INTO route_stops (route_date, crew_id, stop_number, job_id, address, latitude, longitude, eta, "
            "created_by, last_edited_by, last_edited_at, version) VALUES (?, '', ?, NULL, ?, 29.0, -80.9, ?, "
            "'seed', 'seed', '2026-01-01T00:00:00Z', 1)",
            (DATE, n, f"Stop {n}", f"08:{n * 10:02d}"),
        )
    conn.commit()
    conn.close()
    sid = _stops(db_path)[2]["id"]
    res = db_reorder_and_replan(db_path, sid, 1, "dave")
    assert res.startswith("✅") and "re-planned" not in res
    assert [r["address"] for r in _stops(db_path)] == ["Stop 3", "Stop 1", "Stop 2"]


def test_a_day_that_cannot_be_replanned_falls_back(db_path):
    """Route rows that point at jobs which no longer exist can't go through the planner."""
    conn = sqlite3.connect(db_path)
    for n, jid in ((1, "JOB-9001"), (2, "JOB-9002")):
        conn.execute(
            "INSERT INTO route_stops (route_date, crew_id, stop_number, job_id, address, latitude, longitude, eta, "
            "created_by, last_edited_by, last_edited_at, version) VALUES (?, '', ?, ?, ?, 29.0, -80.9, ?, "
            "'seed', 'seed', '2026-01-01T00:00:00Z', 1)",
            (DATE, n, jid, f"Addr {n}", f"08:{n * 10:02d}"),
        )
    conn.commit()
    conn.close()
    sid = _stops(db_path)[1]["id"]
    res = db_reorder_and_replan(db_path, sid, 1, "dave")
    assert res.startswith("✅") and "re-planned" not in res           # narrow nudge did it
    assert [r["job_id"] for r in _stops(db_path)] == ["JOB-9002", "JOB-9001"]


# ── the MCP tool ──────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


def test_the_tool_uses_the_replan_and_refreshes_the_saved_phone_link(tmp_path, monkeypatch, mcp_mod):
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(tmp_path / "x.xlsx"))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    monkeypatch.setattr(mcp_mod, "_get_personal_owner_address", lambda: {})
    db = str(tmp_path / "ai_prowler_jobs.db")

    def make(name, street, start, dur):
        cust_result = mcp_mod.create_customer({"Company Name": name}, filepath="", backup=False, ctx=None)
        cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
        out = mcp_mod.create_job({
            "CustomerID": cust_id, "Customer Name / Company": name, "Service Date": DATE, "Street Address": street,
            "City": "NSB", "State": "FL", "Start Time": start, "Est. Duration": dur, "Est. Duration Unit": "min",
            "Latitude (AI Geocode)": 29.0, "Longitude (AI Geocode)": -80.9,
        }, filepath="", backup=False, ctx=None)
        return out.split("NEW_JOB_ID=")[1].splitlines()[0].strip()

    a = make("Alpha", "1 Alpha St", "08:00", 30)
    b = make("Bravo", "2 Bravo St", "09:00", 30)
    c = make("Charlie", "3 Charlie St", "10:00", 30)
    res = mcp_mod.apply_route_order(DATE, f"{a},{b},{c}", ctx=None)
    assert "Applied route" in res
    before = sqlite3.connect(db).execute("SELECT route_map_url FROM jobs WHERE job_id = ?", (a,)).fetchone()[0]

    out = mcp_mod.reorder_route_stop(str(_stop_id(db, c)), 1, ctx=None)
    assert out.startswith("✅ Moved stop and re-planned"), out
    assert "📍 Phone route link saved" in out
    after = sqlite3.connect(db).execute("SELECT route_map_url FROM jobs WHERE job_id = ?", (a,)).fetchone()[0]
    assert after and after != before                        # the link follows the new order
    assert _order(db) == [c, a, b]
