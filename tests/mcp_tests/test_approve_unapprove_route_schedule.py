"""
tests/mcp_tests/test_approve_unapprove_route_schedule.py
====================================================
Mileage/routing follow-up (2026-09-20). Covers db_approve_route_schedule
and db_unapprove_route_schedule — the Route tab's two dedicated Approve/
Un-approve buttons, replacing the old client-side update_job_spreadsheet
loop that had no way back once a soft job's Start/End Time was
overwritten.

Core guarantee under test: Original Start Time/Original End Time are an
ordinary, independently-editable field pair (same mechanism as any other
column) that NEITHER approve nor unapprove ever writes to — only a
genuine manual edit (update_job_spreadsheet) or job creation itself sets
them. This is what makes any number of approve/un-approve round trips,
in either order, always land back on the customer's real agreed schedule.

Run with:
    run_tests.bat tests\\mcp\\test_approve_unapprove_route_schedule.py -v
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from db_access import init_db
from db_write_ops import db_create_customer, db_create_job, db_update_job
from db_route_ops import db_approve_route_schedule, db_unapprove_route_schedule

ROUTE_DATE = "2026-09-22"


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _job_id(create_result: str) -> str:
    return create_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _create_job(db_path, customer="Cust", start="08:00", end="09:00",
                 schedule_type="soft", duration=60, duration_unit="min", crew="Jake"):
    # Job Board Architecture Spec §5.1 (2026-09-22): create_job now requires
    # a real, existing CustomerID.
    cust_result = db_create_customer(db_path, {"Company Name": customer}, actor="dave")
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    fields = {
        "CustomerID (Customers!A)": cust_id,
        "Customer Name / Company": customer,
        "Service Date": ROUTE_DATE,
        "Street Address": "1 Main St", "City": "NSB", "State": "FL",
        "Start Time": start, "End Time": end,
        "Schedule Type (Hard/Soft)": schedule_type,
        "Est. Duration": duration, "Est. Duration Unit": duration_unit,
        "Crew / Technician": crew,
    }
    return _job_id(db_create_job(db_path, fields, actor="dave"))


def _seed_route_stop(db_path, job_id, eta, crew="Jake", route_date=ROUTE_DATE, stop_number=1):
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO route_stops (route_date, crew_id, stop_number, job_id, address, "
        "latitude, longitude, eta, created_by, last_edited_by, last_edited_at, version) "
        "VALUES (?, ?, ?, ?, 'x', 29.0, -80.9, ?, 'seed', 'seed', '2026-01-01T00:00:00Z', 1)",
        (route_date, crew, stop_number, job_id, eta),
    )
    conn.commit()
    conn.close()


def _get_job(db_path, job_id):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    conn.close()
    return dict(row)


# ── db_approve_route_schedule ───────────────────────────────────────────

def test_approve_pushes_eta_and_computed_end_time(db_path):
    job = _create_job(db_path, start="08:00", end="08:30", duration=45)
    _seed_route_stop(db_path, job, eta="09:15")

    result = db_approve_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert result.startswith("✅"), result
    assert job in result

    row = _get_job(db_path, job)
    assert row["start_time"] == "09:15"
    assert row["end_time"] == "10:00"  # 09:15 + 45 min


def test_approve_never_touches_original_start_end_time(db_path):
    """The core guarantee: approving a route must never change what the
    customer was actually told."""
    job = _create_job(db_path, start="08:00", end="08:30", duration=30)
    row_before = _get_job(db_path, job)
    assert row_before["original_start_time"] == "08:00"
    assert row_before["original_end_time"] == "08:30"

    _seed_route_stop(db_path, job, eta="11:00")
    result = db_approve_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert result.startswith("✅"), result

    row_after = _get_job(db_path, job)
    assert row_after["start_time"] == "11:00"  # changed
    assert row_after["original_start_time"] == "08:00"  # untouched
    assert row_after["original_end_time"] == "08:30"  # untouched


def test_approve_skips_hard_jobs_entirely(db_path):
    job = _create_job(db_path, start="08:00", end="09:00", schedule_type="hard")
    _seed_route_stop(db_path, job, eta="11:00")

    result = db_approve_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert result.startswith("✅"), result
    assert "hard job" in result.lower()

    row = _get_job(db_path, job)
    assert row["start_time"] == "08:00"  # unchanged — never approved
    assert row["end_time"] == "09:00"


def test_approve_nothing_to_do_message_when_no_route(db_path):
    result = db_approve_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert result.startswith("✅"), result
    assert "nothing to approve" in result.lower()


def test_approve_respects_crew_filter(db_path):
    jake_job = _create_job(db_path, customer="Jake's", crew="Jake")
    maria_job = _create_job(db_path, customer="Maria's", crew="Maria")
    _seed_route_stop(db_path, jake_job, eta="10:00", crew="Jake")
    _seed_route_stop(db_path, maria_job, eta="12:00", crew="Maria")

    result = db_approve_route_schedule(db_path, ROUTE_DATE, "Jake", actor="dave")
    assert result.startswith("✅"), result
    assert jake_job in result
    assert maria_job not in result

    assert _get_job(db_path, jake_job)["start_time"] == "10:00"
    assert _get_job(db_path, maria_job)["start_time"] == "08:00"  # untouched


# ── db_unapprove_route_schedule ─────────────────────────────────────────

def test_unapprove_reverts_to_original(db_path):
    job = _create_job(db_path, start="07:00", end="07:45", duration=45)
    _seed_route_stop(db_path, job, eta="11:00")
    db_approve_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert _get_job(db_path, job)["start_time"] == "11:00"  # confirm approve worked

    result = db_unapprove_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert result.startswith("↩️"), result
    assert job in result

    row = _get_job(db_path, job)
    assert row["start_time"] == "07:00"
    assert row["end_time"] == "07:45"
    # Original itself is still intact after reverting to it.
    assert row["original_start_time"] == "07:00"
    assert row["original_end_time"] == "07:45"


def test_unapprove_skips_hard_jobs(db_path):
    job = _create_job(db_path, start="08:00", end="09:00", schedule_type="hard")
    result = db_unapprove_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert result.startswith("↩️"), result
    assert "hard job" in result.lower()
    assert _get_job(db_path, job)["start_time"] == "08:00"


def test_unapprove_works_without_any_route_stops(db_path):
    """The real design point: un-approve operates on jobs SCHEDULED that
    date, not on whatever's currently in route_stops — so it still works
    even if the route was since rebuilt or deleted."""
    job = _create_job(db_path, start="07:00", end="07:45")
    # Simulate a prior approval having changed Start/End Time directly,
    # with no route_stops row present at all right now.
    db_update_job(db_path, job, {"Start Time": "13:00", "End Time": "13:45"}, actor="dave")
    assert _get_job(db_path, job)["start_time"] == "13:00"

    result = db_unapprove_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert result.startswith("↩️"), result
    row = _get_job(db_path, job)
    assert row["start_time"] == "07:00"
    assert row["end_time"] == "07:45"


def test_unapprove_reports_job_with_no_recorded_original(db_path):
    job = _create_job(db_path, start="07:00", end="07:45")
    # Wipe Original Start Time directly, simulating a job created before
    # this feature existed on an install that hasn't backfilled yet.
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE jobs SET original_start_time = NULL, original_end_time = NULL WHERE job_id = ?", (job,))
    conn.commit()
    conn.close()

    result = db_unapprove_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert result.startswith("↩️"), result
    assert "no recorded original" in result.lower()
    assert job in result
    # Left untouched, not blanked.
    assert _get_job(db_path, job)["start_time"] == "07:00"


def test_unapprove_respects_crew_filter(db_path):
    jake_job = _create_job(db_path, customer="Jake's", crew="Jake", start="07:00", end="07:30")
    maria_job = _create_job(db_path, customer="Maria's", crew="Maria", start="09:00", end="09:30")
    for j in (jake_job, maria_job):
        db_update_job(db_path, j, {"Start Time": "15:00"}, actor="dave")

    result = db_unapprove_route_schedule(db_path, ROUTE_DATE, "Jake", actor="dave")
    assert result.startswith("↩️"), result
    assert jake_job in result
    assert maria_job not in result
    assert _get_job(db_path, jake_job)["start_time"] == "07:00"
    assert _get_job(db_path, maria_job)["start_time"] == "15:00"  # untouched


# ── Round trip: the actual scenario this feature exists for ────────────

def test_multiple_approve_unapprove_cycles_never_lose_the_original(db_path):
    """The literal trial-and-error workflow this was built for: approve a
    route, decide it's wrong, un-approve, try a different route, approve
    again, un-approve again — Original Start/End Time must never drift."""
    job = _create_job(db_path, start="08:00", end="08:45", duration=45)

    _seed_route_stop(db_path, job, eta="10:00")
    db_approve_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert _get_job(db_path, job)["start_time"] == "10:00"

    db_unapprove_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert _get_job(db_path, job)["start_time"] == "08:00"

    # A second, different trial route.
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM route_stops WHERE route_date = ?", (ROUTE_DATE,))
    conn.commit()
    conn.close()
    _seed_route_stop(db_path, job, eta="13:30")
    db_approve_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert _get_job(db_path, job)["start_time"] == "13:30"

    db_unapprove_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    final = _get_job(db_path, job)
    assert final["start_time"] == "08:00"
    assert final["end_time"] == "08:45"
    assert final["original_start_time"] == "08:00"
    assert final["original_end_time"] == "08:45"


# ── db_create_job defaulting Original from Start/End Time ──────────────

def test_create_job_defaults_original_from_start_end_time(db_path):
    job = _create_job(db_path, start="09:00", end="09:30")
    row = _get_job(db_path, job)
    assert row["original_start_time"] == "09:00"
    assert row["original_end_time"] == "09:30"


def test_create_job_respects_explicit_original_if_given(db_path):
    cust_result = db_create_customer(db_path, {"Company Name": "X"}, actor="dave")
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    fields = {
        "CustomerID (Customers!A)": cust_id,
        "Customer Name / Company": "X", "Service Date": ROUTE_DATE,
        "Street Address": "1 Main St", "City": "NSB", "State": "FL",
        "Start Time": "09:00", "End Time": "09:30",
        "Original Start Time": "07:00", "Original End Time": "07:30",
    }
    job = _job_id(db_create_job(db_path, fields, actor="dave"))
    row = _get_job(db_path, job)
    assert row["original_start_time"] == "07:00"
    assert row["original_end_time"] == "07:30"
