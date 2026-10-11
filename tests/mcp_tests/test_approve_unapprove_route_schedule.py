"""
tests/mcp_tests/test_approve_unapprove_route_schedule.py
====================================================
Mileage/routing follow-up (2026-09-20), rewritten for the 2026-10-05
approve semantics (replaced the old ETA-push behavior on 2026-10-08).

Covers db_approve_route_schedule and db_unapprove_route_schedule — the
Route tab's two dedicated Approve/Un-approve buttons.

Semantics under test (David's rule — a job's window always reflects the
customer settings):
  - Approve is a PURE FLAG: it records a row in route_approvals per crew
    found in route_stops for the date, which grants email eligibility and
    link pinning/viewing for the route. It NEVER writes to a job's Start
    Time / End Time / Original Start/End Time. The routed arrival/departure
    times live in route_stops, not on the job.
  - Un-approve is the exact inverse: it deletes the approval row(s),
    revokes email eligibility, and clears route_stops.map_url plus each
    routed job's Route Map URL so nothing approved-only remains viewable.
    It also NEVER writes to job Start/End Time — approve never changed
    them, so there is nothing to restore.
  - Original Start Time/Original End Time are an ordinary,
    independently-editable field pair (same mechanism as any other
    column) that NEITHER approve nor unapprove ever writes to — only a
    genuine manual edit (update_job_spreadsheet) or job creation itself
    sets them.

Run with:
    run_tests.bat tests\\mcp_tests\\test_approve_unapprove_route_schedule.py -v
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
from db_write_ops import db_create_customer, db_create_job
from db_route_ops import (
    db_approve_route_schedule,
    db_unapprove_route_schedule,
    db_is_route_approved,
)

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


def _seed_route_stop(db_path, job_id, eta, crew="Jake", route_date=ROUTE_DATE,
                     stop_number=1, map_url=None):
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO route_stops (route_date, crew_id, stop_number, job_id, address, "
        "latitude, longitude, eta, map_url, created_by, last_edited_by, last_edited_at, version) "
        "VALUES (?, ?, ?, ?, 'x', 29.0, -80.9, ?, ?, 'seed', 'seed', '2026-01-01T00:00:00Z', 1)",
        (route_date, crew, stop_number, job_id, eta, map_url),
    )
    conn.commit()
    conn.close()


def _get_job(db_path, job_id):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    conn.close()
    return dict(row)


def _approvals(db_path, route_date=ROUTE_DATE):
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT route_date, crew_id FROM route_approvals WHERE route_date = ?",
        (route_date,),
    ).fetchall()
    conn.close()
    return [tuple(r) for r in rows]


def _set_route_link(db_path, job_id, url="https://maps.example/route"):
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE route_stops SET map_url = ? WHERE job_id = ?", (url, job_id))
    conn.execute("UPDATE jobs SET route_map_url = ? WHERE job_id = ?", (url, job_id))
    conn.commit()
    conn.close()


def _stop_map_url(db_path, job_id):
    conn = sqlite3.connect(db_path)
    url = conn.execute(
        "SELECT map_url FROM route_stops WHERE job_id = ?", (job_id,)).fetchone()[0]
    conn.close()
    return url


# ── db_approve_route_schedule ───────────────────────────────────────────


def test_approve_records_approval_flag(db_path):
    job = _create_job(db_path)
    _seed_route_stop(db_path, job, eta="09:15")

    result = db_approve_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert result.startswith("✅"), result
    assert "Route approved for %s" % ROUTE_DATE in result
    assert "Email is now allowed" in result

    assert db_is_route_approved(db_path, ROUTE_DATE, "Jake")
    assert (ROUTE_DATE, "Jake") in _approvals(db_path)


def test_approve_never_touches_job_start_end_time(db_path):
    """The core guarantee: approving a route must never change what the
    customer was actually told — not Start/End Time, not Original."""
    job = _create_job(db_path, start="08:00", end="08:30", duration=30)
    row_before = _get_job(db_path, job)
    assert row_before["original_start_time"] == "08:00"
    assert row_before["original_end_time"] == "08:30"

    _seed_route_stop(db_path, job, eta="11:00")
    result = db_approve_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert result.startswith("✅"), result
    assert "No job time windows were changed" in result

    row_after = _get_job(db_path, job)
    assert row_after["start_time"] == "08:00"  # unchanged — approval is a pure flag
    assert row_after["end_time"] == "08:30"
    assert row_after["original_start_time"] == "08:00"
    assert row_after["original_end_time"] == "08:30"


def test_approve_treats_hard_jobs_like_soft(db_path):
    """Approval is a pure flag — no job is ever skipped for its schedule
    type; the message no longer mentions hard jobs at all."""
    job = _create_job(db_path, start="08:00", end="09:00", schedule_type="hard")
    _seed_route_stop(db_path, job, eta="11:00")

    result = db_approve_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert result.startswith("✅"), result
    assert "hard" not in result.lower()

    assert db_is_route_approved(db_path, ROUTE_DATE, "Jake")
    row = _get_job(db_path, job)
    assert row["start_time"] == "08:00"
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
    assert "(Jake)" in result

    assert db_is_route_approved(db_path, ROUTE_DATE, "Jake")
    assert not db_is_route_approved(db_path, ROUTE_DATE, "Maria")

    # Windows untouched for both crews — approval never pushes ETAs.
    assert _get_job(db_path, jake_job)["start_time"] == "08:00"
    assert _get_job(db_path, maria_job)["start_time"] == "08:00"


# ── db_unapprove_route_schedule ─────────────────────────────────────────


def test_unapprove_removes_approval_and_revokes_links(db_path):
    job = _create_job(db_path, start="07:00", end="07:45")
    _seed_route_stop(db_path, job, eta="11:00", map_url="https://maps.example/r1")
    _set_route_link(db_path, job)

    db_approve_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert db_is_route_approved(db_path, ROUTE_DATE, "Jake")

    result = db_unapprove_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert result.startswith("↩️"), result
    assert "Route un-approved for %s" % ROUTE_DATE in result

    assert not db_is_route_approved(db_path, ROUTE_DATE, "Jake")
    assert _approvals(db_path) == []
    assert _stop_map_url(db_path, job) is None
    assert _get_job(db_path, job)["route_map_url"] == ""


def test_unapprove_never_touches_job_start_end_time(db_path):
    """Approve never changed them, so un-approve has nothing to restore —
    the job's window is exactly what it was before the round trip."""
    job = _create_job(db_path, start="07:00", end="07:45")
    _seed_route_stop(db_path, job, eta="11:00")
    db_approve_route_schedule(db_path, ROUTE_DATE, "", actor="dave")

    result = db_unapprove_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert result.startswith("↩️"), result
    assert "No job time windows were changed" in result

    row = _get_job(db_path, job)
    assert row["start_time"] == "07:00"
    assert row["end_time"] == "07:45"
    assert row["original_start_time"] == "07:00"
    assert row["original_end_time"] == "07:45"


def test_unapprove_nothing_to_do_when_never_approved(db_path):
    _create_job(db_path)  # job exists, but nothing was ever approved
    result = db_unapprove_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert result.startswith("✅"), result
    assert "nothing to un-approve" in result.lower()

    # And with truly nothing on the date at all.
    result = db_unapprove_route_schedule(db_path, "2026-10-01", "", actor="dave")
    assert result.startswith("✅"), result
    assert "nothing to un-approve" in result.lower()


def test_unapprove_clears_leftover_links_without_prior_approval(db_path):
    """A rebuilt route may still carry viewable links from a deleted
    approval — un-approve still sweeps them up."""
    job = _create_job(db_path, start="07:00", end="07:45")
    _seed_route_stop(db_path, job, eta="11:00")
    _set_route_link(db_path, job)

    result = db_unapprove_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert result.startswith("↩️"), result
    assert _stop_map_url(db_path, job) is None
    assert _get_job(db_path, job)["route_map_url"] == ""


def test_unapprove_respects_crew_filter(db_path):
    jake_job = _create_job(db_path, customer="Jake's", crew="Jake")
    maria_job = _create_job(db_path, customer="Maria's", crew="Maria")
    _seed_route_stop(db_path, jake_job, eta="10:00", crew="Jake")
    _seed_route_stop(db_path, maria_job, eta="12:00", crew="Maria")
    db_approve_route_schedule(db_path, ROUTE_DATE, "", actor="dave")

    result = db_unapprove_route_schedule(db_path, ROUTE_DATE, "Jake", actor="dave")
    assert result.startswith("↩️"), result

    assert not db_is_route_approved(db_path, ROUTE_DATE, "Jake")
    assert db_is_route_approved(db_path, ROUTE_DATE, "Maria")
    # Windows untouched for both.
    assert _get_job(db_path, jake_job)["start_time"] == "08:00"
    assert _get_job(db_path, maria_job)["start_time"] == "08:00"


# ── Round trip ──────────────────────────────────────────────────────────


def test_multiple_approve_unapprove_cycles_keep_windows_stable(db_path):
    """Approve/un-approve round trips are idempotent with respect to the
    job's window: Original Start/End Time must never drift."""
    job = _create_job(db_path, start="08:00", end="08:45", duration=45)

    _seed_route_stop(db_path, job, eta="10:00")
    db_approve_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert db_is_route_approved(db_path, ROUTE_DATE, "Jake")
    assert _get_job(db_path, job)["start_time"] == "08:00"  # never pushed

    db_unapprove_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert not db_is_route_approved(db_path, ROUTE_DATE, "Jake")

    # A second, different trial route.
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM route_stops WHERE route_date = ?", (ROUTE_DATE,))
    conn.commit()
    conn.close()
    _seed_route_stop(db_path, job, eta="13:30")
    db_approve_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert db_is_route_approved(db_path, ROUTE_DATE, "Jake")

    db_unapprove_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert not db_is_route_approved(db_path, ROUTE_DATE, "Jake")
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
