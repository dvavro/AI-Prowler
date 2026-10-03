"""
tests/mcp_tests/test_job_board_hard_time_violation_phase13.py
========================================================
Job Board Architecture Spec §14.8/§14.11 Phase 13 — Job Board sync &
persistent hard-time-violation flagging.

Covers db_read_ops.db_get_jobs_changed_since's new standing
_hard_time_violation/_hard_time_violation_detail computed fields
(§14.8) and the route_stops-side join that surfaces a hard job whose
violation status changed as a side effect of a route-only write (§13.5
precedent, extended per §14.11 Phase 13's own testing requirement).

Does not cover the Job Board card's frontend badge rendering
(jobs/index.html's boardCardHTML()) — this codebase has no JS test
harness (see Phase 11's own testing note); that half is verified by
node --check (syntax only) plus manual QA, same posture as every other
frontend-only piece of this feature.

Run with:
    run_tests.bat tests\\mcp\\test_job_board_hard_time_violation_phase13.py -v
"""
from __future__ import annotations

import sqlite3
import sys
import time
from pathlib import Path

import pytest

from db_access import init_db, utcnow_iso
from db_read_ops import db_get_jobs_changed_since
from db_write_ops import db_create_customer, db_create_job

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

ROUTE_DATE = "2026-09-22"


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _job_id(create_result: str) -> str:
    return create_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _create_job(db_path, schedule_type="soft", start_time=None, end_time=None,
                 customer="Cust", crew="Jake"):
    # Job Board Architecture Spec §5.1 (2026-09-22): create_job now requires
    # a real, existing CustomerID.
    cust_result = db_create_customer(db_path, {"Company Name": customer}, actor="dave")
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    fields = {
        "CustomerID (Customers!A)": cust_id,
        "Customer Name / Company": customer,
        "Service Date": ROUTE_DATE,
        "Crew / Technician": crew,
        "Schedule Type (Hard/Soft)": schedule_type,
    }
    if start_time:
        fields["Start Time"] = start_time
    if end_time:
        fields["End Time"] = end_time
    return _job_id(db_create_job(db_path, fields, actor="dave"))


def _seed_route_stop(db_path, job_id, eta, route_date=ROUTE_DATE, crew_id="Jake",
                      last_edited_at=None):
    """Directly inserts a route_stops row for `job_id`, bypassing the
    normal db_write_route_stops/reorder_route_stop write paths — lets a
    test control `eta` and `last_edited_at` precisely without needing a
    full route build. Mirrors the _seed_stop() helper convention already
    established in test_reorder_route_stop_phase10.py."""
    conn = sqlite3.connect(db_path)
    cur = conn.execute(
        "INSERT INTO route_stops (route_date, crew_id, stop_number, job_id, address, "
        "latitude, longitude, eta, created_by, last_edited_by, last_edited_at, version) "
        "VALUES (?, ?, 1, ?, 'Test address', 29.0, -80.9, ?, 'seed', 'seed', ?, 1)",
        (route_date, crew_id, job_id, eta, last_edited_at or utcnow_iso()),
    )
    conn.commit()
    stop_id = cur.lastrowid
    conn.close()
    return stop_id


def _update_route_stop_eta(db_path, job_id, new_eta, last_edited_at=None):
    """Simulates a route rebuild/reorder updating an EXISTING stop's ETA
    in place (what reorder_route_stop/db_suggest_route_schedule actually
    do) — as opposed to _seed_route_stop's initial INSERT, which would
    collide with route_stops' UNIQUE(route_date, crew_id, stop_number)
    constraint on a second call for the same stop."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE route_stops SET eta = ?, last_edited_at = ? WHERE job_id = ?",
        (new_eta, last_edited_at or utcnow_iso(), job_id),
    )
    conn.commit()
    conn.close()


def _poll(db_path, since):
    return db_get_jobs_changed_since(db_path, since, sheet_name="Jobs_Schedule")


def _find(rows, job_id):
    matching = [r for r in rows if r.get("JobID (JOB-####)") == job_id]
    assert matching, f"job {job_id} not present in poll results: {[r.get('JobID (JOB-####)') for r in rows]}"
    return matching[0]


# ── Basic flag correctness ───────────────────────────────────────────────

def test_soft_job_never_flagged_even_with_a_start_time(db_path):
    since = utcnow_iso()
    time.sleep(1.1)
    job_id = _create_job(db_path, schedule_type="soft", start_time="08:00")
    _seed_route_stop(db_path, job_id, eta="10:00")  # wildly off, but soft

    rows = _poll(db_path, since)
    record = _find(rows, job_id)
    assert record["_hard_time_violation"] is False
    assert record["_hard_time_violation_detail"] is None


def test_hard_job_with_no_route_yet_not_flagged(db_path):
    since = utcnow_iso()
    time.sleep(1.1)
    job_id = _create_job(db_path, schedule_type="hard", start_time="08:00", end_time="09:00")
    # No route_stops row at all — an as-yet-unrouted hard job isn't a
    # violation, it's simply not evaluated yet (§14.8 "advisory, never
    # invented" posture).

    rows = _poll(db_path, since)
    record = _find(rows, job_id)
    assert record["_hard_time_violation"] is False
    assert record["_hard_time_violation_detail"] is None


def test_hard_job_within_tolerance_not_flagged(db_path):
    since = utcnow_iso()
    time.sleep(1.1)
    job_id = _create_job(db_path, schedule_type="hard", start_time="08:00", end_time="09:00")
    _seed_route_stop(db_path, job_id, eta="08:05")  # 5 min off, within default 10-min tolerance

    rows = _poll(db_path, since)
    record = _find(rows, job_id)
    assert record["_hard_time_violation"] is False
    # Detail is still populated even within tolerance, so a caller that
    # wants "on track" context has it.
    assert record["_hard_time_violation_detail"] is not None


def test_hard_job_outside_tolerance_flagged(db_path):
    since = utcnow_iso()
    time.sleep(1.1)
    job_id = _create_job(db_path, schedule_type="hard", start_time="08:00", end_time="09:00")
    _seed_route_stop(db_path, job_id, eta="09:10")  # 70 min off — well past tolerance

    rows = _poll(db_path, since)
    record = _find(rows, job_id)
    assert record["_hard_time_violation"] is True
    detail = record["_hard_time_violation_detail"]
    assert "08:00" in detail
    assert "09:10" in detail
    assert "70 min" in detail


# ── Persists across poll cycles (§14.10, not a one-time toast) ──────────

def test_violation_persists_across_repeated_polls(db_path):
    since = utcnow_iso()
    time.sleep(1.1)
    job_id = _create_job(db_path, schedule_type="hard", start_time="08:00", end_time="09:00")
    _seed_route_stop(db_path, job_id, eta="09:10")

    first = _find(_poll(db_path, since), job_id)
    second = _find(_poll(db_path, since), job_id)
    assert first["_hard_time_violation"] is True
    assert second["_hard_time_violation"] is True


# ── Regression guard: route-side write alone surfaces the job ──────────

def test_polling_surfaces_hard_job_after_route_only_write(db_path):
    """The direct regression case §14.11 Phase 13 calls for: a route
    approval/rebuild writes route_stops, never the job's own row, for a
    hard job (its committed time is never derived from the route). The
    job's own last_edited_at therefore never moves — without the
    §13.5-style join this test guards, the board would never learn the
    violation status changed."""
    job_id = _create_job(db_path, schedule_type="hard", start_time="08:00", end_time="09:00")
    # Initial route puts it right on time — no violation, and this write
    # happens BEFORE the poll baseline, same as an already-settled board.
    _seed_route_stop(db_path, job_id, eta="08:00")

    since = utcnow_iso()
    time.sleep(1.1)
    # Job's own row is untouched — only route_stops changes, simulating a
    # route rebuild that pushed this stop's ETA later.
    _update_route_stop_eta(db_path, job_id, "09:10")

    rows = _poll(db_path, since)
    record = _find(rows, job_id)
    assert record["_hard_time_violation"] is True


def test_soft_job_route_only_write_not_surfaced(db_path):
    """Scoped to hard jobs only — a soft job's route_stops row changes
    constantly during ordinary route building and carries no board-
    visible commitment to violate, so a route-only write must NOT pull
    an unrelated soft job into the poll results."""
    job_id = _create_job(db_path, schedule_type="soft")
    _seed_route_stop(db_path, job_id, eta="08:00")

    since = utcnow_iso()
    time.sleep(1.1)
    _update_route_stop_eta(db_path, job_id, "09:00")

    rows = _poll(db_path, since)
    matching = [r for r in rows if r.get("JobID (JOB-####)") == job_id]
    assert not matching, "soft job's route-only change should not be surfaced by the hard-only join"


# ── Regression: existing job polling behavior for a job with no ─────────
# schedule_type opinion is unaffected (byte-identical posture, §14.10).

def test_default_soft_job_polling_unaffected_by_new_fields(db_path):
    since = utcnow_iso()
    time.sleep(1.1)
    job_id = _create_job(db_path)  # defaults: soft, no start/end time

    rows = _poll(db_path, since)
    record = _find(rows, job_id)
    assert record["_hard_time_violation"] is False
    assert record["_hard_time_violation_detail"] is None
    # Every ordinary field still present and correct — new fields are
    # additive, not a replacement of the existing record shape.
    assert record["Customer Name / Company"] == "Cust"


# ── Crew-restricted (server-mode) polling still carries the flag ───────

def test_restricted_crew_still_sees_own_violation_flag(db_path):
    """A field_crew member's Job Board is scoped to their own jobs
    (restrict=True, crew_name matching), same as every other polled
    field — the violation flag must not be dropped or miscomputed just
    because the caller is crew-restricted rather than an unrestricted
    owner/staff view."""
    since = utcnow_iso()
    time.sleep(1.1)
    mine = _create_job(db_path, schedule_type="hard", start_time="08:00",
                        end_time="09:00", crew="Jake")
    _seed_route_stop(db_path, mine, eta="09:10", crew_id="Jake")
    theirs = _create_job(db_path, schedule_type="hard", start_time="08:00",
                          end_time="09:00", crew="Sam")
    _seed_route_stop(db_path, theirs, eta="09:10", crew_id="Sam")

    rows = db_get_jobs_changed_since(
        db_path, since, sheet_name="Jobs_Schedule", restrict=True, crew_name="jake",
    )
    job_ids = [r.get("JobID (JOB-####)") for r in rows]
    assert mine in job_ids
    assert theirs not in job_ids
    mine_record = _find(rows, mine)
    assert mine_record["_hard_time_violation"] is True

