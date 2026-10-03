"""
tests/mcp_tests/test_db_log_time_entry_identity.py
================================================
DB-backed replacement for tests/mcp_tests/test_log_time_entry_identity.py.

That file built openpyxl workbooks and called log_time_entry(filepath=...)
directly -- since db_log_time_entry (db_write_ops.py) is the real
implementation now, an .xlsx fixture is never read by the tool at all, so
every one of those tests degenerated into "No job found" regardless of
what the fixture contained. tests/mcp_tests/test_log_time_entry_isolated.py
replaced its field-writing/GPS mechanics coverage, but not the identity
and ambiguous-match behavior this file covers:

  - Job identification requires an unambiguous single match (zero matches
    -> error; 2+ matches -> error listing candidates), via the shared
    _find_unique_job() helper.
  - Server mode: "start" stamps the CALLER's own name into Crew, not the
    job's pre-assigned crew, and the already-open check is scoped to the
    caller's own entries only (a second crew member can start their own
    entry on the same job).
  - Server mode: "stop" only finds/closes an open entry the SAME caller
    opened -- a coworker's open entry is invisible to "stop", with a
    message distinguishing "no entry" from "someone else has one."
  - Personal mode (user_id="") is unaffected -- any open entry counts as
    "yours", matching the single-user posture the field-mechanics tests
    in test_log_time_entry_isolated.py already exercise.

Written directly against db_write_ops.db_log_time_entry (same db_path
fixture pattern as test_db_route_ops_phase1.py) rather than through a
subprocess + mocked ctx -- db_log_time_entry already takes user_id/
user_display_name as plain arguments, so there's no ctx-mocking needed
to exercise server-mode identity here.

Run with:
    run_tests.bat tests\\mcp\\test_db_log_time_entry_identity.py -v
"""
import sqlite3

import pytest

from db_access import init_db
from db_write_ops import db_create_customer, db_create_job, db_log_time_entry


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _cust_id(db_path, name="X"):
    """Job Board Architecture Spec §5.1 (2026-09-22): create_job now
    requires a real, existing CustomerID."""
    result = db_create_customer(db_path, {"Company Name": name}, actor="dave")
    return result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()


# ══════════════════════════════════════════════════════════════════════════
# Ambiguous / no-match job identification
# ══════════════════════════════════════════════════════════════════════════

def test_no_match_at_all_rejected(db_path):
    result = db_log_time_entry(db_path, "totally nonexistent job", "start", "", "")
    assert "❌" in result
    assert "No job found" in result


def test_ambiguous_match_rejected_with_candidates(db_path):
    """Two jobs both containing 'Daytona' -- must not silently pick one."""
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "Crabby's Daytona"), "Customer Name / Company": "Crabby's Daytona"}, actor="dave")
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "Sunshine Realty Daytona"), "Customer Name / Company": "Sunshine Realty Daytona"}, actor="dave")
    result = db_log_time_entry(db_path, "Daytona", "start", "", "")
    assert "❌" in result
    assert "matches 2 jobs" in result
    assert "JOB-0001" in result
    assert "JOB-0002" in result


def test_exact_unique_match_succeeds(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "Crabby's Daytona"), "Customer Name / Company": "Crabby's Daytona"}, actor="dave")
    result = db_log_time_entry(db_path, "JOB-0001", "start", "", "")
    assert "Clocked IN" in result


# ══════════════════════════════════════════════════════════════════════════
# Server-mode identity -- crew stamping, ownership scoping
# ══════════════════════════════════════════════════════════════════════════

def test_crew_field_uses_caller_not_job_assignment(db_path):
    """The job's own pre-assigned Crew / Technician must NOT be what gets
    stamped onto the time entry -- the CALLER's name is."""
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "X"), "Customer Name / Company": "X", "Crew / Technician": "Pre-Assigned Person"},
                  actor="dave")
    result = db_log_time_entry(db_path, "JOB-0001", "start", "jake-r", "Jake R")
    assert "Clocked IN" in result

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT crew, crew_user_id FROM time_entries WHERE job_id = 'JOB-0001'").fetchone()
    conn.close()
    assert row["crew"] == "Jake R"
    assert row["crew_user_id"] == "jake-r"


def test_second_user_can_start_own_entry_same_job(db_path):
    """Two different crew members clocking into the SAME job at the same
    time must both succeed -- ownership scoping is per-caller, not
    per-job."""
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "X"), "Customer Name / Company": "X"}, actor="dave")
    first = db_log_time_entry(db_path, "JOB-0001", "start", "jake-r", "Jake R")
    assert "Clocked IN" in first
    second = db_log_time_entry(db_path, "JOB-0001", "start", "sam-t", "Sam T")
    assert "Clocked IN" in second


def test_same_user_double_start_still_blocked(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "X"), "Customer Name / Company": "X"}, actor="dave")
    db_log_time_entry(db_path, "JOB-0001", "start", "jake-r", "Jake R")
    result = db_log_time_entry(db_path, "JOB-0001", "start", "jake-r", "Jake R")
    assert "already open" in result


def test_cannot_stop_coworkers_open_entry(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "X"), "Customer Name / Company": "X"}, actor="dave")
    db_log_time_entry(db_path, "JOB-0001", "start", "jake-r", "Jake R")
    result = db_log_time_entry(db_path, "JOB-0001", "stop", "sam-t", "Sam T")
    assert "❌" in result
    assert "someone else" in result.lower()


def test_own_entry_can_still_be_stopped_among_multiple_open(db_path):
    """With two coworkers' entries open on the same job, each can stop
    only their own."""
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "X"), "Customer Name / Company": "X"}, actor="dave")
    db_log_time_entry(db_path, "JOB-0001", "start", "jake-r", "Jake R")
    db_log_time_entry(db_path, "JOB-0001", "start", "sam-t", "Sam T")
    result = db_log_time_entry(db_path, "JOB-0001", "stop", "jake-r", "Jake R")
    assert "Clocked OUT" in result

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = {r["crew_user_id"]: r["clock_out"] for r in
            conn.execute("SELECT crew_user_id, clock_out FROM time_entries WHERE job_id = 'JOB-0001'")}
    conn.close()
    assert rows["jake-r"] is not None
    assert rows["sam-t"] is None  # Sam's entry untouched


# ══════════════════════════════════════════════════════════════════════════
# Personal mode -- unaffected (user_id="")
# ══════════════════════════════════════════════════════════════════════════

def test_personal_mode_completely_unaffected(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "X"), "Customer Name / Company": "X", "Crew / Technician": "David Vavro"},
                  actor="dave")
    result = db_log_time_entry(db_path, "JOB-0001", "start", "", "")
    assert "Clocked IN" in result

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT crew, crew_user_id FROM time_entries WHERE job_id = 'JOB-0001'").fetchone()
    conn.close()
    # Personal mode: no caller identity to stamp, so it falls back to the
    # job's own Crew / Technician field.
    assert row["crew"] == "David Vavro"
    assert row["crew_user_id"] is None

    stop_result = db_log_time_entry(db_path, "JOB-0001", "stop", "", "")
    assert "Clocked OUT" in stop_result


def test_clock_out_writes_actual_duration_back_to_jobs(db_path):
    """Clocking out must write elapsed minutes back to jobs.actual_duration
    -- ported from tests/unit/test_contractor_tools.py::TestLogTimeEntry::
    test_CT_20 (that version was silently vacuous: its openpyxl fixture
    never actually got a matching row after migration, so its assertion
    was skipped rather than exercised)."""
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "X"), "Customer Name / Company": "X"}, actor="dave")
    db_log_time_entry(db_path, "JOB-0001", "start", "", "")

    conn = sqlite3.connect(db_path)
    # Back-date the clock-in so a real elapsed time exists without a
    # real-time sleep in the test.
    conn.execute(
        "UPDATE time_entries SET clock_in = datetime(clock_in, '-35 minutes') "
        "WHERE job_id = 'JOB-0001'"
    )
    conn.commit()
    conn.close()

    stop_result = db_log_time_entry(db_path, "JOB-0001", "stop", "", "")
    assert "Clocked OUT" in stop_result

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT actual_duration FROM jobs WHERE job_id = 'JOB-0001'").fetchone()
    conn.close()
    assert row is not None
    assert 32 <= int(row[0]) <= 38, f"Expected ~35 min, got {row[0]}"
