"""
tests/mcp_tests/test_conflict_detection_phase4.py
===============================================
Job Board Architecture Spec — Phase 4 (spec §6.2, §11).

Direct unit tests for db_update_row's optimistic-concurrency check
(expected_version), across all four update wrappers (db_update_job,
db_update_customer, db_update_invoice, db_update_quote). MCP-layer
wiring (update_job_spreadsheet's new expected_version param, both
modes) is covered separately in test_conflict_detection_phase4_mcp_wiring.py.

Run with:
    run_tests.bat tests\\mcp\\test_conflict_detection_phase4.py -v
"""
import sqlite3

import pytest

from db_access import init_db
from db_write_ops import db_create_customer, db_create_job, db_update_customer, db_update_job


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _version(db_path, table, id_col, id_val):
    conn = sqlite3.connect(db_path)
    row = conn.execute(f"SELECT version FROM {table} WHERE {id_col} = ?", (id_val,)).fetchone()
    conn.close()
    return row[0]


def _value(db_path, table, col, id_col, id_val):
    conn = sqlite3.connect(db_path)
    row = conn.execute(f"SELECT {col} FROM {table} WHERE {id_col} = ?", (id_val,)).fetchone()
    conn.close()
    return row[0]


def _cust_id(db_path, name="A"):
    """Job Board Architecture Spec §5.1 (2026-09-22): create_job now
    requires a real, existing CustomerID — create one and return its ID
    for callers to pass through."""
    result = db_create_customer(db_path, {"Company Name": name}, actor="dave")
    return result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()


# ── Backward compatibility: no expected_version ─────────────────────────

def test_no_expected_version_always_succeeds(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "A"}, actor="dave")
    result = db_update_job(db_path, "JOB-0001", {"Job Status": "Complete"}, actor="dave")
    assert result.startswith("✅"), result
    assert _value(db_path, "jobs", "job_status", "job_id", "JOB-0001") == "Complete"


def test_new_row_starts_at_version_1(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "A"}, actor="dave")
    assert _version(db_path, "jobs", "job_id", "JOB-0001") == 1


# ── Matching version succeeds and bumps the counter ─────────────────────

def test_matching_expected_version_succeeds(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "A"}, actor="dave")
    result = db_update_job(db_path, "JOB-0001", {"Job Status": "Complete"}, actor="dave",
                            expected_version=1)
    assert result.startswith("✅"), result
    assert "NEW_VERSION=2" in result
    assert _version(db_path, "jobs", "job_id", "JOB-0001") == 2


def test_version_keeps_incrementing_across_edits(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "A"}, actor="dave")
    db_update_job(db_path, "JOB-0001", {"Job Status": "Scheduled"}, actor="dave", expected_version=1)
    result = db_update_job(db_path, "JOB-0001", {"Job Status": "Complete"}, actor="dave",
                            expected_version=2)
    assert result.startswith("✅"), result
    assert _version(db_path, "jobs", "job_id", "JOB-0001") == 3


# ── THE core Phase 4 scenario: stale write rejected ─────────────────────

def test_stale_expected_version_rejected_cleanly(db_path):
    """Two sessions both load version 1. Session A writes first (bumps to
    2). Session B then tries to write with its now-stale expected_version
    (1) — must be rejected, with NOTHING written, and A's change intact."""
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "A", "Job Status": "Scheduled"}, actor="dave")

    session_a = db_update_job(db_path, "JOB-0001", {"Job Status": "In Progress"}, actor="jake",
                               expected_version=1)
    assert session_a.startswith("✅"), session_a

    session_b = db_update_job(db_path, "JOB-0001", {"Job Status": "Complete"}, actor="maria",
                               expected_version=1)  # stale — the row is now at version 2
    assert session_b.startswith("❌"), session_b
    assert "Conflict" in session_b
    assert "reload and try again" in session_b

    # Session A's write is intact — session B's rejected write changed nothing.
    assert _value(db_path, "jobs", "job_status", "job_id", "JOB-0001") == "In Progress"
    assert _version(db_path, "jobs", "job_id", "JOB-0001") == 2


def test_conflict_message_names_who_and_when(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "A"}, actor="dave")
    db_update_job(db_path, "JOB-0001", {"Job Status": "In Progress"}, actor="jake", expected_version=1)
    result = db_update_job(db_path, "JOB-0001", {"Job Status": "Complete"}, actor="maria",
                            expected_version=1)
    assert "jake" in result
    assert "version 2" in result  # current version
    assert "version 1" in result  # what maria's session loaded


def test_conflict_check_applies_to_customers_too(db_path):
    db_create_customer(db_path, {"Company Name": "A"}, actor="dave")
    db_update_customer(db_path, "CUST-0001", {"Phone": "111-1111"}, actor="dave", expected_version=1)
    result = db_update_customer(db_path, "CUST-0001", {"Phone": "222-2222"}, actor="dave",
                                 expected_version=1)  # stale
    assert result.startswith("❌")
    assert _value(db_path, "customers", "phone", "customer_id", "CUST-0001") == "111-1111"


# ── Ordering: permission check happens before the version check ─────────

def test_permission_denial_takes_priority_over_version_conflict(db_path):
    """An unauthorized caller should never learn who edited a row they
    can't touch anyway — check_fn (permission) must run before the
    version check, not after."""
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "A", "Crew / Technician": "Someone Else"},
                  actor="dave")
    result = db_update_job(
        db_path, "JOB-0001", {"Job Status": "Complete"}, actor="jake",
        restrict=True, crew_name="jake r",  # not assigned to jake
        expected_version=999,  # deliberately wrong — should never even be checked
    )
    assert result.startswith("❌")
    assert "assigned to you" in result
    assert "Conflict" not in result  # never reached the version check


def test_correct_version_but_denied_permission_still_fails(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "A", "Crew / Technician": "Someone Else"},
                  actor="dave")
    result = db_update_job(
        db_path, "JOB-0001", {"Job Status": "Complete"}, actor="jake",
        restrict=True, crew_name="jake r",
        expected_version=1,  # this IS the correct version...
    )
    assert result.startswith("❌")
    assert "assigned to you" in result  # ...but permission still blocks it
