"""
tests/mcp_tests/test_db_get_board_updates_phase3.py
=================================================
Job Board Architecture Spec — Phase 3 (spec §6.1, §11).

Direct unit tests for db_read_ops.db_get_jobs_changed_since — the
`WHERE last_edited_at > ?` query backing the admin Job Board's 60-second
polling. MCP-layer wiring (the real get_board_updates() @mcp.tool(), both
modes) is covered separately in test_get_board_updates_phase3_mcp_wiring.py.

Run with:
    run_tests.bat tests\\mcp\\test_db_get_board_updates_phase3.py -v
"""
import sqlite3
import time

import pytest

from db_access import init_db
from db_read_ops import db_get_jobs_changed_since
from db_write_ops import db_create_customer, db_create_job, db_update_job


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _last_edited_at(db_path, table, id_col, id_val):
    conn = sqlite3.connect(db_path)
    row = conn.execute(f"SELECT last_edited_at FROM {table} WHERE {id_col} = ?", (id_val,)).fetchone()
    conn.close()
    return row[0]


def _cust_id(db_path, name="A"):
    """Job Board Architecture Spec §5.1 (2026-09-22): create_job now
    requires a real, existing CustomerID."""
    result = db_create_customer(db_path, {"Company Name": name}, actor="dave")
    return result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()


def test_nothing_changed_returns_empty_list(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "A"}, actor="dave")
    far_future = "2099-01-01T00:00:00"
    rows = db_get_jobs_changed_since(db_path, far_future)
    assert rows == []


def test_new_row_is_returned_when_since_is_in_the_past(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "A"}, actor="dave")
    far_past = "2000-01-01T00:00:00"
    rows = db_get_jobs_changed_since(db_path, far_past)
    assert len(rows) == 1
    assert rows[0]["Customer Name / Company"] == "A"
    assert "_last_edited_at" in rows[0]


def test_only_rows_edited_after_since_are_returned(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "Old"), "Customer Name / Company": "Old"}, actor="dave")
    cutoff = _last_edited_at(db_path, "jobs", "job_id", "JOB-0001")
    time.sleep(1.1)  # last_edited_at has second-level granularity (timespec="seconds")
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "New"), "Customer Name / Company": "New"}, actor="dave")

    rows = db_get_jobs_changed_since(db_path, cutoff)
    names = {r["Customer Name / Company"] for r in rows}
    assert "New" in names
    assert "Old" not in names


def test_update_to_existing_row_bumps_last_edited_at(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "A"}, actor="dave")
    cutoff = _last_edited_at(db_path, "jobs", "job_id", "JOB-0001")
    time.sleep(1.1)  # last_edited_at has second-level granularity (timespec="seconds")
    db_update_job(db_path, "JOB-0001", {"Job Status": "Complete"}, actor="dave")

    rows = db_get_jobs_changed_since(db_path, cutoff)
    assert len(rows) == 1
    assert rows[0]["Job Status"] == "Complete"


def test_full_row_returned_not_trimmed_to_changed_field(db_path):
    """Unlike db_read_job_spreadsheet's text digest, this must return
    every populated field on a changed row, not just the one that
    changed — the client refreshes a whole card, not a single cell."""
    db_create_job(db_path, {
        "CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "A", "Service Type": "Window", "Quote Amount ($)": 100,
    }, actor="dave")
    cutoff = "2000-01-01T00:00:00"
    rows = db_get_jobs_changed_since(db_path, cutoff)
    assert rows[0]["Service Type"] == "Window"
    assert rows[0]["Quote Amount ($)"] == 100


def test_blank_fields_omitted(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "A"}, actor="dave")
    rows = db_get_jobs_changed_since(db_path, "2000-01-01T00:00:00")
    assert "Service Type" not in rows[0]


def test_customers_sheet_supported(db_path):
    db_create_customer(db_path, {"Company Name": "Blue Wave"}, actor="dave")
    rows = db_get_jobs_changed_since(db_path, "2000-01-01T00:00:00", sheet_name="Customers")
    assert len(rows) == 1
    assert rows[0]["Company Name"] == "Blue Wave"


def test_not_yet_wired_sheet_raises(db_path):
    # Updated 2026-09-12 (Database-tab expansion): Route_Planner is now
    # fully wired (see test_database_tab_read_expansion.py) — a
    # genuinely nonexistent sheet name is the right fixture now.
    with pytest.raises(ValueError, match="Nonexistent_Sheet"):
        db_get_jobs_changed_since(db_path, "2000-01-01T00:00:00", sheet_name="Nonexistent_Sheet")


def test_field_crew_restricted_to_own_jobs(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "Mine"), "Customer Name / Company": "Mine", "Crew / Technician": "Jake R"}, actor="dave")
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "Not Mine"), "Customer Name / Company": "Not Mine", "Crew / Technician": "Someone Else"}, actor="dave")
    rows = db_get_jobs_changed_since(db_path, "2000-01-01T00:00:00", restrict=True, crew_name="jake r")
    names = {r["Customer Name / Company"] for r in rows}
    assert names == {"Mine"}


def test_crew_scope_never_applies_to_customers(db_path):
    db_create_customer(db_path, {"Company Name": "Anyone"}, actor="dave")
    rows = db_get_jobs_changed_since(
        db_path, "2000-01-01T00:00:00", sheet_name="Customers", restrict=True, crew_name="jake r",
    )
    assert len(rows) == 1


def test_results_ordered_oldest_edit_first(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "First"), "Customer Name / Company": "First"}, actor="dave")
    time.sleep(0.01)
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "Second"), "Customer Name / Company": "Second"}, actor="dave")
    rows = db_get_jobs_changed_since(db_path, "2000-01-01T00:00:00")
    assert [r["Customer Name / Company"] for r in rows] == ["First", "Second"]
