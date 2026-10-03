"""
Tests for delete_job / db_delete_job — the Jobs-sheet equivalent of
delete_customer/delete_quote (added 2026-09-18 alongside the Sheet tab's
row-level Delete button, gated to Cancelled jobs only). A Completed job
must be permanently un-deletable through this tool, since it's what
income/accounting is built on.

Run: py -m pytest tests\\mcp\\test_delete_job.py -v
"""

import os

import pytest

from db_access import get_connection, init_db, transaction
from db_write_ops import db_create_customer, db_create_job, db_delete_job, db_update_row, JOBS_HEADER_MAP


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _make_job(db_path, status="Cancelled", customer_name="ZTEST Delete Me"):
    # Job Board Architecture Spec §5.1 (2026-09-22): create_job now requires
    # a real, existing CustomerID.
    cust_result = db_create_customer(db_path, {"Company Name": customer_name}, actor="david")
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    result = db_create_job(
        db_path,
        {"CustomerID (Customers!A)": cust_id, "Customer Name / Company": customer_name, "Service Date": "2026-09-18",
         "Job Status": status},
        actor="david",
    )
    return result.split("NEW_JOB_ID=")[1].strip()


def _set_status(db_path, job_id, status):
    db_update_row(db_path, "jobs", JOBS_HEADER_MAP, "job_id", job_id,
                   {"Job Status": status}, actor="someone_else")


# ── Guard 1: must already be Cancelled ──────────────────────────────────

def test_refuses_to_delete_scheduled_job(db_path):
    job_id = _make_job(db_path, status="Scheduled")
    result = db_delete_job(db_path, job_id, confirm=True)
    assert result.startswith("❌")
    assert "not Cancelled" in result
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    conn.close()
    assert row is not None  # nothing deleted


def test_completed_job_permanently_refused_even_with_confirm(db_path):
    job_id = _make_job(db_path, status="Complete")
    result = db_delete_job(db_path, job_id, confirm=True)
    assert result.startswith("❌")
    assert "Completed" in result
    assert "Hide completed jobs" in result
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    conn.close()
    assert row is not None


# ── Guard 2: confirm required ────────────────────────────────────────────

def test_preview_without_confirm_deletes_nothing(db_path):
    job_id = _make_job(db_path)
    result = db_delete_job(db_path, job_id, confirm=False)
    assert result.startswith("❌")
    assert "confirm=True" in result
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    conn.close()
    assert row is not None


def test_preview_reports_linked_row_counts(db_path):
    job_id = _make_job(db_path)
    with transaction(db_path) as conn:
        conn.execute(
            "INSERT INTO time_entries (entry_id, job_id, entry_date) VALUES (?, ?, ?)",
            ("TE-0001", job_id, "2026-09-18"),
        )
    result = db_delete_job(db_path, job_id, confirm=False)
    assert "Time entries: 1" in result


# ── Not found / ambiguous ────────────────────────────────────────────────

def test_not_found_returns_error(db_path):
    result = db_delete_job(db_path, "JOB-9999", confirm=True)
    assert result.startswith("❌")
    assert "No job found" in result


def test_ambiguous_match_refused_nothing_deleted(db_path):
    _make_job(db_path, customer_name="ZTEST Alpha")
    _make_job(db_path, customer_name="ZTEST Alphb")
    result = db_delete_job(db_path, "ZTEST Alph", confirm=True)
    assert result.startswith("❌")
    assert "matches 2 jobs" in result
    conn = get_connection(db_path)
    count = conn.execute("SELECT COUNT(*) AS n FROM jobs").fetchone()["n"]
    conn.close()
    assert count == 2


# ── Successful delete, no linked records ─────────────────────────────────

def test_deletes_cancelled_job_with_no_linked_records(db_path):
    job_id = _make_job(db_path)
    result = db_delete_job(db_path, job_id, confirm=True)
    assert result.startswith("✅")
    assert "Safety backup saved first" in result
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    conn.close()
    assert row is None


# ── Cascade delete ────────────────────────────────────────────────────────

def test_cascade_deletes_invoices_time_entries_route_stops(db_path):
    job_id = _make_job(db_path)

    with transaction(db_path) as conn:
        conn.execute(
            "INSERT INTO invoices (invoice_id, job_id, total_due) VALUES (?, ?, ?)",
            ("INV-0001", job_id, 150.0),
        )
        # jobs<->invoices circular FK: link the job back to its invoice —
        # the exact case that requires nulling jobs.invoice_id before the
        # invoice row can be deleted (foreign_keys=ON, db_access.py).
        conn.execute("UPDATE jobs SET invoice_id = ? WHERE job_id = ?", ("INV-0001", job_id))
        conn.execute(
            "INSERT INTO time_entries (entry_id, job_id, entry_date) VALUES (?, ?, ?)",
            ("TE-0001", job_id, "2026-09-18"),
        )
        conn.execute(
            "INSERT INTO route_stops (route_date, crew_id, stop_number, job_id) "
            "VALUES (?, ?, ?, ?)",
            ("2026-09-18", "david", 1, job_id),
        )

    result = db_delete_job(db_path, job_id, confirm=True)
    assert result.startswith("✅"), result

    conn = get_connection(db_path)
    assert conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone() is None
    assert conn.execute("SELECT * FROM invoices WHERE invoice_id = 'INV-0001'").fetchone() is None
    assert conn.execute("SELECT * FROM time_entries WHERE entry_id = 'TE-0001'").fetchone() is None
    assert conn.execute("SELECT * FROM route_stops WHERE job_id = ?", (job_id,)).fetchone() is None
    conn.close()


def test_safety_backup_file_actually_created(db_path):
    job_id = _make_job(db_path)
    result = db_delete_job(db_path, job_id, confirm=True)
    assert result.startswith("✅")
    backup_line = [l for l in result.splitlines() if "Safety backup saved first" in l][0]
    backup_path = backup_line.split(":", 1)[1].strip()
    assert os.path.exists(backup_path)


def test_completed_job_status_changed_after_check_refused_even_with_confirm(db_path):
    job_id = _make_job(db_path, status="Cancelled")
    _set_status(db_path, job_id, "Complete")
    result = db_delete_job(db_path, job_id, confirm=True)
    assert result.startswith("❌")
    assert "Completed" in result
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    conn.close()
    assert row is not None
