"""
Tests for delete_customer / db_delete_customer — the one narrow exception
to AI-Prowler's "never delete" rule (added 2026-09-15 at the owner's
request, so ZTEST/mistaken customer records can actually be cleaned up).

Run: py -m pytest tests\\mcp\\test_delete_customer.py -v
"""

import os

import pytest

from db_access import get_connection, init_db, transaction
from db_write_ops import (
    db_create_customer,
    db_create_job,
    db_delete_customer,
    db_update_customer,
)


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _make_customer(db_path, name="ZTEST Delete Me", status="Inactive"):
    result = db_create_customer(
        db_path, {"Company Name": name, "Status Active/Inactive": status}, actor="david"
    )
    return result.split("NEW_CUST_ID=")[1].strip()


def _make_job(db_path, customer_id):
    result = db_create_job(
        db_path,
        {"Customer Name / Company": "whatever", "CustomerID": customer_id, "Service Date": "2026-09-16"},
        actor="david",
    )
    return result.split("NEW_JOB_ID=")[1].strip()


# ── Guard 1: must already be Inactive ───────────────────────────────────

def test_refuses_to_delete_active_customer(db_path):
    cust_id = _make_customer(db_path, status="Active")
    result = db_delete_customer(db_path, cust_id, confirm=True)
    assert result.startswith("❌")
    assert "still Active" in result
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM customers WHERE customer_id = ?", (cust_id,)).fetchone()
    conn.close()
    assert row is not None  # nothing deleted


# ── Guard 2: confirm required ───────────────────────────────────────────

def test_preview_without_confirm_deletes_nothing(db_path):
    cust_id = _make_customer(db_path)
    result = db_delete_customer(db_path, cust_id, confirm=False)
    assert result.startswith("❌")
    assert "confirm=True" in result
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM customers WHERE customer_id = ?", (cust_id,)).fetchone()
    conn.close()
    assert row is not None


def test_preview_reports_linked_row_counts(db_path):
    cust_id = _make_customer(db_path)
    _make_job(db_path, cust_id)
    _make_job(db_path, cust_id)
    result = db_delete_customer(db_path, cust_id, confirm=False)
    assert "Jobs:          2" in result


# ── Not found / ambiguous ───────────────────────────────────────────────

def test_not_found_returns_error(db_path):
    result = db_delete_customer(db_path, "CUST-9999", confirm=True)
    assert result.startswith("❌")
    assert "No customer found" in result


def test_ambiguous_match_refused_nothing_deleted(db_path):
    _make_customer(db_path, name="ZTEST Alpha")
    _make_customer(db_path, name="ZTEST Alphb")
    result = db_delete_customer(db_path, "ZTEST Alph", confirm=True)
    assert result.startswith("❌")
    assert "matches 2 customers" in result
    conn = get_connection(db_path)
    count = conn.execute("SELECT COUNT(*) AS n FROM customers").fetchone()["n"]
    conn.close()
    assert count == 2


# ── Successful delete, no linked records ────────────────────────────────

def test_deletes_customer_with_no_linked_records(db_path):
    cust_id = _make_customer(db_path)
    result = db_delete_customer(db_path, cust_id, confirm=True)
    assert result.startswith("✅")
    assert "Safety backup saved first" in result
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM customers WHERE customer_id = ?", (cust_id,)).fetchone()
    conn.close()
    assert row is None


# ── Cascade delete ───────────────────────────────────────────────────────

def test_cascade_deletes_jobs_invoices_quotes_time_entries_route_stops(db_path):
    cust_id = _make_customer(db_path)
    job_id = _make_job(db_path, cust_id)

    with transaction(db_path) as conn:
        conn.execute(
            "INSERT INTO invoices (invoice_id, job_id, customer_id, total_due) VALUES (?, ?, ?, ?)",
            ("INV-0001", job_id, cust_id, 150.0),
        )
        # jobs<->invoices circular FK: link the job back to its invoice —
        # the exact case that requires nulling jobs.invoice_id before the
        # invoice row can be deleted (foreign_keys=ON, db_access.py).
        conn.execute("UPDATE jobs SET invoice_id = ? WHERE job_id = ?", ("INV-0001", job_id))
        conn.execute(
            "INSERT INTO quotes (quote_id, customer_id) VALUES (?, ?)",
            ("QTE-0001", cust_id),
        )
        conn.execute(
            "INSERT INTO time_entries (entry_id, job_id, entry_date) VALUES (?, ?, ?)",
            ("TE-0001", job_id, "2026-09-16"),
        )
        conn.execute(
            "INSERT INTO route_stops (route_date, crew_id, stop_number, job_id, customer_id) "
            "VALUES (?, ?, ?, ?, ?)",
            ("2026-09-16", "david", 1, job_id, cust_id),
        )

    result = db_delete_customer(db_path, cust_id, confirm=True)
    assert result.startswith("✅"), result

    conn = get_connection(db_path)
    assert conn.execute("SELECT * FROM customers WHERE customer_id = ?", (cust_id,)).fetchone() is None
    assert conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone() is None
    assert conn.execute("SELECT * FROM invoices WHERE invoice_id = 'INV-0001'").fetchone() is None
    assert conn.execute("SELECT * FROM quotes WHERE quote_id = 'QTE-0001'").fetchone() is None
    assert conn.execute("SELECT * FROM time_entries WHERE entry_id = 'TE-0001'").fetchone() is None
    assert conn.execute("SELECT * FROM route_stops WHERE job_id = ?", (job_id,)).fetchone() is None
    conn.close()


def test_safety_backup_file_actually_created(db_path):
    cust_id = _make_customer(db_path)
    result = db_delete_customer(db_path, cust_id, confirm=True)
    assert result.startswith("✅")
    backup_line = [l for l in result.splitlines() if "Safety backup saved first" in l][0]
    backup_path = backup_line.split(":", 1)[1].strip()
    assert os.path.exists(backup_path)


def test_reactivated_customer_refused_even_with_confirm(db_path):
    cust_id = _make_customer(db_path)
    db_update_customer(db_path, cust_id, {"Status Active/Inactive": "Active"}, actor="someone_else")
    result = db_delete_customer(db_path, cust_id, confirm=True)
    assert result.startswith("❌")
    assert "still Active" in result
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM customers WHERE customer_id = ?", (cust_id,)).fetchone()
    conn.close()
    assert row is not None
