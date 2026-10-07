"""
Tests for delete_service_pricing / db_delete_service_pricing — added
2026-09-15 alongside delete_customer, at the owner's request, so a
mistaken or discontinued price entry can actually be removed instead of
piling up forever. Unlike delete_customer, this needs no Inactive-first
gate and no cascade, since nothing in the schema references
service_pricing by foreign key (Jobs and Invoices always store their own
copied Service Type/amount at creation time, never a live link back to
the price list).

Run: py -m pytest tests\\mcp\\test_delete_service_pricing.py -v
"""

import os

import pytest

from db_access import get_connection, init_db
from db_write_ops import (
    db_create_customer,
    db_create_job,
    db_create_service_pricing,
    db_delete_service_pricing,
)


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _make_pricing(db_path, code="WIN", name="Window Washing", price=150.0):
    result = db_create_service_pricing(
        db_path,
        {"Service Code": code, "Name": name, "Base Price ($)": price},
        actor="david",
    )
    return result.split("NEW_SERVICE_CODE=")[1].strip()


# ── Not found ────────────────────────────────────────────────────────────

def test_not_found_returns_error(db_path):
    result = db_delete_service_pricing(db_path, "NOPE", confirm=True)
    assert result.startswith("❌")
    assert "No pricing entry found" in result


# ── Guard: confirm required ─────────────────────────────────────────────

def test_preview_without_confirm_deletes_nothing(db_path):
    code = _make_pricing(db_path)
    result = db_delete_service_pricing(db_path, code, confirm=False)
    assert result.startswith("❌")
    assert "confirm=True" in result
    conn = get_connection(db_path)
    row = conn.execute(
        "SELECT * FROM service_pricing WHERE service_code = ?", (code,)
    ).fetchone()
    conn.close()
    assert row is not None


def test_preview_reports_name_and_price(db_path):
    code = _make_pricing(db_path, code="PRESS", name="Pressure Wash", price=200.0)
    result = db_delete_service_pricing(db_path, code, confirm=False)
    assert "Pressure Wash" in result
    assert "200" in result


# ── Successful delete ────────────────────────────────────────────────────

def test_deletes_pricing_entry(db_path):
    code = _make_pricing(db_path)
    result = db_delete_service_pricing(db_path, code, confirm=True)
    assert result.startswith("✅")
    assert "Safety backup saved first" in result
    conn = get_connection(db_path)
    row = conn.execute(
        "SELECT * FROM service_pricing WHERE service_code = ?", (code,)
    ).fetchone()
    conn.close()
    assert row is None


def test_safety_backup_file_actually_created(db_path):
    code = _make_pricing(db_path)
    result = db_delete_service_pricing(db_path, code, confirm=True)
    backup_line = [l for l in result.splitlines() if "Safety backup saved first" in l][0]
    backup_path = backup_line.split(":", 1)[1].strip()
    assert os.path.exists(backup_path)


# ── No cascade needed — a job that already used this price is untouched ──

def test_deleting_pricing_entry_does_not_affect_jobs_that_already_used_it(db_path):
    code = _make_pricing(db_path, code="WIN", name="Window Washing", price=150.0)
    cust_result = db_create_customer(db_path, {"Company Name": "ZTEST Whoever"}, actor="david")
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    job_result = db_create_job(
        db_path,
        {
            "CustomerID (Customers!A)": cust_id,
            "Customer Name / Company": "ZTEST Whoever",
            "Service Type": "Window Washing",
            "Service Date": "2026-09-16",
            "Quote Amount ($)": 150.0,
        },
        actor="david",
    )
    job_id = job_result.split("NEW_JOB_ID=")[1].strip()

    result = db_delete_service_pricing(db_path, code, confirm=True)
    assert result.startswith("✅")

    conn = get_connection(db_path)
    job_row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    conn.close()
    assert job_row is not None
    assert job_row["service_type"] == "Window Washing"
    assert job_row["quote_amount"] == 150.0
