"""
tests/mcp_tests/test_no_sales_tax_backend.py
============================================
Backend tests for per-job "No Sales Tax" (2026-10-08).

Covers the claim in COMPLETE_USER_GUIDE.md (Jobs_Schedule columns):
  * `no_sales_tax` INTEGER column on the jobs table (1 = tax-exempt)
  * Invoices for tax-exempt jobs compute $0 tax

Isolated: tmp_path scratch databases only, in-process imports of
db_schema / db_write_ops / db_read_ops (same pattern as
test_db_write_ops_phase1.py — no ai_prowler_mcp import, no network).

Each test fails on the pre-2026-10-08 code (no column, no header-map
entry, tax always computed) and passes after.

Run: pytest tests/mcp_tests/test_no_sales_tax_backend.py -v
"""
from __future__ import annotations

import sqlite3

import pytest

from db_access import get_connection, init_db, transaction
from db_schema import apply_schema
from db_write_ops import (
    JOBS_HEADER_MAP,
    db_create_customer,
    db_create_invoice,
    db_create_job,
    db_update_job,
)
from db_read_ops import db_read_job_spreadsheet


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs_nst.db")
    init_db(path)
    return path


def _job_row(db_path, job_id) -> dict:
    conn = get_connection(db_path)
    try:
        row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    finally:
        conn.close()
    assert row is not None, f"job {job_id} not found"
    return dict(row)


def _invoices(db_path) -> list[dict]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT * FROM invoices").fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def _make_customer(db_path) -> str:
    result = db_create_customer(db_path, {"Company Name": "Tax Test Co"}, actor="david")
    assert result.startswith("✅"), result
    return result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()


def _make_priced_job(db_path, customer_id, updates_extra=None):
    """One priced job (quote 200, discount 20). Returns job_id."""
    updates = {
        "CustomerID": customer_id,
        "Customer Name / Company": "Tax Test Co",
        "Quote Amount ($)": 200,
        "Discount Applied ($)": 20,
        "Job Status": "Scheduled",
    }
    if updates_extra:
        updates.update(updates_extra)
    result = db_create_job(db_path, updates, actor="david")
    assert result.startswith("✅"), result
    return result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


# ── Schema: fresh installs ────────────────────────────────────────────

def test_fresh_schema_has_no_sales_tax_column(db_path):
    conn = get_connection(db_path)
    try:
        cols = {r[1]: r for r in conn.execute("PRAGMA table_info(jobs)").fetchall()}
    finally:
        conn.close()
    assert "no_sales_tax" in cols, "jobs table missing no_sales_tax after apply_schema"
    assert cols["no_sales_tax"][2].upper() == "INTEGER"
    assert cols["no_sales_tax"][4] == "0"  # PRAGMA dflt_value comes back as text


def test_fresh_schema_default_is_zero(db_path):
    """A job written without the flag must land taxable (0), never invent an exemption."""
    cust_id = _make_customer(db_path)
    job_id = _make_priced_job(db_path, cust_id)
    assert _job_row(db_path, job_id)["no_sales_tax"] == 0


# ── Schema: migration on existing installs ────────────────────────────

def test_migration_adds_column_to_legacy_table(db_path):
    """Simulate a pre-2026-10-08 database: drop the column, re-run
    apply_schema, and confirm the migration re-adds it with existing rows
    defaulting to 0 (taxable). Idempotent: running twice is a no-op."""
    conn = get_connection(db_path)
    try:
        conn.execute("ALTER TABLE jobs DROP COLUMN no_sales_tax")
        cols = {r[1] for r in conn.execute("PRAGMA table_info(jobs)").fetchall()}
        assert "no_sales_tax" not in cols  # now looks like a legacy DB
    finally:
        conn.close()

    cust_id = _make_customer(db_path)
    job_id = _make_priced_job(db_path, cust_id)

    conn = get_connection(db_path)
    try:
        apply_schema(conn)   # what every startup does
        apply_schema(conn)   # idempotency: second run must not fail either
        cols = {r[1]: r for r in conn.execute("PRAGMA table_info(jobs)").fetchall()}
    finally:
        conn.close()

    assert "no_sales_tax" in cols
    assert cols["no_sales_tax"][2].upper() == "INTEGER"
    assert _job_row(db_path, job_id)["no_sales_tax"] == 0


# ── Write path: create / update accept the flag ───────────────────────

def test_header_map_accepts_no_sales_tax():
    assert JOBS_HEADER_MAP.get("No Sales Tax") == "no_sales_tax"


def test_create_job_persists_no_sales_tax_flag(db_path):
    cust_id = _make_customer(db_path)
    job_id = _make_priced_job(db_path, cust_id, {"No Sales Tax": 1})
    assert _job_row(db_path, job_id)["no_sales_tax"] == 1


def test_update_job_toggles_no_sales_tax(db_path):
    cust_id = _make_customer(db_path)
    job_id = _make_priced_job(db_path, cust_id)
    assert _job_row(db_path, job_id)["no_sales_tax"] == 0

    result = db_update_job(db_path, job_id, {"No Sales Tax": 1}, actor="david")
    assert result.startswith("✅"), result
    assert _job_row(db_path, job_id)["no_sales_tax"] == 1

    result = db_update_job(db_path, job_id, {"No Sales Tax": 0}, actor="david")
    assert result.startswith("✅"), result
    assert _job_row(db_path, job_id)["no_sales_tax"] == 0


# ── Invoice math: $0 tax for exempt jobs ───────────────────────────────

def test_invoice_for_tax_exempt_job_stores_zero_tax(db_path):
    """no_sales_tax=1 -> tax STORED as 0 (not just hidden); total = quote - discount."""
    cust_id = _make_customer(db_path)
    job_id = _make_priced_job(db_path, cust_id, {"No Sales Tax": 1})

    result = db_create_invoice(db_path, job_id, "david", tax_rate=0.07)
    assert result.startswith("✅"), result
    assert "Tax (exempt)" in result

    invs = _invoices(db_path)
    assert len(invs) == 1
    inv = invs[0]
    assert inv["tax"] == 0.0, f"tax-exempt job must store $0 tax, got {inv['tax']}"
    assert inv["taxable_amt"] == 180.0
    assert inv["total_due"] == 180.0, f"total must be quote-discount only, got {inv['total_due']}"


def test_invoice_for_taxable_job_computes_tax_normally(db_path):
    """no_sales_tax=0 (or default) -> the old formula is byte-for-byte unchanged."""
    cust_id = _make_customer(db_path)
    job_id = _make_priced_job(db_path, cust_id, {"No Sales Tax": 0})

    result = db_create_invoice(db_path, job_id, "david", tax_rate=0.07)
    assert result.startswith("✅"), result
    assert "Tax (7%)" in result

    invs = _invoices(db_path)
    assert len(invs) == 1
    inv = invs[0]
    assert inv["tax"] == round(180.0 * 0.07, 2) == 12.60
    assert inv["total_due"] == round(180.0 + 12.60, 2) == 192.60


def test_invoice_for_legacy_null_no_sales_tax_computes_tax(db_path):
    """A row whose no_sales_tax is explicitly NULL (e.g. a blank write that
    cleared it) is treated as taxable -- the NULL guard path, not the 1 path.
    (Plain ADD COLUMN ... DEFAULT 0 backfills existing rows with 0, so NULL
    can only arise from an explicit write.)"""
    cust_id = _make_customer(db_path)
    job_id = _make_priced_job(db_path, cust_id)
    with transaction(db_path) as conn:
        conn.execute("UPDATE jobs SET no_sales_tax = NULL WHERE job_id = ?", (job_id,))
    row = _job_row(db_path, job_id)
    assert row["no_sales_tax"] is None

    result = db_create_invoice(db_path, job_id, "david", tax_rate=0.07)
    assert result.startswith("✅"), result
    invs = _invoices(db_path)
    assert len(invs) == 1
    assert invs[0]["tax"] == 12.60
    assert invs[0]["total_due"] == 192.60


# ── Read path: the frontend can display the flag ──────────────────────

def test_reads_return_no_sales_tax_field(db_path):
    cust_id = _make_customer(db_path)
    exempt_id = _make_priced_job(db_path, cust_id, {"No Sales Tax": 1})
    taxable_id = _make_priced_job(db_path, cust_id)

    text = db_read_job_spreadsheet(db_path, sheet_name="Jobs_Schedule")
    assert isinstance(text, str)
    assert "No Sales Tax" in text, "read path must surface the No Sales Tax field"
    # Both the exempt and the taxable job appear with their flag value
    assert exempt_id in text and taxable_id in text
