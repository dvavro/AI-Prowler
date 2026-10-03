"""
tests/mcp_tests/test_fk_blank_coercion_bugfix.py
==============================================
Real bug found during live browser testing of the Job Board kanban UI:
the Jobs PWA's edit form always sends every field, blank or not —
including 'InvoiceID (INV-####)': '' for the extremely common case of a
job that has no invoice yet. jobs.invoice_id is a real FK
(REFERENCES invoices(invoice_id)); SQLite's FK enforcement only exempts
NULL from the "must match an existing row" check, so writing the literal
empty string there fails with a raw, unhelpful "FOREIGN KEY constraint
failed" — reproduced live via update_job_spreadsheet through the actual
edit-modal-shaped update dict.

Fixed by coercing a blank/empty value destined for any FK column
(customer_id, invoice_id, job_id, quote_id, crew_user_id) to NULL before
it reaches the SQL parameter, in the single shared _coerce_value()
choke point both db_create_row and db_update_row funnel every field
through.

Updated 2026-09-22 (Job Board Architecture Spec §5.1, customer-before-job
requirement): db_create_job now requires a valid, existing CustomerID —
a blank/missing one is rejected outright with a clear ❌ before
_coerce_value ever runs, rather than being silently coerced to NULL and
the job created anyway. Every db_create_job() call below that used to
rely on "Customer Name / Company alone is enough" now creates a real
customer first and passes its CustomerID — these are UPDATE-path
(InvoiceID) coercion tests, unaffected in substance by §5.1, they just
need a job to exist first. test_blank_customer_id_on_create_no_longer_crashes
is renamed/repurposed below to assert the new §5.1 behavior instead of
the old "coerced to NULL, job still created" behavior it can no longer
have — see that test's own docstring.

Run with:
    run_tests.bat tests\\mcp\\test_fk_blank_coercion_bugfix.py -v
"""
import sqlite3

import pytest

from db_access import init_db
from db_write_ops import db_create_customer, db_create_job, db_update_job


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def test_blank_invoice_id_on_update_no_longer_crashes(db_path):
    """The exact live-repro scenario: edit a job that has no invoice yet,
    saving the full edit-modal-shaped updates dict including a blank
    InvoiceID field."""
    db_create_customer(db_path, {"Company Name": "A"}, actor="dave")
    db_create_job(db_path, {"CustomerID (Customers!A)": "CUST-0001",
                             "Customer Name / Company": "A"}, actor="dave")
    result = db_update_job(db_path, "JOB-0001", {
        "Job Status": "In Progress",
        "Payment Status": "",
        "Recurrence": "One-time",
        "Quote Amount ($)": 0,
        "Discount Applied ($)": 0,
        "InvoiceID (INV-####)": "",          # <-- the field that crashed
        "Invoice Sent Date": "",
    }, actor="dave")
    assert result.startswith("✅"), result

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT invoice_id, job_status FROM jobs WHERE job_id = 'JOB-0001'").fetchone()
    conn.close()
    assert row == (None, "In Progress")  # NULL, not the empty string


def test_blank_customer_id_on_create_no_longer_crashes(db_path):
    """Repurposed 2026-09-22 (spec §5.1): this used to assert that a blank
    CustomerID on create_job was silently coerced to NULL and the job
    created anyway — that is now exactly the behavior §5.1 prohibits.
    create_job's own pre-check (db_write_ops.db_create_job) now intercepts
    a blank/missing CustomerID before _coerce_value ever runs, and returns
    a clear ❌ rather than crashing OR silently creating an unlinked job.
    No row is created — this is the "no longer crashes" guarantee's new
    shape: a clean, actionable error instead of a raw exception."""
    result = db_create_job(db_path, {
        "Customer Name / Company": "No customer record yet",
        "CustomerID (Customers!A)": "",
    }, actor="dave")
    assert result.startswith("❌"), result
    assert "customer_id is required" in result

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT COUNT(*) FROM jobs").fetchone()
    conn.close()
    assert row == (0,)  # nothing was created


def test_real_invoice_id_still_writes_correctly(db_path):
    """The fix must only touch BLANK values — a real, valid FK value
    still needs to actually write and still needs to be validated (a
    bogus non-blank InvoiceID should still fail)."""
    db_create_customer(db_path, {"Company Name": "A"}, actor="dave")
    db_create_job(db_path, {"CustomerID (Customers!A)": "CUST-0001",
                             "Customer Name / Company": "A",
                             "Quote Amount ($)": 100}, actor="dave")

    from db_write_ops import db_create_invoice
    inv_result = db_create_invoice(db_path, "JOB-0001", actor="dave")
    assert inv_result.startswith("✅"), inv_result

    result = db_update_job(db_path, "JOB-0001", {"InvoiceID (INV-####)": "INV-0001"}, actor="dave")
    assert result.startswith("✅"), result
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT invoice_id FROM jobs WHERE job_id = 'JOB-0001'").fetchone()
    conn.close()
    assert row == ("INV-0001",)


def test_bogus_nonblank_invoice_id_still_rejected(db_path):
    """A non-blank value that doesn't correspond to a real invoice must
    still hit the FK constraint — the fix narrowly targets BLANK values,
    it doesn't disable FK enforcement."""
    db_create_customer(db_path, {"Company Name": "A"}, actor="dave")
    db_create_job(db_path, {"CustomerID (Customers!A)": "CUST-0001",
                             "Customer Name / Company": "A"}, actor="dave")
    with pytest.raises(sqlite3.IntegrityError):
        db_update_job(db_path, "JOB-0001", {"InvoiceID (INV-####)": "INV-9999"}, actor="dave")


def test_blank_customer_id_on_customer_create_unaffected(db_path):
    """customers.customer_id is the PRIMARY KEY, not a foreign key, and
    is excluded from being overwritten before _coerce_value ever runs —
    confirms the FK column set doesn't accidentally clash with an
    unrelated same-named primary key column on a different table."""
    result = db_create_customer(db_path, {"Company Name": "X"}, actor="dave")
    assert result.startswith("✅"), result
