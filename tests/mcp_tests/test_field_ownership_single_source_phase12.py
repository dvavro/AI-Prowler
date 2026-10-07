"""
tests/mcp_tests/test_field_ownership_single_source_phase12.py
========================================================
Job Board Architecture Spec §12 (Field Ownership & Live-Join Policy).

Direct regression tests for the JOB-0007 bug: marking an invoice
paid-cash in the Jobs PWA updated invoices.payment_status, but the Jobs
tab kept reading jobs.payment_status — its own separately stored copy —
so no refresh could ever surface the change. §12 closes this bug class
by making every duplicated field single-sourced: read paths always join
the owning record live (db_read_ops._apply_live_join_overlays), and
write paths refuse to touch the row's own copy once it's linked to an
owner (db_write_ops.make_invoice_owned_job_check /
make_customer_owned_check / make_computed_customer_rollup_check).

Covers all four cases from the spec:
  A) Invoice-owned fields on jobs (Payment Status, Quote Amount,
     Discount Applied, Service Type, Service Details)
  B) Customer-owned fields (Customer Name / Company, Customer Type)
  C) Dead job columns (Invoice Total ($))
  D) Customer rollups (Total Jobs Completed, Lifetime Revenue,
     Last Service Date, Next Sched. Date)

Run with:
    run_tests.bat tests\\mcp\\test_field_ownership_single_source_phase12.py -v
"""
from __future__ import annotations

import sqlite3
import sys
import time
from pathlib import Path

import pytest

from db_access import init_db, utcnow_iso
from db_read_ops import db_get_jobs_changed_since, db_read_job_spreadsheet
from db_write_ops import (
    db_create_customer,
    db_create_invoice,
    db_create_job,
    db_update_customer,
    db_update_invoice,
    db_update_job,
)

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


# ── helpers ──────────────────────────────────────────────────────────────

def _extract(result: str, marker: str) -> str:
    return result.split(marker)[1].splitlines()[0].strip()


def _raw_job_column(db_path, job_id, column):
    """Reads a column DIRECTLY off the jobs table, bypassing every
    overlay — used to prove the job's own stored copy is untouched even
    though the live-join read shows the invoice's value."""
    conn = sqlite3.connect(db_path)
    row = conn.execute(f"SELECT {column} FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    conn.close()
    return row[0] if row else None


def _raw_invoice_column(db_path, invoice_id, column):
    conn = sqlite3.connect(db_path)
    row = conn.execute(f"SELECT {column} FROM invoices WHERE invoice_id = ?", (invoice_id,)).fetchone()
    conn.close()
    return row[0] if row else None


def _column_exists(db_path, table, column):
    conn = sqlite3.connect(db_path)
    cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    conn.close()
    return column in cols


def _make_customer(db_path, company_name, customer_type="Residential"):
    result = db_create_customer(
        db_path,
        {"Company Name": company_name, "Customer Type Comm/Res": customer_type},
        actor="dave",
    )
    return _extract(result, "NEW_CUST_ID=")


def _make_job(db_path, customer_name, quote_amount=200.0, customer_id=None, job_status=""):
    # Job Board Architecture Spec §5.1 (2026-09-22): create_job now requires
    # a real, existing CustomerID — auto-create one (matching customer_name)
    # when the caller doesn't already have one to link. Callers that
    # deliberately need a job with NO linked customer (a legacy/free-text
    # row predating this requirement) use _seed_customerless_job instead,
    # which bypasses db_create_job's new check via a direct INSERT.
    if not customer_id:
        cust_result = db_create_customer(db_path, {"Company Name": customer_name}, actor="dave")
        customer_id = _extract(cust_result, "NEW_CUST_ID=")
    updates = {"CustomerID": customer_id, "Customer Name / Company": customer_name, "Quote Amount ($)": quote_amount}
    if job_status:
        updates["Job Status"] = job_status
    result = db_create_job(db_path, updates, actor="dave")
    return _extract(result, "NEW_JOB_ID=")


def _seed_customerless_job(db_path, customer_name, quote_amount=200.0):
    """Simulates a job created before the §5.1 customer-before-job
    requirement existed — a genuine legacy row with no customer_id at all.
    Bypasses db_create_job (which now requires one) via a direct INSERT,
    for the one test whose premise is exactly this legacy state."""
    conn = sqlite3.connect(db_path)
    cur = conn.execute(
        "INSERT INTO jobs (job_id, customer_name, quote_amount, created_by, "
        "last_edited_by, last_edited_at, version) "
        "VALUES (?, ?, ?, 'dave', 'dave', datetime('now'), 1)",
        (f"JOB-LEGACY-{customer_name[:6]}", customer_name, quote_amount),
    )
    conn.commit()
    job_id = cur.lastrowid
    conn.close()
    # job_id text PK is what we inserted, not the integer rowid.
    return f"JOB-LEGACY-{customer_name[:6]}"


def _make_invoice(db_path, job_id, **kwargs):
    result = db_create_invoice(db_path, job_id, actor="dave", **kwargs)
    assert "NEW_INVOICE_ID=" in result, result
    return _extract(result, "NEW_INVOICE_ID=")


# ── Case A: invoice-owned fields — the JOB-0007 bug itself ──────────────

class TestInvoiceOwnedFieldsCaseA:

    def test_payment_status_change_on_invoice_reflected_on_job_read(self, db_path):
        """The exact JOB-0007 scenario: mark the invoice's Payment Status
        Cash, then read the Jobs sheet — it must show Cash, not the job's
        own stale 'Unpaid' copy, with no propagation step in between."""
        job_id = _make_job(db_path, "Torres LLC", quote_amount=150.0)
        inv_id = _make_invoice(db_path, job_id)

        result = db_update_invoice(db_path, inv_id, {"Payment Status": "Cash"}, actor="dave")
        assert "updated" in result.lower(), result

        jobs_view = db_read_job_spreadsheet(db_path, sheet_name="Jobs_Schedule")
        assert "Payment Status: Cash" in jobs_view, jobs_view
        assert "Payment Status: Unpaid" not in jobs_view

        # The job's OWN stored column is allowed to still say Unpaid —
        # that's fine and expected; the point is nothing ever reads it
        # again once an invoice exists.
        assert _raw_job_column(db_path, job_id, "payment_status") != "Cash"

    def test_polling_endpoint_surfaces_invoice_only_change(self, db_path):
        """db_get_jobs_changed_since must surface a job whose invoice
        changed, even though only invoices.last_edited_at moved — a
        change to an invoice-owned field is a change to the job as far
        as anyone polling the Job Board is concerned."""
        job_id = _make_job(db_path, "Blue Wave Cafe", quote_amount=300.0)
        inv_id = _make_invoice(db_path, job_id)

        since = utcnow_iso()
        time.sleep(1.1)  # ensure a strictly later last_edited_at (second-granularity)

        db_update_invoice(db_path, inv_id, {"Payment Status": "Check"}, actor="dave")

        changed = db_get_jobs_changed_since(db_path, since, sheet_name="Jobs_Schedule")
        matching = [r for r in changed if r.get("JobID (JOB-####)") == job_id]
        assert matching, f"job {job_id} not surfaced by polling after its invoice changed"
        assert matching[0]["Payment Status"] == "Check"

    def test_writing_invoice_owned_field_on_invoiced_job_is_silently_dropped(self, db_path):
        """Spec §13.6 revision: a direct write to Payment Status/Quote
        Amount on an already-invoiced job is silently DROPPED, not hard-
        rejected — the Jobs PWA's edit form resubmits the whole row it
        loaded on every save, so a hard rejection here would make an
        ordinary edit to any OTHER field on an invoiced job impossible
        the moment a locked field happened to ride along unchanged (this
        exact bug was found testing live against JOB-0008/INV-0003).
        The field is dropped, the invoice's real value is untouched, and
        the response says why."""
        job_id = _make_job(db_path, "Harbor Inn", quote_amount=500.0)
        inv_id = _make_invoice(db_path, job_id)
        db_update_invoice(db_path, inv_id, {"Payment Status": "Paid"}, actor="dave")

        result = db_update_job(db_path, job_id, {"Payment Status": "Unpaid"}, actor="dave")
        assert result.startswith("✅"), result
        assert "Payment Status" in result and inv_id in result

        # The invoice's real value must be untouched by the dropped write.
        assert _raw_invoice_column(db_path, inv_id, "payment_status") == "Paid"

        result2 = db_update_job(db_path, job_id, {"Quote Amount ($)": 999.0}, actor="dave")
        assert result2.startswith("✅"), result2
        assert _raw_invoice_column(db_path, inv_id, "subtotal") == 500.0

    def test_locked_field_dropped_but_legitimate_change_in_same_call_still_applies(self, db_path):
        """The exact scenario found live: saving a real change (Job
        Status) alongside an untouched, now-locked field (Payment
        Status) in the SAME call must still apply the real change —
        only the locked field is dropped, not the whole request."""
        job_id = _make_job(db_path, "Blended Update Co", quote_amount=300.0)
        inv_id = _make_invoice(db_path, job_id)

        result = db_update_job(db_path, job_id,
                                {"Job Status": "In Progress", "Payment Status": "Unpaid"},
                                actor="dave")
        assert result.startswith("✅"), result
        assert "Job Status -> In Progress" in result
        assert "Payment Status" in result  # reported as dropped, not silently missing
        assert _raw_job_column(db_path, job_id, "job_status") == "In Progress"

    def test_pre_invoice_job_fields_remain_directly_editable(self, db_path):
        """No invoice yet -> nothing to join to -> editing the job's own
        Payment Status / Quote Amount / Service Type works exactly as
        before. This is the regression guard for the ordinary, much more
        common, not-yet-invoiced workflow."""
        job_id = _make_job(db_path, "Sunshine Realty", quote_amount=100.0)

        result = db_update_job(db_path, job_id, {"Quote Amount ($)": 175.0,
                                                  "Service Type": "Pressure Wash"}, actor="dave")
        assert result.startswith("✅"), result
        assert _raw_job_column(db_path, job_id, "quote_amount") == 175.0
        assert _raw_job_column(db_path, job_id, "service_type") == "Pressure Wash"


# ── Case C: dead job columns read live from the invoice ─────────────────

class TestDeadColumnsCaseC:

    def test_dead_columns_dropped_from_schema(self, db_path):
        """Spec §13.6: these columns are retired entirely, not just
        ignored — a fresh database should never have created them."""
        assert not _column_exists(db_path, "jobs", "invoice_total")
        assert not _column_exists(db_path, "jobs", "actual_amount")
        assert not _column_exists(db_path, "jobs", "tax_pct")
        assert not _column_exists(db_path, "customers", "last_service_date")
        assert not _column_exists(db_path, "customers", "next_scheduled_date")
        assert not _column_exists(db_path, "customers", "total_jobs_completed")
        assert not _column_exists(db_path, "customers", "lifetime_revenue")

    def test_existing_database_migrated_drops_the_columns(self, tmp_path):
        """Spec §13.6: an existing database created before this change
        still has the old columns until apply_schema runs once more —
        confirms the migration actually fires on a real pre-existing
        table, not just on a database that never had the columns.
        Builds the 'legacy' state by taking a fully current schema and
        adding the seven old columns back directly (bypassing
        apply_schema) — this keeps every other column/index the real
        schema expects intact, rather than hand-rolling a stripped-down
        fake table that would fail on unrelated CREATE INDEX statements.
        """
        import sqlite3 as _sqlite3
        from db_schema import apply_schema

        path = str(tmp_path / "legacy.db")
        conn = _sqlite3.connect(path)
        apply_schema(conn)
        conn.execute("ALTER TABLE jobs ADD COLUMN invoice_total REAL")
        conn.execute("ALTER TABLE jobs ADD COLUMN actual_amount REAL")
        conn.execute("ALTER TABLE jobs ADD COLUMN tax_pct REAL")
        conn.execute("ALTER TABLE customers ADD COLUMN last_service_date TEXT")
        conn.execute("ALTER TABLE customers ADD COLUMN next_scheduled_date TEXT")
        conn.execute("ALTER TABLE customers ADD COLUMN total_jobs_completed INTEGER")
        conn.execute("ALTER TABLE customers ADD COLUMN lifetime_revenue REAL")
        conn.commit()
        conn.close()

        assert _column_exists(path, "jobs", "invoice_total")  # sanity: legacy state really has it

        conn = _sqlite3.connect(path)
        apply_schema(conn)
        conn.close()

        assert not _column_exists(path, "jobs", "invoice_total")
        assert not _column_exists(path, "jobs", "actual_amount")
        assert not _column_exists(path, "jobs", "tax_pct")
        assert not _column_exists(path, "customers", "last_service_date")
        assert not _column_exists(path, "customers", "next_scheduled_date")
        assert not _column_exists(path, "customers", "total_jobs_completed")
        assert not _column_exists(path, "customers", "lifetime_revenue")

    def test_invoice_total_reads_from_invoice_not_stored_job_value(self, db_path):
        job_id = _make_job(db_path, "Crabby's Daytona", quote_amount=400.0)
        inv_id = _make_invoice(db_path, job_id, tax_rate=0.07)

        expected_total = _raw_invoice_column(db_path, inv_id, "total_due")
        jobs_view = db_read_job_spreadsheet(db_path, sheet_name="Jobs_Schedule")
        assert f"Invoice Total ($): {expected_total}" in jobs_view, jobs_view

    def test_actual_amount_and_tax_pct_read_live_from_invoice(self, db_path):
        """Spec §13.3: actual_amount reads from invoices.taxable_amt
        (quote - discount, before tax); tax_pct is derived from the
        invoice's own effective rate (tax / taxable_amt), reflecting a
        per-invoice tax_rate override rather than assuming today's
        default rate applied historically."""
        job_id = _make_job(db_path, "Anchor Marina Supply", quote_amount=500.0)
        inv_id = _make_invoice(db_path, job_id, discount=50.0, tax_rate=0.08)

        expected_taxable = _raw_invoice_column(db_path, inv_id, "taxable_amt")
        expected_tax = _raw_invoice_column(db_path, inv_id, "tax")
        expected_pct = round(expected_tax / expected_taxable, 4)

        jobs_view = db_read_job_spreadsheet(db_path, sheet_name="Jobs_Schedule")
        assert f"Actual Amount ($) =Quote-Discount: {expected_taxable}" in jobs_view, jobs_view
        assert f"Tax (Tax%): {expected_pct}" in jobs_view, jobs_view

    def test_writing_computed_job_fields_directly_is_always_rejected(self, db_path):
        """Unlike Case A's fields, Invoice Total / Actual Amount / Tax%
        have no job-owned draft state at all — the write is a no-op
        regardless of invoice status, since nothing has ever computed a
        real value for them pre-invoice either. db_update_job's
        "nothing else in this request was writable" ✅ (not ❌) is the
        established response for a request touching ONLY computed/locked
        fields — see db_write_ops.py's own comment on that branch, and
        test_create_job_with_computed_field_does_not_crash just below,
        which asserts the identical shape for the create path."""
        job_id = _make_job(db_path, "Pre-Invoice Test Co", quote_amount=200.0)

        result = db_update_job(db_path, job_id, {"Invoice Total ($)": 999.0}, actor="dave")
        assert result.startswith("✅"), result
        assert "computed live" in result.lower()

        result2 = db_update_job(db_path, job_id, {"Tax (Tax%)": 0.5}, actor="dave")
        assert result2.startswith("✅"), result2
        assert "computed live" in result2.lower()

    def test_create_job_with_computed_field_does_not_crash(self, db_path):
        """db_create_job has no check_fn hook at all — the SQL-safety
        filter in _split_computed_only is the actual backstop here, and
        must silently drop the field rather than raise a raw sqlite
        'no such column' error."""
        cust_id = _make_customer(db_path, "New Co")
        result = db_create_job(db_path, {"CustomerID": cust_id, "Customer Name / Company": "New Co",
                                          "Invoice Total ($)": 123.0}, actor="dave")
        assert result.startswith("✅"), result
        assert "computed live" in result.lower()


    def test_excel_export_shows_live_values_not_blanks(self, db_path, tmp_path):
        """db_export_ops.py imports the same display-pairs lists as the
        read tools but builds its own SELECT — a real regression risk
        the schema drop exposed: without also applying the live-join
        overlay there, the exported Invoice Total / Actual Amount / Tax%
        / rollup columns would silently go blank for every row instead
        of showing the same live values the Jobs/Customers tabs show."""
        import openpyxl
        from db_export_ops import db_export_to_excel

        cust_id = _make_customer(db_path, "Export Test Co")
        job_id = _make_job(db_path, "Export Test Co", quote_amount=300.0,
                            customer_id=cust_id, job_status="Complete")
        inv_id = _make_invoice(db_path, job_id, tax_rate=0.07)
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE invoices SET amount_paid = 321.0 WHERE invoice_id = ?", (inv_id,))
        conn.commit()
        conn.close()
        expected_total = _raw_invoice_column(db_path, inv_id, "total_due")

        out = str(tmp_path / "export.xlsx")
        result = db_export_to_excel(db_path, out)
        assert result.startswith("✅"), result

        wb = openpyxl.load_workbook(out)
        jobs_ws = wb["Jobs_Schedule"]
        headers = [c.value for c in jobs_ws[1]]
        job_row = [c.value for c in jobs_ws[2]]
        job_dict = dict(zip(headers, job_row))
        assert job_dict["Invoice Total ($)"] == expected_total

        customers_ws = wb["Customers"]
        headers = [c.value for c in customers_ws[1]]
        cust_row = [c.value for c in customers_ws[2]]
        cust_dict = dict(zip(headers, cust_row))
        assert cust_dict["Total Jobs Completed"] == 1
        assert cust_dict["Lifetime Revenue ($)"] == 321.0


# ── Case B: customer-owned fields ────────────────────────────────────────

class TestCustomerOwnedFieldsCaseB:

    def test_customer_rename_propagates_to_job_and_invoice_on_next_read(self, db_path):
        cust_id = _make_customer(db_path, "Old Name LLC")
        job_id = _make_job(db_path, "Old Name LLC", quote_amount=250.0, customer_id=cust_id)
        inv_id = _make_invoice(db_path, job_id)

        rename_result = db_update_customer(db_path, cust_id, {"Company Name": "New Name LLC"}, actor="dave")
        assert rename_result.startswith("✅"), rename_result

        jobs_view = db_read_job_spreadsheet(db_path, sheet_name="Jobs_Schedule")
        assert "New Name LLC" in jobs_view
        assert "Old Name LLC" not in jobs_view

        invoices_view = db_read_job_spreadsheet(db_path, sheet_name="Invoices")
        assert "New Name LLC" in invoices_view

    def test_writing_customer_name_on_linked_job_is_rejected(self, db_path):
        """Same "nothing else in this request was writable" ✅ shape as
        the computed-fields case above — Customer Name / Company is
        Customers-owned once a real customer_id is linked, so the write
        is a silent no-op, not a hard error."""
        cust_id = _make_customer(db_path, "Anchor Marina")
        job_id = _make_job(db_path, "Anchor Marina", quote_amount=100.0, customer_id=cust_id)

        result = db_update_job(db_path, job_id, {"Customer Name / Company": "Wrong Name"}, actor="dave")
        assert result.startswith("✅"), result
        assert "customer" in result.lower()

    def test_free_text_job_with_no_customer_id_keeps_own_name_editable(self, db_path):
        """No customer_id -> nothing to join to -> the job's own typed-in
        name is legitimately authoritative and stays directly editable.
        Uses _seed_customerless_job (a legacy row predating §5.1's
        customer-before-job requirement) since db_create_job itself can no
        longer create a job with no customer_id."""
        job_id = _seed_customerless_job(db_path, "Walk-in Customer", quote_amount=80.0)

        result = db_update_job(db_path, job_id, {"Customer Name / Company": "Corrected Walk-in Name"},
                                actor="dave")
        assert result.startswith("✅"), result
        assert _raw_job_column(db_path, job_id, "customer_name") == "Corrected Walk-in Name"


# ── Case D: customer rollups always computed live ────────────────────────

class TestCustomerRollupsCaseD:

    def test_total_jobs_completed_and_lifetime_revenue_computed_live(self, db_path):
        cust_id = _make_customer(db_path, "Marina Bay Condos")
        job1 = _make_job(db_path, "Marina Bay Condos", quote_amount=300.0,
                          customer_id=cust_id, job_status="Complete")
        _make_job(db_path, "Marina Bay Condos", quote_amount=150.0,
                  customer_id=cust_id, job_status="Scheduled")
        inv_id = _make_invoice(db_path, job1)
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE invoices SET amount_paid = 300.0 WHERE invoice_id = ?", (inv_id,))
        conn.commit()
        conn.close()

        customers_view = db_read_job_spreadsheet(db_path, sheet_name="Customers")
        assert "Total Jobs Completed: 1" in customers_view, customers_view
        assert "Lifetime Revenue ($): 300.0" in customers_view, customers_view

        # Nothing was ever written to these columns — proves the numbers
        # are computed at read time, not stale stored values (the columns
        # don't even exist anymore; see test_dead_columns_dropped_from_schema).
        assert not _column_exists(db_path, "customers", "total_jobs_completed")
        assert not _column_exists(db_path, "customers", "lifetime_revenue")

    def test_direct_write_to_rollup_fields_rejected_for_any_role(self, db_path):
        """Not just field_crew — staff/owner/manager (restrict=False) get
        the same "nothing else in this request was writable" ✅ no-op
        (not a hard ❌) for a direct write to a computed rollup, matching
        the shape asserted elsewhere in this file for computed/locked
        fields — there's no role for which the write actually lands, but
        a locked-field write isn't treated as an error condition."""
        cust_id = _make_customer(db_path, "Palmetto Plaza")

        result = db_update_customer(db_path, cust_id, {"Total Jobs Completed": 99}, actor="dave",
                                     restrict=False)
        assert result.startswith("✅"), result

        result2 = db_update_customer(db_path, cust_id, {"Lifetime Revenue ($)": 50000.0}, actor="dave",
                                      restrict=False)
        assert result2.startswith("✅"), result2

        result3 = db_update_customer(db_path, cust_id, {"Last Service Date": "01/01/2020"}, actor="dave",
                                      restrict=False)
        assert result3.startswith("✅"), result3
