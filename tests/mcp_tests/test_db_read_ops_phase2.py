"""
tests/mcp_tests/test_db_read_ops_phase2.py
========================================
Job Board Architecture Spec — Phase 2 (spec §5, §11).

Direct unit tests for db_read_ops.db_read_job_spreadsheet, mirroring
test_db_write_ops_phase1.py's convention: exercise the storage-layer
function directly (no ctx, no subprocess) with restrict/crew_name passed
as plain arguments, since the MCP-layer ctx-to-restrict wiring itself is
covered separately (test_job_board_phase2_read_wiring.py).

Run with:
    run_tests.bat tests\\mcp\\test_db_read_ops_phase2.py -v
"""
import sqlite3

import pytest

from db_access import init_db
from db_read_ops import db_read_job_spreadsheet
from db_write_ops import db_create_customer, db_create_invoice, db_create_job, db_create_quote


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _cust_id(db_path, name="A"):
    """Job Board Architecture Spec §5.1 (2026-09-22): create_job now
    requires a real, existing CustomerID."""
    result = db_create_customer(db_path, {"Company Name": name}, actor="dave")
    return result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()


# ── Basic dispatch / happy path ─────────────────────────────────────────

def test_defaults_to_jobs_schedule(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "Jane Smith"), "Customer Name / Company": "Jane Smith"}, actor="dave")
    result = db_read_job_spreadsheet(db_path)
    assert "📋 Jobs_Schedule" in result
    assert "Jane Smith" in result
    assert "1 row(s)" in result


def test_customers_sheet(db_path):
    db_create_customer(db_path, {"Company Name": "Blue Wave Cafe", "Phone": "386-555-0101"}, actor="dave")
    result = db_read_job_spreadsheet(db_path, sheet_name="Customers")
    assert "📋 Customers" in result
    assert "Blue Wave Cafe" in result
    assert "386-555-0101" in result


def test_invoices_sheet(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "X", "Quote Amount ($)": 100}, actor="dave")
    db_create_invoice(db_path, "JOB-0001", actor="dave")
    result = db_read_job_spreadsheet(db_path, sheet_name="Invoices")
    assert "📋 Invoices" in result
    assert "INV-0001" in result


def test_quotes_sheet(db_path):
    db_create_quote(db_path, {"Customer Name / Company": "X"}, actor="dave")
    result = db_read_job_spreadsheet(db_path, sheet_name="Quotes")
    assert "📋 Quotes" in result
    assert "QTE-0001" in result


def test_not_yet_wired_sheet_fails_clearly(db_path):
    # Updated 2026-09-12 (Database-tab expansion): Route_Planner was the
    # example of an unwired sheet at Phase 2 — it's now fully wired
    # (see test_database_tab_read_expansion.py), so this test's own
    # assumption became stale along with the feature it was checking.
    # A genuinely nonexistent sheet name is the right fixture now.
    result = db_read_job_spreadsheet(db_path, sheet_name="Nonexistent_Sheet")
    assert result.startswith("❌")
    assert "Nonexistent_Sheet" in result


def test_no_rows_message(db_path):
    result = db_read_job_spreadsheet(db_path)
    assert result.startswith("📋 No rows found")


def test_blank_fields_omitted(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "X"}, actor="dave")
    result = db_read_job_spreadsheet(db_path)
    # Fields never set (e.g. Service Type) shouldn't appear at all.
    assert "Service Type:" not in result


def test_max_rows_respected(db_path):
    for i in range(5):
        db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, f"Cust {i}"), "Customer Name / Company": f"Cust {i}"}, actor="dave")
    result = db_read_job_spreadsheet(db_path, max_rows=2)
    assert "2 row(s)" in result


def test_max_rows_capped_at_500(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "X"}, actor="dave")
    # Should not raise even with an absurd max_rows — silently capped.
    result = db_read_job_spreadsheet(db_path, max_rows=99999)
    assert "1 row(s)" in result


# ── Date filtering, including multi-day jobs ────────────────────────────

def test_filter_date_matches_single_day_job(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "A"), "Customer Name / Company": "A", "Service Date": "2026-04-05"}, actor="dave")
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "B"), "Customer Name / Company": "B", "Service Date": "2026-04-06"}, actor="dave")
    result = db_read_job_spreadsheet(db_path, filter_date="04/05/2026")
    assert "1 row(s)" in result
    assert "Customer Name / Company: A" in result
    assert "Customer Name / Company: B" not in result


def test_filter_date_within_multi_day_range(db_path):
    db_create_job(db_path, {
        "CustomerID (Customers!A)": _cust_id(db_path, "MultiDay"),
        "Customer Name / Company": "MultiDay",
        "Service Date": "2026-04-05",
        "End Date (blank = single-day job)": "2026-04-08",
    }, actor="dave")
    # A date in the middle of the range must match.
    result = db_read_job_spreadsheet(db_path, filter_date="04/07/2026")
    assert "1 row(s)" in result
    assert "MultiDay" in result
    # R-058 overrun: while the job is still open it's still being worked after
    # its End Date, so the next working day matches too ...
    result2 = db_read_job_spreadsheet(db_path, filter_date="04/09/2026")
    assert "MultiDay" in result2
    # ... and once it's Complete, a date after the range must not match.
    from db_write_ops import db_update_job
    db_update_job(db_path, "JOB-0001", {"Job Status": "Complete"}, actor="dave")
    result3 = db_read_job_spreadsheet(db_path, filter_date="04/09/2026")
    assert result3.startswith("📋 No rows found")


def test_filter_date_blank_or_invalid_end_date_treated_as_single_day(db_path):
    db_create_job(db_path, {
        "CustomerID (Customers!A)": _cust_id(db_path, "BadEnd"),
        "Customer Name / Company": "BadEnd",
        "Service Date": "2026-04-05",
        "End Date (blank = single-day job)": "2026-04-01",  # earlier than start — ignored
    }, actor="dave")
    # Only the Service Date itself should match, not the (invalid) earlier End Date.
    result = db_read_job_spreadsheet(db_path, filter_date="04/05/2026")
    assert "BadEnd" in result
    result2 = db_read_job_spreadsheet(db_path, filter_date="04/03/2026")
    assert result2.startswith("📋 No rows found")


def test_filter_date_today_keyword(db_path):
    import datetime
    today_iso = datetime.date.today().isoformat()
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "Today"), "Customer Name / Company": "Today", "Service Date": today_iso}, actor="dave")
    result = db_read_job_spreadsheet(db_path, filter_date="today")
    assert "Today" in result


def test_filter_date_unparseable_rejected(db_path):
    result = db_read_job_spreadsheet(db_path, filter_date="not-a-date")
    assert result.startswith("❌")


def test_filter_date_only_applies_to_jobs_sheet(db_path):
    """Customers has no Service Date column — filter_date should simply
    have no effect there rather than erroring."""
    db_create_customer(db_path, {"Company Name": "X"}, actor="dave")
    result = db_read_job_spreadsheet(db_path, sheet_name="Customers", filter_date="04/05/2026")
    assert "X" in result


# ── Crew scoping ─────────────────────────────────────────────────────────

def test_field_crew_sees_only_own_jobs(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "Mine"), "Customer Name / Company": "Mine", "Crew / Technician": "Jake R"}, actor="dave")
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "Not Mine"), "Customer Name / Company": "Not Mine", "Crew / Technician": "Someone Else"}, actor="dave")
    result = db_read_job_spreadsheet(db_path, restrict=True, crew_name="jake r")
    assert "Mine" in result
    assert "Not Mine" not in result


def test_field_crew_blank_crew_row_excluded(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "Unassigned"), "Customer Name / Company": "Unassigned"}, actor="dave")
    result = db_read_job_spreadsheet(db_path, restrict=True, crew_name="jake r")
    assert result.startswith("📋 No rows found")
    assert "assigned to you" in result


def test_crew_scope_never_applies_to_customers_sheet(db_path):
    """Customers must stay fully readable regardless of restrict —
    send_email/send_sms name lookups depend on this."""
    db_create_customer(db_path, {"Company Name": "Anyone"}, actor="dave")
    result = db_read_job_spreadsheet(db_path, sheet_name="Customers", restrict=True, crew_name="jake r")
    assert "Anyone" in result


def test_owner_unrestricted_sees_all(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "A"), "Customer Name / Company": "A", "Crew / Technician": "Jake R"}, actor="dave")
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "B"), "Customer Name / Company": "B", "Crew / Technician": "Someone Else"}, actor="dave")
    result = db_read_job_spreadsheet(db_path, restrict=False)
    assert "A" in result and "B" in result


# ── Date display formatting ──────────────────────────────────────────────

def test_dates_displayed_as_mmddyyyy(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "X", "Service Date": "2026-04-05"}, actor="dave")
    result = db_read_job_spreadsheet(db_path)
    assert "04/05/2026" in result
    assert "2026-04-05" not in result
