"""
tests/mcp_tests/test_db_export_ops_phase6.py
==========================================
Job Board Architecture Spec — Phase 6 (spec §7, §11).

Direct unit tests for db_export_ops.db_export_to_excel. MCP-layer
wiring (the real export_to_excel() @mcp.tool(), both modes) is covered
separately in test_export_to_excel_phase6_mcp_wiring.py.

Testing requirements from the spec, addressed here:
  - Exported file opens cleanly (openpyxl can reload it without error —
    the automated proxy available for "no repair prompts in Excel").
  - Every DB table's current data appears correctly in the corresponding
    exported sheet, with correct column headers.
  - The export is genuinely inert: editing and saving the exported file
    has zero effect on the live database — tested explicitly below,
    not assumed from the one-way code path alone.

Run with:
    run_tests.bat tests\\mcp\\test_db_export_ops_phase6.py -v
"""
import sqlite3

import openpyxl
import pytest

from db_access import init_db
from db_export_ops import db_export_to_excel
from db_write_ops import db_create_customer, db_create_invoice, db_create_job, db_create_quote


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


@pytest.fixture
def output_path(tmp_path):
    return str(tmp_path / "export.xlsx")


def _cust_id(db_path, name="A"):
    """Job Board Architecture Spec §5.1 (2026-09-22): create_job now
    requires a real, existing CustomerID."""
    result = db_create_customer(db_path, {"Company Name": name}, actor="dave")
    return result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()


def test_export_creates_a_file_openable_by_openpyxl(db_path, output_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "A"}, actor="dave")
    result = db_export_to_excel(db_path, output_path)
    assert result.startswith("✅"), result

    # Reloading with openpyxl is the automated proxy for "Excel opens it
    # cleanly, no repair prompt" — a corrupted or malformed workbook
    # would raise here.
    wb = openpyxl.load_workbook(output_path)
    assert "Jobs_Schedule" in wb.sheetnames


def test_every_table_gets_its_own_sheet(db_path, output_path):
    db_export_to_excel(db_path, output_path)
    wb = openpyxl.load_workbook(output_path)
    expected = {"Jobs_Schedule", "Customers", "Invoices", "Quotes",
                "TimeLog", "Route_Planner", "Settings", "Services_Pricing"}
    assert expected.issubset(set(wb.sheetnames))


def test_jobs_sheet_has_correct_headers_and_data(db_path, output_path):
    # Job Board Architecture Spec §13 (field ownership): once a job has a
    # real customer_id, customer_name is Customers-owned — the customer
    # must actually be named "Torres Residence" for that name to appear,
    # not just any customer linked by ID (an explicit, differing
    # "Customer Name / Company" on the job itself is silently dropped by
    # _split_field_ownership in favor of the real customer's name).
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "Torres Residence"), "Customer Name / Company": "Torres Residence",
                             "Service Type": "Window"}, actor="dave")
    db_export_to_excel(db_path, output_path)
    wb = openpyxl.load_workbook(output_path)
    ws = wb["Jobs_Schedule"]
    headers = [c.value for c in ws[1]]
    assert "JobID (JOB-####)" in headers
    assert "Customer Name / Company" in headers

    cust_col = headers.index("Customer Name / Company") + 1
    data_row = [c.value for c in ws[2]]
    assert data_row[cust_col - 1] == "Torres Residence"


def test_customers_invoices_quotes_all_populated(db_path, output_path):
    cust_id = _cust_id(db_path, "Blue Wave")
    db_create_job(db_path, {"CustomerID (Customers!A)": cust_id, "Customer Name / Company": "X", "Quote Amount ($)": 100}, actor="dave")
    db_create_invoice(db_path, "JOB-0001", actor="dave")
    db_create_quote(db_path, {"Customer Name / Company": "Y"}, actor="dave")

    db_export_to_excel(db_path, output_path)
    wb = openpyxl.load_workbook(output_path)

    assert wb["Customers"].max_row == 2  # header + 1 row
    assert wb["Invoices"].max_row == 2
    assert wb["Quotes"].max_row == 2


def test_empty_database_still_produces_all_sheets_header_only(db_path, output_path):
    result = db_export_to_excel(db_path, output_path)
    assert result.startswith("✅"), result
    wb = openpyxl.load_workbook(output_path)
    for sheet in ("Jobs_Schedule", "Customers", "Invoices", "Quotes"):
        assert wb[sheet].max_row == 1  # header row only


def test_row_counts_reported_in_confirmation(db_path, output_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "A"), "Customer Name / Company": "A"}, actor="dave")
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "B"), "Customer Name / Company": "B"}, actor="dave")
    result = db_export_to_excel(db_path, output_path)
    assert "Jobs_Schedule: 2 row(s)" in result


def test_overwrites_existing_export_file(db_path, output_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "A"), "Customer Name / Company": "A"}, actor="dave")
    db_export_to_excel(db_path, output_path)

    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "B"), "Customer Name / Company": "B"}, actor="dave")
    db_export_to_excel(db_path, output_path)

    wb = openpyxl.load_workbook(output_path)
    assert wb["Jobs_Schedule"].max_row == 3  # header + 2 jobs now


# ══════════════════════════════════════════════════════════════════════════
# THE core Phase 6 property: export is genuinely inert (one-way)
# ══════════════════════════════════════════════════════════════════════════

def test_editing_and_saving_export_has_zero_effect_on_live_db(db_path, output_path):
    """Explicit test of the property the entire redesign depends on
    (spec §7, §11 testing requirement) — don't just assume the one-way
    direction holds because the code never reads output_path back."""
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "Original"), "Customer Name / Company": "Original"}, actor="dave")
    db_export_to_excel(db_path, output_path)

    # Edit the exported file directly and save it, exactly as a human
    # opening it in Excel and typing over a cell would.
    wb = openpyxl.load_workbook(output_path)
    ws = wb["Jobs_Schedule"]
    headers = [c.value for c in ws[1]]
    cust_col = headers.index("Customer Name / Company") + 1
    ws.cell(row=2, column=cust_col).value = "Tampered With"
    wb.save(output_path)

    # The live database must be completely unaffected by that edit.
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT customer_name FROM jobs WHERE job_id = 'JOB-0001'").fetchone()
    conn.close()
    assert row[0] == "Original"

    # A fresh read via any AI-Prowler tool also still shows the original —
    # confirming nothing in the read path was fooled by the tampered export.
    from db_read_ops import db_read_job_spreadsheet
    result = db_read_job_spreadsheet(db_path)
    assert "Original" in result
    assert "Tampered With" not in result


def test_export_never_reads_an_existing_file_at_output_path(db_path, output_path, tmp_path):
    """A pre-existing file at output_path (e.g. a stale export a human
    has been editing) must be silently overwritten, never merged with
    or read from — export_to_excel builds entirely from the live DB."""
    # Plant a bogus pre-existing "export" with data that isn't in the DB.
    bogus = openpyxl.Workbook()
    bogus["Sheet"].append(["This should never appear anywhere"])
    bogus.save(output_path)

    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "Real Data"), "Customer Name / Company": "Real Data"}, actor="dave")
    db_export_to_excel(db_path, output_path)

    wb = openpyxl.load_workbook(output_path)
    assert "Sheet" not in wb.sheetnames
    all_values = []
    for sheet in wb.sheetnames:
        for row in wb[sheet].iter_rows(values_only=True):
            all_values.extend(row)
    assert "This should never appear anywhere" not in all_values
    assert "Real Data" in all_values
