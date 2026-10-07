"""
tests/mcp_tests/test_job_board_phase1_mcp_wiring.py
=================================================
Job Board Architecture Spec — Phase 1 (spec §5, §11).

Integration tests for the actual @mcp.tool() write functions
(create_job, create_customer, create_quote, create_invoice,
log_time_entry, update_job_spreadsheet) now that their internals call
db_write_ops instead of openpyxl. Complements test_db_write_ops_phase1.py
(which tests db_write_ops functions directly, including the full
crew-scoping matrix) by proving the MCP tool layer wires those functions
up correctly: path resolution (_resolve_job_db_path), the public
function signatures, and end-to-end behavior through a realistic
create -> invoice -> clock -> update chain.

Why a NEW file rather than editing test_create_invoice_isolated.py /
test_log_time_entry_isolated.py in place: those files build .xlsx
fixtures directly with openpyxl and read results back the same way —
that's the actual thing this migration replaced, so those assertions
now check a store the tool no longer writes to. They still document real
openpyxl-era edge cases (decorated multi-line headers, formula-cell
staleness) that no longer apply to a real-column SQLite schema. Retiring
or rewriting them is tracked separately; this file is the DB-backed
replacement for their "does the real tool function work end-to-end"
coverage, using the same subprocess-isolation pattern they established.

Personal mode only (ctx=None) — the full crew-scoping allow/deny matrix
is already covered at the db_write_ops layer in test_db_write_ops_phase1.py
using restrict=True/crew_name directly; faking a server-mode FastMCP
Context here would duplicate that coverage without testing anything new
about the MCP-layer wiring itself.

Run with:
    run_tests.bat tests\\mcp\\test_job_board_phase1_mcp_wiring.py -v
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import textwrap
import datetime
from pathlib import Path

import pytest

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent


def _run(tmp_path: Path, db_path: Path, call: str) -> str:
    """Run one `m.<call>` expression against ai_prowler_mcp.py in an
    isolated subprocess (HOME/USERPROFILE redirected into tmp_path, same
    convention as test_create_invoice_isolated.py / test_log_time_entry_
    isolated.py), returning the tool's string result."""
    scratch_home = tmp_path / "scratch_home"
    scratch_home.mkdir(exist_ok=True)

    script = textwrap.dedent(f"""
        import sys, json
        sys.path.insert(0, {str(SRC_ROOT)!r})
        import ai_prowler_mcp as m
        result = {call}
        print("RESULT_JSON_START" + json.dumps(result) + "RESULT_JSON_END")
    """)

    env = os.environ.copy()
    env["USERPROFILE"] = str(scratch_home)
    env["HOME"] = str(scratch_home)

    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(SRC_ROOT), env=env,
        capture_output=True, text=True, timeout=90,
    )
    if "RESULT_JSON_START" not in proc.stdout:
        raise AssertionError(
            f"Subprocess did not return a result.\n"
            f"--- stdout ---\n{proc.stdout}\n"
            f"--- stderr ---\n{proc.stderr}\n"
            f"--- returncode --- {proc.returncode}"
        )
    payload = proc.stdout.split("RESULT_JSON_START", 1)[1].split("RESULT_JSON_END", 1)[0]
    return json.loads(payload)


def _marker(result: str, key: str) -> str:
    for line in result.splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip()
    raise AssertionError(f"{key}= marker not found in: {result!r}")


@pytest.fixture
def db_path(tmp_path) -> Path:
    """A fresh, not-yet-existing .db path. _resolve_job_db_path only
    honors an explicit filepath argument in personal mode when it ends
    in '.db' — passing this path as `filepath` to each tool call keeps
    every call in this test on the SAME scratch database rather than the
    default ~/.ai-prowler/ai_prowler_jobs.db location."""
    return tmp_path / "scratch_job_board.db"


# ══════════════════════════════════════════════════════════════════════════
# create_job / create_customer / create_quote — DB wiring smoke tests
# ══════════════════════════════════════════════════════════════════════════

def test_create_customer_wired_to_db(tmp_path, db_path):
    result = _run(tmp_path, db_path, (
        f"m.create_customer({{'Company Name': 'Blue Wave Cafe', 'Phone': '386-555-0101'}}, "
        f"{str(db_path)!r}, False, None)"
    ))
    assert result.startswith("✅"), result
    cust_id = _marker(result, "NEW_CUST_ID")
    assert cust_id == "CUST-0001"

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT company_name, phone FROM customers WHERE customer_id = ?",
                        (cust_id,)).fetchone()
    conn.close()
    assert row == ("Blue Wave Cafe", "386-555-0101")


def test_create_job_wired_to_db(tmp_path, db_path):
    # Job Board Architecture Spec §5.1 (2026-09-22): create_job now requires
    # a real, existing CustomerID.
    cust_result = _run(tmp_path, db_path, (
        f"m.create_customer({{'Company Name': 'Jane Smith'}}, "
        f"{str(db_path)!r}, False, None)"
    ))
    cust_id = _marker(cust_result, "NEW_CUST_ID")
    result = _run(tmp_path, db_path, (
        f"m.create_job({{'CustomerID': {cust_id!r}, 'Customer Name / Company': 'Jane Smith', "
        f"'Service Type': 'Window', 'Job Status': 'Scheduled'}}, "
        f"{str(db_path)!r}, False, None)"
    ))
    assert result.startswith("✅"), result
    job_id = _marker(result, "NEW_JOB_ID")
    assert job_id == "JOB-0001"
    assert "Re-index the spreadsheet" not in result  # no .xlsx involved anymore

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT customer_name, service_type, job_status FROM jobs WHERE job_id = ?",
                        (job_id,)).fetchone()
    conn.close()
    assert row == ("Jane Smith", "Window", "Scheduled")


def test_create_quote_wired_to_db(tmp_path, db_path):
    result = _run(tmp_path, db_path, (
        f"m.create_quote({{'Customer Name / Company': 'Jane Smith', "
        f"'Subtotal ($)': 150.0, 'Status (Open/Approved/Declined)': 'Open'}}, "
        f"{str(db_path)!r}, False, None)"
    ))
    assert result.startswith("✅"), result
    assert _marker(result, "NEW_QTE_ID") == "QTE-0001"


def test_create_job_ids_increment_across_calls(tmp_path, db_path):
    cust_result = _run(tmp_path, db_path, f"m.create_customer({{'Company Name': 'A'}}, {str(db_path)!r}, False, None)")
    cust_id = _marker(cust_result, "NEW_CUST_ID")
    r1 = _run(tmp_path, db_path, f"m.create_job({{'CustomerID': {cust_id!r}, 'Customer Name / Company': 'A'}}, {str(db_path)!r}, False, None)")
    r2 = _run(tmp_path, db_path, f"m.create_job({{'CustomerID': {cust_id!r}, 'Customer Name / Company': 'B'}}, {str(db_path)!r}, False, None)")
    assert _marker(r1, "NEW_JOB_ID") == "JOB-0001"
    assert _marker(r2, "NEW_JOB_ID") == "JOB-0002"


# ══════════════════════════════════════════════════════════════════════════
# create_invoice — financial calc through the real MCP tool function
# ══════════════════════════════════════════════════════════════════════════

def test_create_invoice_financial_calc_end_to_end(tmp_path, db_path):
    cust_result = _run(tmp_path, db_path, f"m.create_customer({{'Company Name': 'Torres Residence'}}, {str(db_path)!r}, False, None)")
    cust_id = _marker(cust_result, "NEW_CUST_ID")
    job_result = _run(tmp_path, db_path, (
        f"m.create_job({{'CustomerID': {cust_id!r}, 'Customer Name / Company': 'Torres Residence', "
        f"'Quote Amount ($)': 200, 'Discount Applied ($)': 20, "
        f"'Service Type': 'Window'}}, {str(db_path)!r}, False, None)"
    ))
    job_id = _marker(job_result, "NEW_JOB_ID")

    inv_result = _run(tmp_path, db_path, (
        f"m._create_invoice_impl({job_id!r}, None, None, '', '', 0.07, 30, "
        f"{str(db_path)!r}, False, None)"
    ))
    assert inv_result.startswith("✅"), inv_result
    inv_id = _marker(inv_result, "NEW_INVOICE_ID")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT subtotal, discount, taxable_amt, tax, total_due FROM invoices WHERE invoice_id = ?",
        (inv_id,),
    ).fetchone()
    conn.close()
    # subtotal 200, discount 20 -> taxable 180, tax 7% -> 12.60, total 192.60
    assert row["subtotal"] == 200.0
    assert row["discount"] == 20.0
    assert row["taxable_amt"] == 180.0
    assert row["tax"] == 12.6
    assert row["total_due"] == 192.6

    # Second invoice attempt on the same job must be refused, not silently
    # duplicated (spec Phase 1 explicit one-invoice-per-job contract).
    dup_result = _run(tmp_path, db_path, (
        f"m._create_invoice_impl({job_id!r}, None, None, '', '', 0.07, 30, "
        f"{str(db_path)!r}, False, None)"
    ))
    assert dup_result.startswith("❌")
    assert inv_id in dup_result


def test_create_invoice_blank_job_identifier_rejected(tmp_path, db_path):
    result = _run(tmp_path, db_path, (
        f"m._create_invoice_impl('   ', None, None, '', '', 0.07, 30, {str(db_path)!r}, False, None)"
    ))
    assert result.startswith("❌")
    assert "cannot be blank" in result


# ══════════════════════════════════════════════════════════════════════════
# log_time_entry — clock in/out through the real MCP tool function
# ══════════════════════════════════════════════════════════════════════════

def test_log_time_entry_clock_in_out_cycle(tmp_path, db_path):
    cust_result = _run(tmp_path, db_path, f"m.create_customer({{'Company Name': 'Harbor Inn'}}, {str(db_path)!r}, False, None)")
    cust_id = _marker(cust_result, "NEW_CUST_ID")
    job_result = _run(tmp_path, db_path, (
        f"m.create_job({{'CustomerID': {cust_id!r}, 'Customer Name / Company': 'Harbor Inn'}}, {str(db_path)!r}, False, None)"
    ))
    job_id = _marker(job_result, "NEW_JOB_ID")

    start_result = _run(tmp_path, db_path, (
        f"m._log_time_entry_impl({job_id!r}, 'start', {str(db_path)!r}, None)"
    ))
    assert start_result.startswith("⏱️"), start_result
    assert "Clocked IN" in start_result

    # A second start before stopping must be refused, not silently open a
    # duplicate entry.
    second_start = _run(tmp_path, db_path, (
        f"m._log_time_entry_impl({job_id!r}, 'start', {str(db_path)!r}, None)"
    ))
    assert second_start.startswith("⚠️")

    # Backdate clock_in using Python's own local-naive clock — matching
    # db_log_time_entry's own datetime.datetime.now() (see the identical
    # note in test_db_write_ops_phase1.py). SQLite's datetime('now') is
    # UTC and would introduce a timezone-offset skew here instead.
    backdated = (datetime.datetime.now() - datetime.timedelta(minutes=45)).strftime("%Y-%m-%d %H:%M:%S")
    conn = sqlite3.connect(db_path)
    conn.execute(
        "UPDATE time_entries SET clock_in = ? WHERE job_id = ?",
        (backdated, job_id),
    )
    conn.commit()
    conn.close()

    stop_result = _run(tmp_path, db_path, (
        f"m._log_time_entry_impl({job_id!r}, 'stop', {str(db_path)!r}, None)"
    ))
    assert stop_result.startswith("⏱️"), stop_result
    assert "Clocked OUT" in stop_result
    assert "Actual Duration written to Jobs_Schedule" in stop_result

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT actual_duration FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    conn.close()
    assert row[0] is not None and row[0] > 0


def test_log_time_entry_stop_without_start_rejected(tmp_path, db_path):
    cust_result = _run(tmp_path, db_path, f"m.create_customer({{'Company Name': 'X'}}, {str(db_path)!r}, False, None)")
    cust_id = _marker(cust_result, "NEW_CUST_ID")
    job_result = _run(tmp_path, db_path, f"m.create_job({{'CustomerID': {cust_id!r}, 'Customer Name / Company': 'X'}}, {str(db_path)!r}, False, None)")
    job_id = _marker(job_result, "NEW_JOB_ID")
    result = _run(tmp_path, db_path, f"m._log_time_entry_impl({job_id!r}, 'stop', {str(db_path)!r}, None)")
    assert result.startswith("❌")


# ══════════════════════════════════════════════════════════════════════════
# update_job_spreadsheet — Jobs_Schedule / Customers / Invoices / Quotes
# ══════════════════════════════════════════════════════════════════════════

def test_update_job_spreadsheet_updates_jobs_sheet(tmp_path, db_path):
    cust_result = _run(tmp_path, db_path, f"m.create_customer({{'Company Name': 'X'}}, {str(db_path)!r}, False, None)")
    cust_id = _marker(cust_result, "NEW_CUST_ID")
    job_result = _run(tmp_path, db_path, f"m.create_job({{'CustomerID': {cust_id!r}, 'Customer Name / Company': 'X'}}, {str(db_path)!r}, False, None)")
    job_id = _marker(job_result, "NEW_JOB_ID")

    result = _run(tmp_path, db_path, (
        f"m.update_job_spreadsheet({job_id!r}, {{'Job Status': 'Complete'}}, "
        f"{str(db_path)!r}, 'JobID (JOB-####)', '', False, -1, -1, None)"
    ))
    assert result.startswith("✅"), result

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT job_status FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    conn.close()
    assert row[0] == "Complete"


def test_update_job_spreadsheet_updates_customers_sheet(tmp_path, db_path):
    cust_result = _run(tmp_path, db_path, f"m.create_customer({{'Company Name': 'X'}}, {str(db_path)!r}, False, None)")
    cust_id = _marker(cust_result, "NEW_CUST_ID")

    result = _run(tmp_path, db_path, (
        f"m.update_job_spreadsheet({cust_id!r}, {{'Phone': '386-555-9999'}}, "
        f"{str(db_path)!r}, 'CustomerID (CUST-####)', 'Customers', False, -1, -1, None)"
    ))
    assert result.startswith("✅"), result

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT phone FROM customers WHERE customer_id = ?", (cust_id,)).fetchone()
    conn.close()
    assert row[0] == "386-555-9999"


def test_update_job_spreadsheet_updates_invoices_sheet(tmp_path, db_path):
    cust_result = _run(tmp_path, db_path, f"m.create_customer({{'Company Name': 'X'}}, {str(db_path)!r}, False, None)")
    cust_id = _marker(cust_result, "NEW_CUST_ID")
    job_result = _run(tmp_path, db_path, (
        f"m.create_job({{'CustomerID': {cust_id!r}, 'Customer Name / Company': 'X', 'Quote Amount ($)': 100}}, "
        f"{str(db_path)!r}, False, None)"
    ))
    job_id = _marker(job_result, "NEW_JOB_ID")
    inv_result = _run(tmp_path, db_path, (
        f"m._create_invoice_impl({job_id!r}, None, None, '', '', 0.07, 30, "
        f"{str(db_path)!r}, False, None)"
    ))
    inv_id = _marker(inv_result, "NEW_INVOICE_ID")

    result = _run(tmp_path, db_path, (
        f"m.update_job_spreadsheet({inv_id!r}, {{'Payment Status': 'Paid'}}, "
        f"{str(db_path)!r}, 'InvoiceID (INV-####)', 'Invoices', False, -1, -1, None)"
    ))
    assert result.startswith("✅"), result

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT payment_status FROM invoices WHERE invoice_id = ?", (inv_id,)).fetchone()
    conn.close()
    assert row[0] == "Paid"


def test_update_job_spreadsheet_updates_quotes_sheet(tmp_path, db_path):
    quote_result = _run(tmp_path, db_path, (
        f"m.create_quote({{'Customer Name / Company': 'X'}}, {str(db_path)!r}, False, None)"
    ))
    quote_id = _marker(quote_result, "NEW_QTE_ID")

    result = _run(tmp_path, db_path, (
        f"m.update_job_spreadsheet({quote_id!r}, {{'Status (Open/Approved/Declined)': 'Approved'}}, "
        f"{str(db_path)!r}, 'QuoteID (QTE-####)', 'Quotes', False, -1, -1, None)"
    ))
    assert result.startswith("✅"), result

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT status FROM quotes WHERE quote_id = ?", (quote_id,)).fetchone()
    conn.close()
    assert row[0] == "Approved"


def test_update_job_spreadsheet_updates_route_planner_sheet(tmp_path, db_path):
    """2026-09-14: Route_Planner WAS the Phase 1 "honest gap" example (no
    route_stops table yet, so this had to fail clearly rather than silently
    no-op). route_stops shipped since then and update_job_spreadsheet's
    sheet dispatch table now maps 'Route_Planner' -> db_update_route_stop,
    so this is real, working support, not a documented gap. A bogus id now
    gets the same generic "no row found" message any other sheet gets."""
    cust_result = _run(tmp_path, db_path, f"m.create_customer({{'Company Name': 'X'}}, {str(db_path)!r}, False, None)")
    cust_id = _marker(cust_result, "NEW_CUST_ID")
    job_result = _run(tmp_path, db_path, (
        f"m.create_job({{'CustomerID': {cust_id!r}, 'Customer Name / Company': 'X'}}, "
        f"{str(db_path)!r}, False, None)"
    ))
    job_id = _marker(job_result, "NEW_JOB_ID")

    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO route_stops (route_date, crew_id, stop_number, job_id) "
        "VALUES (?, ?, ?, ?)",
        ("2026-09-14", "Jake", 1, job_id),
    )
    conn.commit()
    stop_id = conn.execute("SELECT id FROM route_stops WHERE job_id = ?", (job_id,)).fetchone()[0]
    conn.close()

    result = _run(tmp_path, db_path, (
        f"m.update_job_spreadsheet({stop_id!r}, {{'Stop #': 2}}, "
        f"{str(db_path)!r}, 'ID', 'Route_Planner', False, -1, -1, None)"
    ))
    assert result.startswith("✅"), result

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT stop_number FROM route_stops WHERE id = ?", (stop_id,)).fetchone()
    conn.close()
    assert row[0] == 2


def test_update_job_spreadsheet_route_planner_bogus_id_not_found(tmp_path, db_path):
    """A bogus Route_Planner id is a plain not-found, like any other sheet
    -- not a special 'not yet wired' rejection (see test above)."""
    result = _run(tmp_path, db_path, (
        f"m.update_job_spreadsheet('x', {{'Stop #': 1}}, {str(db_path)!r}, "
        f"'ID', 'Route_Planner', False, -1, -1, None)"
    ))
    assert result.startswith("❌")
    assert "no row found" in result.lower()



def test_update_job_spreadsheet_row_index_not_yet_supported(tmp_path, db_path):
    result = _run(tmp_path, db_path, (
        f"m.update_job_spreadsheet('x', {{'a': 1}}, {str(db_path)!r}, "
        f"'Customer', '', False, 0, -1, None)"
    ))
    assert result.startswith("❌")
