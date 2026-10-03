"""
tests/mcp_tests/test_ar_aging_report_phase2.py
============================================
Job Board Architecture Spec — Phase 2 (spec §5, §11).

Tests for db_read_ops.db_get_ar_aging_report (direct) and the real
get_ar_aging_report() @mcp.tool() (in-process, personal + server mode),
mirroring the split already established for read_job_spreadsheet in
test_db_read_ops_phase2.py / test_job_board_phase2_read_wiring.py.

Run with:
    run_tests.bat tests\\mcp\\test_ar_aging_report_phase2.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from db_access import init_db
from db_read_ops import db_get_ar_aging_report
from db_write_ops import db_create_customer, db_create_invoice, db_create_job

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _make_invoice(db_path, customer_name, quote_amount, due_days=30, payment_status=None):
    # Job Board Architecture Spec §5.1 (2026-09-22): create_job now requires
    # a real, existing CustomerID — create one with the SAME name so the
    # §13 field-ownership join doesn't overwrite the expected customer_name
    # with something else.
    cust_result = db_create_customer(db_path, {"Company Name": customer_name}, actor="dave")
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    db_create_job(db_path, {"CustomerID (Customers!A)": cust_id, "Customer Name / Company": customer_name,
                             "Quote Amount ($)": quote_amount}, actor="dave")
    job_id = f"JOB-{_next_job_num(db_path):04d}"
    result = db_create_invoice(db_path, job_id, actor="dave", due_days=due_days)
    inv_id = result.split("NEW_INVOICE_ID=")[1].splitlines()[0].strip()
    if payment_status:
        import sqlite3
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE invoices SET payment_status = ? WHERE invoice_id = ?",
                     (payment_status, inv_id))
        conn.commit()
        conn.close()
    return job_id, inv_id


def _next_job_num(db_path):
    import sqlite3
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT COUNT(*) FROM jobs").fetchone()
    conn.close()
    return row[0]  # jobs are 1-indexed and this is called AFTER creating the newest one


# ── Direct db_read_ops tests ─────────────────────────────────────────────

def test_no_outstanding_invoices(db_path):
    result = db_get_ar_aging_report(db_path)
    assert result.startswith("✅ No outstanding invoices")


def test_current_bucket_for_not_yet_due_invoice(db_path):
    _make_invoice(db_path, "Fresh Co", 100, due_days=30)
    result = db_get_ar_aging_report(db_path)
    assert "Current (not yet due)" in result
    assert "Fresh Co" in result
    assert "TOTAL OUTSTANDING" in result


def test_overdue_bucket_by_as_of_date(db_path):
    import sqlite3
    _make_invoice(db_path, "Overdue Co", 100, due_days=30)
    # Force the due date into the past relative to a later as_of_date.
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE invoices SET due_date = '2026-01-01'")
    conn.commit()
    conn.close()
    result = db_get_ar_aging_report(db_path, as_of_date="2026-02-15")
    assert "90+ days overdue" not in result or "Overdue Co" in result
    assert "Overdue Co" in result
    assert "overdue" in result.lower()


def test_paid_invoices_excluded(db_path):
    _make_invoice(db_path, "Paid Co", 100, payment_status="Paid")
    result = db_get_ar_aging_report(db_path)
    assert result.startswith("✅ No outstanding invoices")


def test_zero_balance_excluded(db_path):
    import sqlite3
    _make_invoice(db_path, "ZeroBal Co", 100)
    conn = sqlite3.connect(db_path)
    # balance_due is a GENERATED ALWAYS AS (total_due - amount_paid) column
    # (spec §13, _fix_invoices_balance_due) — it can no longer be written
    # directly. Setting amount_paid = total_due drives balance_due to 0
    # the same way a real payment would.
    conn.execute("UPDATE invoices SET amount_paid = total_due")
    conn.commit()
    conn.close()
    result = db_get_ar_aging_report(db_path)
    assert result.startswith("✅ No outstanding invoices")


def test_bucket_boundaries(db_path):
    import sqlite3
    _make_invoice(db_path, "Bucket31", 50)
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE invoices SET due_date = '2026-01-01' WHERE customer_name = 'Bucket31'")
    conn.commit()
    conn.close()
    # 45 days after due date -> 31-60 bucket
    result = db_get_ar_aging_report(db_path, as_of_date="2026-02-15")
    assert "31 – 60 days overdue" in result
    assert "Bucket31" in result


def test_invalid_as_of_date_rejected(db_path):
    result = db_get_ar_aging_report(db_path, as_of_date="not-a-date")
    assert result.startswith("❌")


def test_multiple_invoices_sum_to_grand_total(db_path):
    _make_invoice(db_path, "A", 100)   # $100 + 7% tax = $107.00
    _make_invoice(db_path, "B", 200)   # $200 + 7% tax = $214.00
    result = db_get_ar_aging_report(db_path)
    assert "321.00" in result  # 107.00 + 214.00 (report right-pads the $ field)


# ══════════════════════════════════════════════════════════════════════════
# MCP-layer wiring: personal + server mode
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


def _make_ctx(user):
    if user is None:
        return None
    ctx = MagicMock()
    ctx.request_context.request.state.user = user
    return ctx


def test_personal_mode_ar_report(tmp_path, monkeypatch, mcp_mod):
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)

    cust_result = mcp_mod.create_customer({"Company Name": "Personal Co"}, filepath="", backup=False, ctx=None)
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    job_result = mcp_mod.create_job({"CustomerID": cust_id, "Customer Name / Company": "Personal Co", "Quote Amount ($)": 100},
                                     filepath="", backup=False, ctx=None)
    job_id = job_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()
    mcp_mod.create_invoice(job_id, filepath="", backup=False, ctx=None)

    result = mcp_mod.get_ar_aging_report(ctx=None)
    assert "Personal Co" in result
    assert "AR AGING REPORT" in result


def test_server_mode_ar_report_not_crew_scoped(tmp_path, monkeypatch, mcp_mod):
    """Unlike Jobs_Schedule reads, the AR report is an admin financial
    view and must show every invoice regardless of who created the
    underlying job — matching the original tool's lack of crew scoping."""
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))

    owner = {"id": "dave", "name": "Dave Owner", "role": "owner", "status": "active", "scopes": []}
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: owner)
    cust_result = mcp_mod.create_customer({"Company Name": "Server Co"}, filepath="", backup=False, ctx=_make_ctx(owner))
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    job_result = mcp_mod.create_job({"CustomerID": cust_id, "Customer Name / Company": "Server Co", "Quote Amount ($)": 150,
                                      "Crew / Technician": "Jake R"},
                                     filepath="", backup=False, ctx=_make_ctx(owner))
    job_id = job_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()
    mcp_mod.create_invoice(job_id, filepath="", backup=False, ctx=_make_ctx(owner))

    # R-068 (2026-09-29): owner + managers only. A manager sees EVERY invoice
    # (still not crew-scoped); the field crew who did the job is refused.
    mgr = {"id": "mia-m", "name": "Mia M", "role": "manager", "status": "active", "scopes": []}
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: mgr)
    result = mcp_mod.get_ar_aging_report(ctx=_make_ctx(mgr))
    assert "Server Co" in result
    crew = {"id": "jake-r", "name": "Jake R", "role": "field_crew", "status": "active", "scopes": []}
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: crew)
    result = mcp_mod.get_ar_aging_report(ctx=_make_ctx(crew))
    assert result.startswith("❌") and "Server Co" not in result
