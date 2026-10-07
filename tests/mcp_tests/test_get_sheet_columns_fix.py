"""
tests/mcp_tests/test_get_sheet_columns_fix.py
===========================================
Job Board Architecture Spec — Database-tab expansion (2026-09-12).

Real bug found while wiring the Database tab's generic add/edit form:
get_sheet_columns() was still fully openpyxl-based, calling the OLD
.xlsx path resolver and trying to open a file that generally no longer
exists once an install has moved to the SQLite-backed job store — it had
been silently broken for EVERY sheet since Phase 1 began, not just the
newly-wired ones. This tests the fix: db_get_sheet_columns() in
db_read_ops.py, and the real get_sheet_columns() @mcp.tool() wired to it.

Run with:
    run_tests.bat tests\\mcp\\test_get_sheet_columns_fix.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from db_access import init_db
from db_read_ops import db_get_sheet_columns

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _cols(result: str) -> list:
    for line in result.splitlines():
        if line.startswith("COLUMNS:"):
            return [c.strip() for c in line[len("COLUMNS:"):].split("|")]
    return []


def _dropdowns(result: str) -> dict:
    out = {}
    for line in result.splitlines():
        if line.startswith("DROPDOWN:"):
            col, _, opts = line[len("DROPDOWN:"):].partition("=")
            out[col.strip()] = [o.strip() for o in opts.split(",")]
    return out


# ══════════════════════════════════════════════════════════════════════════
# Direct unit tests, all eight sheets — confirms the "silently broken for
# every sheet" claim is now false for all of them, not just the new four.
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("sheet", [
    "Jobs_Schedule", "Customers", "Invoices", "Quotes",
    "TimeLog", "Route_Planner", "Settings", "Services_Pricing",
])
def test_columns_returned_for_every_wired_sheet(db_path, sheet):
    result = db_get_sheet_columns(db_path, sheet)
    assert result.startswith("COLUMNS:"), f"{sheet}: {result}"
    assert len(_cols(result)) > 0


def test_unwired_sheet_fails_clearly(db_path):
    result = db_get_sheet_columns(db_path, "AI-Prowler-Commands")
    assert result.startswith("❌")


def test_customers_columns_include_expected_fields(db_path):
    result = db_get_sheet_columns(db_path, "Customers")
    cols = _cols(result)
    assert "Company Name" in cols
    assert "Phone" in cols
    assert "CustomerID (CUST-####)" in cols


def test_settings_columns(db_path):
    result = db_get_sheet_columns(db_path, "Settings")
    cols = _cols(result)
    assert "Setting" in cols
    assert "Value" in cols


def test_route_planner_columns_include_id(db_path):
    """The real bug this whole change chain was found through: Route_
    Planner's id_column moved from 'Stop #' to 'ID' once route_stops got
    a real integer primary key — confirms 'ID' is actually present."""
    result = db_get_sheet_columns(db_path, "Route_Planner")
    cols = _cols(result)
    assert "ID" in cols


# ══════════════════════════════════════════════════════════════════════════
# Dropdown metadata
# ══════════════════════════════════════════════════════════════════════════

def test_customers_dropdowns(db_path):
    result = db_get_sheet_columns(db_path, "Customers")
    dd = _dropdowns(result)
    assert dd["Status Active/Inactive"] == ["Active", "Inactive"]
    assert "Weekly" in dd["Frequency"]


def test_invoices_payment_status_dropdown(db_path):
    result = db_get_sheet_columns(db_path, "Invoices")
    dd = _dropdowns(result)
    assert dd["Payment Status"] == ["Unpaid", "Partial", "Paid", "Cash", "Check", "Zelle", "Venmo", "Other"]


def test_quotes_status_dropdown(db_path):
    result = db_get_sheet_columns(db_path, "Quotes")
    dd = _dropdowns(result)
    assert dd["Status (Open/Approved/Declined)"] == ["Open", "Approved", "Declined"]


def test_timelog_has_no_dropdowns(db_path):
    """No known enum-like columns on TimeLog — confirms the map doesn't
    invent dropdowns for sheets that were never given one."""
    result = db_get_sheet_columns(db_path, "TimeLog")
    assert _dropdowns(result) == {}


# ══════════════════════════════════════════════════════════════════════════
# MCP-layer wiring — the real tool, both modes
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


def test_mcp_tool_personal_mode(tmp_path, monkeypatch, mcp_mod):
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)

    result = mcp_mod.get_sheet_columns("Customers", filepath="", ctx=None)
    assert result.startswith("COLUMNS:")
    assert "Company Name" in result


def test_mcp_tool_settings_sheet(tmp_path, monkeypatch, mcp_mod):
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)

    result = mcp_mod.get_sheet_columns("Settings", filepath="", ctx=None)
    assert "Setting" in result
    assert "Value" in result
