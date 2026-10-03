"""
tests/mcp_tests/test_export_to_excel_phase6_mcp_wiring.py
=======================================================
Job Board Architecture Spec — Phase 6 (spec §7, §11).

In-process tests for the real export_to_excel() @mcp.tool(), covering
BOTH personal mode (ctx=None) and server mode (mocked ctx). Proves the
MCP-layer wiring — _resolve_job_db_path() resolution and the default
output_path derivation — feeding into db_export_ops's already-proven
export logic.

Run with:
    run_tests.bat tests\\mcp\\test_export_to_excel_phase6_mcp_wiring.py -v
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import openpyxl
import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


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


def _owner(uid="dave"):
    return {"id": uid, "name": "Dave Owner", "role": "owner", "status": "active", "scopes": []}


def _set_user(monkeypatch, mcp_mod, user):
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)


# ══════════════════════════════════════════════════════════════════════════
# Personal mode (ctx=None)
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def personal_env(tmp_path, monkeypatch, mcp_mod):
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    return tmp_path


def test_personal_mode_default_output_path(personal_env, mcp_mod):
    cust_result = mcp_mod.create_customer({"Company Name": "A"}, filepath="", backup=False, ctx=None)
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    mcp_mod.create_job({"CustomerID": cust_id, "Customer Name / Company": "A"}, filepath="", backup=False, ctx=None)
    result = mcp_mod.export_to_excel(ctx=None)
    assert result.startswith("✅"), result

    # Default output_path lands next to the database, timestamped.
    exports = [f for f in os.listdir(personal_env) if f.startswith("AI-Prowler_Job_Tracker_Export_")]
    assert len(exports) == 1
    wb = openpyxl.load_workbook(str(personal_env / exports[0]))
    assert "Jobs_Schedule" in wb.sheetnames


def test_personal_mode_explicit_output_path(personal_env, mcp_mod, tmp_path):
    cust_result = mcp_mod.create_customer({"Company Name": "A"}, filepath="", backup=False, ctx=None)
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    mcp_mod.create_job({"CustomerID": cust_id, "Customer Name / Company": "A"}, filepath="", backup=False, ctx=None)
    target = str(tmp_path / "my_export.xlsx")
    result = mcp_mod.export_to_excel(output_path=target, ctx=None)
    assert result.startswith("✅"), result
    assert os.path.exists(target)


# ══════════════════════════════════════════════════════════════════════════
# Server mode (mocked ctx)
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def server_env(tmp_path, monkeypatch, mcp_mod):
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    return tmp_path


def test_server_mode_export_reflects_live_data(server_env, monkeypatch, mcp_mod, tmp_path):
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    cust_result = mcp_mod.create_customer({"Company Name": "Blue Wave"}, filepath="", backup=False, ctx=_make_ctx(owner))
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    mcp_mod.create_job({"CustomerID": cust_id, "Customer Name / Company": "Blue Wave"}, filepath="", backup=False,
                        ctx=_make_ctx(owner))

    target = str(tmp_path / "server_export.xlsx")
    result = mcp_mod.export_to_excel(output_path=target, ctx=_make_ctx(owner))
    assert result.startswith("✅"), result

    wb = openpyxl.load_workbook(target)
    assert wb["Customers"].max_row == 2
    assert wb["Jobs_Schedule"].max_row == 2


def test_server_mode_ignores_filepath_argument(server_env, monkeypatch, mcp_mod, tmp_path):
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    cust_result = mcp_mod.create_customer({"Company Name": "Real"}, filepath="", backup=False, ctx=_make_ctx(owner))
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    mcp_mod.create_job({"CustomerID": cust_id, "Customer Name / Company": "Real"}, filepath="", backup=False,
                        ctx=_make_ctx(owner))

    decoy_db = tmp_path / "decoy.db"
    target = str(tmp_path / "export.xlsx")
    result = mcp_mod.export_to_excel(filepath=str(decoy_db), output_path=target, ctx=_make_ctx(owner))
    assert result.startswith("✅"), result
    assert not decoy_db.exists()

    wb = openpyxl.load_workbook(target)
    values = []
    for row in wb["Jobs_Schedule"].iter_rows(values_only=True):
        values.extend(row)
    assert "Real" in values
