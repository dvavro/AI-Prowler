"""
tests/mcp_tests/test_job_board_phase2_read_wiring.py
==================================================
Job Board Architecture Spec — Phase 2 (spec §5, §11).

In-process tests (same convention as test_job_board_phase1_server_mode.py
and test_job_spreadsheet_scope.py) for the actual read_job_spreadsheet()
@mcp.tool() function, covering BOTH personal mode (ctx=None) and server
mode (mocked ctx via monkeypatched _current_user), proving the MCP-layer
wiring itself: _resolve_job_db_path() resolution and _job_crew_scope()
derivation feeding into db_read_ops.db_read_job_spreadsheet correctly.
The read logic itself (date filtering, crew-scope row filtering, per-
sheet dispatch) is already exhaustively covered directly in
test_db_read_ops_phase2.py.

Run with:
    run_tests.bat tests\\mcp\\test_job_board_phase2_read_wiring.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

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


def _field_crew(uid="jake-r", name="Jake R"):
    return {"id": uid, "name": name, "role": "field_crew", "status": "active", "scopes": []}


def _owner(uid="dave"):
    return {"id": uid, "name": "Dave Owner", "role": "owner", "status": "active", "scopes": []}


def _set_user(monkeypatch, mcp_mod, user):
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)


def _cust_id(mcp_mod, name="A", ctx=None):
    """Job Board Architecture Spec §5.1 (2026-09-22): create_job now
    requires a real, existing CustomerID."""
    result = mcp_mod.create_customer({"Company Name": name}, filepath="", backup=False, ctx=ctx)
    return result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()


# ══════════════════════════════════════════════════════════════════════════
# Personal mode (ctx=None)
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def personal_env(tmp_path, monkeypatch, mcp_mod):
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    return tmp_path / "ai_prowler_jobs.db"


def test_personal_mode_reads_own_jobs_unfiltered(personal_env, mcp_mod):
    mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "A"), "Customer Name / Company": "A"}, filepath="", backup=False, ctx=None)
    mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "B"), "Customer Name / Company": "B", "Crew / Technician": "Someone"}, filepath="", backup=False, ctx=None)
    result = mcp_mod.read_job_spreadsheet(ctx=None)
    assert "A" in result and "B" in result
    assert "2 row(s)" in result


def test_personal_mode_customers_sheet(personal_env, mcp_mod):
    mcp_mod.create_customer({"Company Name": "Blue Wave Cafe"}, filepath="", backup=False, ctx=None)
    result = mcp_mod.read_job_spreadsheet(sheet_name="Customers", ctx=None)
    assert "Blue Wave Cafe" in result


def test_personal_mode_date_filter(personal_env, mcp_mod):
    mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "A"), "Customer Name / Company": "A", "Service Date": "2026-04-05"}, filepath="", backup=False, ctx=None)
    mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "B"), "Customer Name / Company": "B", "Service Date": "2026-04-06"}, filepath="", backup=False, ctx=None)
    result = mcp_mod.read_job_spreadsheet(filter_date="04/05/2026", ctx=None)
    assert "Customer Name / Company: A" in result
    assert "Customer Name / Company: B" not in result


def test_personal_mode_route_planner_not_yet_supported(personal_env, mcp_mod):
    # Updated 2026-09-12 (Database-tab expansion): Route_Planner is now
    # fully wired for reads (see test_database_tab_read_expansion.py) —
    # this test's own premise became stale along with the gap it was
    # checking. Confirms the read now succeeds cleanly instead.
    result = mcp_mod.read_job_spreadsheet(sheet_name="Route_Planner", ctx=None)
    assert not result.startswith("❌")


# ══════════════════════════════════════════════════════════════════════════
# Server mode (mocked ctx)
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def server_env(tmp_path, monkeypatch, mcp_mod):
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    return tmp_path / "ai_prowler_jobs.db"


def test_server_mode_field_crew_sees_only_own_jobs(server_env, monkeypatch, mcp_mod):
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "Mine", ctx=_make_ctx(owner)), "Customer Name / Company": "Mine", "Crew / Technician": "Jake R"},
                        filepath="", backup=False, ctx=_make_ctx(owner))
    mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "Not Mine", ctx=_make_ctx(owner)), "Customer Name / Company": "Not Mine", "Crew / Technician": "Someone Else"},
                        filepath="", backup=False, ctx=_make_ctx(owner))

    crew = _field_crew()
    _set_user(monkeypatch, mcp_mod, crew)
    result = mcp_mod.read_job_spreadsheet(ctx=_make_ctx(crew))
    assert "Mine" in result
    assert "Not Mine" not in result


def test_server_mode_owner_sees_every_row(server_env, monkeypatch, mcp_mod):
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "A", ctx=_make_ctx(owner)), "Customer Name / Company": "A", "Crew / Technician": "Jake R"},
                        filepath="", backup=False, ctx=_make_ctx(owner))
    mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "B", ctx=_make_ctx(owner)), "Customer Name / Company": "B", "Crew / Technician": "Someone Else"},
                        filepath="", backup=False, ctx=_make_ctx(owner))
    result = mcp_mod.read_job_spreadsheet(ctx=_make_ctx(owner))
    assert "A" in result and "B" in result


def test_server_mode_customers_sheet_never_filtered_for_field_crew(server_env, monkeypatch, mcp_mod):
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    mcp_mod.create_customer({"Company Name": "Anyone"}, filepath="", backup=False, ctx=_make_ctx(owner))

    crew = _field_crew()
    _set_user(monkeypatch, mcp_mod, crew)
    result = mcp_mod.read_job_spreadsheet(sheet_name="Customers", ctx=_make_ctx(crew))
    assert "Anyone" in result


def test_server_mode_ignores_filepath_argument(server_env, monkeypatch, mcp_mod, tmp_path):
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "Real", ctx=_make_ctx(owner)), "Customer Name / Company": "Real"}, filepath="", backup=False, ctx=_make_ctx(owner))

    decoy = tmp_path / "decoy.db"
    result = mcp_mod.read_job_spreadsheet(filepath=str(decoy), ctx=_make_ctx(owner))
    assert "Real" in result
    assert not decoy.exists()
