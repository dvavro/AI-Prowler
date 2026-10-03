"""
tests/mcp_tests/test_database_tab_expansion_mcp_wiring.py
=======================================================
Job Board Architecture Spec — Database-tab expansion (2026-09-12).

In-process tests for the real update_job_spreadsheet()/create_setting()/
create_service_pricing() @mcp.tool()s against the four newly-wired
tables, covering BOTH personal mode (ctx=None) and server mode (mocked
ctx). Proves the MCP-layer wiring (_ujs_dispatch extension, _job_crew_
scope feeding into the new check_fns) through the real tool functions,
not just the db_write_ops layer already covered directly.

Run with:
    run_tests.bat tests\\mcp\\test_database_tab_expansion_mcp_wiring.py -v
"""
from __future__ import annotations

import sqlite3
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


def _job_id(create_result: str) -> str:
    return create_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _cust_id(mcp_mod, name="X", ctx=None):
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


def test_personal_mode_create_and_update_setting(personal_env, mcp_mod):
    result = mcp_mod.create_setting({"Setting": "tax_rate", "Value": "0.07"}, filepath="", backup=False, ctx=None)
    assert result.startswith("✅"), result

    result2 = mcp_mod.update_job_spreadsheet(
        "tax_rate", {"Value": "0.08"}, filepath="",
        id_column="Setting", sheet_name="Settings", backup=False, ctx=None,
    )
    assert result2.startswith("✅"), result2


def test_personal_mode_create_and_update_service_pricing(personal_env, mcp_mod):
    result = mcp_mod.create_service_pricing({"Service Code": "WIN", "Base Price ($)": 150},
                                             filepath="", backup=False, ctx=None)
    assert result.startswith("✅"), result

    result2 = mcp_mod.update_job_spreadsheet(
        "WIN", {"Base Price ($)": 175}, filepath="",
        id_column="Service Code", sheet_name="Services_Pricing", backup=False, ctx=None,
    )
    assert result2.startswith("✅"), result2


def test_personal_mode_read_timelog_and_route_planner(personal_env, mcp_mod):
    job_result = mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod), "Customer Name / Company": "X", "Crew / Technician": "Dave"},
                                     filepath="", backup=False, ctx=None)
    job_id = _job_id(job_result)
    mcp_mod.log_time_entry(job_id, "start", filepath="", ctx=None)

    result = mcp_mod.read_job_spreadsheet(sheet_name="TimeLog", filepath="", ctx=None)
    assert "1 row(s)" in result


def test_personal_mode_update_timelog_entry(personal_env, mcp_mod):
    job_result = mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod), "Customer Name / Company": "X", "Crew / Technician": "Dave"},
                                     filepath="", backup=False, ctx=None)
    job_id = _job_id(job_result)
    mcp_mod.log_time_entry(job_id, "start", filepath="", ctx=None)

    conn = sqlite3.connect(str(personal_env))
    entry_id = conn.execute("SELECT entry_id FROM time_entries LIMIT 1").fetchone()[0]
    conn.close()

    result = mcp_mod.update_job_spreadsheet(
        entry_id, {"Notes": "forgot to note the address issue"}, filepath="",
        id_column="EntryID", sheet_name="TimeLog", backup=False, ctx=None,
    )
    assert result.startswith("✅"), result


# ══════════════════════════════════════════════════════════════════════════
# Server mode (mocked ctx)
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def server_env(tmp_path, monkeypatch, mcp_mod):
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    return tmp_path / "ai_prowler_jobs.db"


def test_server_mode_field_crew_denied_creating_setting(server_env, monkeypatch, mcp_mod):
    crew = _field_crew()
    _set_user(monkeypatch, mcp_mod, crew)
    result = mcp_mod.create_setting({"Setting": "x", "Value": "y"}, filepath="", backup=False,
                                     ctx=_make_ctx(crew))
    assert result.startswith("❌"), result


def test_server_mode_owner_can_create_setting(server_env, monkeypatch, mcp_mod):
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    result = mcp_mod.create_setting({"Setting": "x", "Value": "y"}, filepath="", backup=False,
                                     ctx=_make_ctx(owner))
    assert result.startswith("✅"), result


def test_server_mode_field_crew_denied_updating_service_pricing(server_env, monkeypatch, mcp_mod):
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    mcp_mod.create_service_pricing({"Service Code": "WIN", "Base Price ($)": 150},
                                    filepath="", backup=False, ctx=_make_ctx(owner))

    crew = _field_crew()
    _set_user(monkeypatch, mcp_mod, crew)
    result = mcp_mod.update_job_spreadsheet(
        "WIN", {"Base Price ($)": 999}, filepath="",
        id_column="Service Code", sheet_name="Services_Pricing", backup=False, ctx=_make_ctx(crew),
    )
    assert result.startswith("❌"), result


def test_server_mode_field_crew_denied_reading_service_pricing(server_env, monkeypatch, mcp_mod):
    """Renamed and rewritten 2026-09-24 — was
    test_server_mode_field_crew_can_read_service_pricing, asserting the
    OPPOSITE of what's now the deliberate, documented behavior.

    This predates the 2026-09-23 owner-requested policy change that blocks
    field_crew from Services_Pricing (along with Settings, Quotes, and
    Invoices) entirely — see _field_crew_sheet_denied /
    _FIELD_CREW_BLOCKED_SHEETS in ai_prowler_mcp.py. The old docstring here
    said "read access stays open... they need to see current pricing to do
    their job" — that was the intended design before the owner tightened
    it; reads are now blocked the same as writes, matching the sibling
    test_server_mode_field_crew_denied_updating_service_pricing above."""
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    mcp_mod.create_service_pricing({"Service Code": "WIN"}, filepath="", backup=False, ctx=_make_ctx(owner))

    crew = _field_crew()
    _set_user(monkeypatch, mcp_mod, crew)
    result = mcp_mod.read_job_spreadsheet(sheet_name="Services_Pricing", filepath="", ctx=_make_ctx(crew))
    assert result.startswith("❌"), result
    assert "Services_Pricing" in result


def test_server_mode_field_crew_denied_updating_others_time_entry(server_env, monkeypatch, mcp_mod):
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    job_result = mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "X", ctx=_make_ctx(owner)), "Customer Name / Company": "X", "Crew / Technician": "Someone Else"},
                                     filepath="", backup=False, ctx=_make_ctx(owner))
    job_id = _job_id(job_result)
    mcp_mod.log_time_entry(job_id, "start", filepath="", ctx=_make_ctx(owner))

    conn = sqlite3.connect(str(server_env))
    entry_id = conn.execute("SELECT entry_id FROM time_entries LIMIT 1").fetchone()[0]
    conn.close()

    crew = _field_crew()
    _set_user(monkeypatch, mcp_mod, crew)
    result = mcp_mod.update_job_spreadsheet(
        entry_id, {"Notes": "not mine"}, filepath="",
        id_column="EntryID", sheet_name="TimeLog", backup=False, ctx=_make_ctx(crew),
    )
    assert result.startswith("❌"), result


def test_server_mode_field_crew_can_update_own_time_entry(server_env, monkeypatch, mcp_mod):
    owner = _owner()
    crew = _field_crew()
    _set_user(monkeypatch, mcp_mod, owner)
    job_result = mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "X", ctx=_make_ctx(owner)), "Customer Name / Company": "X", "Crew / Technician": crew["name"]},
                                     filepath="", backup=False, ctx=_make_ctx(owner))
    job_id = _job_id(job_result)

    _set_user(monkeypatch, mcp_mod, crew)
    mcp_mod.log_time_entry(job_id, "start", filepath="", ctx=_make_ctx(crew))

    conn = sqlite3.connect(str(server_env))
    entry_id = conn.execute("SELECT entry_id FROM time_entries LIMIT 1").fetchone()[0]
    conn.close()

    result = mcp_mod.update_job_spreadsheet(
        entry_id, {"Notes": "corrected the address"}, filepath="",
        id_column="EntryID", sheet_name="TimeLog", backup=False, ctx=_make_ctx(crew),
    )
    assert result.startswith("✅"), result


def test_server_mode_ignores_filepath_argument_for_settings(server_env, monkeypatch, mcp_mod, tmp_path):
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    decoy = tmp_path / "decoy.db"
    result = mcp_mod.create_setting({"Setting": "x", "Value": "y"}, filepath=str(decoy),
                                     backup=False, ctx=_make_ctx(owner))
    assert result.startswith("✅"), result
    assert not decoy.exists()
