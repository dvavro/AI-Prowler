"""
tests/mcp_tests/test_get_board_updates_phase3_mcp_wiring.py
=========================================================
Job Board Architecture Spec — Phase 3 (spec §6.1, §11).

In-process tests for the real get_board_updates() @mcp.tool(), covering
BOTH personal mode (ctx=None) and server mode (mocked ctx). Proves the
MCP-layer wiring: _resolve_job_db_path() resolution, the ctx-derived
crew-scoping decision, and JSON serialization of db_read_ops.
db_get_jobs_changed_since's results through the real tool function.

Run with:
    run_tests.bat tests\\mcp\\test_get_board_updates_phase3_mcp_wiring.py -v
"""
from __future__ import annotations

import json
import sys
import time
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


def test_personal_mode_returns_json_array(personal_env, mcp_mod):
    mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "A"), "Customer Name / Company": "A"}, filepath="", backup=False, ctx=None)
    result = mcp_mod.get_board_updates(since="2000-01-01T00:00:00", ctx=None)
    rows = json.loads(result)
    assert isinstance(rows, list)
    assert len(rows) == 1
    assert rows[0]["Customer Name / Company"] == "A"


def test_personal_mode_nothing_changed_empty_array(personal_env, mcp_mod):
    mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "A"), "Customer Name / Company": "A"}, filepath="", backup=False, ctx=None)
    result = mcp_mod.get_board_updates(since="2099-01-01T00:00:00", ctx=None)
    assert json.loads(result) == []


def test_personal_mode_route_planner_not_supported(personal_env, mcp_mod):
    # Updated 2026-09-12 (Database-tab expansion): Route_Planner is now
    # fully wired (see test_database_tab_read_expansion.py) — confirms
    # the call now succeeds (an empty array, since no stops exist yet)
    # rather than an error payload.
    result = mcp_mod.get_board_updates(since="2000-01-01T00:00:00", sheet_name="Route_Planner", ctx=None)
    assert json.loads(result) == []


# ══════════════════════════════════════════════════════════════════════════
# Server mode (mocked ctx)
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def server_env(tmp_path, monkeypatch, mcp_mod):
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    return tmp_path / "ai_prowler_jobs.db"


def test_server_mode_field_crew_sees_only_own_updates(server_env, monkeypatch, mcp_mod):
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "Mine", ctx=_make_ctx(owner)), "Customer Name / Company": "Mine", "Crew / Technician": "Jake R"},
                        filepath="", backup=False, ctx=_make_ctx(owner))
    mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "Not Mine", ctx=_make_ctx(owner)), "Customer Name / Company": "Not Mine", "Crew / Technician": "Someone Else"},
                        filepath="", backup=False, ctx=_make_ctx(owner))

    crew = _field_crew()
    _set_user(monkeypatch, mcp_mod, crew)
    result = mcp_mod.get_board_updates(since="2000-01-01T00:00:00", ctx=_make_ctx(crew))
    rows = json.loads(result)
    names = {r["Customer Name / Company"] for r in rows}
    assert names == {"Mine"}


def test_server_mode_owner_sees_all_updates(server_env, monkeypatch, mcp_mod):
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "A", ctx=_make_ctx(owner)), "Customer Name / Company": "A", "Crew / Technician": "Jake R"},
                        filepath="", backup=False, ctx=_make_ctx(owner))
    mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "B", ctx=_make_ctx(owner)), "Customer Name / Company": "B", "Crew / Technician": "Someone Else"},
                        filepath="", backup=False, ctx=_make_ctx(owner))

    result = mcp_mod.get_board_updates(since="2000-01-01T00:00:00", ctx=_make_ctx(owner))
    rows = json.loads(result)
    names = {r["Customer Name / Company"] for r in rows}
    assert names == {"A", "B"}


def test_server_mode_customers_never_crew_filtered(server_env, monkeypatch, mcp_mod):
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    mcp_mod.create_customer({"Company Name": "Anyone"}, filepath="", backup=False, ctx=_make_ctx(owner))

    crew = _field_crew()
    _set_user(monkeypatch, mcp_mod, crew)
    result = mcp_mod.get_board_updates(since="2000-01-01T00:00:00", sheet_name="Customers", ctx=_make_ctx(crew))
    rows = json.loads(result)
    assert len(rows) == 1
    assert rows[0]["Company Name"] == "Anyone"


def test_server_mode_polling_cycle_only_returns_new_changes(server_env, monkeypatch, mcp_mod):
    """Simulates the actual Job Board polling loop: poll, get nothing new,
    someone edits a job, poll again with the previous response's newest
    _last_edited_at as `since` — only the new edit comes back."""
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    job_result = mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "X", ctx=_make_ctx(owner)), "Customer Name / Company": "X"}, filepath="", backup=False,
                                     ctx=_make_ctx(owner))
    job_id = job_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()

    first_poll = json.loads(mcp_mod.get_board_updates(since="2000-01-01T00:00:00", ctx=_make_ctx(owner)))
    newest_since = first_poll[-1]["_last_edited_at"]

    # Immediately polling again with that cursor finds nothing new yet.
    second_poll = json.loads(mcp_mod.get_board_updates(since=newest_since, ctx=_make_ctx(owner)))
    assert second_poll == []

    time.sleep(1.1)  # last_edited_at has second-level granularity
    mcp_mod.update_job_spreadsheet(job_id, {"Job Status": "Complete"}, filepath="",
                                    id_column="JobID (JOB-####)", sheet_name="Jobs_Schedule",
                                    backup=False, ctx=_make_ctx(owner))

    third_poll = json.loads(mcp_mod.get_board_updates(since=newest_since, ctx=_make_ctx(owner)))
    assert len(third_poll) == 1
    assert third_poll[0]["Job Status"] == "Complete"


def test_same_second_change_is_not_missed(server_env, monkeypatch, mcp_mod):
    """2026-10-02 (E2E BRD-06): a change made in the SAME second as the newest
    change the Board had already seen was skipped forever, because
    last_edited_at had whole-second precision and the poll asks for rows
    strictly AFTER the cursor. No sleep here on purpose — the edit lands well
    inside the same second as the create. Fixed by millisecond timestamps."""
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    job_result = mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "S", ctx=_make_ctx(owner)),
                                     "Customer Name / Company": "S"}, filepath="", backup=False,
                                    ctx=_make_ctx(owner))
    job_id = job_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()
    first_poll = json.loads(mcp_mod.get_board_updates(since="2000-01-01T00:00:00", ctx=_make_ctx(owner)))
    cursor = first_poll[-1]["_last_edited_at"]

    time.sleep(0.01)   # a few ms — still the same second
    mcp_mod.update_job_spreadsheet(job_id, {"Job Status": "In Progress"}, filepath="",
                                   id_column="JobID (JOB-####)", sheet_name="Jobs_Schedule",
                                   backup=False, ctx=_make_ctx(owner))
    next_poll = json.loads(mcp_mod.get_board_updates(since=cursor, ctx=_make_ctx(owner)))
    assert [r["Job Status"] for r in next_poll] == ["In Progress"], \
        f"same-second change missed by the Board poll (cursor {cursor})"


def test_old_whole_second_timestamps_still_compare_correctly():
    """Rows written before the change keep whole-second last_edited_at values;
    a new millisecond value in the same second must sort after them as text,
    and a whole-second cursor must still pick up later millisecond rows."""
    old = "2026-10-02T12:00:05+00:00"
    new_same_second = "2026-10-02T12:00:05.123+00:00"
    new_next_second = "2026-10-02T12:00:06.001+00:00"
    assert new_same_second > old
    assert new_next_second > new_same_second > old
    assert not (old > new_same_second)


def test_server_mode_ignores_filepath_argument(server_env, monkeypatch, mcp_mod, tmp_path):
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "A", ctx=_make_ctx(owner)), "Customer Name / Company": "A"}, filepath="", backup=False, ctx=_make_ctx(owner))

    decoy = tmp_path / "decoy.db"
    result = mcp_mod.get_board_updates(since="2000-01-01T00:00:00", filepath=str(decoy), ctx=_make_ctx(owner))
    rows = json.loads(result)
    assert len(rows) == 1
    assert not decoy.exists()
