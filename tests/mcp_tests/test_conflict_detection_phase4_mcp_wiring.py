"""
tests/mcp_tests/test_conflict_detection_phase4_mcp_wiring.py
==========================================================
Job Board Architecture Spec — Phase 4 (spec §6.2, §11).

In-process tests for the real update_job_spreadsheet() @mcp.tool()'s new
expected_version parameter, covering BOTH personal mode (ctx=None) and
server mode (mocked ctx). Proves the MCP-layer wiring — the tool's -1
sentinel convention (matching create_invoice's tax_rate=-1.0 pattern)
correctly translates to "skip the check" vs. a real version — feeding
into db_write_ops's already-proven conflict logic.

Run with:
    run_tests.bat tests\\mcp\\test_conflict_detection_phase4_mcp_wiring.py -v
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


def _job_status(db_path, job_id):
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT job_status FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    conn.close()
    return row[0]


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


def test_personal_mode_default_skips_version_check(personal_env, mcp_mod):
    """expected_version left at its -1 default must behave exactly like
    before this feature existed — unconditional overwrite."""
    job_result = mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod), "Customer Name / Company": "A"}, filepath="", backup=False, ctx=None)
    job_id = job_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()
    mcp_mod.update_job_spreadsheet(job_id, {"Job Status": "X"}, filepath="",
                                    id_column="JobID (JOB-####)", backup=False, ctx=None)
    # Second write with no expected_version still succeeds even though
    # the row is no longer at version 1.
    result = mcp_mod.update_job_spreadsheet(job_id, {"Job Status": "Complete"}, filepath="",
                                             id_column="JobID (JOB-####)", backup=False, ctx=None)
    assert result.startswith("✅"), result


def test_personal_mode_matching_version_succeeds(personal_env, mcp_mod):
    job_result = mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod), "Customer Name / Company": "A"}, filepath="", backup=False, ctx=None)
    job_id = job_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()
    result = mcp_mod.update_job_spreadsheet(job_id, {"Job Status": "Complete"}, filepath="",
                                             id_column="JobID (JOB-####)", backup=False,
                                             expected_version=1, ctx=None)
    assert result.startswith("✅"), result
    assert "NEW_VERSION=2" in result


def test_personal_mode_stale_version_rejected(personal_env, mcp_mod):
    job_result = mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod), "Customer Name / Company": "A"}, filepath="", backup=False, ctx=None)
    job_id = job_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()
    mcp_mod.update_job_spreadsheet(job_id, {"Job Status": "In Progress"}, filepath="",
                                    id_column="JobID (JOB-####)", backup=False,
                                    expected_version=1, ctx=None)
    result = mcp_mod.update_job_spreadsheet(job_id, {"Job Status": "Complete"}, filepath="",
                                             id_column="JobID (JOB-####)", backup=False,
                                             expected_version=1, ctx=None)  # stale
    assert result.startswith("❌")
    assert "reload and try again" in result
    assert _job_status(personal_env, job_id) == "In Progress"


# ══════════════════════════════════════════════════════════════════════════
# Server mode (mocked ctx)
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def server_env(tmp_path, monkeypatch, mcp_mod):
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    return tmp_path / "ai_prowler_jobs.db"


def test_server_mode_two_crew_members_racing_the_same_job(server_env, monkeypatch, mcp_mod):
    """The realistic Phase 4 scenario: two crew members (or admin + crew)
    both open the same job, one saves first, the second's stale write is
    rejected rather than silently clobbering the first save."""
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    job_result = mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "X", ctx=_make_ctx(owner)), "Customer Name / Company": "X", "Crew / Technician": "Jake R"},
                                     filepath="", backup=False, ctx=_make_ctx(owner))
    job_id = job_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()

    crew = _field_crew()
    _set_user(monkeypatch, mcp_mod, crew)

    # Both "load" the job at version 1.
    first_save = mcp_mod.update_job_spreadsheet(
        job_id, {"Job Status": "In Progress"}, filepath="",
        id_column="JobID (JOB-####)", sheet_name="Jobs_Schedule", backup=False,
        expected_version=1, ctx=_make_ctx(crew),
    )
    assert first_save.startswith("✅"), first_save

    second_save = mcp_mod.update_job_spreadsheet(
        job_id, {"Job Status": "Complete"}, filepath="",
        id_column="JobID (JOB-####)", sheet_name="Jobs_Schedule", backup=False,
        expected_version=1, ctx=_make_ctx(crew),  # stale now
    )
    assert second_save.startswith("❌")
    assert "reload and try again" in second_save
    assert _job_status(server_env, job_id) == "In Progress"


def test_server_mode_field_crew_permission_checked_before_version(server_env, monkeypatch, mcp_mod):
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    job_result = mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "X", ctx=_make_ctx(owner)), "Customer Name / Company": "X", "Crew / Technician": "Someone Else"},
                                     filepath="", backup=False, ctx=_make_ctx(owner))
    job_id = job_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()

    crew = _field_crew()
    _set_user(monkeypatch, mcp_mod, crew)
    result = mcp_mod.update_job_spreadsheet(
        job_id, {"Job Status": "Complete"}, filepath="",
        id_column="JobID (JOB-####)", sheet_name="Jobs_Schedule", backup=False,
        expected_version=999, ctx=_make_ctx(crew),  # wrong on purpose
    )
    assert result.startswith("❌")
    assert "assigned to you" in result
    assert "Conflict" not in result


def test_server_mode_owner_unrestricted_still_gets_version_check(server_env, monkeypatch, mcp_mod):
    """Being unrestricted (owner) exempts you from crew-scoping, not from
    conflict detection — the version check is orthogonal to role."""
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    job_result = mcp_mod.create_job({"CustomerID": _cust_id(mcp_mod, "X", ctx=_make_ctx(owner)), "Customer Name / Company": "X"}, filepath="", backup=False,
                                     ctx=_make_ctx(owner))
    job_id = job_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()

    mcp_mod.update_job_spreadsheet(job_id, {"Job Status": "In Progress"}, filepath="",
                                    id_column="JobID (JOB-####)", backup=False,
                                    expected_version=1, ctx=_make_ctx(owner))
    result = mcp_mod.update_job_spreadsheet(job_id, {"Job Status": "Complete"}, filepath="",
                                             id_column="JobID (JOB-####)", backup=False,
                                             expected_version=1, ctx=_make_ctx(owner))  # stale
    assert result.startswith("❌")
    assert "reload and try again" in result
