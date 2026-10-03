"""
tests/mcp_tests/test_data_portability_phase8_mcp_wiring.py
========================================================
Job Board Architecture Spec Phase 8 (spec §12) — MCP-layer wiring for
backup_job_database(), restore_job_database(), export_to_csv(). Both
personal and server mode, through the real @mcp.tool() functions.

Updated 2026-09-24: backup_database/restore_database were renamed to
backup_job_database/restore_job_database (to avoid the name being mistaken
for backing up the ChromaDB knowledge-base index, which has no backup tool
of its own) — this file's tool calls were never updated to match, causing
every test here except the export_to_csv ones to fail with
"module 'ai_prowler_mcp' has no attribute 'backup_database'". Fixed by
renaming the calls here to match; nothing about what's being tested
changed.

Run with:
    run_tests.bat tests\\mcp\\test_data_portability_phase8_mcp_wiring.py -v
"""
from __future__ import annotations

import os
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


def _owner(uid="dave"):
    return {"id": uid, "name": "Dave Owner", "role": "owner", "status": "active", "scopes": []}


@pytest.fixture
def personal_env(tmp_path, monkeypatch, mcp_mod):
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    return tmp_path / "ai_prowler_jobs.db"


def test_personal_mode_backup_database(personal_env, mcp_mod, tmp_path):
    mcp_mod.create_customer({"Company Name": "X"}, filepath="", backup=False, ctx=None)
    dest = str(tmp_path / "manual_backup.db")
    result = mcp_mod.backup_job_database(filepath="", destination_path=dest, ctx=None)
    assert result.startswith("✅"), result
    assert os.path.exists(dest)


def test_personal_mode_restore_requires_confirm(personal_env, mcp_mod, tmp_path):
    mcp_mod.create_customer({"Company Name": "X"}, filepath="", backup=False, ctx=None)
    backup_path = str(tmp_path / "b.db")
    mcp_mod.backup_job_database(filepath="", destination_path=backup_path, ctx=None)

    result = mcp_mod.restore_job_database(backup_path, filepath="", confirm=False, ctx=None)
    assert result.startswith("❌")
    assert "confirm=True" in result


def test_personal_mode_restore_round_trip(personal_env, mcp_mod, tmp_path):
    mcp_mod.create_customer({"Company Name": "Blue Wave Cafe"}, filepath="", backup=False, ctx=None)
    backup_path = str(tmp_path / "b.db")
    mcp_mod.backup_job_database(filepath="", destination_path=backup_path, ctx=None)

    mcp_mod.create_customer({"Company Name": "Extra Co"}, filepath="", backup=False, ctx=None)
    result = mcp_mod.restore_job_database(backup_path, filepath="", confirm=True, ctx=None)
    assert result.startswith("✅"), result

    conn = sqlite3.connect(str(personal_env))
    count = conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0]
    conn.close()
    assert count == 1  # back to just Blue Wave Cafe


def test_personal_mode_export_to_csv(personal_env, mcp_mod, tmp_path):
    mcp_mod.create_customer({"Company Name": "X"}, filepath="", backup=False, ctx=None)
    out_dir = str(tmp_path / "csv_out")
    result = mcp_mod.export_to_csv(filepath="", output_dir=out_dir, tables=["Customers"], ctx=None)
    assert result.startswith("✅"), result
    assert os.path.exists(os.path.join(out_dir, "Customers.csv"))


def test_export_to_csv_accepts_display_sheet_names(personal_env, mcp_mod, tmp_path):
    """export_to_csv's `tables` arg accepts the display names users
    actually see in the app (Invoices, Customers, ...) not just the
    underlying table names — confirms the sheet-name -> table-name
    translation layer works end to end."""
    mcp_mod.create_customer({"Company Name": "X"}, filepath="", backup=False, ctx=None)
    out_dir = str(tmp_path / "csv_named")
    result = mcp_mod.export_to_csv(filepath="", output_dir=out_dir, tables=["Customers"], ctx=None)
    assert "Customers.csv: 1 row" in result


# ══════════════════════════════════════════════════════════════════════════
# Server mode
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def server_env(tmp_path, monkeypatch, mcp_mod):
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    return tmp_path / "ai_prowler_jobs.db"


def test_server_mode_backup_ignores_filepath_argument(server_env, monkeypatch, mcp_mod, tmp_path):
    owner = _owner()
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: owner)
    mcp_mod.create_customer({"Company Name": "X"}, filepath="", backup=False, ctx=_make_ctx(owner))

    decoy = tmp_path / "decoy.db"
    dest = str(tmp_path / "server_backup.db")
    result = mcp_mod.backup_job_database(filepath=str(decoy), destination_path=dest, ctx=_make_ctx(owner))
    assert result.startswith("✅"), result
    assert not decoy.exists()


def test_server_mode_export_to_csv(server_env, monkeypatch, mcp_mod, tmp_path):
    owner = _owner()
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: owner)
    mcp_mod.create_customer({"Company Name": "X"}, filepath="", backup=False, ctx=_make_ctx(owner))

    out_dir = str(tmp_path / "server_csv")
    result = mcp_mod.export_to_csv(filepath="", output_dir=out_dir, tables=["Customers"], ctx=_make_ctx(owner))
    assert result.startswith("✅"), result
