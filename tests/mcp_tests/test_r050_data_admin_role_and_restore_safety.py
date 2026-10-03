"""
R-050 (2026-09-28): data-admin tools and restore safety (server mode).

1. Export to Excel / CSV / QuickBooks, Backup and Restore are for the owner,
   managers and staff. A field_crew caller is always refused and nothing is
   written. Personal mode (no signed-in user) is unchanged.
2. Restore is meant for moving to a new PC. In server mode, when the live
   database already has business records (jobs, customers, invoices, quotes,
   time entries, route stops), a confirmed restore is still refused unless
   replace_existing=True as well. Every warning shows live-vs-backup counts.
   The safety backup is still made first.

Run: run_tests.bat tests\\mcp\\test_r050_data_admin_role_and_restore_safety.py -v
"""
import os
import sqlite3
import sys
from pathlib import Path

import pytest

from db_access import init_db
from db_backup_ops import (
    db_backup_database,
    db_business_row_count,
    db_restore_database,
)
from db_write_ops import db_create_customer

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


def _count(path, table):
    conn = sqlite3.connect(path)
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


@pytest.fixture
def live(tmp_path):
    p = str(tmp_path / "live" / "jobs.db")
    os.makedirs(os.path.dirname(p))
    init_db(p)
    db_create_customer(p, {"Company Name": "Live Co"}, actor="t")
    return p


@pytest.fixture
def backup(tmp_path):
    p = str(tmp_path / "bk" / "backup.db")
    os.makedirs(os.path.dirname(p))
    init_db(p)
    db_create_customer(p, {"Company Name": "Backup Co 1"}, actor="t")
    db_create_customer(p, {"Company Name": "Backup Co 2"}, actor="t")
    return p


# ── db level ────────────────────────────────────────────────────────────────

def test_fresh_database_counts_as_empty(tmp_path):
    p = str(tmp_path / "fresh.db")
    init_db(p)
    assert db_business_row_count(p) == 0


def test_counting_a_missing_file_does_not_create_it(tmp_path):
    p = str(tmp_path / "nope.db")
    assert db_business_row_count(p) == 0
    assert not os.path.exists(p)


def test_unconfirmed_warning_shows_live_and_backup_counts(live, backup):
    r = db_restore_database(live, backup, confirm=False, require_replace=True)
    assert r.startswith("❌")
    assert "Live now: 0 jobs, 1 customers" in r
    assert "In the backup: 0 jobs, 2 customers" in r
    assert "NOT empty" in r
    assert "replace_existing=True" in r
    assert _count(live, "customers") == 1


def test_server_mode_non_empty_live_refused_even_with_confirm(live, backup):
    r = db_restore_database(live, backup, confirm=True, require_replace=True)
    assert r.startswith("❌ Restore refused")
    assert "Nothing was changed" in r
    assert _count(live, "customers") == 1
    # refused before the safety backup, so no backup folder was made
    assert not os.path.exists(os.path.join(os.path.dirname(live), "backup"))


def test_server_mode_replace_existing_restores_and_keeps_safety_copy(live, backup):
    r = db_restore_database(live, backup, confirm=True, require_replace=True,
                            replace_existing=True)
    assert r.startswith("✅"), r
    assert _count(live, "customers") == 2
    bdir = os.path.join(os.path.dirname(live), "backup")
    files = os.listdir(bdir)
    assert len(files) == 1
    assert _count(os.path.join(bdir, files[0]), "customers") == 1


def test_server_mode_empty_live_restores_without_replace_flag(tmp_path, backup):
    p = str(tmp_path / "new_pc" / "jobs.db")
    os.makedirs(os.path.dirname(p))
    init_db(p)
    r = db_restore_database(p, backup, confirm=True, require_replace=True)
    assert r.startswith("✅"), r
    assert _count(p, "customers") == 2


def test_server_mode_no_live_file_yet_restores(tmp_path, backup):
    p = str(tmp_path / "brand_new" / "jobs.db")
    r = db_restore_database(p, backup, confirm=True, require_replace=True)
    assert r.startswith("✅"), r
    assert _count(p, "customers") == 2


def test_personal_mode_unchanged_confirm_is_enough(live, backup):
    r = db_restore_database(live, backup, confirm=True)
    assert r.startswith("✅"), r
    assert _count(live, "customers") == 2


# ── tool level ──────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture
def tool_env(live, monkeypatch, mcp_mod):
    monkeypatch.setattr(mcp_mod, "_resolve_job_db_path", lambda ctx, filepath="": live)
    return live


def _as(mcp_mod, monkeypatch, role):
    if role is None:
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    else:
        monkeypatch.setattr(mcp_mod, "_current_user",
                            lambda ctx: {"id": "u-t", "name": "Tess T", "role": role})


def _calls(mcp_mod, tmp_path, backup):
    out = str(tmp_path / "out")
    return {
        "excel": lambda: mcp_mod.export_to_excel(output_path=os.path.join(out, "x.xlsx"), ctx=None),
        "csv": lambda: mcp_mod.export_to_csv(output_dir=out, ctx=None),
        "qb": lambda: mcp_mod.export_to_quickbooks_csv(output_dir=out, ctx=None),
        "backup": lambda: mcp_mod.backup_job_database(destination_path=os.path.join(out, "b.db"), ctx=None),
        "restore": lambda: mcp_mod.restore_job_database(backup, confirm=True,
                                                        replace_existing=True, ctx=None),
    }


@pytest.mark.parametrize("which", ["excel", "csv", "qb", "backup", "restore"])
def test_field_crew_refused_and_nothing_written(which, tool_env, backup, tmp_path,
                                                monkeypatch, mcp_mod):
    _as(mcp_mod, monkeypatch, "field_crew")
    r = _calls(mcp_mod, tmp_path, backup)[which]()
    assert r.startswith("❌"), r
    assert "field crew" in r and "Nothing was done" in r
    assert not os.path.exists(str(tmp_path / "out"))
    assert _count(tool_env, "customers") == 1


@pytest.mark.parametrize("role", ["owner", "manager", "staff", None])
def test_other_roles_and_personal_mode_can_backup(role, tool_env, backup, tmp_path,
                                                  monkeypatch, mcp_mod):
    _as(mcp_mod, monkeypatch, role)
    r = _calls(mcp_mod, tmp_path, backup)["backup"]()
    assert r.startswith("✅"), r


@pytest.mark.parametrize("role", ["owner", "manager", "staff"])
def test_other_roles_can_export_csv(role, tool_env, backup, tmp_path, monkeypatch, mcp_mod):
    _as(mcp_mod, monkeypatch, role)
    r = _calls(mcp_mod, tmp_path, backup)["csv"]()
    assert "field crew" not in r
    assert os.path.isdir(str(tmp_path / "out"))


def test_tool_server_mode_non_empty_needs_replace_existing(tool_env, backup,
                                                           monkeypatch, mcp_mod):
    _as(mcp_mod, monkeypatch, "owner")
    monkeypatch.setattr(mcp_mod, "_IS_SERVER_MODE", True)
    r = mcp_mod.restore_job_database(backup, confirm=True, ctx=None)
    assert r.startswith("❌ Restore refused"), r
    assert _count(tool_env, "customers") == 1
    r = mcp_mod.restore_job_database(backup, confirm=True, replace_existing=True, ctx=None)
    assert r.startswith("✅"), r
    assert _count(tool_env, "customers") == 2


def test_tool_personal_mode_confirm_is_enough(tool_env, backup, monkeypatch, mcp_mod):
    _as(mcp_mod, monkeypatch, None)
    monkeypatch.setattr(mcp_mod, "_IS_SERVER_MODE", False)
    r = mcp_mod.restore_job_database(backup, confirm=True, ctx=None)
    assert r.startswith("✅"), r


def test_gui_restore_asks_for_typed_replace_in_server_mode():
    src = (_SRC / "rag_gui.py").read_text(encoding="utf-8")
    i = src.index("def _restore_from_backup_gui")
    body = src[i:i + 6000]
    assert "db_business_row_count" in body
    assert "Type REPLACE" in body
    assert "replace_existing=_replace_existing" in body
    assert "_is_business_server_mode()" in body


def test_catalog_no_longer_says_no_role_gate():
    import mcp_tool_catalog as cat
    rows = cat.TOOL_CATALOG
    assert "no role gate" not in rows["restore_job_database"].description
    for t in ("export_to_excel", "export_to_csv", "export_to_quickbooks_csv",
              "backup_job_database", "restore_job_database"):
        assert "field crew" in rows[t].description, t
