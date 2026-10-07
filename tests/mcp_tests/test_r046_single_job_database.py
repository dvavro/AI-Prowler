"""
R-046 (2026-09-28, from the SRV-DB review): one shared job database for every
server-mode user.

The spreadsheet era allowed per-user job files ("Model B": <user_id>.xlsx next
to the master). After the SQLite move two leftovers stayed in the code:
  * _resolve_job_db_path picked <db folder>\\<user_id>.db for a user if such a
    file existed — a stray file with a user's id as its name would silently
    have given that user a separate, empty set of jobs;
  * _job_crew_scope skipped the crew filter when the path was the user's
    "own" <uid>.xlsx / <uid>.db next to the Excel export (dead since the
    database moved to the state folder, but misleading).
Both are removed, and so is the unused _resolve_job_spreadsheet_path.
David (2026-09-28): there is only ever one job database.

Run: run_tests.bat tests\\mcp\\test_r046_single_job_database.py -v
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


def _ctx(user):
    ctx = MagicMock()
    ctx.request_context.request.state.user = user
    return ctx


OWNER = {"id": "dave", "name": "Dave Owner", "role": "owner", "status": "active", "scopes": []}
CREW = {"id": "jake-r", "name": "Jake R", "role": "field_crew", "status": "active", "scopes": []}


@pytest.fixture
def env(tmp_path, monkeypatch, mcp_mod):
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(tmp_path / "t.xlsx"))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    return tmp_path


def _as(monkeypatch, mcp_mod, user):
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
    return _ctx(user)


def _job(mcp_mod, ctx, name, crew):
    c = mcp_mod.create_customer({"Company Name": name}, filepath="", backup=False, ctx=ctx)
    cid = c.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    out = mcp_mod.create_job({"CustomerID": cid, "Customer Name / Company": name, "Crew / Technician": crew},
                             filepath="", backup=False, ctx=ctx)
    return out.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def test_R046_01_stray_user_db_file_is_ignored(env, monkeypatch, mcp_mod):
    (env / "jake-r.db").write_bytes(b"")          # a file named after the user
    ctx = _as(monkeypatch, mcp_mod, CREW)
    assert mcp_mod._resolve_job_db_path(ctx) == str(env / "ai_prowler_jobs.db")


def test_R046_02_every_user_gets_the_same_database(env, monkeypatch, mcp_mod):
    (env / "jake-r.db").write_bytes(b"")
    (env / "dave.db").write_bytes(b"")
    paths = {mcp_mod._resolve_job_db_path(_as(monkeypatch, mcp_mod, u)) for u in (OWNER, CREW)}
    assert paths == {str(env / "ai_prowler_jobs.db")}


def test_R046_03_server_mode_ignores_filepath_argument(env, monkeypatch, mcp_mod):
    ctx = _as(monkeypatch, mcp_mod, CREW)
    assert mcp_mod._resolve_job_db_path(ctx, str(env / "jake-r.db")) == str(env / "ai_prowler_jobs.db")


def test_R046_04_field_crew_filtered_even_on_their_old_own_file_path(env, monkeypatch, mcp_mod):
    """The old Model B exemption: fp == <export folder>/<uid>.db meant 'no filter'."""
    ctx = _as(monkeypatch, mcp_mod, CREW)
    for own in (env / "jake-r.db", env / "jake-r.xlsx"):
        assert mcp_mod._job_crew_scope(ctx, str(own)) == (True, "jake r")


def test_R046_05_crew_with_stray_file_still_sees_their_shared_jobs(env, monkeypatch, mcp_mod):
    octx = _as(monkeypatch, mcp_mod, OWNER)
    mine = _job(mcp_mod, octx, "Mine", "Jake R")
    _job(mcp_mod, octx, "Theirs", "Someone Else")
    (env / "jake-r.db").write_bytes(b"")
    cctx = _as(monkeypatch, mcp_mod, CREW)
    out = mcp_mod.read_job_spreadsheet(sheet_name="Jobs_Schedule", ctx=cctx)
    assert mine in out and "Theirs" not in out, out[:400]


def test_R046_06_owner_and_staff_unrestricted(env, monkeypatch, mcp_mod):
    for role in ("owner", "manager", "staff"):
        u = dict(OWNER, role=role)
        assert mcp_mod._job_crew_scope(_as(monkeypatch, mcp_mod, u), "") == (False, "")


def test_R046_07_spreadsheet_era_resolver_is_gone(mcp_mod):
    assert not hasattr(mcp_mod, "_resolve_job_spreadsheet_path")
    src = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    assert 'f"{user_id}.db"' not in src and 'f"{uid}.db"' not in src
