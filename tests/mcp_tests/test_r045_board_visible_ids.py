"""
R-045 (was gap G-12, found live 2026-09-27 by SRV-MULTI-02): a job the owner
re-assigned away from a field crew member stayed on that person's open Job
Board until they tapped refresh. The Board's 60-second poll only upserts rows
that changed AND are visible, so a job that stops being visible never came
back to tell it to go. (A deleted job lingered the same way for everyone.)

Fix: get_board_updates(with_ids=True) also returns every JobID the caller may
see right now (same crew rule); the Board drops any card not in that list.
Without with_ids the reply is unchanged (a plain JSON array).

Run: run_tests.bat tests\\mcp\\test_r045_board_visible_ids.py -v
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

EPOCH = "2000-01-01T00:00:00"
FUTURE = "2099-01-01T00:00:00"


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
    return tmp_path / "ai_prowler_jobs.db"


def _as(monkeypatch, mcp_mod, user):
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
    return _ctx(user)


def _job(mcp_mod, ctx, name, crew):
    c = mcp_mod.create_customer({"Company Name": name}, filepath="", backup=False, ctx=ctx)
    cid = c.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    out = mcp_mod.create_job({"CustomerID": cid, "Customer Name / Company": name, "Crew / Technician": crew},
                             filepath="", backup=False, ctx=ctx)
    return out.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def test_R045_01_without_with_ids_reply_is_unchanged(env, monkeypatch, mcp_mod):
    ctx = _as(monkeypatch, mcp_mod, OWNER)
    _job(mcp_mod, ctx, "A", "Jake R")
    assert isinstance(json.loads(mcp_mod.get_board_updates(since=EPOCH, ctx=ctx)), list)


def test_R045_02_with_ids_returns_rows_and_every_visible_id(env, monkeypatch, mcp_mod):
    ctx = _as(monkeypatch, mcp_mod, OWNER)
    a = _job(mcp_mod, ctx, "A", "Jake R")
    b = _job(mcp_mod, ctx, "B", "Someone Else")
    d = json.loads(mcp_mod.get_board_updates(since=FUTURE, with_ids=True, ctx=ctx))
    assert d["rows"] == [], "nothing changed since FUTURE"
    assert set(d["ids"]) == {a, b}, "ids must list every visible job, changed or not"


def test_R045_03_field_crew_ids_follow_the_crew_rule(env, monkeypatch, mcp_mod):
    octx = _as(monkeypatch, mcp_mod, OWNER)
    mine = _job(mcp_mod, octx, "Mine", "Jake R")
    _job(mcp_mod, octx, "Theirs", "Someone Else")
    cctx = _as(monkeypatch, mcp_mod, CREW)
    d = json.loads(mcp_mod.get_board_updates(since=EPOCH, with_ids=True, ctx=cctx))
    assert d["ids"] == [mine]
    assert {r["Customer Name / Company"] for r in d["rows"]} == {"Mine"}


def test_R045_04_reassigned_job_drops_out_of_the_crews_ids(env, monkeypatch, mcp_mod):
    """The SRV-MULTI-02 scenario at the server level."""
    from db_write_ops import db_update_job
    octx = _as(monkeypatch, mcp_mod, OWNER)
    mine = _job(mcp_mod, octx, "Mine", "Jake R")
    cctx = _as(monkeypatch, mcp_mod, CREW)
    assert json.loads(mcp_mod.get_board_updates(since=EPOCH, with_ids=True, ctx=cctx))["ids"] == [mine]
    db_update_job(str(env), mine, {"Crew / Technician": "Someone Else"}, actor="dave")
    d = json.loads(mcp_mod.get_board_updates(since=EPOCH, with_ids=True, ctx=cctx))
    assert d["ids"] == [] and d["rows"] == [], "re-assigned job still visible to the old crew"


def test_R045_05_with_ids_ignored_for_other_sheets(env, monkeypatch, mcp_mod):
    ctx = _as(monkeypatch, mcp_mod, OWNER)
    mcp_mod.create_customer({"Company Name": "C"}, filepath="", backup=False, ctx=ctx)
    out = json.loads(mcp_mod.get_board_updates(since=EPOCH, sheet_name="Customers", with_ids=True, ctx=ctx))
    assert isinstance(out, list)


def test_R045_06_board_page_drops_cards_not_in_ids():
    """Source-level: the Board asks with_ids and filters to the returned ids,
    with a fallback for a server that predates with_ids."""
    html = (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")
    assert "with_ids: true" in html
    assert "keep.has(String(_boardJobId(r)))" in html
    assert "/with_ids/.test(" in html, "fallback for an older server is missing"
