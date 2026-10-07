"""
R-047 (2026-09-28, was gap G-14): get_route_drive_matrix and apply_route_order
follow the same crew rule as the other route tools (R-039). In server mode a
field_crew caller may only read the drive matrix for, and write the order of,
their OWN route: blank means theirs, any other crew is refused and nothing is
written. owner / manager / staff and personal mode are unchanged.

These are the two tools a Claude chat ("route today's jobs and email me the
link") and the AI Routing run use.

Run: run_tests.bat tests\\mcp\\test_r047_route_matrix_apply_scope.py -v
"""
import sqlite3
import sys
from pathlib import Path

import pytest

from db_access import init_db

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

CREW = "Sam Crew"
OTHER = "Val Other"
DAY = "2026-09-27"
TS = "2026-09-27T12:00:00+00:00"


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture
def env(tmp_path, monkeypatch, mcp_mod):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    conn = sqlite3.connect(path)
    for jid, crew in (("JOB-0101", CREW), ("JOB-0202", OTHER)):
        conn.execute("INSERT INTO jobs (job_id, crew, service_date, last_edited_at) VALUES (?,?,?,?)",
                     (jid, crew, DAY, TS))
    conn.execute("INSERT INTO route_stops (route_date, crew_id, stop_number, job_id, last_edited_at) "
                 "VALUES (?,?,?,?,?)", (DAY, OTHER, 1, "JOB-0202", TS))
    conn.commit()
    conn.close()
    monkeypatch.setattr(mcp_mod, "_resolve_job_db_path", lambda ctx, filepath="": path)
    return path


def _as(mcp_mod, monkeypatch, role, name=CREW):
    monkeypatch.setattr(mcp_mod, "_current_user",
                        lambda ctx: {"id": "u-test", "name": name, "role": role})


def _stops(path):
    return sqlite3.connect(path).execute(
        "SELECT route_date, crew_id, stop_number, job_id FROM route_stops ORDER BY id").fetchall()


@pytest.fixture
def spy(monkeypatch):
    """Records the crew each db-level call actually receives."""
    import db_route_ops
    seen = {}

    def fake_matrix(db_path, route_date, crew, **k):
        seen["matrix"] = crew
        return "MATRIX"

    def fake_apply(db_path, route_date, stop_order, crew, actor, **k):
        seen["apply"] = crew
        return "✅ applied"
    monkeypatch.setattr(db_route_ops, "db_route_drive_matrix", fake_matrix)
    monkeypatch.setattr(db_route_ops, "db_apply_route_order", fake_apply)
    return seen


def _matrix(mcp_mod, crew):
    return mcp_mod.get_route_drive_matrix(route_date=DAY, crew=crew, ctx=None)


def _apply(mcp_mod, crew, order="JOB-0202"):
    return mcp_mod.apply_route_order(route_date=DAY, stop_order=order, crew=crew, ctx=None)


@pytest.mark.parametrize("fn", [_matrix, _apply])
def test_field_crew_refused_another_crew(mcp_mod, env, monkeypatch, spy, fn):
    _as(mcp_mod, monkeypatch, "field_crew")
    before = _stops(env)
    out = fn(mcp_mod, OTHER)
    assert out.startswith("❌") and "own route" in out, out
    assert spy == {}, "refused call still reached the database layer"
    assert _stops(env) == before


def test_field_crew_blank_crew_means_own_route(mcp_mod, env, monkeypatch, spy):
    _as(mcp_mod, monkeypatch, "field_crew")
    _matrix(mcp_mod, "")
    _apply(mcp_mod, "", "JOB-0101")
    assert spy == {"matrix": CREW, "apply": CREW}


@pytest.mark.parametrize("asked", [CREW, " sam crew "])
def test_field_crew_own_name_allowed(mcp_mod, env, monkeypatch, spy, asked):
    _as(mcp_mod, monkeypatch, "field_crew")
    assert _matrix(mcp_mod, asked) == "MATRIX"
    assert spy["matrix"] == CREW


@pytest.mark.parametrize("role", ["owner", "manager", "staff"])
@pytest.mark.parametrize("asked", ["", OTHER])
def test_other_roles_unchanged(mcp_mod, env, monkeypatch, spy, role, asked):
    _as(mcp_mod, monkeypatch, role)
    _matrix(mcp_mod, asked)
    _apply(mcp_mod, asked)
    # R-055 (2026-09-28, extended to every role the same day): a BLANK crew
    # now means the caller's own route (the name _as() gives them) — owner
    # included; a named crew is unchanged.
    want = CREW if asked == "" else asked
    assert spy == {"matrix": want, "apply": want}


def test_personal_mode_unchanged(mcp_mod, env, monkeypatch, spy):
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    _matrix(mcp_mod, "")
    _apply(mcp_mod, "")
    assert spy == {"matrix": "", "apply": ""}


def test_field_crew_real_apply_cannot_touch_other_route(mcp_mod, env, monkeypatch):
    """No spy: the real db layer — Val's stop must be untouched."""
    _as(mcp_mod, monkeypatch, "field_crew")
    out = _apply(mcp_mod, "", "JOB-0202")     # blank crew = his own; JOB-0202 isn't his job
    assert (DAY, OTHER, 1, "JOB-0202") in _stops(env), f"Val's stop changed:\n{out}"
