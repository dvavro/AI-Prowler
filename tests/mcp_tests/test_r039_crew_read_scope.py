"""
tests/mcp_tests/test_r039_crew_read_scope.py
======================================
R-039 (2026-09-27, was gap G-02, found live by SRV-SCR-06/07): in SERVER
MODE a field_crew user's reads of TimeLog and Route_Planner must return only
their own rows, exactly like Jobs_Schedule always has:

  * TimeLog       -> only clock-ins THEY logged (time_entries.crew is the
                     person who clocked in — even on someone else's job)
  * Route_Planner -> only their own route's stops (route_stops.crew_id)

Covers both read paths: read_job_spreadsheet and get_board_updates.
owner / manager / staff and personal mode still see every row.
"""
import json
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
SINCE = "2026-09-27T00:00:00"


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
    conn.execute("INSERT INTO jobs (job_id, crew, service_date, last_edited_at) VALUES (?,?,?,?)",
                 ("JOB-0101", CREW, DAY, TS))
    conn.execute("INSERT INTO jobs (job_id, crew, service_date, last_edited_at) VALUES (?,?,?,?)",
                 ("JOB-0202", OTHER, DAY, TS))
    # Sam clocks in on his own job; the owner clocks in on OTHER's job.
    conn.execute("INSERT INTO time_entries (entry_id, job_id, entry_date, crew, last_edited_at) "
                 "VALUES (?,?,?,?,?)", ("TE-0101", "JOB-0101", DAY, CREW, TS))
    conn.execute("INSERT INTO time_entries (entry_id, job_id, entry_date, crew, last_edited_at) "
                 "VALUES (?,?,?,?,?)", ("TE-0202", "JOB-0202", DAY, "Owner Person", TS))
    conn.execute("INSERT INTO route_stops (route_date, crew_id, stop_number, job_id, last_edited_at) "
                 "VALUES (?,?,?,?,?)", (DAY, CREW, 1, "JOB-0101", TS))
    conn.execute("INSERT INTO route_stops (route_date, crew_id, stop_number, job_id, last_edited_at) "
                 "VALUES (?,?,?,?,?)", (DAY, OTHER, 1, "JOB-0202", TS))
    conn.commit()
    conn.close()
    monkeypatch.setattr(mcp_mod, "_resolve_job_db_path", lambda ctx, filepath="": path)
    return path


def _as(mcp_mod, monkeypatch, role, name=CREW):
    monkeypatch.setattr(mcp_mod, "_current_user",
                        lambda ctx: {"id": "u-test", "name": name, "role": role})


def _read(mcp_mod, sheet):
    return mcp_mod.read_job_spreadsheet(sheet_name=sheet, max_rows=500, ctx=None)


def test_scoped_sheet_list_is_exactly_the_three(mcp_mod):
    assert mcp_mod._CREW_SCOPED_READ_SHEETS == {"Jobs_Schedule", "TimeLog", "Route_Planner"}


@pytest.mark.parametrize("sheet", ["TimeLog", "Route_Planner", "Jobs_Schedule"])
def test_field_crew_read_sees_only_own_rows(mcp_mod, env, monkeypatch, sheet):
    _as(mcp_mod, monkeypatch, "field_crew")
    out = _read(mcp_mod, sheet)
    assert "JOB-0101" in out, out
    assert "JOB-0202" not in out, f"R-039: field crew sees another crew's {sheet} row:\n{out}"


def test_field_crew_timelog_is_who_clocked_in_not_whose_job(mcp_mod, env, monkeypatch):
    # OTHER is the crew on JOB-0202, but the clock-in there was logged by the
    # owner — OTHER must not see it (it isn't theirs), and neither may Sam.
    _as(mcp_mod, monkeypatch, "field_crew", name=OTHER)
    out = _read(mcp_mod, "TimeLog")
    assert "TE-0202" not in out and "TE-0101" not in out, out


@pytest.mark.parametrize("sheet", ["TimeLog", "Route_Planner"])
def test_field_crew_board_updates_see_only_own_rows(mcp_mod, env, monkeypatch, sheet):
    _as(mcp_mod, monkeypatch, "field_crew")
    out = mcp_mod.get_board_updates(since=SINCE, sheet_name=sheet, ctx=None)
    rows = json.loads(out)
    assert isinstance(rows, list) and rows, out
    assert "JOB-0101" in out
    assert "JOB-0202" not in out, f"R-039: get_board_updates leaks another crew's {sheet} row"


@pytest.mark.parametrize("role", ["owner", "manager", "staff"])
@pytest.mark.parametrize("sheet", ["TimeLog", "Route_Planner"])
def test_other_roles_still_see_every_row(mcp_mod, env, monkeypatch, role, sheet):
    _as(mcp_mod, monkeypatch, role)
    out = _read(mcp_mod, sheet)
    assert "JOB-0101" in out and "JOB-0202" in out, out


@pytest.mark.parametrize("sheet", ["TimeLog", "Route_Planner"])
def test_personal_mode_sees_every_row(mcp_mod, env, monkeypatch, sheet):
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    out = _read(mcp_mod, sheet)
    assert "JOB-0101" in out and "JOB-0202" in out, out


def test_customers_still_unfiltered_for_field_crew(mcp_mod, env, monkeypatch):
    _as(mcp_mod, monkeypatch, "field_crew")
    out = _read(mcp_mod, "Customers")
    assert "do not have access to the" not in out


# ── R-039 write side (was G-01): route tools act only on the crew's own route ──

@pytest.mark.parametrize("asked", ["", "Sam Crew", "  sam crew  ", "SAM CREW"])
def test_route_crew_helper_field_crew_gets_own_name(mcp_mod, env, monkeypatch, asked):
    _as(mcp_mod, monkeypatch, "field_crew")
    crew, err = mcp_mod._route_crew_for_caller(None, env, asked)
    assert err == "" and crew == CREW


@pytest.mark.parametrize("asked", [OTHER, "(unassigned)", "Sam"])
def test_route_crew_helper_field_crew_refused_for_anyone_else(mcp_mod, env, monkeypatch, asked):
    _as(mcp_mod, monkeypatch, "field_crew")
    crew, err = mcp_mod._route_crew_for_caller(None, env, asked)
    assert crew == "" and err.startswith("❌") and "own route" in err


@pytest.mark.parametrize("role", ["owner", "manager", "staff"])
@pytest.mark.parametrize("asked", ["", OTHER])
def test_route_crew_helper_other_roles_unchanged(mcp_mod, env, monkeypatch, role, asked):
    # R-055 (2026-09-28, extended to every role): a blank crew is the caller's
    # OWN route (the name _as() gives them); a named person is unchanged.
    _as(mcp_mod, monkeypatch, role)
    want = CREW if asked == "" else asked
    assert mcp_mod._route_crew_for_caller(None, env, asked) == (want, "")


def test_route_crew_helper_personal_mode_unchanged(mcp_mod, env, monkeypatch):
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    assert mcp_mod._route_crew_for_caller(None, env, "") == ("", "")


def _call_route_tool(mcp_mod, tool, crew):
    fn = getattr(mcp_mod, tool)
    if tool == "build_daily_route":
        return fn(route_date=DAY, crew=crew, email_link=False, ctx=None)
    return fn(route_date=DAY, crew=crew, ctx=None)


_ROUTE_TOOLS = ["build_daily_route", "suggest_route_schedule", "approve_route_schedule",
                "unapprove_route_schedule", "prescreen_route_jobs"]


@pytest.mark.parametrize("tool", _ROUTE_TOOLS)
def test_field_crew_route_tools_refuse_another_crew(mcp_mod, env, monkeypatch, tool):
    _as(mcp_mod, monkeypatch, "field_crew")
    before = sqlite3.connect(env).execute(
        "SELECT route_date, crew_id, stop_number, job_id FROM route_stops ORDER BY id").fetchall()
    out = _call_route_tool(mcp_mod, tool, OTHER)
    assert out.startswith("❌") and "own route" in out, out
    after = sqlite3.connect(env).execute(
        "SELECT route_date, crew_id, stop_number, job_id FROM route_stops ORDER BY id").fetchall()
    assert before == after, "refused call still changed route_stops"


@pytest.mark.parametrize("tool", ["approve_route_schedule", "unapprove_route_schedule",
                                  "prescreen_route_jobs"])
def test_field_crew_blank_crew_runs_on_own_route(mcp_mod, env, monkeypatch, tool):
    # Blank used to mean "every crew"; for field crew it now means their own route.
    import db_route_ops
    seen = {}
    target = {"approve_route_schedule": "db_approve_route_schedule",
              "unapprove_route_schedule": "db_unapprove_route_schedule",
              "prescreen_route_jobs": "db_prescreen_route_jobs"}[tool]

    def fake(db_path, route_date, crew, *a, **k):
        seen["crew"] = crew
        return [] if tool == "prescreen_route_jobs" else "✅ ok"
    monkeypatch.setattr(db_route_ops, target, fake)
    _as(mcp_mod, monkeypatch, "field_crew")
    _call_route_tool(mcp_mod, tool, "")
    assert seen.get("crew") == CREW


@pytest.mark.parametrize("tool", ["approve_route_schedule", "unapprove_route_schedule"])
def test_owner_blank_crew_means_own_route(mcp_mod, env, monkeypatch, tool):
    # Was "owner blank = every crew"; R-055 (David 2026-09-28): owners self-serve
    # their own route like everyone else — they name a person to plan theirs.
    import db_route_ops
    seen = {}
    target = {"approve_route_schedule": "db_approve_route_schedule",
              "unapprove_route_schedule": "db_unapprove_route_schedule"}[tool]

    def fake(db_path, route_date, crew, *a, **k):
        seen["crew"] = crew
        return "✅ ok"
    monkeypatch.setattr(db_route_ops, target, fake)
    _as(mcp_mod, monkeypatch, "owner")
    _call_route_tool(mcp_mod, tool, "")
    assert seen.get("crew") == CREW
