"""
🗓️ Plan Week (2026-10-22, David) — any AI chat suggests moving SOFT jobs so
jobs near each other are done on the same day; the user approves in the Jobs app.

  WP-01  'Week Plan Distance (miles)': default 5, seeded into Settings, editable,
         a bad value falls back to 5
  WP-02  what may move: soft, open, not paused, single-day, not in the past
  WP-03  where it may move: working days this week, not past, Preferred Day(s)
         (the job's own, else its customer's)
  WP-04  nearby pairs use the distance setting
  WP-05  validate_moves accepts good moves and refuses every rule break, with why
  WP-06  the prompt: WK- code, machine, distance, confirm step, both AI tools
  WP-07  get_week_plan_data only answers its own WK- code
  WP-08  propose_week_moves saves a SUGGESTION — no job changes
  WP-09  approve moves only the ticked jobs, re-checks each, closes the suggestion
  WP-10  dismiss moves nothing
  WP-11  a WK- code can't save a route; field crew only plan their own week
  WP-12  Jobs app: the button sits after 📋 Any AI; allow-lists, catalog, guard

Run: run_tests.bat tests\\mcp_tests\\test_week_plan.py -v
"""
import datetime as dt
import json
import re
import sqlite3
import sys
from pathlib import Path

import pytest
import requests

from db_access import init_db
from db_write_ops import db_create_customer, db_create_job

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import week_plan as wp                                       # noqa: E402

MON = dt.date(2030, 1, 7)                                    # a Monday
TUE, WED, THU, FRI, SAT = (MON + dt.timedelta(days=i) for i in (1, 2, 3, 4, 5))
HOME = (29.0258, -80.9270)                                   # New Smyrna Beach
NEAR = (29.0310, -80.9330)                                   # ~0.5 mi away
FAR = (29.2108, -81.0228)                                    # Daytona, ~14 mi away


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no network in this test")
    monkeypatch.setattr(requests, "get", boom)


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _job(db, name, day, where=HOME, *, crew="Sam Crew", hard=False, status="Scheduled", paused=False,
         end=None, pref="", cust_pref="", minutes=60):
    c = db_create_customer(db, {"Company Name": name}, actor="t")
    cid = c.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    r = db_create_job(db, {"CustomerID (Customers!A)": cid, "Customer Name / Company": name,
                           "Service Date": day.isoformat(), "Street Address": "1 Main St", "City": "NSB",
                           "State": "FL", "Crew / Technician": crew, "Est. Duration": minutes,
                           "Est. Duration Unit": "min", "Latitude (AI Geocode)": where[0],
                           "Longitude (AI Geocode)": where[1]}, actor="t")
    jid = r.split("NEW_JOB_ID=")[1].splitlines()[0].strip()
    conn = sqlite3.connect(db)
    conn.execute("UPDATE jobs SET schedule_type=?, job_status=?, paused=?, end_date=?, preferred_days=? WHERE job_id=?",
                 ("Hard" if hard else "Soft", status, "1" if paused else "", end.isoformat() if end else "",
                  pref, jid))
    conn.execute("UPDATE customers SET preferred_days=? WHERE customer_id=?", (cust_pref, cid))
    conn.commit()
    conn.close()
    return jid


def _date_of(db, jid):
    return sqlite3.connect(db).execute("SELECT service_date FROM jobs WHERE job_id=?", (jid,)).fetchone()[0][:10]


def _set(db, key, value):
    conn = sqlite3.connect(db)
    conn.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                 (key, value))
    conn.commit()
    conn.close()


# ── module rules ─────────────────────────────────────────────────────────────
def test_WP01_distance_setting(db):
    import db_write_ops
    assert ("Week Plan Distance (miles)", "5") == db_write_ops.DEFAULT_SETTINGS[
        [k for k, *_ in db_write_ops.DEFAULT_SETTINGS].index("Week Plan Distance (miles)")][:2]
    db_write_ops.db_seed_default_settings(db)
    assert wp.read_week_plan_miles(db) == 5.0
    _set(db, wp.WEEK_PLAN_MILES_KEY, "2.5")
    assert wp.read_week_plan_miles(db) == 2.5
    for bad in ("", "abc", "0"):
        _set(db, wp.WEEK_PLAN_MILES_KEY, bad)
        assert wp.read_week_plan_miles(db) == 5.0, bad
    _set(db, wp.WEEK_PLAN_MILES_KEY, "5000")
    assert wp.read_week_plan_miles(db) == 100.0


def test_WP02_what_may_move(db):
    ids = {
        "soft": _job(db, "Soft", TUE),
        "hard": _job(db, "Hard", TUE, hard=True),
        "done": _job(db, "Done", TUE, status="Complete"),
        "going": _job(db, "Going", TUE, status="In Progress"),
        "paused": _job(db, "Paused", TUE, paused=True),
        "multi": _job(db, "Multi", TUE, end=THU),
    }
    jobs = {j["job_id"]: j for j in wp.load_week(db, MON)}
    today = MON
    assert wp.why_not_movable(jobs[ids["soft"]], today) == ""
    assert "hard" in wp.why_not_movable(jobs[ids["hard"]], today)
    assert "Complete" in wp.why_not_movable(jobs[ids["done"]], today)
    assert "in progress" in wp.why_not_movable(jobs[ids["going"]], today)
    assert "paused" in wp.why_not_movable(jobs[ids["paused"]], today)
    assert "multi-day" in wp.why_not_movable(jobs[ids["multi"]], today)
    assert "past" in wp.why_not_movable(jobs[ids["soft"]], WED)


def test_WP03_where_it_may_move(db):
    plain = _job(db, "Plain", TUE)
    thu_job = _job(db, "JobPref", TUE, pref="Thursday", cust_pref="Monday")
    cust = _job(db, "CustPref", TUE, cust_pref="Mon, Fri")
    jobs = {j["job_id"]: j for j in wp.load_week(db, MON)}
    wd = frozenset(range(5))
    assert wp.allowed_days(jobs[plain], MON, wd, MON) == [d.isoformat() for d in (MON, TUE, WED, THU, FRI)]
    assert wp.allowed_days(jobs[plain], MON, wd, WED) == [d.isoformat() for d in (WED, THU, FRI)]
    assert wp.allowed_days(jobs[thu_job], MON, wd, MON) == [THU.isoformat()]            # job's own wins
    assert wp.allowed_days(jobs[cust], MON, wd, MON) == [MON.isoformat(), FRI.isoformat()]
    assert SAT.isoformat() in wp.allowed_days(jobs[plain], MON, frozenset(range(6)), MON)


def test_WP04_nearby_pairs_follow_the_setting(db):
    a = _job(db, "A", MON, HOME)
    b = _job(db, "B", THU, NEAR)
    c = _job(db, "C", WED, FAR)
    jobs = wp.load_week(db, MON)
    pairs = wp.nearby_pairs(jobs, 5, MON)
    assert [(p["a"], p["b"]) for p in pairs] == [(a, b)] and 0.2 < pairs[0]["miles"] < 1.0
    assert len(wp.nearby_pairs(jobs, 25, MON)) == 3
    _set(db, wp.WEEK_PLAN_MILES_KEY, "20")
    assert len(wp.week_data(db, MON, "", MON)["nearby_pairs"]) == 3


def test_WP05_validate_moves(db):
    a = _job(db, "A", MON, HOME)
    b = _job(db, "B", THU, NEAR)
    hard = _job(db, "H", WED, hard=True)
    thu_only = _job(db, "T", TUE, pref="Thursday")
    other = _job(db, "O", TUE, crew="Val Other")
    big = _job(db, "Big", THU, minutes=420)
    moves = wp.parse_moves(json.dumps([
        {"job_id": b, "to": MON.isoformat(), "reason": "0.5 mi from A"},
        {"job_id": b, "to": TUE.isoformat()},                    # listed twice
        {"job_id": hard, "to": THU.isoformat()},
        {"job_id": thu_only, "to": MON.isoformat()},
        {"job_id": a, "to": SAT.isoformat()},
        {"job_id": a, "to": MON.isoformat()},                    # already there
        {"job_id": "JOB-9999", "to": MON.isoformat()},
        {"job_id": other, "to": MON.isoformat()},                # other crew
        {"job_id": big, "to": "next thursday"},
    ]))
    ok, bad, warn = wp.validate_moves(db, MON, "Sam Crew", moves, MON)
    assert [(m["job_id"], m["from"], m["to"]) for m in ok] == [(b, THU.isoformat(), MON.isoformat())]
    why = dict(bad)
    assert "listed twice" in why[b]
    assert "hard" in why[hard]
    assert "may move to: " + THU.isoformat() in why[thu_only]
    assert "isn't allowed" in why[a] or "already" in why[a]
    assert "not one of this week's jobs" in why["JOB-9999"] and "not one of" in why[other]
    assert "isn't a date" in why[big]
    # overloading a day is a warning, not a refusal
    many = [_job(db, f"M{i}", TUE, minutes=240) for i in range(3)]
    ok2, _, warn2 = wp.validate_moves(db, MON, "Sam Crew",
                                      wp.parse_moves([{"job_id": j, "to": WED.isoformat()} for j in many]), MON)
    assert len(ok2) == 3 and warn2 and "more than" in warn2[0]


# ── MCP tools ────────────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture
def env(db, tmp_path, monkeypatch, mcp_mod):
    monkeypatch.setattr(mcp_mod, "_resolve_job_db_path", lambda ctx, filepath="": db)
    monkeypatch.setattr(mcp_mod, "_route_codes_path", lambda: tmp_path / "codes.json")
    monkeypatch.setattr(mcp_mod, "_week_proposals_path", lambda: tmp_path / "week.json")
    monkeypatch.setattr(mcp_mod, "_route_machine_label", lambda: "AI-Prowler Personal on TESTPC")
    monkeypatch.setattr(mcp_mod, "_today_local", lambda: MON)
    return db


def _code(text):
    m = re.match(r"ROUTE_CODE: (WK-[A-Z0-9]{6})\nMADE_BY: ([^\n]+)\n\n", text)
    assert m, text[:300]
    return m.group(1), text[m.end():]


def test_WP06_prompt(mcp_mod, env):
    code, text = _code(mcp_mod.get_week_plan_prompt(week_start=THU.isoformat(), ctx=None))
    assert f"for the week {MON.isoformat()} to {(MON + dt.timedelta(days=6)).isoformat()}" in text
    assert f'confirm_route_code(code="{code}")' in text
    assert f'get_week_plan_data(route_code="{code}")' in text and f'propose_week_moves(route_code="{code}"' in text
    assert "within 5 miles" in text and "Never move a HARD job" in text and "DATE only" in text
    assert mcp_mod.confirm_route_code(code).startswith("MATCH") and "the week of " + MON.isoformat() in \
        mcp_mod.confirm_route_code(code)
    assert mcp_mod.get_week_plan_prompt(week_start="soon", ctx=None).startswith("❌")


def test_WP07_data_only_for_its_own_week_code(mcp_mod, env):
    a = _job(env, "A", MON, HOME)
    code, _ = _code(mcp_mod.get_week_plan_prompt(week_start=MON.isoformat(), ctx=None))
    data = json.loads(mcp_mod.get_week_plan_data(code))
    assert [j["job_id"] for j in data["jobs"]] == [a] and data["nearby_miles"] == 5.0
    assert mcp_mod.get_week_plan_data("WK-ZZZZZZ").startswith("❌ WRONG AI-PROWLER")
    rt = mcp_mod.get_ai_route_prompt(route_date=MON.isoformat(), ctx=None).split("\n")[0].split(": ")[1]
    assert "not a 🗓️ Plan Week code" in mcp_mod.get_week_plan_data(rt)


def _proposal(mcp_mod, env):
    a = _job(env, "A", MON, HOME)
    b = _job(env, "B", THU, NEAR)
    c = _job(env, "C", WED, NEAR)
    code, _ = _code(mcp_mod.get_week_plan_prompt(week_start=MON.isoformat(), ctx=None))
    out = mcp_mod.propose_week_moves(code, json.dumps([
        {"job_id": b, "to": MON.isoformat(), "reason": "0.5 mi from A"},
        {"job_id": c, "to": MON.isoformat(), "reason": "0.5 mi from A"},
        {"job_id": "JOB-9999", "to": MON.isoformat()}]))
    return code, a, b, c, out


def test_WP08_propose_is_only_a_suggestion(mcp_mod, env):
    code, a, b, c, out = _proposal(mcp_mod, env)
    assert out.startswith("✅ Saved 2 suggested move(s)") and "NOTHING has changed yet" in out
    assert "JOB-9999" in out and "Not accepted" in out
    assert _date_of(env, b) == THU.isoformat() and _date_of(env, c) == WED.isoformat()
    p = json.loads(mcp_mod.get_week_proposal(week_start=FRI.isoformat(), ctx=None))["proposal"]
    assert p["code"] == code and [m["job_id"] for m in p["moves"]] == [b, c]
    assert mcp_mod.propose_week_moves(code, "not json").startswith("❌ Couldn't read moves")


def test_WP09_approve_moves_ticked_jobs_rechecked(mcp_mod, env):
    code, a, b, c, _ = _proposal(mcp_mod, env)
    conn = sqlite3.connect(env)                     # c changed since the AI looked
    conn.execute("UPDATE jobs SET schedule_type='Hard' WHERE job_id=?", (c,))
    conn.commit()
    conn.close()
    out = mcp_mod.apply_week_moves(code, f"{b},{c}")
    assert out.startswith("✅ Moved 1 of 2"), out
    assert _date_of(env, b) == MON.isoformat() and _date_of(env, c) == WED.isoformat()
    assert "hard" in out.split(c)[1].splitlines()[0]
    assert mcp_mod.apply_week_moves(code, b).startswith("❌ That suggestion is no longer waiting")
    assert json.loads(mcp_mod.get_week_proposal(week_start=MON.isoformat(), ctx=None))["proposal"] is None


def test_WP10_dismiss_moves_nothing(mcp_mod, env):
    code, a, b, c, _ = _proposal(mcp_mod, env)
    assert mcp_mod.dismiss_week_proposal(code).startswith("✅ Suggestion dismissed")
    assert _date_of(env, b) == THU.isoformat()
    assert mcp_mod.apply_week_moves(code, b).startswith("❌")


def test_WP11_codes_dont_cross_and_crew_rules(mcp_mod, env, monkeypatch):
    code, a, b, c, _ = _proposal(mcp_mod, env)
    out = mcp_mod.apply_route_order(route_date=MON.isoformat(), stop_order=a, route_code=code, ctx=None)
    assert "Plan Week code" in out and "Nothing was written" in out
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: {"id": "u", "name": "Val Other", "role": "field_crew"})
    assert mcp_mod.apply_week_moves(code, b).startswith("❌")             # Sam's week, not Val's
    # a field crew member can't make a week plan for someone else's week...
    assert mcp_mod.get_week_plan_prompt(week_start=MON.isoformat(), crew="Sam Crew", ctx=None).startswith("❌")
    # ...and a blank crew means their own
    _, text = _code(mcp_mod.get_week_plan_prompt(week_start=MON.isoformat(), ctx=None))
    assert "crew 'Val Other'" in text


def test_WP12_jobs_app_and_lists():
    html = (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")
    cp, wk, em = (html.index(f'id="{i}"') for i in ("routeCopyAiBtn", "routeWeekPlanBtn", "routeEmailRouteBtn"))
    assert cp < wk < em
    assert 'onclick="openWeekPlan()"' in html and "function openWeekPlan()" in html
    for tool in ("get_week_plan_prompt", "get_week_proposal", "apply_week_moves", "dismiss_week_proposal"):
        assert f"mcpCall('{tool}'" in html, tool
    src = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    from mcp_tool_catalog import JOBS_APP_TOOLS, TOOL_CATALOG
    for tool in ("get_week_plan_prompt", "get_week_proposal", "apply_week_moves", "dismiss_week_proposal",
                 "get_week_plan_data", "propose_week_moves"):
        assert src.count(f'"{tool}"') >= 2, f"{tool} missing from a /pwa-api allow-list"
        assert tool in JOBS_APP_TOOLS and tool in TOOL_CATALOG
    sys.path.insert(0, str(_SRC / "tests" / "gui_jobs_e2e"))
    import safety
    assert "apply_week_moves" in safety.SCOPED and "propose_week_moves" in safety.READ
