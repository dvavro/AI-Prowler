"""Mileage tracker — MCP tool wrappers in both modes (spec test plan,
integration section). Calls the real @mcp.tool() functions in-process with a
scratch database; network hooks are faked. Covers role gates, field-crew
isolation, the text/voice confirm step, the tracking switch, the clock-out
hook, and that every mileage tool is in both /pwa-api allow-lists and the
Jobs-app tool set.
"""
import json
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

MILEAGE_TOOLS = ["get_mileage_log", "build_mileage_log", "add_mileage_trip", "update_mileage_trip",
                 "fix_mileage_gap", "manage_vehicles", "get_mileage_report", "mileage_settings"]


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


def _ctx(user):
    if user is None:
        return None
    c = MagicMock()
    c.request_context.request.state.user = user
    return c


OWNER = {"id": "u_owner", "name": "Dave Owner", "role": "owner", "status": "active", "scopes": []}
CREW_A = {"id": "u_sam", "name": "Sam", "role": "field_crew", "status": "active", "scopes": []}
CREW_B = {"id": "u_pat", "name": "Pat", "role": "field_crew", "status": "active", "scopes": []}


@pytest.fixture
def env(tmp_path, monkeypatch, mcp_mod):
    import db_mileage_ops as mo
    from db_access import get_connection
    from db_schema import apply_schema
    db = str(tmp_path / "jobs.db")
    conn = get_connection(db)
    apply_schema(conn)
    for uid in ("u_owner", "u_sam", "u_pat"):
        conn.execute("INSERT OR IGNORE INTO users (id) VALUES (?)", (uid,))
    conn.close()
    monkeypatch.setattr(mcp_mod, "_resolve_job_db_path", lambda ctx, fp="": db)
    monkeypatch.setattr(mo, "ROUTER", lambda a, b: round((abs(a[0] - b[0]) + abs(a[1] - b[1])) * 10, 1) if a and b else None)
    monkeypatch.setattr(mo, "GEOCODER", lambda addr: {"HOME": (0.0, 0.0), "Bank": (0.0, 0.5)}.get(addr))
    monkeypatch.setattr(mo, "HOME_RESOLVER", lambda crew: "HOME")
    return db


def _as(monkeypatch, mcp_mod, user):
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
    return _ctx(user)


def test_tools_registered_everywhere(mcp_mod):
    from mcp_tool_catalog import JOBS_APP_TOOLS, TOOL_CATALOG
    src = Path(mcp_mod.__file__).read_text(encoding="utf-8")
    srv = src[src.index("_srv_pa_allowed = {"):]
    srv = srv[:srv.index("}")]
    per = src[src.index("_allowed_tools = {"):]
    per = per[:per.index("}")]
    for t in MILEAGE_TOOLS:
        assert callable(getattr(mcp_mod, t)), t
        assert t in JOBS_APP_TOOLS and t in TOOL_CATALOG, t
        assert f'"{t}"' in srv and f'"{t}"' in per, t


def test_personal_mode_owner_full_access(env, monkeypatch, mcp_mod):
    ctx = _as(monkeypatch, mcp_mod, None)
    r = mcp_mod.add_mileage_trip(to_place="Bank", purpose="Bank – deposit", miles="6", date="2026-10-02", ctx=ctx)
    assert r.startswith("✅"), r
    log = json.loads(mcp_mod.get_mileage_log(start_date="2026-10-01", end_date="2026-10-31", ctx=ctx))
    assert log["is_admin"] and len(log["trips"]) == 1
    assert "Deduction summary" in mcp_mod.get_mileage_report(start_date="2026-10-01", end_date="2026-10-31", ctx=ctx)
    assert "locked" in mcp_mod.mileage_settings(action="lock", period="2026-09", ctx=ctx)


def test_field_crew_sees_and_edits_only_own(env, monkeypatch, mcp_mod):
    ca = _as(monkeypatch, mcp_mod, CREW_A)
    mcp_mod.add_mileage_trip(to_place="Bank", purpose="Bank – deposit for Sam", miles="5", date="2026-10-03", ctx=ca)
    cb = _as(monkeypatch, mcp_mod, CREW_B)
    mcp_mod.add_mileage_trip(to_place="Bank", purpose="Bank – deposit for Pat", miles="7", date="2026-10-03", ctx=cb)
    pat_log = json.loads(mcp_mod.get_mileage_log(start_date="2026-10-01", end_date="2026-10-31", ctx=cb))
    assert [t["purpose"] for t in pat_log["trips"]] == ["Bank – deposit for Pat"]
    assert pat_log["is_admin"] is False
    sam_trip = "TRIP-0001"
    r = mcp_mod.update_mileage_trip(trip_id=sam_trip, reason="x", miles="9", ctx=cb)
    assert "own trips" in r
    co = _as(monkeypatch, mcp_mod, OWNER)
    all_log = json.loads(mcp_mod.get_mileage_log(start_date="2026-10-01", end_date="2026-10-31", ctx=co))
    assert len(all_log["trips"]) == 2


def test_owner_only_actions_refused_for_crew(env, monkeypatch, mcp_mod):
    c = _as(monkeypatch, mcp_mod, CREW_A)
    assert "owner or a manager" in mcp_mod.mileage_settings(action="set_enabled", enabled=False, ctx=c)
    assert "owner or a manager" in mcp_mod.build_mileage_log(start_date="2026-01-01", end_date="2026-10-01", ctx=c)
    assert "own crew-owned" in mcp_mod.manage_vehicles(action="add", vin="1HGCM82633A004352", ownership="business", ctx=c)
    r = mcp_mod.manage_vehicles(action="add", vin="1HGCM82633A004352", ownership="crew", ctx=c)
    assert r.startswith("✅") and "crew-owned" in r


def test_text_entry_confirms_before_saving(env, monkeypatch, mcp_mod):
    ctx = _as(monkeypatch, mcp_mod, None)
    r = mcp_mod.add_mileage_trip(text="Bank deposit at Chase, 6 miles", ctx=ctx)
    assert r.startswith("📝")
    assert json.loads(mcp_mod.get_mileage_log(start_date="2026-01-01", end_date="2099-12-31", ctx=ctx))["trips"] == []
    r = mcp_mod.add_mileage_trip(text="Bank deposit at Chase, 6 miles", confirm=False, ctx=ctx)
    assert r.startswith("✅"), r
    r = mcp_mod.add_mileage_trip(text="drove to the store", ctx=ctx)
    assert r.startswith("❓")


def test_tracking_switch_blocks_new_trips(env, monkeypatch, mcp_mod):
    ctx = _as(monkeypatch, mcp_mod, None)
    mcp_mod.mileage_settings(action="set_enabled", enabled=False, ctx=ctx)
    assert "turned off" in mcp_mod.add_mileage_trip(to_place="Bank", purpose="Bank – deposit", miles="3", ctx=ctx)
    assert json.loads(mcp_mod.mileage_settings(action="get", ctx=ctx))["enabled"] is False
    mcp_mod.mileage_settings(action="set_enabled", enabled=True, ctx=ctx)
    assert mcp_mod.add_mileage_trip(to_place="Bank", purpose="Bank – deposit", miles="3", ctx=ctx).startswith("✅")


def test_clock_out_builds_trips_in_background(env, monkeypatch, mcp_mod):
    from db_access import get_connection
    ctx = _as(monkeypatch, mcp_mod, None)
    conn = get_connection(env)
    conn.execute("INSERT INTO jobs (job_id, customer_name, latitude, longitude, service_type, crew) "
                 "VALUES ('JOB-0001','Norwoods',1.0,0.0,'Window','David')")
    conn.close()
    assert "Clocked IN" in mcp_mod.log_time_entry("JOB-0001", "start", ctx=ctx)
    out = mcp_mod.log_time_entry("JOB-0001", "stop", ctx=ctx)
    assert "Clocked OUT" in out
    for _ in range(50):          # the build runs on a background thread
        log = json.loads(mcp_mod.get_mileage_log(ctx=ctx))
        if log["trips"]:
            break
        time.sleep(0.1)
    labels = [(t["from_label"], t["to_label"]) for t in log["trips"]]
    assert ("Home", "Norwoods") in labels and ("Norwoods", "Home") in labels


def test_gap_fix_tool_and_split(env, monkeypatch, mcp_mod):
    from db_access import get_connection
    ctx = _as(monkeypatch, mcp_mod, None)
    day = "2026-10-05"
    conn = get_connection(env)
    conn.execute("INSERT INTO jobs (job_id, customer_name, latitude, longitude, service_type) "
                 "VALUES ('JOB-0001','A',1.0,0.0,'Window'),('JOB-0002','B',1.0,1.0,'Window')")
    conn.execute("INSERT INTO time_entries (entry_id, job_id, entry_date, clock_in, clock_out) VALUES "
                 "('TE-0001','JOB-0001',?,?,NULL),('TE-0002','JOB-0002',?,?,?)",
                 (day, f"{day} 08:00:00", day, f"{day} 10:00:00", f"{day} 11:00:00"))
    conn.close()
    log = json.loads(mcp_mod.get_mileage_log(start_date=day, end_date=day, ctx=ctx))
    assert any(g["entry_id"] == "TE-0001" for g in log["gaps"])
    r = mcp_mod.fix_mileage_gap("TE-0001", "09:00", "phone died", ctx=ctx)
    assert r.startswith("✅"), r
    log = json.loads(mcp_mod.get_mileage_log(start_date=day, end_date=day, ctx=ctx))
    leg = [t for t in log["trips"] if t["from_label"] == "A" and t["to_label"] == "B"][0]
    r = mcp_mod.update_mileage_trip(trip_id=leg["trip_id"], reason="supplies", action="split",
                                    via_place="Bank", via_purpose="Bank – deposit", ctx=ctx)
    assert r.startswith("✅"), r
    h = mcp_mod.update_mileage_trip(trip_id=leg["trip_id"], reason="view", action="history", ctx=ctx)
    assert "void" in h
