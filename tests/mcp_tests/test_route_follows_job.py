"""The route follows the job (2026-09-25).

The Route page is a place to experiment: move a job to another day, cancel
one, re-route, try again. So:
  * moving a job to another date takes its stop off the old date's route
    (on the edit itself, and again whenever a route is written);
  * a multi-day job keeps its stops on every day inside its date range;
  * cancelling a job takes it off every route, and the route engines and the
    prescreen skip cancelled jobs.
Found live: 5 jobs moved 9/24 -> 9/25 left their stops behind on 9/24.
"""
import json
import sqlite3
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# Relative to today (2026-10-02): these were fixed dates in September, and on
# 2026-10-02 "OLD" (09-24) turned 8 days old — past ROUTE_STOP_STALE_DAYS (7),
# so writing a second route swept OLD's stops away as stale and the multi-day
# test failed on its own. Future dates are never swept.
import datetime as _dt
_BASE = _dt.date.today() + _dt.timedelta(days=7)
OLD, NEW = _BASE.isoformat(), (_BASE + _dt.timedelta(days=1)).isoformat()


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


@pytest.fixture
def env(tmp_path, monkeypatch, mcp_mod):
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(tmp_path / "x.xlsx"))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    return tmp_path / "ai_prowler_jobs.db"


def _job(mcp_mod, name, street, date=OLD, **extra):
    cust = mcp_mod.create_customer({"Company Name": name}, filepath="", backup=False, ctx=None)
    cid = cust.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    fields = {"CustomerID": cid, "Customer Name / Company": name, "Service Date": date,
              "Street Address": street, "City": "New Smyrna Beach", "State": "FL", "ZIP": "32168",
              "Latitude (AI Geocode)": 29.02, "Longitude (AI Geocode)": -80.92}
    fields.update(extra)
    out = mcp_mod.create_job(fields, filepath="", backup=False, ctx=None)
    return out.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _stop(job_id, addr):
    return {"crew": "", "job_id": job_id, "cust_id": None, "address": addr, "lat": 29.02,
            "lon": -80.92, "arrival": "08:00", "leg_drive_min": 5, "leg_drive_miles": 1.0,
            "map_url": None}


def _route(db, date, stops):
    from db_route_ops import db_write_route_stops
    db_write_route_stops(str(db), date, stops, "test", single_crew=True)


def _stops_on(db, date):
    con = sqlite3.connect(str(db))
    try:
        return [r[0] for r in con.execute(
            "SELECT job_id FROM route_stops WHERE route_date = ? ORDER BY stop_number", (date,))]
    finally:
        con.close()


def _edit(mcp_mod, jid, updates):
    return mcp_mod.update_job_spreadsheet(jid, updates, id_column="JobID (JOB-####)",
                                          filepath="", backup=False, ctx=None)


def test_moving_a_job_takes_its_stop_off_the_old_day(env, mcp_mod):
    a = _job(mcp_mod, "Riverside", "300 Riverside Dr")
    b = _job(mcp_mod, "Canal", "500 Canal St")
    _route(env, OLD, [_stop(a, "300 Riverside Dr"), _stop(b, "500 Canal St")])
    assert _stops_on(env, OLD) == [a, b]
    assert _edit(mcp_mod, a, {"Service Date": NEW}).startswith("✅")
    assert _stops_on(env, OLD) == [b]                # a's stale stop is gone; b untouched


def test_routing_the_new_day_also_clears_stale_stops(env, mcp_mod):
    a = _job(mcp_mod, "Riverside", "300 Riverside Dr")
    _route(env, OLD, [_stop(a, "300 Riverside Dr")])
    # date changed behind the edit hook's back (e.g. old data, direct SQL)
    con = sqlite3.connect(str(env)); con.execute("UPDATE jobs SET service_date=? WHERE job_id=?", (NEW, a))
    con.commit(); con.close()
    assert _stops_on(env, OLD) == [a]
    _route(env, NEW, [_stop(a, "300 Riverside Dr")])
    assert _stops_on(env, NEW) == [a] and _stops_on(env, OLD) == []


def test_multi_day_job_keeps_stops_inside_its_range(env, mcp_mod):
    a = _job(mcp_mod, "Condos", "4711 S Atlantic Ave", date=OLD,
             **{"End Date (blank = single-day job)": NEW})
    _route(env, OLD, [_stop(a, "4711 S Atlantic Ave")])
    _route(env, NEW, [_stop(a, "4711 S Atlantic Ave")])
    assert _stops_on(env, OLD) == [a] and _stops_on(env, NEW) == [a]


def test_cancelling_a_job_takes_it_off_the_route(env, mcp_mod):
    a = _job(mcp_mod, "Riverside", "300 Riverside Dr")
    b = _job(mcp_mod, "Canal", "500 Canal St")
    _route(env, OLD, [_stop(a, "300 Riverside Dr"), _stop(b, "500 Canal St")])
    assert _edit(mcp_mod, a, {"Job Status": "Cancelled"}).startswith("✅")
    assert _stops_on(env, OLD) == [b]


def test_route_engines_and_prescreen_skip_cancelled_jobs(env, mcp_mod):
    from db_route_ops import db_get_jobs_for_route
    a = _job(mcp_mod, "Live", "300 Riverside Dr", date=NEW)
    c = _job(mcp_mod, "Gone", "300 Riverside Dr", date=NEW, **{"Job Status": "Cancelled"})
    ids = [j["job_id"] for j in db_get_jobs_for_route(str(env), NEW)]
    assert a in ids and c not in ids
    res = json.loads(mcp_mod.prescreen_route_jobs(NEW, output="json", ctx=None))
    # same address as a live job, but cancelled -> no duplicate-address error
    assert not any(c in i["job_ids"] for i in res["issues"])


def test_job_with_no_service_date_keeps_its_stop(env, mcp_mod):
    # Only a job KNOWN to belong to another day loses its stop; a hand-placed
    # stop for an undated job is left alone.
    a = _job(mcp_mod, "Undated", "300 Riverside Dr", date="")
    _route(env, OLD, [_stop(a, "300 Riverside Dr")])
    assert _stops_on(env, OLD) == [a]


def test_removing_a_stop_replans_the_day_and_refreshes_the_link(env, mcp_mod, monkeypatch):
    # 2026-09-25: 🗑️ used to leave the rest of the day's times and the saved
    # phone link (which still included the removed stop) stale.
    a = _job(mcp_mod, "Riverside", "300 Riverside Dr")
    b = _job(mcp_mod, "Canal", "500 Canal St")
    _route(env, OLD, [_stop(a, "300 Riverside Dr"), _stop(b, "500 Canal St")])
    con = sqlite3.connect(str(env))
    stop_id = con.execute("SELECT id FROM route_stops WHERE job_id = ?", (a,)).fetchone()[0]
    con.close()
    calls = []
    monkeypatch.setattr(mcp_mod, "replan_route_day",
                        lambda d, crew="", filepath="", ctx=None: calls.append((d, crew)) or "✅ re-planned")
    # preview only: nothing deleted, nothing re-planned
    mcp_mod.delete_route_stop(str(stop_id), confirm=False, ctx=None)
    assert _stops_on(env, OLD) == [a, b] and calls == []
    out = mcp_mod.delete_route_stop(str(stop_id), confirm=True, ctx=None)
    assert out.startswith("✅") and "phone link updated" in out
    assert _stops_on(env, OLD) == [b]
    assert calls == [(OLD, "")]                        # re-planned the stop's own day


def test_other_edits_leave_the_route_alone(env, mcp_mod):
    a = _job(mcp_mod, "Riverside", "300 Riverside Dr")
    _route(env, OLD, [_stop(a, "300 Riverside Dr")])
    assert _edit(mcp_mod, a, {"Service Type": "Pressure Wash"}).startswith("✅")
    assert _stops_on(env, OLD) == [a]
