"""
R-056 (2026-09-28, David): a job may be assigned to SEVERAL people, picked from
a list of the team's users (no typing, so names can't be misspelled). When a
shared job's people each route their own day, the job is on EACH person's
route — for any role. People self-serve their routes.

  * db_route_ops: the crew filter is a case-insensitive membership test on the
    job's comma list ("Samual Cronin, Vicki Vavro"); a matched job is routed
    under the routing person's own (route_date, crew_id); a blank-crew server
    build expands a shared job to one copy per person; a stop that still reads
    "A, B" is written to both people's routes, never to an "A, B" route.
  * approve / unapprove / prescreen follow the same membership rule.
  * list_team_members: names + roles of active users only (never tokens,
    emails, phones); server mode only; in the Jobs app allow-list, the tool
    catalog and the E2E guard's READ set.
  * jobs/index.html: the Crew / Technician picker, and membership matching on
    the Route tab.

Run: run_tests.bat tests\\mcp\\test_r056_shared_jobs_and_team_picker.py -v
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest
import requests

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from db_access import init_db                                  # noqa: E402
from db_write_ops import db_create_customer, db_create_job     # noqa: E402
import db_route_ops as ro                                      # noqa: E402
import db_write_ops as write_ops                               # noqa: E402

VICKI, SAM, DAVID = "Vicki Vavro", "Samual Cronin", "David Vavro"
SHARED = f"{SAM}, {VICKI}"
DAY = "2026-09-29"


@pytest.fixture
def db(tmp_path):
    p = str(tmp_path / "jobs.db")
    init_db(p)
    return p


@pytest.fixture(autouse=True)
def _no_home(monkeypatch):
    monkeypatch.setattr(write_ops, "db_read_owner_home_address", lambda: "")


class _Resp:
    def __init__(self, d):
        self._d = d

    def json(self):
        return self._d


@pytest.fixture
def osrm(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda url, *a, **k: _Resp(
        {"code": "Ok", "routes": [{"legs": [{"duration": 600}], "distance": 1000, "duration": 600}]}))


def _job(db, crew, street="1 Main St", lat=29.0, lon=-80.9, customer=None, start="", orig=""):
    customer = customer or f"Cust {crew} {street}"
    cust = db_create_customer(db, {"Company Name": customer}, actor="dave")
    cid = cust.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    fields = {
        "CustomerID (Customers!A)": cid, "Customer Name / Company": customer,
        "Service Date": DAY, "Street Address": street, "City": "New Smyrna Beach", "State": "FL",
        "Crew / Technician": crew, "Est. Duration": 60, "Est. Duration Unit": "min",
    }
    if lat is not None:
        fields["Latitude (AI Geocode)"] = lat
        fields["Longitude (AI Geocode)"] = lon
    if start:
        fields["Start Time"] = start
    r = db_create_job(db, fields, actor="dave")
    jid = r.split("NEW_JOB_ID=")[1].splitlines()[0].strip()
    if orig:
        c = sqlite3.connect(db)
        c.execute("UPDATE jobs SET original_start_time = ? WHERE job_id = ?", (orig, jid))
        c.commit()
        c.close()
    return jid


def _job_row(db, jid):
    c = sqlite3.connect(db)
    c.row_factory = sqlite3.Row
    r = dict(c.execute("SELECT * FROM jobs WHERE job_id = ?", (jid,)).fetchone())
    c.close()
    return r


def _stops(db, crew_id):
    c = sqlite3.connect(db)
    c.row_factory = sqlite3.Row
    rows = c.execute("SELECT * FROM route_stops WHERE route_date = ? AND crew_id = ? ORDER BY stop_number",
                     (DAY, crew_id)).fetchall()
    c.close()
    return [dict(r) for r in rows]


def _crew_ids(db):
    c = sqlite3.connect(db)
    ids = {r[0] for r in c.execute("SELECT DISTINCT crew_id FROM route_stops WHERE route_date = ?", (DAY,))}
    c.close()
    return ids


# ── helpers ──────────────────────────────────────────────────────────────────
def test_crew_names_and_match():
    assert ro._crew_names(" Samual Cronin ,Vicki Vavro,, ") == [SAM, VICKI]
    assert ro._crew_names("") == [] and ro._crew_names(None) == []
    assert ro._crew_match(SHARED, "vicki vavro") == VICKI
    assert ro._crew_match(SHARED, "Vicki") == ""          # whole names only
    assert ro._crew_match(SHARED, "") == ""


# ── which jobs are on whose route ────────────────────────────────────────────
def test_shared_job_is_on_each_persons_route(db):
    shared = _job(db, SHARED, "10 Flagler Ave")
    own_v = _job(db, VICKI, "20 Canal St")
    own_s = _job(db, SAM, "30 Third Ave")
    v = ro.db_get_jobs_for_route(db, DAY, VICKI)
    s = ro.db_get_jobs_for_route(db, DAY, SAM)
    assert {j["job_id"] for j in v} == {shared, own_v}
    assert {j["job_id"] for j in s} == {shared, own_s}
    assert ro.db_get_jobs_for_route(db, DAY, DAVID) == []
    # routed under the ROUTING person; the full assignment is kept alongside
    sv = [j for j in v if j["job_id"] == shared][0]
    assert sv["crew"] == VICKI and sv["job_crew"] == SHARED


def test_crew_match_ignores_case(db):
    jid = _job(db, SHARED)
    assert [j["job_id"] for j in ro.db_get_jobs_for_route(db, DAY, "VICKI VAVRO")] == [jid]


def test_blank_crew_expands_only_when_asked(db):
    jid = _job(db, SHARED)
    once = ro.db_get_jobs_for_route(db, DAY, "")
    assert len(once) == 1 and once[0]["crew"] == SHARED           # personal mode: one route
    both = ro.db_get_jobs_for_route(db, DAY, "", expand_multi=True)
    assert sorted(j["crew"] for j in both) == sorted([SAM, VICKI])
    assert {j["job_id"] for j in both} == {jid}


def _stop(db, jid, crew, arrival="09:00"):
    return {"crew": crew, "job_id": jid, "cust_id": _job_row(db, jid)["customer_id"],
            "address": "a", "lat": 1, "lon": 1, "arrival": arrival}


def test_write_never_creates_a_combined_route(db):
    jid = _job(db, SHARED)
    ro.db_write_route_stops(db, DAY, [_stop(db, jid, SHARED)], actor="t")
    assert _crew_ids(db) == {SAM, VICKI}
    assert [s["job_id"] for s in _stops(db, VICKI)] == [jid]
    assert [s["job_id"] for s in _stops(db, SAM)] == [jid]


def test_personal_mode_write_still_one_route(db):
    jid = _job(db, SHARED)
    ro.db_write_route_stops(db, DAY, [_stop(db, jid, SHARED)], actor="t", single_crew=True)
    assert _crew_ids(db) == {""}


# ── the route engines ────────────────────────────────────────────────────────
def test_each_person_self_routes_the_shared_job(db, osrm):
    shared = _job(db, SHARED, "10 Flagler Ave", 29.02, -80.92)
    own_v = _job(db, VICKI, "20 Canal St", 29.03, -80.93)
    own_s = _job(db, SAM, "30 Third Ave", 29.04, -80.94)
    ro.db_suggest_route_schedule(db, DAY, VICKI, actor=VICKI)
    v = {s["job_id"] for s in _stops(db, VICKI)}
    ro.db_suggest_route_schedule(db, DAY, SAM, actor=SAM)
    s = {s["job_id"] for s in _stops(db, SAM)}
    assert shared in v and own_v in v and own_s not in v
    assert shared in s and own_s in s and own_v not in s
    # Samual's build didn't disturb Vicki's route
    assert {x["job_id"] for x in _stops(db, VICKI)} == v
    assert SHARED not in _crew_ids(db)


def test_blank_server_build_puts_shared_job_on_both_routes(db, osrm):
    shared = _job(db, SHARED, "10 Flagler Ave", 29.02, -80.92)
    ro.db_suggest_route_schedule(db, DAY, "", actor="owner")
    assert shared in {s["job_id"] for s in _stops(db, VICKI)}
    assert shared in {s["job_id"] for s in _stops(db, SAM)}
    assert SHARED not in _crew_ids(db)


def test_approve_matches_route_name_case_insensitively(db):
    jid = _job(db, VICKI, "20 Canal St", start="08:00")
    ro.db_write_route_stops(db, DAY, [_stop(db, jid, VICKI, "10:15")], actor="t")
    out = ro.db_approve_route_schedule(db, DAY, "vicki vavro", actor="t")
    assert "Approved 1 job" in out
    assert _job_row(db, jid)["start_time"] == "10:15"


def test_unapprove_reaches_shared_job(db):
    jid = _job(db, SHARED, "10 Flagler Ave", start="10:15", orig="08:00")
    ro.db_unapprove_route_schedule(db, DAY, VICKI, actor="t")
    assert _job_row(db, jid)["start_time"] == "08:00"


def test_prescreen_checks_shared_job_on_each_route(db):
    shared = _job(db, SHARED, "10 Flagler Ave", lat=None)      # not geocoded -> an error
    for crew in (VICKI, SAM):
        issues = ro.db_prescreen_route_jobs(db, DAY, crew)
        hit = [i for i in issues if i["code"] == "NOT_GEOCODED"]
        assert hit and hit[0]["job_ids"] == [shared] and hit[0]["crew"] == crew


def test_prescreen_blank_groups_duplicates_per_person(db):
    a = _job(db, SHARED, "10 Flagler Ave", customer="Same Place")
    b = _job(db, VICKI, "10 Flagler Ave", customer="Same Place")
    issues = ro.db_prescreen_route_jobs(db, DAY, "")
    dups = [i for i in issues if i["code"] == "DUPLICATE_ADDRESS"]
    # the shared job and Vicki's own job collide on VICKI's route only
    assert [d["crew"] for d in dups] == [VICKI] and set(dups[0]["job_ids"]) == {a, b}


# ── list_team_members ────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


USERS = {"users": {
    "tok-a": {"name": DAVID, "role": "owner", "status": "active", "email": "d@x.com", "phone": "1"},
    "tok-b": {"name": VICKI, "role": "manager", "email": "v@x.com"},
    "tok-c": {"name": SAM, "role": "field_crew", "status": "active", "email": "s@x.com"},
    "tok-d": {"name": "Gone Person", "role": "field_crew", "status": "revoked"},
    "tok-e": {"name": "vicki vavro", "role": "staff"},            # same person twice -> once
    "tok-f": {"name": "Bad, Name", "role": "staff"},              # comma would break the list
}}


def test_list_team_members_names_and_roles_only(mcp_mod, monkeypatch):
    monkeypatch.setattr(mcp_mod, "_IS_SERVER_MODE", True)
    monkeypatch.setattr(mcp_mod, "_load_users", lambda: USERS)
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: {"name": SAM, "role": "field_crew"})
    out = mcp_mod.list_team_members(ctx=None)
    assert json.loads(out)["members"] == [
        {"name": DAVID, "role": "owner"},
        {"name": SAM, "role": "field_crew"},
        {"name": VICKI, "role": "manager"},
    ]
    for secret in ("tok-", "@x.com", "phone", "Gone Person", "Bad, Name"):
        assert secret not in out


def test_list_team_members_personal_mode_empty(mcp_mod, monkeypatch):
    monkeypatch.setattr(mcp_mod, "_IS_SERVER_MODE", False)
    monkeypatch.setattr(mcp_mod, "_load_users", lambda: USERS)
    assert json.loads(mcp_mod.list_team_members(ctx=None)) == {"members": []}


def test_list_team_members_wired_everywhere():
    src = (_SRC / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    i = src.index("_srv_pa_allowed = {")
    assert '"list_team_members"' in src[i:src.index("}", i)]
    import mcp_tool_catalog as cat
    assert "list_team_members" in cat.JOBS_APP_TOOLS and "list_team_members" in cat.TOOL_CATALOG
    safety = (_SRC / "tests" / "gui_jobs_e2e" / "safety.py").read_text(encoding="utf-8")
    j = safety.index("READ = {")
    assert '"list_team_members"' in safety[j:safety.index("}", j)]


# ── the Jobs app ─────────────────────────────────────────────────────────────
@pytest.fixture(scope="module")
def html():
    return (_SRC / "jobs" / "index.html").read_text(encoding="utf-8")


def test_app_has_crew_picker_on_both_forms(html):
    assert 'id="jfCrewPicker"' in html and "mcpCall('list_team_members'" in html
    assert html.count("_renderCrewPicker();") >= 2        # edit form + add form
    i = html.index("async function _renderCrewPicker()")
    body = html[i:i + 2500]
    assert "state.serverMode" in body and "not a current user" in body
    assert "names.join(', ')" in html                      # saved as "A, B"


def test_app_route_tab_uses_membership(html):
    assert "function _crewHas(cell, name)" in html
    i = html.index("var _ownDefault = _routeOwnDefaultName();")
    seg = html[i:i + 1200]
    assert "_crewHas(s['Crew / Technician'], crew)" in seg
    assert "_crewHas(s['Crew / Technician'], _ownDefault)" in seg
    assert "_crewHas(j['Crew / Technician'], _who)" in html
    # the person list splits shared jobs into one option per person
    assert "_crewNames(r['Crew / Technician']).forEach" in html
