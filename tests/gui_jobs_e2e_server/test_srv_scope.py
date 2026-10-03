"""Server mode — field crew can't touch another crew's job or route stop
(spec §6.11.5 SRV-SCOPE-03, SRV-SCOPE-11).

U3 Samual (field_crew) works through his OWN session (direct /pwa-api calls,
still through the write guard — every target is ZTEST data on the sandbox
date). Test jobs (owner-made): J-A with Crew = Samual, J-B with Crew = Vicki,
both routed by the owner on the sandbox date. Whatever Samual tries on J-B,
the owner's read-back of J-B and of Vicki's route stop must be unchanged.

SRV-SCOPE-11 (G-05): log_time_entry's crew check is advisory in the code
("Crew / Technician is scheduling reference, not access control"). The spec
expects a refusal; whether a crew member may clock in on a co-worker's job
(helping out) is David's call — marked xfail(strict) until he decides.

Run: run_tests_gui_jobs_e2e.bat --server --human -k test_srv_scope
"""
import logging

import pytest

from api import parse_records
from safety import SANDBOX_DATE

log = logging.getLogger("e2e_srv")

CREW = "Samual Cronin"
OTHER = "Vicki Vavro"


def _refused(text: str) -> bool:
    t = str(text).lstrip()
    return t.startswith(("❌", "⛔")) or ('"error"' in t and "access" in t.lower())


def _stop_for(owner_api, jid):
    """Route_Planner row(s) for this job on the sandbox date, as the owner sees them."""
    rows = parse_records(owner_api.call("read_job_spreadsheet",
                                        {"sheet_name": "Route_Planner", "max_rows": 1000}, expect_ok=False))
    return [r for r in rows if jid in r.values()]


def _job(owner_api, jid):
    rows = parse_records(owner_api.call("read_job_spreadsheet",
                                        {"sheet_name": "Jobs_Schedule", "max_rows": 1000}, expect_ok=False))
    return [r for r in rows if r.get("JobID (JOB-####)") == jid]


@pytest.fixture
def routed_jobs(clean_slate, data, owner_api):
    mine = data.job("SCOPE mine", **{"Crew / Technician": CREW, "Est. Duration": 30, "Est. Duration Unit": "min"})
    theirs = data.job("SCOPE theirs", "brannon", **{"Crew / Technician": OTHER,
                                                    "Est. Duration": 30, "Est. Duration Unit": "min"})
    for crew in (CREW, OTHER):
        out = owner_api.call("build_daily_route", {"route_date": SANDBOX_DATE, "crew": crew, "email_link": False})
        assert not _refused(out), f"owner couldn't build {crew}'s route: {out[:200]!r}"
    stops = _stop_for(owner_api, theirs)
    assert len(stops) == 1, f"expected one route stop for Vicki's job {theirs}, found {len(stops)}"
    return {"mine": mine, "theirs": theirs, "their_stop": stops[0]}


# ── SRV-SCOPE-03: delete / un-route / reorder / re-plan another crew's work ──
ACTIONS = {
    "delete_job":         lambda j: ("delete_job", {"job_identifier": j["theirs"], "confirm": True}),
    "delete_route_stop":  lambda j: ("delete_route_stop", {"stop_id": j["their_stop"]["ID"], "confirm": True}),
    "reorder_route_stop": lambda j: ("reorder_route_stop", {"stop_id": j["their_stop"]["ID"], "new_position": 1}),
    "delete_route":       lambda j: ("delete_route", {"route_date": SANDBOX_DATE, "crew": OTHER, "confirm": True}),
    "replan_route_day":   lambda j: ("replan_route_day", {"route_date": SANDBOX_DATE, "crew": OTHER}),
}


@pytest.mark.parametrize("action", list(ACTIONS))
def test_SRV_SCOPE_03_crew_cannot_change_another_crews_job_or_stop(routed_jobs, owner_api, api_as, action):
    job_before = _job(owner_api, routed_jobs["theirs"])
    stop_before = _stop_for(owner_api, routed_jobs["theirs"])
    mine_before = _stop_for(owner_api, routed_jobs["mine"])
    tool, args = ACTIONS[action](routed_jobs)

    out = api_as("U3").call(tool, args, expect_ok=False)
    log.info(f"[SRV-SCOPE-03 {action}] Samual -> {str(out).splitlines()[0][:160] if out else '(empty)'}")

    # the part that matters: nothing of Vicki's changed …
    assert _job(owner_api, routed_jobs["theirs"]) == job_before, f"{action}: Vicki's job changed"
    assert _stop_for(owner_api, routed_jobs["theirs"]) == stop_before, f"{action}: Vicki's route stop changed"
    # … Samual's own route wasn't hit instead (a crew-name mix-up would do that) …
    assert _stop_for(owner_api, routed_jobs["mine"]) == mine_before, \
        f"{action}: asked about Vicki's route, but Samual's own route changed"
    # … and he was told no, rather than a success message
    assert _refused(out), f"{action}: not refused — reply: {str(out)[:200]!r}"


# ── SRV-SCOPE-11 (G-05): clock in on another crew's job ─────────────────────
# David's decision 2026-09-27: ALLOWED — a crew member helping on a
# co-worker's job logs their own time on it. What must hold: the entry is
# recorded under the person who clocked in, never under the job's crew.
def test_SRV_SCOPE_11_crew_may_clock_in_on_coworkers_job_under_own_name(routed_jobs, api_as, owner_api):
    sam = api_as("U3")
    out = sam.call("log_time_entry", {"job_identifier": routed_jobs["theirs"], "action": "start"},
                   expect_ok=False)
    log.info(f"[SRV-SCOPE-11] Samual clock-in on Vicki's job -> {str(out).splitlines()[0][:160]}")
    try:
        assert not _refused(out), f"G-05 (allowed by David): clock-in on a co-worker's job refused: {out[:200]!r}"
        rows = [r for r in parse_records(owner_api.call("read_job_spreadsheet",
                                                        {"sheet_name": "TimeLog", "max_rows": 1000},
                                                        expect_ok=False))
                if routed_jobs["theirs"] in r.values()]
        assert rows, "no TimeLog entry for the clock-in"
        assert any(CREW in r.values() for r in rows), f"entry isn't under Samual's name: {rows[-1]}"
    finally:
        sam.call("log_time_entry", {"job_identifier": routed_jobs["theirs"], "action": "stop"}, expect_ok=False)


def test_SRV_SCOPE_11_control_crew_can_clock_in_on_own_job(routed_jobs, api_as):
    sam = api_as("U3")
    out = sam.call("log_time_entry", {"job_identifier": routed_jobs["mine"], "action": "start"}, expect_ok=False)
    try:
        assert not _refused(out), f"Samual can't clock in on his own job: {str(out)[:200]!r}"
    finally:
        sam.call("log_time_entry", {"job_identifier": routed_jobs["mine"], "action": "stop"}, expect_ok=False)


# ── SRV-SCOPE-14: same address on two crews' jobs ────────────────────────────
def _prescreen(owner_api, crew=""):
    import json
    out = owner_api.call("prescreen_route_jobs", {"route_date": SANDBOX_DATE, "crew": crew, "output": "json"},
                         expect_ok=False)
    d = json.loads(out)
    assert d.get("ok"), f"prescreen failed: {out[:200]!r}"
    return d["issues"]


# Since R-055 (David 2026-09-28, every role): a blank crew means "MY OWN jobs",
# the owner included — so these checks name the crew they're about.
def test_SRV_SCOPE_14_same_address_on_two_crews_is_not_a_duplicate(clean_slate, data, owner_api):
    a = data.job("DUP crewA", "city_hall", **{"Crew / Technician": CREW})
    b = data.job("DUP crewB", "city_hall", **{"Crew / Technician": OTHER})
    dups = [i for crew in (CREW, OTHER) for i in _prescreen(owner_api, crew)
            if i["code"] == "DUPLICATE_ADDRESS" and {a, b} <= set(i["job_ids"])]
    log.info(f"[SRV-SCOPE-14] duplicate-address issues for the two-crew pair: {dups}")
    assert not dups, ("same address on two DIFFERENT crews' jobs was flagged as a duplicate — they're "
                      f"on separate routes, so it can't break a map link: {dups}")


def test_SRV_SCOPE_14_control_same_address_same_crew_is_flagged(clean_slate, data, owner_api):
    """Proves the check above isn't passing because the duplicate check is broken."""
    a = data.job("DUP same1", "city_hall", **{"Crew / Technician": CREW})
    b = data.job("DUP same2", "city_hall", **{"Crew / Technician": CREW})
    dups = [i for i in _prescreen(owner_api, CREW) if i["code"] == "DUPLICATE_ADDRESS" and {a, b} <= set(i["job_ids"])]
    assert dups, "two jobs at the same address on ONE crew's route weren't flagged"
    assert dups[0].get("crew", CREW) not in ("", "(unassigned)"), f"duplicate reported without its crew: {dups[0]}"


# ── SRV-SCOPE-15: the owner plans each crew's day (R-055: by naming the crew) ─
def test_SRV_SCOPE_15_owner_routes_every_crew_separately(clean_slate, data, owner_api):
    a = data.job("ALL crewA", "city_hall", **{"Crew / Technician": CREW,
                                              "Est. Duration": 30, "Est. Duration Unit": "min"})
    b = data.job("ALL crewB", "brannon", **{"Crew / Technician": OTHER,
                                            "Est. Duration": 30, "Est. Duration Unit": "min"})
    for crew in (CREW, OTHER):
        out = owner_api.call("build_daily_route", {"route_date": SANDBOX_DATE, "crew": crew, "email_link": False})
        log.info(f"[SRV-SCOPE-15] owner builds {crew}'s route -> {str(out).splitlines()[0][:160]}")
        assert not _refused(out), f"owner couldn't route {crew}: {out[:200]!r}"
    for jid, crew in ((a, CREW), (b, OTHER)):
        stops = _stop_for(owner_api, jid)
        assert len(stops) == 1, f"{jid} ({crew}): expected one route stop, found {len(stops)}"
        crew_cells = [v for k, v in stops[0].items() if "crew" in k.lower()]
        assert crew in crew_cells, f"{jid}'s stop isn't on {crew}'s route: {stops[0]}"
    # each crew's prescreen reports its own issues under that crew (never "(unassigned)")
    unassigned = [i for crew in (CREW, OTHER) for i in _prescreen(owner_api, crew)
                  if i.get("crew") == "(unassigned)" and ({a, b} & set(i["job_ids"]))]
    assert not unassigned, f"issues for crewed jobs reported as unassigned: {unassigned}"
