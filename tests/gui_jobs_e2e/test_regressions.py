"""Regression catalog (spec §9) — every bug found so far keeps a guard.

Where a bug is already guarded by a specific test, it's listed here and not
duplicated. The tests in THIS file cover the ones the browser suite didn't
reach yet.

  R-001 same address back-to-back in the phone link .... PL-04, PS-09  (test_route_approve_link / test_route_prescreen)
  R-002 1730 vs 1755 SR 44 false "same address" ........ PS-03
  R-003 moved jobs: "5 jobs" but "No route" ............. RB-01
  R-004 moved job left its stop on the old day .......... test_R_004 (below)
  R-005 jobs added after routing invisible ............... RE-09
  R-006 cancelled jobs were still routed ................ test_R_006 (below) + RB-04
  R-007 🗑️ didn't re-plan or refresh the link ........... RE-08, PL-07
  R-008 no street address could be routed .............. PS-04
  R-009 cleanup deleted stops of undated jobs ........... server test tests/mcp_tests/test_route_follows_job.py
  R-010..R-012 price-list uniqueness / lookup / numbers .. server tests tests/mcp_tests/test_live_findings_2026_09_25.py
                                                           (UI version: spec §6.12, Phase 3)
  R-013 orphaned "Home" rows when every job leaves ....... test_R_013 (below) + server tests
  R-014 misleading "re-planned" on last stop removed .... server test tests/mcp_tests/test_live_findings_2026_09_25.py
  R-015 write-guard bypass through the service worker .. harness bypass alarm (conftest.py page fixture) —
                                                           fails ANY test in which that happens

Run: run_tests_gui_jobs_e2e.bat --human -k regressions
"""
from playwright.sync_api import expect

from safety import SANDBOX_DATE, sandbox_day


def _route_today(route, data, specs):
    ids = [data.job(label, place) for label, place in specs]
    route.pick_date(SANDBOX_DATE)
    route.press_route_selected_date(accept_errors=True)
    route.wait_quiet()
    return ids


def _stop_ids_on_screen(route):
    return [s.job_id() for s in route.stops()]


def test_R_004_moving_a_routed_job_takes_its_stop_off_the_old_day(clean_slate, route, api, data):
    ids = _route_today(route, data, [("R004 stays", "city_hall"), ("R004 moves", "brannon")])
    assert set(ids) <= set(_stop_ids_on_screen(route))
    moved = ids[1]
    api.call("update_job_spreadsheet", {"job_identifier": moved, "id_column": "JobID (JOB-####)",
                                        "updates": {"Service Date": sandbox_day(1)}})
    route.page.evaluate("async () => { await loadRoute(); }")
    route.wait_quiet()
    on_screen = _stop_ids_on_screen(route)
    assert moved not in on_screen, f"{moved} moved to {sandbox_day(1)} but is still a stop today: {on_screen}"
    assert ids[0] in on_screen, "the job that stayed should still be a stop"


def test_R_006_a_cancelled_job_is_never_routed(clean_slate, route, api, data):
    ids = [data.job("R006 live", "city_hall"), data.job("R006 cancelled", "brannon")]
    api.call("update_job_spreadsheet", {"job_identifier": ids[1], "id_column": "JobID (JOB-####)",
                                        "updates": {"Job Status": "Cancelled"}})
    route.pick_date(SANDBOX_DATE)
    route.press_route_selected_date(accept_errors=True)
    route.wait_quiet()
    on_screen = _stop_ids_on_screen(route)
    assert ids[0] in on_screen and ids[1] not in on_screen, f"stops: {on_screen}"


def test_R_013_cancelling_every_job_leaves_no_route_rows(clean_slate, route, api, data):
    from api import iso_date
    ids = _route_today(route, data, [("R013 A", "city_hall"), ("R013 B", "brannon")])
    for jid in ids:
        api.call("update_job_spreadsheet", {"job_identifier": jid, "id_column": "JobID (JOB-####)",
                                            "updates": {"Job Status": "Cancelled"}})
    left = [s for s in api.read("Route_Planner") if iso_date(s.get("Route Date", "")) == SANDBOX_DATE]
    assert left == [], f"route rows left on {SANDBOX_DATE} after every job was cancelled: {left}"
    route.page.evaluate("async () => { await loadRoute(); }")
    route.wait_quiet()
    expect(route.page.locator("[data-testid='route-stop']")).to_have_count(0)
