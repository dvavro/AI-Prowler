"""RB-01..RB-04, RB-07, RB-08 (spec §6.5.1).

RB-05 (Run AI Route, safe tier — must be blocked) is covered generically by
test_harness.py's outbound-recorded check; a route-specific one can be added
once RouteScreen grows a run_ai_route() method. RB-06 (Run AI Route, full
tier, real credits) needs the GPS/home-address start-point picker sheet and
is deferred — it's also the one case the spec says to run only before an
AI-Routing release, not on every pass.
"""
import datetime as dt

import pytest
from playwright.sync_api import expect

from safety import SANDBOX_DATE

PLACES_4 = ["city_hall", "brannon", "library", "flagler"]
NEXT_DAY = (dt.date.fromisoformat(SANDBOX_DATE) + dt.timedelta(days=1)).isoformat()


@pytest.fixture
def four_jobs(clean_slate, data):
    """RB-01/03/04/08: 4 ordinary ZTEST jobs on the sandbox date, no route yet."""
    return [data.job(f"RB {i}", place) for i, place in enumerate(PLACES_4, start=1)]


def test_RB_01_unrouted_jobs_show_amber_banner(route, four_jobs):
    route.pick_date(SANDBOX_DATE)
    route.expect_not_routed_banner(job_count=len(four_jobs))
    assert sorted(s.job_id() for s in route.unrouted_jobs()) == sorted(four_jobs)


def test_RB_02_day_whose_only_job_is_cancelled_drops_out(route, clean_slate, data, api, page):
    """Rewritten 2026-09-26 for R-036: a day with no live job is no longer
    offered at all, so the old trick (create a job, cancel it, pick the day) to
    reach the "No jobs on this date" state doesn't exist any more. What a person
    CAN do: have the day on screen, cancel its only job elsewhere, tap ↻ — the
    day must drop out of the list and the cancelled job must not be shown."""
    jid = data.job("RB02 solo", "city_hall")
    route.pick_date(SANDBOX_DATE)
    route.expect_not_routed_banner(job_count=1)
    assert [s.job_id() for s in route.unrouted_jobs()] == [jid]
    api.call("update_job_spreadsheet", {"job_identifier": jid, "sheet_name": "Jobs_Schedule",
                                         "id_column": "JobID (JOB-####)", "updates": {"Job Status": "Cancelled"}})
    page.evaluate("async () => { await loadJobs(); }")
    route.refresh()
    expect(page.locator(f"#routeDatePicker option[value='{SANDBOX_DATE}']")).to_have_count(0)
    assert jid not in [s.job_id() for s in route.stops() + route.unrouted_jobs()]
    if page.locator("#routeDatePicker option").count() == 1 and \
            page.locator("#routeDatePicker").input_value() == "":
        route.expect_no_route_no_jobs()          # nothing scheduled anywhere → the empty state


def test_RB_03_route_selected_date_builds_clean(route, four_jobs, api):
    route.pick_date(SANDBOX_DATE)
    route.press_route_selected_date()
    route.expect_prescreen(errors=0, warnings=0)
    route.expect_stops_include(four_jobs)
    stops = api.read("Route_Planner")
    assert any(s.get("JobID (JOB-####)") in four_jobs for s in stops), "no route_stops row for the built jobs"


def test_RB_04_route_header_count_excludes_cancelled(route, four_jobs, api):
    api.call("update_job_spreadsheet", {"job_identifier": four_jobs[0], "sheet_name": "Jobs_Schedule",
                                         "id_column": "JobID (JOB-####)", "updates": {"Job Status": "Cancelled"}})
    route.pick_date(SANDBOX_DATE)
    # 3 non-cancelled remain; the banner's own count is the header-count proxy
    # here (there's no separate numeric header on this screen — see §6.5.1
    # RB-04's own "N jobs" wording, which this banner text carries).
    route.expect_not_routed_banner(job_count=3)
    assert len(route.unrouted_jobs()) == 3


def test_RB_07_changing_date_clears_prior_route_and_warnings(route, four_jobs, data, api):
    route.pick_date(SANDBOX_DATE)
    route.press_route_selected_date()
    route.expect_prescreen(errors=0, warnings=0)
    # A second date with one job that isn't routed yet (rewritten 2026-09-26 for
    # R-036: a day with only a cancelled job is no longer offered at all).
    other_date = NEXT_DAY
    jid = data.job("RB07 other day", "city_hall", date=other_date)
    route.pick_date(other_date)
    route.expect_no_prescreen()                     # the first day's prescreen is gone
    assert route.stops() == [], "the first day's route is still shown"
    route.expect_not_routed_banner(job_count=1)
    assert [s.job_id() for s in route.unrouted_jobs()] == [jid]


def test_RB_08_reroute_after_manual_change_replaces_order(route, four_jobs, api):
    route.pick_date(SANDBOX_DATE)
    route.press_route_selected_date()
    route.expect_stops_include(four_jobs)
    # Track the stop by its JobID, not its route-row ID: every move re-plans the
    # day and rewrites the route rows with NEW row IDs (so the old stop ID no
    # longer exists even when the move worked — RB-08's failure on 2026-09-25).
    first_job = route.stop(1).job_id()
    # Move stop 1 down manually, confirm it moved …
    route.stop(1).move_down()
    route.pick_date(SANDBOX_DATE)  # refresh
    assert route.stop(2).job_id() == first_job, "manual move didn't take"
    # … then re-route: spec says this is a fresh build (documented behavior,
    # not asserting a specific resulting order — just that it still succeeds
    # and still contains every job).
    route.press_route_selected_date()
    route.expect_stops_include(four_jobs)
