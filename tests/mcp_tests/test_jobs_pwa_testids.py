"""The Jobs-app Playwright E2E suite (tests/gui_jobs_e2e, spec
tests/JOBS_APP_E2E_TEST_SPEC.md §5.2) finds controls by these data-testid
attributes and stable ids. This offline check runs with the normal suite so an
unrelated edit to jobs/index.html can't silently break the E2E tests.

If you intentionally rename/remove one, update the E2E page objects
(tests/gui_jobs_e2e/app.py) and this list together.
"""
from pathlib import Path

import pytest

HTML = (Path(__file__).resolve().parent.parent.parent / "jobs" / "index.html").read_text(encoding="utf-8")

# data-testid -> how many times it must appear in the source (templates count once)
TESTIDS = {
    "auth-unlock": 1, "auth-eye": 1, "profile-signout": 1, "route-help-toggle": 1,
    "prescreen-recheck": 1, "prescreen-close": 1, "prescreen-item": 1, "prescreen-fix": 1,
    "route-stop": 1, "stop-up": 1, "stop-down": 1, "stop-edit": 1, "stop-remove": 1, "stop-drag": 1,
    "unrouted-job": 1, "unrouted-edit": 1, "not-routed-banner": 1, "not-on-route-banner": 1,
    "job-card": 1,
    "nav-jobs": 1, "nav-board": 1, "nav-route": 1, "nav-calendar": 1, "nav-clock": 1,
    "nav-photos": 1, "nav-messages": 1, "nav-sheet": 1, "nav-reports": 1, "nav-profile": 1,
}

# Existing stable ids the E2E suite also relies on (spec §5.2 priority 1)
IDS = [
    "authScreen", "authCode", "authError", "app",
    "screen-jobs", "screen-board", "screen-route", "screen-calendar", "screen-clock",
    "screen-photos", "screen-messages", "screen-reports", "screen-profile",
    "routeDatePicker", "routeMap", "routePrescreen", "routeWarnings", "routeStopsList",
    "routeTodayBtnRoute", "routeAiSuggestBtn", "routeEmailRouteBtn",
    "routeApproveBtn", "routeUnapproveBtn",
    "routeTodayBtn", "jobsAiRouteBtn", "jobsEmailRouteBtn", "jobsPrescreen", "jobsRouteStatus",
]


@pytest.mark.parametrize("testid,count", sorted(TESTIDS.items()))
def test_e2e_testid_present(testid, count):
    assert HTML.count(f'data-testid="{testid}"') == count, (
        f'data-testid="{testid}" must appear {count}x in jobs/index.html — the Playwright E2E suite uses it')


@pytest.mark.parametrize("elem_id", IDS)
def test_e2e_stable_id_present(elem_id):
    assert f'id="{elem_id}"' in HTML, f'id="{elem_id}" is used by the Playwright E2E suite'


def test_row_attributes_the_e2e_suite_reads():
    # rows are located by these, and the route drag code relies on data-stopid
    assert "data-stopid=" in HTML and "data-jobid=" in HTML and "data-idx=" in HTML
    assert "querySelectorAll('.route-stop[data-stopid]')" in HTML
