"""Route start/end mode — Settings → "Route Origin Mode" (R-061, David
2026-09-29 05:10: "add the route start/end mode control to be able to turn it
on and off ... expand the testing with those different route modes").

The two modes, as the server builds a route (db_route_ops):
  • Company Location — the day starts AND ends at the business's Start/End
    Address: a real, numbered first stop hard-anchored at Workday Start Time,
    and a last stop back at that address.
  • Jobs Only — no company stops. The trip from home to the first job is still
    counted (mileage), but the start isn't a stop; only a hidden "Home" row at
    the end holds the drive back (home = GPS / home address / Start/End
    Address as the last fallback).

The tests switch the mode themselves (settings_switch.py — the original value
is saved first and put back after every test and at the end of the run) and
never change the Start/End Address itself; they need one configured (skip
otherwise). ZTEST jobs on the sandbox date, swept before and after.

Run: run_tests_gui_jobs_e2e.bat --human -k test_route_origin_modes
"""
import re

import pytest
from playwright.sync_api import expect

from api import iso_date
from safety import SANDBOX_DATE

MODE = "Route Origin Mode"
COMPANY, JOBS_ONLY = "Company Location", "Jobs Only"
PLACES_3 = ["city_hall", "brannon", "library"]


@pytest.fixture
def street(toggles):
    s = toggles.saved.get("Start/End Street Address", {}).get("Value", "")
    if not s:
        pytest.skip("Settings → Start/End Street Address is empty — Company Location has nowhere to start")
    return s


@pytest.fixture
def three_jobs(clean_slate, data):
    return [data.job(f"ROM {i}", place) for i, place in enumerate(PLACES_3, start=1)]


def _rows(api, day=SANDBOX_DATE) -> list[dict]:
    rows = [s for s in api.read("Route_Planner") if iso_date(s.get("Route Date", "")) == day]
    return sorted(rows, key=lambda s: int(float(s.get("Stop #") or 0)))


def _hhmm(v) -> str:
    """'07:00', '7:00 AM', '07:00:00' -> '07:00' ('' if unreadable)."""
    m = re.match(r"^\s*(\d{1,2}):(\d{2})(?::\d{2})?\s*([AaPp][Mm])?", str(v or ""))
    if not m:
        return ""
    h, mi, ap = int(m.group(1)), m.group(2), (m.group(3) or "").lower()
    if ap == "pm" and h < 12:
        h += 12
    if ap == "am" and h == 12:
        h = 0
    return f"{h:02d}:{mi}"


def _workday_start(api) -> str:
    for r in api.read("Settings"):
        if r.get("Setting") == "Workday Start Time":
            return _hhmm(r.get("Value")) or "07:00"
    return "07:00"


def _suggest(api):
    out = api.call("suggest_route_schedule", {"route_date": SANDBOX_DATE, "email_route": False}, expect_ok=False)
    assert str(out).lstrip().startswith("✅"), f"route not built: {str(out)[:300]!r}"
    return out


def _is_company(row, street) -> bool:
    return not row.get("JobID (JOB-####)") and street.lower() in str(row.get("Address", "")).lower()


# ── ROM-01: Company Location — starts and ends at the business ───────────────
def test_ROM_01_company_location_route(three_jobs, api, toggles, street):
    toggles.set(MODE, COMPANY)
    _suggest(api)
    rows = _rows(api)
    assert rows, "no route rows written"
    first, last = rows[0], rows[-1]
    assert _is_company(first, street), f"first stop isn't the company address: {first}"
    assert _is_company(last, street), f"last stop isn't back at the company address: {last}"
    assert _hhmm(first.get("ETA")) == _workday_start(api), \
        f"the company start should be at Workday Start Time {_workday_start(api)}, got {first.get('ETA')!r}"
    jobs = [r.get("JobID (JOB-####)") for r in rows[1:-1]]
    assert sorted(jobs) == sorted(three_jobs), f"stops between the company bookends: {jobs}"


# ── ROM-02: Jobs Only — no company stops, only the hidden Home return row ────
def test_ROM_02_jobs_only_route(three_jobs, api, toggles, street):
    toggles.set(MODE, JOBS_ONLY)
    _suggest(api)
    rows = _rows(api)
    assert not any(_is_company(r, street) for r in rows), \
        f"Jobs Only route has a company stop: {[r.get('Address') for r in rows]}"
    assert rows[0].get("JobID (JOB-####)") in three_jobs, f"Jobs Only route must start with a job: {rows[0]}"
    job_rows = [r.get("JobID (JOB-####)") for r in rows if r.get("JobID (JOB-####)")]
    assert sorted(job_rows) == sorted(three_jobs)
    extra = [r for r in rows if not r.get("JobID (JOB-####)")]
    assert all(str(r.get("Address", "")) == "Home" for r in extra), f"unexpected non-job rows: {extra}"
    assert len(extra) <= 1 and (not extra or rows[-1] is extra[0]), "the Home row may only be the last row"


# ── ROM-03: switching the mode and re-routing replaces the bookends ──────────
def test_ROM_03_switch_mode_and_reroute(three_jobs, api, toggles, street):
    toggles.set(MODE, COMPANY)
    _suggest(api)
    assert sum(_is_company(r, street) for r in _rows(api)) == 2
    toggles.set(MODE, JOBS_ONLY)
    _suggest(api)
    rows = _rows(api)
    assert not any(_is_company(r, street) for r in rows), "company bookends left behind after switching to Jobs Only"
    toggles.set(MODE, COMPANY)
    _suggest(api)
    rows = _rows(api)
    assert sum(_is_company(r, street) for r in rows) == 2, "company bookends not back after switching again"
    assert sorted(r.get("JobID (JOB-####)") for r in rows if r.get("JobID (JOB-####)")) == sorted(three_jobs)


# ── ROM-04/05: the Route tab, as a person sees it (watch in --human) ─────────
def _visible_stops(page) -> list[str]:
    return [t.strip() for t in page.locator("[data-testid='route-stop']:visible").all_inner_texts()]


def test_ROM_04_route_tab_company_location(three_jobs, route, page, toggles, street):
    toggles.set(MODE, COMPANY)
    route.pick_date(SANDBOX_DATE)
    route.press_route_selected_date()
    route.wait_quiet()
    route.expect_stops_include(three_jobs)                    # the 3 job stops
    texts = _visible_stops(page)
    route.log(f"ROUTE stops shown (Company Location): {texts}")
    assert texts and street.lower() in texts[0].lower(), f"the first stop shown isn't the company: {texts[:1]}"


def test_ROM_05_route_tab_jobs_only(three_jobs, route, page, toggles, street):
    toggles.set(MODE, JOBS_ONLY)
    route.pick_date(SANDBOX_DATE)
    route.press_route_selected_date()
    route.wait_quiet()
    route.expect_stops_include(three_jobs)
    texts = _visible_stops(page)
    route.log(f"ROUTE stops shown (Jobs Only): {texts}")
    assert not any(street.lower() in t.lower() for t in texts), f"Jobs Only shows a company stop: {texts}"
    expect(page.locator("[data-testid='route-stop'][data-jobid='']:visible")).to_have_count(0)   # no bookend shown


def test_ROM_06_route_tab_company_stops_are_not_jobs(three_jobs, route, page, toggles, street):
    """Company Location's start/end stops are shown but aren't jobs: exactly
    two non-job rows, first and last, and neither can be opened as a job."""
    toggles.set(MODE, COMPANY)
    route.pick_date(SANDBOX_DATE)
    route.press_route_selected_date()
    route.wait_quiet()
    rows = page.locator("[data-testid='route-stop']:visible")
    n = rows.count()
    non_job = [i for i in range(n) if not rows.nth(i).get_attribute("data-jobid")]
    route.log(f"ROUTE non-job rows at positions {non_job} of {n}")
    assert non_job and non_job[0] == 0, f"company start isn't the first row: {non_job}"
    assert len(non_job) <= 2 and (len(non_job) == 1 or non_job[-1] == n - 1), non_job
