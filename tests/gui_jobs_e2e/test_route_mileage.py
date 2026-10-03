"""Route mileage — is the day's total miles right? (David 2026-09-29 05:42:
"test the routing (non-AI Routing and AI-Routing) and determine if the total
miles driven is correct for both route modes").

What "correct" means (db_route_ops / jobs/index.html):
  • Company Location — the day is business → jobs → business. The business
    start row has no leg into it; every other row's "Drive Miles" is the drive
    FROM the row before it; the last row is back at the business.
  • Jobs Only — the day is home → jobs → home. Home is not a stop at the
    start: the first job's own leg is the drive from home. A hidden "Home" row
    at the end holds the drive back.
  • The Route tab's day total = the sum of every row's Drive Miles.

Each leg is checked against an INDEPENDENT lookup the test makes itself
(OSRM, the same road map the app uses, asked directly from this PC for the
same two points) and against the straight-line distance (a road can't be
shorter than the crow flies). The per-leg table is written to the run log.

  MILES-01 [both modes]  Route Today (suggest_route_schedule), API
  MILES-02 [both modes]  AI Routing's writer (apply_route_order) with a
                         different visit order — no credits
  MILES-03 [both modes]  Route tab (human mode): the total the person sees
                         equals the sum of the legs
  MILES-04 [both modes]  REAL AI Routing (start_ai_routing → the Claude worker
                         → apply_route_order). Uses Claude credits: only with
                         --tier full, skipped otherwise. Email Route On Build
                         is switched off for it (the worker would email the
                         route) and put back after.

Run: run_tests_gui_jobs_e2e.bat --human -k test_route_mileage
     run_tests_gui_jobs_e2e.bat --human --tier full -k MILES_04   (AI Routing, credits)
"""
import math
import os
import re
import time

import pytest
import requests

from safety import SANDBOX_DATE
from test_route_origin_modes import (COMPANY, JOBS_ONLY, MODE, PLACES_3, _is_company,  # noqa: F401
                                     _rows, _suggest, street, three_jobs)

ROUTE_EMAIL = "Email Route On Build"
MODES = [pytest.param(COMPANY, id="company"), pytest.param(JOBS_ONLY, id="jobs_only")]
TIER = (os.environ.get("E2E_TIER") or "safe").lower()

LEG_TOL_MI = 0.05       # + 2 % — same road map, same two points
TOTAL_TOL_MI = 0.15     # + 1 %
_OSRM = "http://router.project-osrm.org/route/v1/driving/"


# ── independent checks ───────────────────────────────────────────────────────
def _osrm_miles(a, b) -> float:
    """Road miles a→b, asked directly (not through the app)."""
    last = None
    for attempt in range(5):
        try:
            r = requests.get(f"{_OSRM}{a[1]},{a[0]};{b[1]},{b[0]}",
                             params={"overview": "false"}, timeout=30).json()
            if r.get("code") == "Ok":
                return r["routes"][0]["legs"][0]["distance"] / 1609.344
            last = r.get("code")
        except (requests.RequestException, ValueError) as exc:
            last = exc
        time.sleep(1.5)
    pytest.skip(f"the independent road-distance check couldn't reach OSRM ({last}) — miles not judged")


def _crow_miles(a, b) -> float:
    r = 3958.7613
    p1, p2 = math.radians(a[0]), math.radians(b[0])
    dp, dl = p2 - p1, math.radians(b[1] - a[1])
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


def _pt(row):
    try:
        return float(row["Latitude"]), float(row["Longitude"])
    except (KeyError, TypeError, ValueError):
        raise AssertionError(f"route row has no map location: {row}")


def _mi(row):
    v = str(row.get("Drive Miles", "") or "").strip()
    return None if v in ("", "None") else float(v)


def _label(row) -> str:
    return row.get("JobID (JOB-####)") or str(row.get("Address", "?"))[:28]


def check_route_miles(rows, mode, street, log, want_jobs=None) -> float:
    """Checks every leg of a built route and returns the day's total miles."""
    assert rows, "no route rows written"
    job_rows = [r for r in rows if r.get("JobID (JOB-####)")]
    if want_jobs is not None:
        assert sorted(r["JobID (JOB-####)"] for r in job_rows) == sorted(want_jobs), \
            f"route jobs {[_label(r) for r in job_rows]} != {want_jobs}"

    if mode == COMPANY:
        first, last = rows[0], rows[-1]
        assert _is_company(first, street) and _is_company(last, street), \
            f"Company Location must start and end at the business: {[_label(r) for r in rows]}"
        assert not _mi(first), f"nothing is driven INTO the business start row, got {_mi(first)} mi"
        start = _pt(first)
        legs = [(rows[i - 1], rows[i]) for i in range(1, len(rows))]
    else:
        last = rows[-1]
        assert not last.get("JobID (JOB-####)") and str(last.get("Address")) == "Home", \
            ("Jobs Only: no hidden 'Home' row at the end — the drive home isn't counted "
             f"(rows: {[_label(r) for r in rows]})")
        assert all(r.get("JobID (JOB-####)") for r in rows[:-1]), \
            f"Jobs Only must have no other non-job rows: {[_label(r) for r in rows]}"
        start = _pt(last)
        home = {"Address": "Home (start)", "Latitude": start[0], "Longitude": start[1]}
        legs = [(home, rows[0])] + [(rows[i - 1], rows[i]) for i in range(1, len(rows))]

    end = _pt(rows[-1])
    assert abs(end[0] - start[0]) < 1e-4 and abs(end[1] - start[1]) < 1e-4, \
        f"the day doesn't end where it started: start {start}, end {end}"

    table, problems, total, want_total = [], [], 0.0, 0.0
    for a, b in legs:
        got = _mi(b)
        road = _osrm_miles(_pt(a), _pt(b))
        crow = _crow_miles(_pt(a), _pt(b))
        time.sleep(1.1)                       # be polite to the public map server
        table.append(f"  {_label(a):>28} → {_label(b):<28} app {got if got is not None else '—':>6}  "
                     f"road {road:6.2f}  straight {crow:6.2f}")
        want_total += road
        if got is None:
            problems.append(f"{_label(a)} → {_label(b)}: no miles stored (left out of the total)")
            continue
        total += got
        if abs(got - road) > LEG_TOL_MI + 0.02 * road:
            problems.append(f"{_label(a)} → {_label(b)}: app {got:.2f} mi, road {road:.2f} mi")
        if got < 0.95 * crow:
            problems.append(f"{_label(a)} → {_label(b)}: {got:.2f} mi is shorter than the "
                            f"straight line ({crow:.2f} mi)")
    log(f"MILES [{mode}] {len(legs)} legs:\n" + "\n".join(table) +
        f"\n  TOTAL app {total:.2f} mi   road {want_total:.2f} mi")
    assert not problems, "leg miles wrong:\n  " + "\n  ".join(problems)
    assert abs(total - want_total) <= TOTAL_TOL_MI + 0.01 * want_total, \
        f"day total {total:.2f} mi, expected {want_total:.2f} mi"
    return total


@pytest.fixture
def log():
    import logging
    lg = logging.getLogger("e2e")
    return lambda msg: lg.info(msg)


@pytest.fixture
def quiet_route_email(toggles):
    """Route email off for these tests — they're about miles, not email."""
    toggles.set(ROUTE_EMAIL, "Disabled")
    return toggles


# ── MILES-01: Route Today ────────────────────────────────────────────────────
@pytest.mark.parametrize("mode", MODES)
def test_MILES_01_route_today(mode, three_jobs, api, quiet_route_email, street, log):
    quiet_route_email.set(MODE, mode)
    _suggest(api)
    check_route_miles(_rows(api), mode, street, log, want_jobs=three_jobs)


# ── MILES-02: the person reorders a stop (↓ on the Route tab) ────────────────
# (apply_route_order — AI Routing's writer — is not reachable from the Jobs app
# API; only the AI worker calls it, so it's covered by MILES-04.)
def _job_order(api):
    return [r["JobID (JOB-####)"] for r in _rows(api) if r.get("JobID (JOB-####)")]


@pytest.mark.parametrize("mode", MODES)
def test_MILES_02_reorder_recomputes_miles(mode, three_jobs, route, page, api, quiet_route_email, street, log):
    quiet_route_email.set(MODE, mode)
    route.pick_date(SANDBOX_DATE)
    route.press_route_selected_date()
    route.wait_quiet()
    route.expect_stops_include(three_jobs)
    before = _job_order(api)
    with page.expect_request(lambda r: "/pwa-api" in r.url and "reorder_route_stop" in (r.post_data or ""),
                             timeout=20_000):
        route.stop(before[0]).move_down()
    route.wait_quiet()
    after = _job_order(api)
    route.log(f"ROUTE reorder: {before} -> {after}")
    assert after != before and sorted(after) == sorted(before), f"the stop didn't move: {before} -> {after}"
    rows = _rows(api)
    total = check_route_miles(rows, mode, street, log, want_jobs=three_jobs)
    route.refresh()
    route.wait_quiet()
    shown = _shown_total(page, mode)
    assert abs(shown - total) <= 0.1, f"after the reorder the Route tab shows {shown} mi, legs add up to {total:.2f}"


# ── MILES-03: the total the person sees on the Route tab ─────────────────────
_TOTAL_RE = re.compile(r"Total[^/]*/\s*([\d.]+)\s*mi")


def _shown_total(page, mode) -> float:
    if mode == COMPANY:
        text = page.locator("[data-testid='route-stop']:visible").last.inner_text()
    else:
        text = page.locator(".route-stop-bookend[data-stopid='__end__']").inner_text()
        assert "Total for the day" in text, f"Jobs Only End line has no day total: {text!r}"
    m = _TOTAL_RE.findall(text)
    assert m, f"no 'Total …/N mi' on the Route tab: {text!r}"
    return float(m[-1])


@pytest.mark.parametrize("mode", MODES)
def test_MILES_03_route_tab_total(mode, three_jobs, route, page, api, quiet_route_email, street, log):
    quiet_route_email.set(MODE, mode)
    route.pick_date(SANDBOX_DATE)
    route.press_route_selected_date()
    route.wait_quiet()
    route.expect_stops_include(three_jobs)
    rows = _rows(api)
    total = check_route_miles(rows, mode, street, log, want_jobs=three_jobs)
    shown = _shown_total(page, mode)
    route.log(f"ROUTE tab shows {shown:.1f} mi for the day [{mode}]; legs add up to {total:.2f} mi")
    assert abs(shown - total) <= 0.1, f"Route tab shows {shown} mi, the legs add up to {total:.2f} mi"
    first = page.locator("[data-testid='route-stop']:visible").nth(1 if mode == COMPANY else 0).inner_text()
    m = re.search(r"Drove [^/]*/\s*([\d.]+)\s*mi", first)
    assert m and float(m.group(1)) > 0, f"the first job shows no drive to get there: {first!r}"


# ── MILES-04: real AI Routing (credits, --tier full) ─────────────────────────
@pytest.mark.skipif(TIER != "full", reason="real AI Routing uses Claude credits — run with --tier full")
@pytest.mark.parametrize("mode", MODES)
def test_MILES_04_real_ai_routing(mode, three_jobs, api, route, page, quiet_route_email, street, log):
    quiet_route_email.set(MODE, mode)
    started = api.call("start_ai_routing", {"route_date": SANDBOX_DATE}, expect_ok=False)
    m = re.search(r"job_id=([\w\-]+)", str(started))
    assert m, f"AI Routing didn't start: {str(started)[:300]!r}"
    job_id, deadline, status = m.group(1), time.time() + 15 * 60, ""
    while time.time() < deadline:
        status = str(api.call("poll_ai_routing", {"job_id": job_id}, expect_ok=False))
        if not status.startswith("⏳"):
            break
        time.sleep(10)
    log(f"AI Routing [{mode}] finished: {status[:600]}")
    if re.search(r"hit your (session|usage|weekly) limit|usage limit|resets \d", status, re.I):
        pytest.skip(f"Claude usage limit — AI Routing couldn't run: {status[:200]}")
    assert status.startswith("✅"), f"AI Routing didn't finish OK: {status[:400]!r}"
    assert _rows(api), f"AI Routing said DONE but wrote no route (R-065): {status[:300]!r}"
    rows = _rows(api)
    check_route_miles(rows, mode, street, log, want_jobs=three_jobs)
    route.pick_date(SANDBOX_DATE)                 # show it (human mode) and check the shown total
    route.wait_quiet()
    shown = _shown_total(page, mode)
    total = sum(_mi(r) or 0 for r in rows)
    assert abs(shown - total) <= 0.1, f"Route tab shows {shown} mi after AI Routing, legs add up to {total:.2f}"
