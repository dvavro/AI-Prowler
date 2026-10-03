"""
tests/mcp_tests/test_apply_route_order_home_bookend.py
=================================================
Company Location mode + an explicit start/end choice (AI Route picker,
2026-09-19): the company Start/End Address stays a REAL scheduled stop, and the
chosen home/GPS point is added AROUND it as a bookend that is not a stop and
never takes part in the timeline.

Why not just another row through _build_day_timeline: the clock starts at
Workday Start, so a soft Home row ahead of the hard-anchored company clock-in
would make the drive to the company address look like lateness and trip a false
HARD TIME VIOLATION. The bookend is timed OUTSIDE the timeline instead.

Same OSRM/Nominatim mocking convention as test_apply_route_order.py.

Run with:
    run_tests.bat tests\\mcp\\test_apply_route_order_home_bookend.py -v
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest
import requests

from db_access import init_db
from db_write_ops import db_create_customer, db_create_job
from db_route_ops import db_apply_route_order
import db_route_ops as route_ops
import db_write_ops as write_ops

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

ROUTE_DATE = "2026-09-22"
LEG_MIN = 10.0
HOME = (29.0, -80.9)


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


@pytest.fixture(autouse=True)
def _no_real_home_address(monkeypatch):
    # Guards against a real, on-disk ~/.ai-prowler/config.json home address
    # leaking into a test — db_read_owner_home_address() genuinely still
    # exists and is unchanged; the original fixture just patched it on the
    # wrong module (db_route_ops/"route_ops") — it's defined in and called
    # from WITHIN db_write_ops.py's own _resolve_jobs_only_origin (a bare
    # name lookup in that module's namespace), so it must be patched on
    # db_write_ops itself to actually take effect. This test file's own
    # Company Location address (db_read_route_address, read by
    # db_route_ops.py directly) is a SEPARATE function entirely and must
    # stay unmocked — _company_location() below sets real Settings rows
    # for it, and every "with home" test still needs that real read to
    # succeed for the company-address stop to appear at all.
    monkeypatch.setattr(write_ops, "db_read_owner_home_address", lambda: "")


class _FakeResponse:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


def _install_full_route_mock(monkeypatch, leg_minutes=LEG_MIN, leg_miles=4.0):
    leg = {"duration": leg_minutes * 60, "distance": leg_miles * 1609.344}

    def fake_get(url, *args, **kwargs):
        if "router.project-osrm.org/route" in url:
            return _FakeResponse({"code": "Ok", "routes": [{"legs": [leg]}]})
        if "nominatim.openstreetmap.org/search" in url:
            return _FakeResponse([{"lat": "29.5", "lon": "-81.0"}])
        raise AssertionError(f"unexpected requests.get URL in test: {url}")
    monkeypatch.setattr(requests, "get", fake_get)


def _job_id(create_result: str) -> str:
    return create_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _create_job(db_path, customer="Cust", lat=29.01, lon=-80.91, crew="Jake"):
    # Job Board Architecture Spec §5.1 (2026-09-22): create_job now requires
    # a real, existing CustomerID.
    cust_result = db_create_customer(db_path, {"Company Name": customer}, actor="dave")
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    fields = {
        "CustomerID (Customers!A)": cust_id,
        "Customer Name / Company": customer, "Service Date": ROUTE_DATE,
        "Street Address": "1 Main St", "City": "NSB", "State": "FL",
        "Crew / Technician": crew, "Est. Duration": 60, "Est. Duration Unit": "min",
        "Latitude (AI Geocode)": lat, "Longitude (AI Geocode)": lon,
    }
    return _job_id(db_create_job(db_path, fields, actor="dave"))


def _route_stops(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM route_stops WHERE route_date = ? ORDER BY crew_id, stop_number",
        (ROUTE_DATE,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _set_setting(db_path, pairs):
    conn = sqlite3.connect(db_path)
    for key, value in pairs:
        conn.execute(
            "INSERT INTO settings (key, value, last_edited_by, last_edited_at) "
            "VALUES (?, ?, 'dave', '2026-01-01T00:00:00Z') "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))
    conn.commit()
    conn.close()


def _company_location(db_path):
    _set_setting(db_path, [
        ("Route Origin Mode", "Company Location"),
        ("Start/End Street Address", "1 Depot Rd"), ("Start/End City", "Town"),
        ("Start/End State", "FL"), ("Start/End ZIP", "12345"),
    ])


def _minutes(hhmm: str) -> int:
    h, m = hhmm.split(":")
    return int(h) * 60 + int(m)


def _apply(db_path, jobs, **kw):
    return db_apply_route_order(db_path, ROUTE_DATE, ",".join(jobs), "", actor="dave", **kw)


# ── the feature ─────────────────────────────────────────────────────────────

def test_company_location_with_home_gives_home_company_job_company_home(db_path, monkeypatch):
    """Updated 2026-09-23: db_apply_route_order's own comment documents a
    "corrected 2026-09-20" fix — the LEADING Home bookend row is never
    written to route_stops at all (the first real stop's own leg already
    carries that mileage); only the TRAILING return-to-home row is, for
    mileage tracking. This test predates that fix by one day and expected
    5 rows (Home-Company-Job-Company-Home); the current, documented,
    intentional shape is 4: Company-Job-Company-Home."""
    _install_full_route_mock(monkeypatch)
    _company_location(db_path)
    j1 = _create_job(db_path)

    result = _apply(db_path, [j1], origin_lat=HOME[0], origin_lon=HOME[1])
    assert result.startswith("✅"), result

    stops = _route_stops(db_path)
    assert len(stops) == 4
    assert [s["job_id"] for s in stops] == [None, j1, None, None]
    # The company address is a real stop at both ends.
    assert stops[0]["address"] == "1 Depot Rd, Town, FL 12345"
    assert stops[2]["address"] == "1 Depot Rd, Town, FL 12345"
    # Only the trailing Home row is ever written.
    assert stops[3]["address"] == "Home"
    assert (stops[3]["latitude"], stops[3]["longitude"]) == HOME


def test_home_bookend_does_not_trip_hard_time_violation(db_path, monkeypatch):
    """The whole reason it's built outside the timeline: the drive from home
    to the company clock-in must not look like the company stop being late."""
    _install_full_route_mock(monkeypatch, leg_minutes=25)
    _company_location(db_path)
    j1 = _create_job(db_path)
    result = _apply(db_path, [j1], origin_lat=HOME[0], origin_lon=HOME[1])
    assert "HARD TIME VIOLATION" not in result, result


def test_leaves_home_early_enough_to_reach_company_at_its_own_eta(db_path, monkeypatch):
    """Updated 2026-09-23: since the leading Home->Company leg's own row is
    never written (see the "corrected 2026-09-20" comment on
    db_apply_route_order), there's no earlier row left to compare it
    against — what's left to verify is that the company stop's own ETA
    stays exactly pinned to Workday Start regardless of that skipped leg,
    and that the leg to the first job correctly reflects real drive time
    PLUS the company stop's own 1-minute dwell."""
    _install_full_route_mock(monkeypatch, leg_minutes=LEG_MIN)
    _company_location(db_path)
    j1 = _create_job(db_path)
    _apply(db_path, [j1], origin_lat=HOME[0], origin_lon=HOME[1])
    stops = _route_stops(db_path)
    assert stops[0]["eta"] == "07:00"  # Workday Start — unaffected by the skipped Home leg
    assert stops[1]["leg_drive_min"] == LEG_MIN
    assert _minutes(stops[1]["eta"]) - _minutes(stops[0]["eta"]) == LEG_MIN + 1  # drive + 1 min dwell


def test_return_home_leg_is_written_with_real_miles(db_path, monkeypatch):
    _install_full_route_mock(monkeypatch, leg_minutes=LEG_MIN)
    _company_location(db_path)
    j1 = _create_job(db_path)
    _apply(db_path, [j1], origin_lat=HOME[0], origin_lon=HOME[1])
    stops = _route_stops(db_path)
    assert stops[3]["leg_drive_min"] == LEG_MIN
    assert stops[3]["leg_drive_miles"] == pytest.approx(4.0, abs=0.01)
    # Arrives home after the company stop's (1 min) dwell plus the drive back.
    assert _minutes(stops[3]["eta"]) == _minutes(stops[2]["eta"]) + 1 + LEG_MIN


def test_all_five_rows_share_the_crews_route(db_path, monkeypatch):
    """Bookend rows must land under the same crew_id as the crew's real
    stops, or they'd be split into a separate route (the bug the company
    bookend logic already documents). Updated 2026-09-23: 4 rows now, not
    5 (see the "corrected 2026-09-20" comment) — the leading Home row is
    never written, so this covers Depot/Job/Depot/Home all sharing one
    crew_id."""
    _install_full_route_mock(monkeypatch)
    _company_location(db_path)
    j1 = _create_job(db_path, crew="Jake")
    _apply(db_path, [j1], origin_lat=HOME[0], origin_lon=HOME[1])
    stops = _route_stops(db_path)
    assert {s["crew_id"] for s in stops} == {"Jake"}
    assert [s["stop_number"] for s in stops] == [1, 2, 3, 4]


# ── regression guards ───────────────────────────────────────────────────────

def test_company_location_without_origin_is_unchanged(db_path, monkeypatch):
    _install_full_route_mock(monkeypatch)
    _company_location(db_path)
    j1 = _create_job(db_path)
    result = _apply(db_path, [j1])
    assert result.startswith("✅"), result
    stops = _route_stops(db_path)
    assert len(stops) == 3
    assert all(s["address"] != "Home" for s in stops)


def test_jobs_only_mode_home_bookend_unchanged(db_path, monkeypatch):
    """Updated 2026-09-23: Jobs Only mode gets the SAME "leading Home row
    never written" fix as Company Location (see db_apply_route_order's own
    "corrected 2026-09-20" comment) — only the trailing return-to-home row
    persists, for mileage tracking. This test's name/docstring predates
    that fix by one day and expected an in-timeline leading Home row too."""
    _install_full_route_mock(monkeypatch)
    j1 = _create_job(db_path)
    result = _apply(db_path, [j1], origin_lat=HOME[0], origin_lon=HOME[1])
    assert result.startswith("✅"), result
    stops = _route_stops(db_path)
    assert [s["job_id"] for s in stops] == [j1, None]
    assert stops[-1]["address"] == "Home"


def test_osrm_failure_on_home_legs_warns_instead_of_crashing(db_path, monkeypatch):
    """The company legs work, but the Home legs come back with no route."""
    _install_full_route_mock(monkeypatch)
    _company_location(db_path)
    j1 = _create_job(db_path)
    real = route_ops._osrm_leg
    home_lat = HOME[0]

    def flaky(lat1, lon1, lat2, lon2):
        if lat1 == home_lat or lat2 == home_lat:
            return None, None
        return real(lat1, lon1, lat2, lon2)
    monkeypatch.setattr(route_ops, "_osrm_leg", flaky)
    result = _apply(db_path, [j1], origin_lat=HOME[0], origin_lon=HOME[1])
    assert result.startswith("✅"), result
    assert "DRIVE TIME UNKNOWN" in result
    # Updated 2026-09-23: 4 rows, not 5 — see the "corrected 2026-09-20"
    # comment on db_apply_route_order (leading Home row never written).
    assert len(_route_stops(db_path)) == 4


def test_wrap_helper_empty_results_is_a_noop():
    assert route_ops._wrap_with_home_bookends([], 1.0, 2.0, "a", "a") == ([], [])
