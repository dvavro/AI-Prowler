"""
tests/mcp_tests/test_apply_route_order.py
====================================
apply_route_order / db_apply_route_order — spec §14.12's "let something
that can actually reason about the day decide the order" tool.

This file did not exist before this session even though the tool itself
(db_apply_route_order, the @mcp.tool() wrapper, both PWA allow-list
entries) was already implemented. Added specifically to cover a real bug
found live (2026-09-19): _build_day_timeline has no origin concept of
its own, and db_apply_route_order — unlike db_suggest_route_schedule —
never bookended the caller's order with a Company Location start/end
waypoint. The practical symptom: the Route tab's first stop showed a
"Total 0min/0.0 mi" cumulative even though the map clearly showed a long
drive from home to stop 1, and there was no return-to-home row at all
when Route Origin Mode was "Company Location".

Same OSRM/Nominatim mocking convention as
test_suggest_route_schedule_phase12.py, which this deliberately mirrors
closely since both tools now share the same start/end bookend logic.

Run with:
    run_tests.bat tests\\mcp\\test_apply_route_order.py -v
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


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


@pytest.fixture(autouse=True)
def _no_real_home_address(monkeypatch):
    """Same test-isolation guard as test_suggest_route_schedule_phase12.py's
    fixture of the same name — see its docstring for the full rationale.
    Both tools now share the Jobs-Only home-bookend feature and the same
    real-machine-config.json risk."""
    monkeypatch.setattr(write_ops, "db_read_owner_home_address", lambda: "")


class _FakeResponse:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


def _install_osrm_mock(monkeypatch, leg_minutes=10.0, leg_miles=None):
    """Every OSRM /route call returns a fixed leg duration (and, unless
    leg_miles is given, no distance key at all — the same mock shape
    test_suggest_route_schedule_phase12.py already uses, deliberately
    kept distance-less to also guard the earlier real bug where
    _osrm_leg's distance lookup used leg["distance"] instead of
    leg.get("distance", 0) and silently killed a perfectly good duration
    whenever distance was absent)."""
    leg = {"duration": leg_minutes * 60}
    if leg_miles is not None:
        leg["distance"] = leg_miles * 1609.344
    def fake_get(url, *args, **kwargs):
        assert "router.project-osrm.org/route" in url
        return _FakeResponse({"code": "Ok", "routes": [{"legs": [leg]}]})
    monkeypatch.setattr(requests, "get", fake_get)


def _install_full_route_mock(monkeypatch, leg_minutes=10.0, leg_miles=None,
                              geo_lat=29.0, geo_lon=-80.9):
    """Extends the OSRM-only mock to also answer the Nominatim geocode
    call _geocode makes for the configured Start/End Address."""
    leg = {"duration": leg_minutes * 60}
    if leg_miles is not None:
        leg["distance"] = leg_miles * 1609.344
    def fake_get(url, *args, **kwargs):
        if "router.project-osrm.org/route" in url:
            return _FakeResponse({"code": "Ok", "routes": [{"legs": [leg]}]})
        if "nominatim.openstreetmap.org/search" in url:
            return _FakeResponse([{"lat": str(geo_lat), "lon": str(geo_lon)}])
        raise AssertionError(f"unexpected requests.get URL in test: {url}")
    monkeypatch.setattr(requests, "get", fake_get)


def _job_id(create_result: str) -> str:
    return create_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _create_job(db_path, customer="Cust", address="1 Main St", lat=29.0, lon=-80.9,
                 crew="Jake", duration=60, duration_unit="min"):
    # Job Board Architecture Spec §5.1 (2026-09-22): create_job now requires
    # a real, existing CustomerID — create one fresh for every job so this
    # helper's callers don't each need to know about it.
    cust_result = db_create_customer(db_path, {"Company Name": customer}, actor="dave")
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    fields = {
        "CustomerID (Customers!A)": cust_id,
        "Customer Name / Company": customer,
        "Service Date": ROUTE_DATE,
        "Street Address": address,
        "City": "NSB", "State": "FL",
        "Crew / Technician": crew,
        "Est. Duration": duration,
        "Est. Duration Unit": duration_unit,
        "Latitude (AI Geocode)": lat,
        "Longitude (AI Geocode)": lon,
    }
    result = db_create_job(db_path, fields, actor="dave")
    return _job_id(result)


def _route_stops(db_path, route_date=ROUTE_DATE):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM route_stops WHERE route_date = ? ORDER BY crew_id, stop_number",
        (route_date,),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _set_company_location(db_path, street="1 Depot Rd", city="Town", state="FL", zip_="12345"):
    conn = sqlite3.connect(db_path)
    for key, value in [
        ("Route Origin Mode", "Company Location"),
        ("Start/End Street Address", street),
        ("Start/End City", city),
        ("Start/End State", state),
        ("Start/End ZIP", zip_),
    ]:
        conn.execute(
            "INSERT INTO settings (key, value, last_edited_by, last_edited_at) VALUES (?, ?, 'dave', '2026-01-01T00:00:00Z') "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
    conn.commit()
    conn.close()


# ── Regression guard: Jobs Only mode unaffected ─────────────────────────

def test_jobs_only_mode_no_start_end_bookend(db_path, monkeypatch):
    """Without Route Origin Mode set to Company Location, apply_route_order
    behaves exactly as before this fix — no synthetic start/end rows, stop
    1's own leg is None (there's genuinely nothing to compute it from)."""
    _install_osrm_mock(monkeypatch, leg_minutes=10)
    j1 = _create_job(db_path, customer="A", lat=29.0, lon=-80.9)
    j2 = _create_job(db_path, customer="B", lat=29.1, lon=-81.0)

    result = db_apply_route_order(db_path, ROUTE_DATE, f"{j1},{j2}", "", actor="dave")
    assert result.startswith("✅"), result

    stops = _route_stops(db_path)
    assert len(stops) == 2
    assert stops[0]["job_id"] == j1
    assert stops[0]["leg_drive_min"] is None


# ── Jobs Only mode's home-office round-trip bookend (mileage-tracking ──
# follow-up, 2026-09-19) — see test_suggest_route_schedule_phase12.py's
# matching tests for the full rationale; db_apply_route_order shares the
# same _resolve_jobs_only_origin/bookend logic, just wired through a flat
# caller-supplied order instead of a per-crew NN loop.

def test_jobs_only_mode_uses_live_gps_as_home_when_given(db_path, monkeypatch):
    """Corrected 2026-09-20: home is never a visible, numbered stop in
    Jobs Only mode — only the real job carries its own home->job1 leg
    directly; a single trailing return-to-home row is kept (the only
    place that leg's mileage can be stored), hidden from the visible
    list client-side, not from the database."""
    _install_osrm_mock(monkeypatch, leg_minutes=12, leg_miles=5.0)
    j1 = _create_job(db_path, customer="A", lat=29.01, lon=-80.91)

    result = db_apply_route_order(
        db_path, ROUTE_DATE, j1, "", actor="dave",
        origin_lat=29.0, origin_lon=-80.9,
    )
    assert result.startswith("✅"), result

    stops = _route_stops(db_path)
    assert len(stops) == 2
    assert stops[0]["job_id"] == j1
    assert stops[0]["leg_drive_min"] == 12
    assert stops[0]["leg_drive_miles"] == pytest.approx(5.0, abs=0.01)
    # schedule_type isn't a route_stops column — soft-ness verified
    # observably: no HARD TIME VIOLATION for the home bookend.
    assert "HARD TIME VIOLATION" not in result
    assert stops[1]["job_id"] is None and stops[1]["address"] == "Home"
    assert stops[1]["leg_drive_min"] == 12


# ── The actual fix: Company Location bookends the caller's order ───────

def test_company_location_mode_writes_start_and_end_with_real_legs(db_path, monkeypatch):
    """The real bug: stop 1's leg (home -> first job) and a return-to-home
    leg were never computed or written at all. With Route Origin Mode =
    Company Location, apply_route_order must now bookend the caller's
    order with a start row (job_id NULL, hard-anchored at Workday Start)
    and an end row (job_id NULL), each carrying a real, non-null
    leg_drive_min/leg_drive_miles — exactly matching
    db_suggest_route_schedule's existing Company Location behavior."""
    _install_full_route_mock(monkeypatch, leg_minutes=15, leg_miles=6.2)
    _set_company_location(db_path)
    j1 = _create_job(db_path, customer="A", lat=29.0, lon=-80.9)
    j2 = _create_job(db_path, customer="B", lat=29.1, lon=-81.0)

    result = db_apply_route_order(db_path, ROUTE_DATE, f"{j1},{j2}", "", actor="dave")
    assert result.startswith("✅"), result

    stops = _route_stops(db_path)
    # start bookend, job 1, job 2, end bookend
    assert len(stops) == 4
    start_row, mid1, mid2, end_row = stops

    assert start_row["job_id"] is None
    assert mid1["job_id"] == j1
    assert mid2["job_id"] == j2
    assert end_row["job_id"] is None

    # The actual fix, verified directly: stop 1 (the real first job) has a
    # real, non-null leg — it's no longer stranded with nothing to drive
    # FROM. Every OSRM call in this test returns the same fixed leg, so
    # every leg (including the home -> job1 one) is 15 min / 6.2 mi.
    assert mid1["leg_drive_min"] == 15
    assert mid1["leg_drive_miles"] == pytest.approx(6.2, abs=0.01)

    # The return-to-home row also carries a real leg — this used to not
    # exist at all.
    assert end_row["leg_drive_min"] == 15
    assert end_row["leg_drive_miles"] == pytest.approx(6.2, abs=0.01)

    # Cumulative total across the whole day (what the Route tab sums) now
    # correctly includes both the leading and trailing home legs, not
    # just the inter-job legs.
    total_min = sum(s["leg_drive_min"] or 0 for s in stops)
    assert total_min == 15 * 3  # home->job1, job1->job2, job2->home


def test_company_location_start_row_is_hard_anchored_at_workday_start(db_path, monkeypatch):
    """The start bookend's ETA must be exactly Workday Start Time — it's
    a real commitment (the crew clocks in there), not just an
    informational marker, same as db_suggest_route_schedule's own
    version of this bookend."""
    _install_full_route_mock(monkeypatch, leg_minutes=15)
    _set_company_location(db_path)
    j1 = _create_job(db_path, customer="A", lat=29.0, lon=-80.9)

    result = db_apply_route_order(db_path, ROUTE_DATE, j1, "", actor="dave")
    assert result.startswith("✅"), result

    stops = _route_stops(db_path)
    start_row = stops[0]
    assert start_row["eta"] == "07:00"  # default Workday Start Time


# ── Existing behavior still intact with the bookend in place ───────────

def test_unknown_job_id_still_rejected_with_company_location_on(db_path, monkeypatch):
    _install_full_route_mock(monkeypatch, leg_minutes=10)
    _set_company_location(db_path)
    j1 = _create_job(db_path, customer="A", lat=29.0, lon=-80.9)

    result = db_apply_route_order(db_path, ROUTE_DATE, f"{j1},JOB-9999", "", actor="dave")
    assert result.startswith("❌")
    assert "Not a geocoded job" in result
    assert _route_stops(db_path) == []


def test_left_out_job_still_reported_not_placed_with_company_location_on(db_path, monkeypatch):
    _install_full_route_mock(monkeypatch, leg_minutes=10)
    _set_company_location(db_path)
    j1 = _create_job(db_path, customer="Placed", lat=29.0, lon=-80.9)
    j2 = _create_job(db_path, customer="LeftOut", lat=29.1, lon=-81.0)

    result = db_apply_route_order(db_path, ROUTE_DATE, j1, "", actor="dave")
    assert result.startswith("✅")
    assert "NOT PLACED" in result
    assert j2 in result
