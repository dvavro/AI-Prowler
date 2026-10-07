"""
tests/mcp_tests/test_reorder_route_stop_phase10.py
=============================================
Job Board Architecture Spec §14.7 — Route & Schedule Advisor, Phase 10
(partial route reorder tool).

Covers db_write_ops.db_reorder_route_stop directly (unit-level, all OSRM
network calls mocked via requests.get monkeypatching — same convention as
test_build_daily_route_phase1_mcp_wiring.py) plus a lighter MCP-wiring
check that the real reorder_route_stop() @mcp.tool() is registered and
present in both PWA API allow-lists (personal + server mode) — the exact
gap class this codebase has been bitten by repeatedly for every prior
route-stop tool (delete_route_stop, build_daily_route, etc.), per the
comments already in ai_prowler_mcp.py.

Run with:
    run_tests.bat tests\\mcp\\test_reorder_route_stop_phase10.py -v
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest
import requests

from db_access import init_db
from db_write_ops import db_create_customer, db_create_job, db_reorder_route_stop
import db_write_ops as write_ops

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

ROUTE_DATE = "2026-09-22"
CREW = "Jake"


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


@pytest.fixture(autouse=True)
def _no_real_home_address(monkeypatch):
    """Same test-isolation guard as test_suggest_route_schedule_phase12.py
    and test_apply_route_order.py's fixture of the same name — see that
    file's docstring for the full rationale. db_reorder_route_stop picked
    up the same Jobs-Only home-bookend fallback (2026-09-19) when a span
    reorder touches position 1, so it's exposed to the same real-machine-
    config.json risk."""
    monkeypatch.setattr(write_ops, "db_read_owner_home_address", lambda: "")


class _FakeResponse:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


def _install_osrm_mock(monkeypatch, leg_minutes=10.0):
    """Every OSRM /route call returns a fixed leg duration, regardless of
    the coordinates passed — keeps the arithmetic in each test simple and
    predictable."""
    def fake_get(url, *args, **kwargs):
        assert "router.project-osrm.org/route" in url
        return _FakeResponse({
            "code": "Ok",
            "routes": [{"legs": [{"duration": leg_minutes * 60}]}],
        })
    monkeypatch.setattr(requests, "get", fake_get)


def _install_osrm_failure_mock(monkeypatch):
    def fake_get(url, *args, **kwargs):
        raise ConnectionError("simulated OSRM outage")
    monkeypatch.setattr(requests, "get", fake_get)


def _seed_stop(db_path, stop_number, job_id=None, lat=29.0, lon=-80.9,
               eta=None, address="", route_date=ROUTE_DATE, crew_id=CREW):
    conn = sqlite3.connect(db_path)
    cur = conn.execute(
        "INSERT INTO route_stops (route_date, crew_id, stop_number, job_id, address, "
        "latitude, longitude, eta, created_by, last_edited_by, last_edited_at, version) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'seed', 'seed', '2026-01-01T00:00:00Z', 1)",
        (route_date, crew_id, stop_number, job_id, address, lat, lon, eta),
    )
    conn.commit()
    stop_id = cur.lastrowid
    conn.close()
    return stop_id


def _get_stop(db_path, stop_id):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM route_stops WHERE id = ?", (stop_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def _set_setting(db_path, key, value):
    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()


def _hard_job(db_path, start_time, end_time="17:00"):
    cust_result = db_create_customer(db_path, {"Company Name": "Hard Co"}, actor="dave")
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    result = db_create_job(
        db_path,
        {
            "CustomerID (Customers!A)": cust_id,
            "Customer Name / Company": "Hard Co",
            "Schedule Type (Hard/Soft)": "hard",
            "Start Time": start_time,
            "End Time": end_time,
        },
        actor="dave",
    )
    return result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


# ── Core reorder behavior ────────────────────────────────────────────────

def test_move_stop_forward_only_touches_affected_span(db_path, monkeypatch):
    _install_osrm_mock(monkeypatch, leg_minutes=10)
    s1 = _seed_stop(db_path, 1, eta="08:00", address="Stop 1")
    s2 = _seed_stop(db_path, 2, eta="08:20", address="Stop 2")
    s3 = _seed_stop(db_path, 3, eta="08:40", address="Stop 3")
    s4 = _seed_stop(db_path, 4, eta="09:00", address="Stop 4")

    before_s1 = _get_stop(db_path, s1)

    result = db_reorder_route_stop(db_path, s4, 2, actor="dave")
    assert result.startswith("✅")

    after_s1 = _get_stop(db_path, s1)
    assert after_s1["version"] == before_s1["version"]
    assert after_s1["last_edited_at"] == before_s1["last_edited_at"]
    assert after_s1["stop_number"] == 1  # untouched, outside the span

    # New order should be: s1, s4, s2, s3
    assert _get_stop(db_path, s4)["stop_number"] == 2
    assert _get_stop(db_path, s2)["stop_number"] == 3
    assert _get_stop(db_path, s3)["stop_number"] == 4

    # ETA chain: anchor = s1's stored eta (08:00) + 10 min to s4, then
    # +10 to s2, then +10 to s3.
    assert _get_stop(db_path, s4)["eta"] == "08:10"
    assert _get_stop(db_path, s2)["eta"] == "08:20"
    assert _get_stop(db_path, s3)["eta"] == "08:30"


def test_move_stop_backward_only_touches_affected_span(db_path, monkeypatch):
    _install_osrm_mock(monkeypatch, leg_minutes=15)
    s1 = _seed_stop(db_path, 1, eta="08:00", address="Stop 1")
    s2 = _seed_stop(db_path, 2, eta="08:20", address="Stop 2")
    s3 = _seed_stop(db_path, 3, eta="08:40", address="Stop 3")
    s4 = _seed_stop(db_path, 4, eta="09:00", address="Stop 4")

    before_s4 = _get_stop(db_path, s4)

    result = db_reorder_route_stop(db_path, s3, 1, actor="dave")
    assert result.startswith("✅")

    after_s4 = _get_stop(db_path, s4)
    assert after_s4["version"] == before_s4["version"]
    assert after_s4["stop_number"] == 4  # untouched, outside the span

    # New order: s3, s1, s2, s4
    assert _get_stop(db_path, s3)["stop_number"] == 1
    assert _get_stop(db_path, s1)["stop_number"] == 2
    assert _get_stop(db_path, s2)["stop_number"] == 3


def test_already_at_target_position_is_a_no_op(db_path, monkeypatch):
    _install_osrm_mock(monkeypatch)
    s1 = _seed_stop(db_path, 1, eta="08:00")
    s2 = _seed_stop(db_path, 2, eta="08:20")
    before = _get_stop(db_path, s2)

    result = db_reorder_route_stop(db_path, s2, 2, actor="dave")
    assert "already at position" in result

    after = _get_stop(db_path, s2)
    assert after == before


def test_new_position_past_end_is_clamped(db_path, monkeypatch):
    _install_osrm_mock(monkeypatch, leg_minutes=5)
    s1 = _seed_stop(db_path, 1, eta="08:00")
    s2 = _seed_stop(db_path, 2, eta="08:10")
    s3 = _seed_stop(db_path, 3, eta="08:20")

    result = db_reorder_route_stop(db_path, s1, 99, actor="dave")
    assert result.startswith("✅")
    assert _get_stop(db_path, s1)["stop_number"] == 3


def test_stop_not_found(db_path):
    result = db_reorder_route_stop(db_path, 99999, 1, actor="dave")
    assert result.startswith("❌")
    assert "No route stop found" in result


def test_invalid_new_position_type(db_path):
    s1 = _seed_stop(db_path, 1)
    result = db_reorder_route_stop(db_path, s1, "not-a-number", actor="dave")
    assert result.startswith("❌")


def test_invalid_new_position_below_one(db_path):
    s1 = _seed_stop(db_path, 1)
    result = db_reorder_route_stop(db_path, s1, 0, actor="dave")
    assert result.startswith("❌")


# ── Crew scoping ─────────────────────────────────────────────────────────

def test_crew_scoping_denies_other_crew(db_path, monkeypatch):
    _install_osrm_mock(monkeypatch)
    s1 = _seed_stop(db_path, 1, crew_id="Jake")
    s2 = _seed_stop(db_path, 2, crew_id="Jake")

    result = db_reorder_route_stop(db_path, s2, 1, actor="sam",
                                    restrict=True, crew_name="Sam")
    assert result.startswith("❌")
    assert "your own route" in result
    assert _get_stop(db_path, s2)["stop_number"] == 2  # unchanged


def test_crew_scoping_allows_own_crew(db_path, monkeypatch):
    _install_osrm_mock(monkeypatch)
    s1 = _seed_stop(db_path, 1, crew_id="Jake")
    s2 = _seed_stop(db_path, 2, crew_id="Jake")

    # _crew_name_in_cell compares the given crew_name, as-is, against the
    # ALREADY-LOWERCASED row_crew list — same convention db_delete_route_stop
    # relies on — so a matching caller passes it pre-lowercased.
    result = db_reorder_route_stop(db_path, s2, 1, actor="jake",
                                    restrict=True, crew_name="jake")
    assert result.startswith("✅")
    assert _get_stop(db_path, s2)["stop_number"] == 1


# ── Hard-time violation warnings ─────────────────────────────────────────

def test_hard_time_violation_flagged_but_write_still_succeeds(db_path, monkeypatch):
    _install_osrm_mock(monkeypatch, leg_minutes=60)  # a full hour drive
    job_id = _hard_job(db_path, start_time="09:00")
    s1 = _seed_stop(db_path, 1, eta="08:00", address="Anchor")
    s2 = _seed_stop(db_path, 2, job_id=job_id, eta="09:00", address="Hard job stop")
    s3 = _seed_stop(db_path, 3, eta="09:30", address="Later stop")

    # Move s3 in front of the hard job — anchor (08:00) + 60 min puts the
    # hard job's new arrival at 09:00... let's push it further off by
    # inserting an extra hop first.
    result = db_reorder_route_stop(db_path, s3, 2, actor="dave")

    assert result.startswith("✅")
    assert "HARD TIME VIOLATION" in result
    assert job_id in result
    # The write still went through despite the warning — advisory only.
    assert _get_stop(db_path, s3)["stop_number"] == 2
    assert _get_stop(db_path, s2)["stop_number"] == 3


def test_hard_time_within_tolerance_no_warning(db_path, monkeypatch):
    _install_osrm_mock(monkeypatch, leg_minutes=2)
    job_id = _hard_job(db_path, start_time="08:12")  # within default 10-min tolerance of 08:10
    s1 = _seed_stop(db_path, 1, eta="08:00", address="Anchor")
    s2 = _seed_stop(db_path, 2, job_id=job_id, eta="08:20", address="Hard job stop")
    s3 = _seed_stop(db_path, 3, eta="08:40", address="Later stop")

    result = db_reorder_route_stop(db_path, s3, 2, actor="dave")
    assert result.startswith("✅")
    assert "HARD TIME VIOLATION" not in result


# ── Anchor at position 1 uses Workday Start Time ────────────────────────

def test_span_starting_at_position_one_anchors_to_workday_start(db_path, monkeypatch):
    _set_setting(db_path, "Workday Start Time", "07:30")
    _install_osrm_mock(monkeypatch, leg_minutes=12)
    s1 = _seed_stop(db_path, 1, eta="08:00", address="Stop 1")
    s2 = _seed_stop(db_path, 2, eta="08:20", address="Stop 2")

    result = db_reorder_route_stop(db_path, s2, 1, actor="dave")
    assert result.startswith("✅")
    # s2 is now first in the route with nothing before it — no drive leg
    # computed to it (matches build_daily_route's no-assumed-origin
    # convention), so its ETA is just the Workday Start Time itself.
    assert _get_stop(db_path, s2)["eta"] == "07:30"
    # s1, now second, gets a real drive leg added.
    assert _get_stop(db_path, s1)["eta"] == "07:42"


# ── Position-1 anchor falls back to a configured origin (mileage- ──────
# tracking follow-up, 2026-09-19) — the actual bug reported live: a
# manual drag/up-down reorder on the Route page always dropped the first
# leg entirely, unlike "Get AI Suggestion"/"Run AI Routing" which already
# fell back to a configured address. No live GPS is available for a
# manual reorder, so this only ever uses the SETTINGS-based fallback —
# the Company Location business address, or Jobs Only's Home Address.

def _install_geocode_mock(monkeypatch, leg_minutes, home_lat, home_lon):
    """OSRM legs return a fixed duration; Nominatim geocode returns a
    fixed (home_lat, home_lon) regardless of the address queried."""
    def fake_get(url, *args, **kwargs):
        if "router.project-osrm.org/route" in url:
            return _FakeResponse({"code": "Ok", "routes": [{"legs": [{"duration": leg_minutes * 60}]}]})
        if "nominatim.openstreetmap.org/search" in url:
            return _FakeResponse([{"lat": str(home_lat), "lon": str(home_lon)}])
        raise AssertionError(f"unexpected URL: {url}")
    monkeypatch.setattr(requests, "get", fake_get)


def test_position_one_falls_back_to_company_location_address(db_path, monkeypatch):
    _install_geocode_mock(monkeypatch, leg_minutes=15, home_lat=29.0, home_lon=-80.9)
    for key, value in [("Route Origin Mode", "Company Location"),
                        ("Start/End Street Address", "1 Depot Rd"),
                        ("Start/End City", "Town"), ("Start/End State", "FL"),
                        ("Start/End ZIP", "12345")]:
        _set_setting(db_path, key, value)
    s1 = _seed_stop(db_path, 1, eta="08:00", address="Stop 1", lat=29.01, lon=-80.91)
    s2 = _seed_stop(db_path, 2, eta="08:20", address="Stop 2", lat=29.02, lon=-80.92)

    result = db_reorder_route_stop(db_path, s2, 1, actor="dave")
    assert result.startswith("✅"), result

    # s2, now first, gets a real leg from the business address — this is
    # the actual fix: previously this was always None/0 regardless of
    # settings.
    moved = _get_stop(db_path, s2)
    assert moved["leg_drive_min"] == 15
    assert moved["leg_drive_miles"] is not None


def test_position_one_falls_back_to_home_address_in_jobs_only_mode(db_path, monkeypatch):
    _install_geocode_mock(monkeypatch, leg_minutes=20, home_lat=29.0, home_lon=-80.9)
    monkeypatch.setattr(write_ops, "db_read_owner_home_address",
                         lambda: "1 Home St, NSB, FL 32168")
    # Route Origin Mode left unset -> Jobs Only (the default).
    s1 = _seed_stop(db_path, 1, eta="08:00", address="Stop 1", lat=29.01, lon=-80.91)
    s2 = _seed_stop(db_path, 2, eta="08:20", address="Stop 2", lat=29.02, lon=-80.92)

    result = db_reorder_route_stop(db_path, s2, 1, actor="dave")
    assert result.startswith("✅"), result

    moved = _get_stop(db_path, s2)
    assert moved["leg_drive_min"] == 20
    assert moved["leg_drive_miles"] is not None


def test_position_one_stays_unanchored_with_neither_configured(db_path, monkeypatch):
    """Regression guard: with no Company Location address and no Home
    Address configured, behavior is unchanged from before this fix — the
    pre-existing "no anchor" shape (drive_min defaults to 0, drive_miles
    stays None), not a crash or a bogus non-zero value."""
    _install_osrm_mock(monkeypatch, leg_minutes=12)
    s1 = _seed_stop(db_path, 1, eta="08:00", address="Stop 1")
    s2 = _seed_stop(db_path, 2, eta="08:20", address="Stop 2")

    result = db_reorder_route_stop(db_path, s2, 1, actor="dave")
    assert result.startswith("✅"), result
    moved = _get_stop(db_path, s2)
    assert moved["leg_drive_min"] == 0
    assert moved["leg_drive_miles"] is None


# ── OSRM failure handling ────────────────────────────────────────────────

def test_osrm_failure_produces_drive_time_unknown_warning(db_path, monkeypatch):
    _install_osrm_failure_mock(monkeypatch)
    s1 = _seed_stop(db_path, 1, eta="08:00", address="Stop 1")
    s2 = _seed_stop(db_path, 2, eta="08:20", address="Stop 2")

    result = db_reorder_route_stop(db_path, s2, 1, actor="dave")
    assert result.startswith("✅")
    assert "DRIVE TIME UNKNOWN" in result
    # Write still succeeds despite the failed OSRM lookup.
    assert _get_stop(db_path, s2)["stop_number"] == 1


# ── MCP wiring / PWA allow-list presence ────────────────────────────────

def test_tool_registered_and_in_both_pwa_allowlists():
    import ai_prowler_mcp as ap
    assert hasattr(ap, "reorder_route_stop")

    src = Path(ap.__file__).read_text(encoding="utf-8")
    # Both the server-mode (_srv_pa_allowed) and personal-mode (_allowed_tools)
    # PWA API bridges gate tool calls through their own hardcoded allow-list,
    # separate from the tool merely existing as a real @mcp.tool() — this
    # codebase has been bitten by that exact gap for every prior route-stop
    # tool (see the comments beside "delete_route_stop" in both blocks).
    assert src.count('"reorder_route_stop"') >= 2
