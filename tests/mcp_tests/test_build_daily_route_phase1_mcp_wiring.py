"""
tests/mcp_tests/test_build_daily_route_phase1_mcp_wiring.py
=========================================================
Job Board Architecture Spec — Phase 1 (spec §4.2, §5, §6.4, §11).

In-process tests for the real build_daily_route() @mcp.tool(), covering
BOTH personal mode (ctx=None) and server mode (mocked ctx). All
Nominatim/OSRM network calls are mocked (requests.get) so these tests
never hit the network and never flake on it — the routing math itself
(TSP ordering, savings comparison) is exercised elsewhere in
ai_prowler_mcp's own history; what matters here is that the storage
touchpoints (db_get_jobs_for_route, db_update_job_geocode,
db_write_route_stops) are wired correctly through the real tool
function in both modes, including the per-crew isolation guarantee
(spec §6.4) at the MCP layer, not just at the db_route_ops layer
already covered directly in test_db_route_ops_phase1.py.

Run with:
    run_tests.bat tests\\mcp\\test_build_daily_route_phase1_mcp_wiring.py -v
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


def _make_ctx(user):
    if user is None:
        return None
    ctx = MagicMock()
    ctx.request_context.request.state.user = user
    return ctx


def _field_crew(uid="jake-r", name="Jake R"):
    return {"id": uid, "name": name, "role": "field_crew", "status": "active", "scopes": []}


def _owner(uid="dave"):
    return {"id": uid, "name": "Dave Owner", "role": "owner", "status": "active", "scopes": []}


def _set_user(monkeypatch, mcp_mod, user):
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)


class _FakeResponse:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


def _install_osrm_route_mock(monkeypatch, num_legs=1, leg_minutes=10.0):
    """Mocks requests.get for the no-origin path: only an OSRM /route call
    (fixed-sequence drive times) happens, since jobs already have lat/lon
    set and no origin is given (no geocoding, no OSRM /trip)."""
    import requests

    def fake_get(url, *args, **kwargs):
        if "router.project-osrm.org/route" in url:
            return _FakeResponse({
                "code": "Ok",
                "routes": [{"legs": [{"duration": leg_minutes * 60} for _ in range(num_legs)]}],
            })
        raise AssertionError(f"Unexpected network call in no-origin test: {url}")

    monkeypatch.setattr(requests, "get", fake_get)


def _marker(result: str, key: str) -> str:
    for line in result.splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip()
    raise AssertionError(f"{key}= marker not found in: {result!r}")


def _job_id(create_result: str) -> str:
    return create_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _cust_id(mcp_mod, name="A", ctx=None):
    """Job Board Architecture Spec §5.1 (2026-09-22): create_job now
    requires a real, existing CustomerID."""
    result = mcp_mod.create_customer({"Company Name": name}, filepath="", backup=False, ctx=ctx)
    return result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()


# ══════════════════════════════════════════════════════════════════════════
# Personal mode (ctx=None)
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def personal_env(tmp_path, monkeypatch, mcp_mod):
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    # Test-isolation guard (mileage-tracking follow-up, 2026-09-19): the
    # SAME real-machine-config.json risk already found and fixed in
    # test_suggest_route_schedule_phase12.py/test_apply_route_order.py/
    # test_reorder_route_stop_phase10.py — build_daily_route's new
    # Jobs-Only home-address fallback (_resolve_route_home ->
    # _get_personal_owner_address in personal mode) would otherwise read
    # whatever's ACTUALLY configured on the machine running this suite,
    # attempting a real geocode network call the strict OSRM-only mock
    # above correctly rejects. Empty dict here = "no home address
    # configured" by default; test_jobs_only_mode_uses_home_address_
    # fallback below overrides this to exercise the actual new feature.
    monkeypatch.setattr(mcp_mod, "_get_personal_owner_address", lambda: {})
    return tmp_path / "ai_prowler_jobs.db"


def test_personal_mode_no_jobs_scheduled(personal_env, mcp_mod):
    result = mcp_mod.build_daily_route("2026-04-05", filepath="", backup=False,
                                        email_link=False, ctx=None)
    assert result.startswith("ℹ️")
    assert "No jobs scheduled" in result


def test_personal_mode_builds_route_and_persists_stops(personal_env, monkeypatch, mcp_mod):
    _install_osrm_route_mock(monkeypatch, num_legs=1, leg_minutes=15.0)

    j1 = _job_id(mcp_mod.create_job({
        "CustomerID": _cust_id(mcp_mod, "A"), "Customer Name / Company": "A", "Service Date": "2026-04-05",
        "Street Address": "1 Main St", "City": "NSB", "State": "FL",
        "Latitude (AI Geocode)": 29.0, "Longitude (AI Geocode)": -80.9,
        "Start Time": "08:00",
    }, filepath="", backup=False, ctx=None))
    j2 = _job_id(mcp_mod.create_job({
        "CustomerID": _cust_id(mcp_mod, "B"), "Customer Name / Company": "B", "Service Date": "2026-04-05",
        "Street Address": "2 Main St", "City": "NSB", "State": "FL",
        "Latitude (AI Geocode)": 29.1, "Longitude (AI Geocode)": -80.8,
        "Start Time": "09:00",
    }, filepath="", backup=False, ctx=None))

    result = mcp_mod.build_daily_route("2026-04-05", filepath="", backup=False,
                                        email_link=False, ctx=None)
    assert result.startswith("🗺️"), result
    assert "Stops:  2" in result

    conn = sqlite3.connect(personal_env)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM route_stops WHERE route_date = '2026-04-05' ORDER BY stop_number"
    ).fetchall()
    conn.close()
    assert len(rows) == 2
    assert {r["job_id"] for r in rows} == {j1, j2}

    # Route URL persisted back onto each job row too.
    conn = sqlite3.connect(personal_env)
    urls = conn.execute("SELECT route_map_url FROM jobs WHERE job_id IN (?, ?)", (j1, j2)).fetchall()
    conn.close()
    assert all(u[0] for u in urls)


def test_personal_mode_crew_filter_only_includes_matching_jobs(personal_env, monkeypatch, mcp_mod):
    _install_osrm_route_mock(monkeypatch)
    mcp_mod.create_job({
        "CustomerID": _cust_id(mcp_mod, "A"), "Customer Name / Company": "A", "Service Date": "2026-04-05", "Crew / Technician": "Jake R",
        "Street Address": "1 Main St", "City": "NSB", "State": "FL",
        "Latitude (AI Geocode)": 29.0, "Longitude (AI Geocode)": -80.9,
    }, filepath="", backup=False, ctx=None)
    mcp_mod.create_job({
        "CustomerID": _cust_id(mcp_mod, "B"), "Customer Name / Company": "B", "Service Date": "2026-04-05", "Crew / Technician": "Maria S",
        "Street Address": "2 Main St", "City": "NSB", "State": "FL",
        "Latitude (AI Geocode)": 29.1, "Longitude (AI Geocode)": -80.8,
    }, filepath="", backup=False, ctx=None)

    result = mcp_mod.build_daily_route("2026-04-05", crew="Jake R", filepath="", backup=False,
                                        email_link=False, ctx=None)
    assert "Stops:  1" in result


def _install_round_trip_mock(monkeypatch, trip_leg_minutes=10.0, return_leg_minutes=12.0,
                              origin_lat=29.0, origin_lon=-80.9):
    """Mocks requests.get for the Company Location round-trip path: a
    Nominatim geocode of the configured Start/End Address, an OSRM /trip
    call (TSP ordering from that origin — source=first, so the origin is
    always waypoint_index 0), and a plain OSRM /route call for the
    single-leg return-to-origin drive time. Sized for exactly one real
    job (2 input points total: origin + job)."""
    import requests

    def fake_get(url, *args, **kwargs):
        if "nominatim.openstreetmap.org/search" in url:
            return _FakeResponse([{"lat": str(origin_lat), "lon": str(origin_lon)}])
        if "router.project-osrm.org/trip" in url:
            return _FakeResponse({
                "code": "Ok",
                "trips": [{"duration": trip_leg_minutes * 60,
                           "legs": [{"duration": trip_leg_minutes * 60}]}],
                "waypoints": [{"waypoint_index": 0}, {"waypoint_index": 1}],
            })
        if "router.project-osrm.org/route" in url:
            return _FakeResponse({"code": "Ok", "routes": [{"duration": return_leg_minutes * 60}]})
        raise AssertionError(f"Unexpected network call in round-trip test: {url}")

    monkeypatch.setattr(requests, "get", fake_get)


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
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
    conn.commit()
    conn.close()


def test_round_trip_mode_writes_start_and_end_as_real_stops(personal_env, monkeypatch, mcp_mod):
    """build_daily_route in Company Location round-trip mode must now
    match suggest_route_schedule's Advisor behavior (spec §6.3/§14
    follow-up, 2026-09-17): the Start/End Address writes as stop #1 (a
    real row, job_id NULL) AND as the final stop, not just an
    informational point that silently influences ordering. The return
    leg's job_id=None write already existed before this change; the
    START leg did not — this is the actual gap being closed."""
    _install_round_trip_mock(monkeypatch, trip_leg_minutes=10.0, return_leg_minutes=12.0)

    j1 = _job_id(mcp_mod.create_job({
        "CustomerID": _cust_id(mcp_mod, "A"), "Customer Name / Company": "A", "Service Date": "2026-04-05",
        "Street Address": "1 Main St", "City": "NSB", "State": "FL",
        "Latitude (AI Geocode)": 29.01, "Longitude (AI Geocode)": -80.91,
    }, filepath="", backup=False, ctx=None))
    # DB is created lazily on first tool call — the settings table only
    # exists once init_db has actually run, hence job creation first.
    _set_company_location(personal_env)

    result = mcp_mod.build_daily_route("2026-04-05", filepath="", backup=False,
                                        email_link=False, accept_reorder=True,
                                        departure_hour=7, ctx=None)
    assert result.startswith("🗺️"), result

    conn = sqlite3.connect(personal_env)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM route_stops WHERE route_date = '2026-04-05' ORDER BY stop_number"
    ).fetchall()
    conn.close()

    assert len(rows) == 3, f"expected start + job + return, got {len(rows)}: {[dict(r) for r in rows]}"
    assert rows[0]["job_id"] is None
    assert rows[0]["address"] == "1 Depot Rd, Town, FL 12345"
    assert rows[0]["eta"] == "07:00"
    assert rows[1]["job_id"] == j1
    assert rows[2]["job_id"] is None
    assert rows[2]["address"] == "1 Depot Rd, Town, FL 12345"
    # The return leg's ETA reflects real drive time from the last real
    # job, not a repeat of the start time.
    assert rows[2]["eta"] != rows[0]["eta"]


def test_jobs_only_mode_no_synthetic_stops_in_build_daily_route(personal_env, monkeypatch, mcp_mod):
    """Regression guard: with Route Origin Mode left at its default, no
    explicit origin= passed, AND no home address configured (personal_env's
    own default), build_daily_route's pre-existing open-path (no-origin)
    behavior is unchanged — no synthetic stops. See
    test_jobs_only_mode_uses_home_address_fallback below for the actual
    new behavior when a home address IS configured."""
    _install_osrm_route_mock(monkeypatch, num_legs=1, leg_minutes=15.0)
    j1 = _job_id(mcp_mod.create_job({
        "CustomerID": _cust_id(mcp_mod, "A"), "Customer Name / Company": "A", "Service Date": "2026-04-05",
        "Street Address": "1 Main St", "City": "NSB", "State": "FL",
        "Latitude (AI Geocode)": 29.0, "Longitude (AI Geocode)": -80.9,
    }, filepath="", backup=False, ctx=None))

    result = mcp_mod.build_daily_route("2026-04-05", filepath="", backup=False,
                                        email_link=False, ctx=None)
    assert result.startswith("🗺️"), result

    conn = sqlite3.connect(personal_env)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM route_stops WHERE route_date = '2026-04-05' ORDER BY stop_number"
    ).fetchall()
    conn.close()
    assert len(rows) == 1
    assert rows[0]["job_id"] == j1


def test_jobs_only_mode_uses_home_address_fallback(personal_env, monkeypatch, mcp_mod):
    """The actual feature (mileage-tracking follow-up, 2026-09-19): "Route
    Today" (the Jobs-page button, which calls this tool with no explicit
    origin=) previously never assumed ANY starting address at all — a
    deliberate product decision (see build_daily_route's own docstring
    comment), which left a home-based business's reported total mileage
    always missing the very first leg of the day. With a Home address
    configured and Route Origin Mode left at Jobs Only (the default),
    build_daily_route now falls back to it via the same _resolve_route_home
    resolver the "Run AI Routing" start/end picker already uses — and
    treats it as a real round trip, same mechanism as Company Location."""
    _install_round_trip_mock(monkeypatch, trip_leg_minutes=10.0, return_leg_minutes=12.0)
    monkeypatch.setattr(mcp_mod, "_get_personal_owner_address",
                         lambda: {"street": "9 Home Ave", "city": "NSB", "state": "FL", "zip": "32168"})
    j1 = _job_id(mcp_mod.create_job({
        "CustomerID": _cust_id(mcp_mod, "A"), "Customer Name / Company": "A", "Service Date": "2026-04-05",
        "Street Address": "1 Main St", "City": "NSB", "State": "FL",
        "Latitude (AI Geocode)": 29.01, "Longitude (AI Geocode)": -80.91,
    }, filepath="", backup=False, ctx=None))

    result = mcp_mod.build_daily_route("2026-04-05", filepath="", backup=False,
                                        email_link=False, accept_reorder=True,
                                        departure_hour=7, ctx=None)
    assert result.startswith("🗺️"), result
    assert "Round trip" in result
    assert "9 Home Ave" in result

    conn = sqlite3.connect(personal_env)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM route_stops WHERE route_date = '2026-04-05' ORDER BY stop_number"
    ).fetchall()
    conn.close()

    # Corrected 2026-09-20: home is never a visible, numbered stop in
    # Jobs Only mode — only scheduled jobs are (and, in Company Location
    # mode, the business address). Stop 1 is the real job, carrying its
    # own home->job1 leg directly (no separate leading "Home" row
    # needed); the trailing return-to-home row is kept (only place that
    # mileage can be stored) but is hidden from the visible list
    # client-side, not from the database.
    assert len(rows) == 2, f"expected job + home-return, got {len(rows)}: {[dict(r) for r in rows]}"
    assert rows[0]["job_id"] == j1
    assert rows[0]["leg_drive_min"] == 10.0  # home -> job1, folded into job1's own leg
    assert rows[1]["job_id"] is None
    assert rows[1]["address"] == "9 Home Ave, NSB FL 32168"


# ══════════════════════════════════════════════════════════════════════════
# Server mode — including the per-crew isolation guarantee at MCP layer
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def server_env(tmp_path, monkeypatch, mcp_mod):
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    return tmp_path / "ai_prowler_jobs.db"


def test_server_mode_two_crews_same_date_do_not_clobber(server_env, monkeypatch, mcp_mod):
    """MCP-layer version of the spec §6.4/§11 regression test: building
    Sam's (Jake's) route for a date, then Vicki's route for the SAME
    date, must leave Jake's stops intact.

    This is a genuine multi-crew server install, so _IS_SERVER_MODE must
    actually be True here — spec §6.3's personal-mode single_crew
    collapse (added alongside this test) is keyed off that same module
    global, and _set_user() alone only fakes role/identity, never the
    install-mode flag. Without this, the test silently exercised
    personal-mode behavior (both crews collapsed into one shared route)
    while still calling itself "server mode" in its own name."""
    monkeypatch.setattr(mcp_mod, "_IS_SERVER_MODE", True)
    _install_osrm_route_mock(monkeypatch)
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)

    j_jake = _job_id(mcp_mod.create_job({
        "CustomerID": _cust_id(mcp_mod, "Jake's Customer", ctx=_make_ctx(owner)), "Customer Name / Company": "Jake's Customer", "Service Date": "2026-04-05",
        "Crew / Technician": "Jake R",
        "Street Address": "1 Main St", "City": "NSB", "State": "FL",
        "Latitude (AI Geocode)": 29.0, "Longitude (AI Geocode)": -80.9,
    }, filepath="", backup=False, ctx=_make_ctx(owner)))
    j_vicki = _job_id(mcp_mod.create_job({
        "CustomerID": _cust_id(mcp_mod, "Vicki's Customer", ctx=_make_ctx(owner)), "Customer Name / Company": "Vicki's Customer", "Service Date": "2026-04-05",
        "Crew / Technician": "Vicki V",
        "Street Address": "2 Main St", "City": "NSB", "State": "FL",
        "Latitude (AI Geocode)": 29.1, "Longitude (AI Geocode)": -80.8,
    }, filepath="", backup=False, ctx=_make_ctx(owner)))

    r1 = mcp_mod.build_daily_route("2026-04-05", crew="Jake R", filepath="", backup=False,
                                    email_link=False, ctx=_make_ctx(owner))
    assert r1.startswith("🗺️"), r1

    r2 = mcp_mod.build_daily_route("2026-04-05", crew="Vicki V", filepath="", backup=False,
                                    email_link=False, ctx=_make_ctx(owner))
    assert r2.startswith("🗺️"), r2
    assert "Cleared" not in r2 or "Cleared 0" not in r2  # Vicki had nothing before this build — sanity, not strict

    conn = sqlite3.connect(server_env)
    conn.row_factory = sqlite3.Row
    jake_rows = conn.execute(
        "SELECT * FROM route_stops WHERE route_date = '2026-04-05' AND crew_id = 'Jake R'"
    ).fetchall()
    vicki_rows = conn.execute(
        "SELECT * FROM route_stops WHERE route_date = '2026-04-05' AND crew_id = 'Vicki V'"
    ).fetchall()
    conn.close()

    assert len(jake_rows) == 1
    assert jake_rows[0]["job_id"] == j_jake
    assert len(vicki_rows) == 1
    assert vicki_rows[0]["job_id"] == j_vicki


def test_server_mode_ignores_filepath_argument(server_env, monkeypatch, mcp_mod, tmp_path):
    _install_osrm_route_mock(monkeypatch)
    owner = _owner()
    _set_user(monkeypatch, mcp_mod, owner)
    mcp_mod.create_job({
        "CustomerID": _cust_id(mcp_mod, "A", ctx=_make_ctx(owner)), "Customer Name / Company": "A", "Service Date": "2026-04-05",
        "Street Address": "1 Main St", "City": "NSB", "State": "FL",
        "Latitude (AI Geocode)": 29.0, "Longitude (AI Geocode)": -80.9,
        # R-055 (2026-09-28): the owner's blank-crew route is now his OWN
        # jobs, so the job is assigned to him.
        "Crew / Technician": owner["name"],
    }, filepath="", backup=False, ctx=_make_ctx(owner))

    decoy = tmp_path / "decoy.db"
    result = mcp_mod.build_daily_route("2026-04-05", filepath=str(decoy), backup=False,
                                        email_link=False, ctx=_make_ctx(owner))
    assert result.startswith("🗺️"), result
    assert not decoy.exists()
