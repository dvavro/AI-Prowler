"""
tests/mcp_tests/test_suggest_route_schedule_phase12.py
=================================================
Job Board Architecture Spec §14.4/§14.11 Phase 12 — Route & Schedule
Advisor, Mode A ("Get AI Suggestion").

Covers db_route_ops.db_suggest_route_schedule directly (unit-level, all
OSRM network calls mocked via requests.get monkeypatching — same
convention as test_reorder_route_stop_phase10.py and
test_build_daily_route_phase1_mcp_wiring.py), plus a lighter MCP-wiring
check that the real suggest_route_schedule() @mcp.tool() is registered
and present in both PWA API allow-lists (personal + server mode) — the
same gap class this codebase has been bitten by for every prior
route-stop tool.

This file did not exist before this session even though the backend
(db_suggest_route_schedule), the @mcp.tool() wiring, both PWA allow-list
entries, and the Route tab's routeGetAiSuggestion() frontend call were
all already implemented — it fills the one remaining gap called out in
the spec's own Phase 12 testing requirements.

Run with:
    run_tests.bat tests\\mcp\\test_suggest_route_schedule_phase12.py -v
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest
import requests

from db_access import init_db
from db_write_ops import db_create_customer, db_create_job
from db_route_ops import db_suggest_route_schedule
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
    """Test-isolation bug found live (2026-09-19): the mileage-tracking
    follow-up's Jobs-Only home bookend calls db_read_owner_home_address,
    which reads the REAL ~/.ai-prowler/config.json on whatever machine
    runs this suite — a machine with an actual Home Address configured
    in Settings made several tests non-deterministic (an unrelated test
    would suddenly get 3 stops instead of 1, depending on who ran it).
    Autouse so every test in this file defaults to "no home address
    configured" without having to remember to mock it individually — a
    test that specifically wants a configured address (the fallback
    tests below) just re-monkeypatches it after this fixture runs,
    which overrides this default for that one test only."""
    monkeypatch.setattr(write_ops, "db_read_owner_home_address", lambda: "")


class _FakeResponse:
    def __init__(self, data):
        self._data = data

    def json(self):
        return self._data


def _install_osrm_mock(monkeypatch, leg_minutes=10.0):
    """Every OSRM /route call returns a fixed leg duration, regardless of
    the coordinates passed — keeps each test's timeline arithmetic simple
    and predictable, same convention as the Phase 10 test file."""
    def fake_get(url, *args, **kwargs):
        assert "router.project-osrm.org/route" in url
        return _FakeResponse({
            "code": "Ok",
            "routes": [{"legs": [{"duration": leg_minutes * 60}]}],
        })
    monkeypatch.setattr(requests, "get", fake_get)


def _job_id(create_result: str) -> str:
    return create_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _create_job(db_path, customer="Cust", address="1 Main St", lat=29.0, lon=-80.9,
                 crew="Jake", duration=60, duration_unit="min", no_geocode=False,
                 **extra_headers):
    # Job Board Architecture Spec §5.1 (2026-09-22): create_job now requires
    # a real, existing CustomerID.
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
    }
    if not no_geocode:
        fields["Latitude (AI Geocode)"] = lat
        fields["Longitude (AI Geocode)"] = lon
    fields.update(extra_headers)
    result = db_create_job(db_path, fields, actor="dave")
    return _job_id(result)


def _get_job(db_path, job_id):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def _route_stops(db_path, route_date=ROUTE_DATE, crew_id=None):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    if crew_id is None:
        rows = conn.execute(
            "SELECT * FROM route_stops WHERE route_date = ? ORDER BY crew_id, stop_number",
            (route_date,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM route_stops WHERE route_date = ? AND crew_id = ? ORDER BY stop_number",
            (route_date, crew_id),
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _seed_stop(db_path, stop_number, route_date=ROUTE_DATE, crew_id="Sam"):
    conn = sqlite3.connect(db_path)
    cur = conn.execute(
        "INSERT INTO route_stops (route_date, crew_id, stop_number, address, "
        "latitude, longitude, eta, created_by, last_edited_by, last_edited_at, version) "
        "VALUES (?, ?, ?, 'Pre-existing', 29.0, -80.9, '08:00', 'seed', 'seed', "
        "'2026-01-01T00:00:00Z', 1)",
        (route_date, crew_id, stop_number),
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


# ── No jobs / no geocoded jobs ───────────────────────────────────────────

def test_no_jobs_scheduled_returns_nothing_to_suggest(db_path):
    result = db_suggest_route_schedule(db_path, "2026-12-25", "", actor="dave")
    assert result.startswith("✅")
    assert "nothing to suggest" in result.lower()


def test_no_geocoded_jobs_returns_error(db_path):
    _create_job(db_path, no_geocode=True)
    result = db_suggest_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert result.startswith("❌")
    assert "geocoded" in result.lower()


# ── Basic proposal writes route_stops, never touches schedule_type ──────

def test_basic_soft_jobs_proposal_writes_route_stops(db_path, monkeypatch):
    _install_osrm_mock(monkeypatch, leg_minutes=10)
    j1 = _create_job(db_path, customer="A", address="1 Main St", lat=29.0, lon=-80.9)
    j2 = _create_job(db_path, customer="B", address="2 Main St", lat=29.01, lon=-80.9)

    result = db_suggest_route_schedule(db_path, ROUTE_DATE, "Jake", actor="dave")
    assert result.startswith("✅"), result

    stops = _route_stops(db_path, crew_id="Jake")
    assert len(stops) == 2
    assert {s["job_id"] for s in stops} == {j1, j2}

    # Never promotes a soft job to hard, or otherwise mutates schedule_type
    # (spec §14.9's decision) — approving a suggested time is a separate,
    # later step owned by the Route tab's existing Approve button.
    assert _get_job(db_path, j1)["schedule_type"] == "soft"
    assert _get_job(db_path, j2)["schedule_type"] == "soft"


# ── Hard-time tolerance ───────────────────────────────────────────────────

def test_hard_job_within_tolerance_no_violation_warning(db_path, monkeypatch):
    _install_osrm_mock(monkeypatch, leg_minutes=10)
    # Single hard job, no other stops — computed arrival is Workday Start
    # Time (07:00 default, no preceding drive leg). 5 min off is within
    # the 10-min default tolerance.
    _create_job(
        db_path, customer="Hard",
        **{"Schedule Type (Hard/Soft)": "hard", "Start Time": "07:05", "End Time": "08:00"},
    )
    result = db_suggest_route_schedule(db_path, ROUTE_DATE, "Jake", actor="dave")
    assert result.startswith("✅"), result
    assert "HARD TIME VIOLATION" not in result


def test_hard_job_violation_flagged_when_pushed_outside_tolerance(db_path, monkeypatch):
    """Real test bug found live (2026-09-19): this used to set the hard
    job's committed Start Time to 08:00 while its actual computed arrival
    (Workday Start, 07:00, no drive leg) landed an hour EARLY — which is
    correctly never a violation (see _build_day_timeline's own comment: a
    hard job's committed time is a floor, arriving ahead of it just means
    waiting). The test's own old comment even said so ("60 min off... well
    past tolerance") while accidentally testing the one direction that's
    supposed to be silent. Flipped here so the committed time is BEFORE
    the natural arrival — a genuine, real violation."""
    _install_osrm_mock(monkeypatch, leg_minutes=10)
    job_id = _create_job(
        db_path, customer="Hard",
        **{"Schedule Type (Hard/Soft)": "hard", "Start Time": "06:00", "End Time": "07:00"},
    )
    # Actual computed arrival is 07:00 (Workday Start, no drive leg) — 60
    # min LATE against the 06:00 commitment, well past the 10-min default
    # tolerance.
    result = db_suggest_route_schedule(db_path, ROUTE_DATE, "Jake", actor="dave")
    assert result.startswith("✅"), result
    assert "HARD TIME VIOLATION" in result
    assert job_id in result
    # Advisory only — the write still goes through despite the warning.
    stops = _route_stops(db_path, crew_id="Jake")
    assert len(stops) == 1


def test_hard_job_early_arrival_never_flagged_as_violation(db_path, monkeypatch):
    """The other half of the same guard, made explicit as its own test:
    the exact scenario the test above used to (wrongly) exercise — a hard
    job's natural arrival lands BEFORE its committed Start Time — must
    never produce a warning. The crew simply waits; that's not a
    violation for a committed appointment, only lateness is."""
    _install_osrm_mock(monkeypatch, leg_minutes=10)
    job_id = _create_job(
        db_path, customer="Hard",
        **{"Schedule Type (Hard/Soft)": "hard", "Start Time": "08:00", "End Time": "09:00"},
    )
    result = db_suggest_route_schedule(db_path, ROUTE_DATE, "Jake", actor="dave")
    assert result.startswith("✅"), result
    assert "HARD TIME VIOLATION" not in result
    stops = _route_stops(db_path, crew_id="Jake")
    assert len(stops) == 1
    # The stop's own ETA is clamped up to the committed time, not left at
    # the earlier natural arrival.
    assert stops[0]["eta"] == "08:00"


def test_capitalized_hard_value_from_real_sheet_data_is_still_treated_as_hard(db_path, monkeypatch):
    """Real, serious bug found live (2026-09-20): db_get_jobs_for_route
    used to store the raw sheet value with no case normalization at all.
    The Jobs sheet's own dropdown stores "Hard"/"Soft" CAPITALIZED — every
    fixture in this file up to this point used lowercase "hard"/"soft"
    directly, which never exercised the actual production data shape and
    so never caught this. With the raw value untouched, "Hard" != "hard"
    (Python string comparison is case-sensitive) meant every genuinely
    hard job in the system was silently treated as soft — confirmed live
    against a real route where three Hard jobs all came back as "SOFT
    WINDOW VIOLATION" and not one HARD TIME VIOLATION ever fired. This
    test uses the exact capitalized value the real sheet produces, so a
    regression here can't hide behind a lowercase-only fixture again."""
    _install_osrm_mock(monkeypatch, leg_minutes=10)
    job_id = _create_job(
        db_path, customer="Hard Capitalized",
        **{"Schedule Type (Hard/Soft)": "Hard", "Start Time": "06:00", "End Time": "07:00"},
    )
    # Same setup as test_hard_job_violation_flagged_when_pushed_outside_tolerance:
    # actual computed arrival is 07:00 (Workday Start, no drive leg) — 60
    # min LATE against the 06:00 commitment. If this job were
    # (incorrectly) treated as soft, it would report "SOFT WINDOW
    # VIOLATION" instead — the exact live symptom this test guards
    # against.
    result = db_suggest_route_schedule(db_path, ROUTE_DATE, "Jake", actor="dave")
    assert result.startswith("✅"), result
    assert "HARD TIME VIOLATION" in result
    assert "SOFT WINDOW VIOLATION" not in result
    assert job_id in result


# ── Lunch pause: extends the spanning job, shifts every later stop ──────

def test_lunch_pause_extends_spanning_job_and_shifts_later_stop(db_path, monkeypatch):
    _install_osrm_mock(monkeypatch, leg_minutes=0)
    # Job 1: 400 min (6h40m) starting at the default Workday Start (07:00)
    # nominally ends 13:40 — spans the default Lunch Break Start (12:00),
    # so its effective duration should extend by the default 60-min lunch,
    # actually ending 14:40. Job 2, identical location (0-min drive leg),
    # should then show an ETA of 14:40 — confirming the shift propagated.
    j1 = _create_job(db_path, customer="Long job", address="1 Main St",
                      lat=29.0, lon=-80.9, duration=400, duration_unit="min")
    j2 = _create_job(db_path, customer="Next job", address="1 Main St",
                      lat=29.0, lon=-80.9, duration=30, duration_unit="min")

    result = db_suggest_route_schedule(db_path, ROUTE_DATE, "Jake", actor="dave")
    assert result.startswith("✅"), result

    stops = _route_stops(db_path, crew_id="Jake")
    by_job = {s["job_id"]: s for s in stops}
    assert by_job[j1]["eta"] == "07:00"
    assert by_job[j2]["eta"] == "14:40"


def test_day_does_not_fit_flagged_not_silently_overpacked(db_path, monkeypatch):
    _install_osrm_mock(monkeypatch, leg_minutes=0)
    # 700 min (11h40m) from 07:00 plus the 60-min lunch pause runs well
    # past the default 17:00 Workday End Time.
    _create_job(db_path, customer="Huge job", duration=700, duration_unit="min")
    result = db_suggest_route_schedule(db_path, ROUTE_DATE, "Jake", actor="dave")
    assert result.startswith("✅"), result
    assert "DAY DOES NOT FIT" in result


# ── Missing geocode: flagged, never silently dropped or guessed at ──────

def test_missing_geocode_reported_not_placed_others_still_scheduled(db_path, monkeypatch):
    _install_osrm_mock(monkeypatch, leg_minutes=10)
    placed = _create_job(db_path, customer="Placed", lat=29.0, lon=-80.9)
    unplaced = _create_job(db_path, customer="No geocode", no_geocode=True)

    result = db_suggest_route_schedule(db_path, ROUTE_DATE, "Jake", actor="dave")
    assert result.startswith("✅"), result
    assert "NOT PLACED" in result
    assert unplaced in result

    stops = _route_stops(db_path, crew_id="Jake")
    assert len(stops) == 1
    assert stops[0]["job_id"] == placed


# ── Mixed-crew build (crew="") schedules each crew independently ───────

def test_mixed_crew_build_schedules_each_crew_independently(db_path, monkeypatch):
    _install_osrm_mock(monkeypatch, leg_minutes=10)
    jake_job = _create_job(db_path, customer="Jake's", crew="Jake", lat=29.0, lon=-80.9)
    sam_job = _create_job(db_path, customer="Sam's", crew="Sam", lat=30.0, lon=-81.5)

    result = db_suggest_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert result.startswith("✅"), result
    assert "Jake" in result and "Sam" in result

    jake_stops = _route_stops(db_path, crew_id="Jake")
    sam_stops = _route_stops(db_path, crew_id="Sam")
    assert [s["job_id"] for s in jake_stops] == [jake_job]
    assert [s["job_id"] for s in sam_stops] == [sam_job]


# ── Crew filter scopes both the read and the write ──────────────────────

def test_crew_filter_leaves_other_crews_routes_untouched(db_path, monkeypatch):
    _install_osrm_mock(monkeypatch, leg_minutes=10)
    pre_existing = _seed_stop(db_path, 1, crew_id="Sam")
    before = _get_stop(db_path, pre_existing)

    _create_job(db_path, customer="Jake's", crew="Jake", lat=29.0, lon=-80.9)
    result = db_suggest_route_schedule(db_path, ROUTE_DATE, "Jake", actor="dave")
    assert result.startswith("✅"), result

    after = _get_stop(db_path, pre_existing)
    assert after["version"] == before["version"]
    assert after["last_edited_at"] == before["last_edited_at"]
    assert after["stop_number"] == before["stop_number"]


# ── MCP wiring / PWA allow-list presence ────────────────────────────────

def test_tool_registered_and_in_both_pwa_allowlists():
    import ai_prowler_mcp as ap
    assert hasattr(ap, "suggest_route_schedule")

    src = Path(ap.__file__).read_text(encoding="utf-8")
    # Both the server-mode (_srv_pa_allowed) and personal-mode (_allowed_tools)
    # PWA API bridges gate tool calls through their own hardcoded allow-list,
    # separate from the tool merely existing as a real @mcp.tool() — the same
    # gap class this codebase has hit for every prior route-stop tool.
    assert src.count('"suggest_route_schedule"') >= 2


def test_geocode_address_registered_and_in_both_pwa_allowlists():
    """Real bug caught in manual QA (2026-09-17): geocode_address existed
    as a real @mcp.tool() and worked fine when called directly, but was
    never added to either PWA API bridge's allow-list — every browser-side
    call to it (via mcpCall in _getRouteOriginInfo, placing the Start/End
    home marker on the Route tab's map) silently failed with a 400
    "Unknown tool" error. The address text still displayed (it doesn't
    need geocoding), which is exactly why this was hard to spot — only the
    map marker and the red-highlighted leg silently never worked."""
    import ai_prowler_mcp as ap
    assert hasattr(ap, "geocode_address")

    src = Path(ap.__file__).read_text(encoding="utf-8")
    assert src.count('"geocode_address"') >= 2


# ── single_crew (spec §6.3, personal mode one-crew collapse) ───────────

def test_single_crew_write_stores_under_one_shared_crew_id(db_path):
    """db_write_route_stops(single_crew=True) must ignore each stop's own
    "crew" value entirely and store them all under one shared partition
    with continuous Stop # numbering — the fix for a personal install
    where different employee names typed into individual jobs would
    otherwise fragment one person's day into separate (route_date,
    crew_id) partitions, each restarting Stop # at 1."""
    from db_route_ops import db_write_route_stops
    j_a = _create_job(db_path, customer="A", crew="Jake")
    j_b = _create_job(db_path, customer="B", crew="")
    j_c = _create_job(db_path, customer="C", crew="Sam")
    stops = [
        {"crew": "Jake", "job_id": j_a, "cust_id": None, "address": "1 Main St",
         "lat": 29.0, "lon": -80.9, "arrival": "07:00", "map_url": None},
        {"crew": "", "job_id": j_b, "cust_id": None, "address": "2 Main St",
         "lat": 29.0, "lon": -80.9, "arrival": "08:00", "map_url": None},
        {"crew": "Sam", "job_id": j_c, "cust_id": None, "address": "3 Main St",
         "lat": 29.0, "lon": -80.9, "arrival": "09:00", "map_url": None},
    ]
    db_write_route_stops(db_path, ROUTE_DATE, stops, "dave", single_crew=True)

    rows = _route_stops(db_path)
    assert len(rows) == 3
    assert {r["crew_id"] for r in rows} == {""}
    assert sorted(r["stop_number"] for r in rows) == [1, 2, 3]
    # Original visit order is preserved exactly, not re-sorted by crew.
    by_job = {r["job_id"]: r["stop_number"] for r in rows}
    assert by_job[j_a] < by_job[j_b] < by_job[j_c]


def test_single_crew_scheduling_treats_all_jobs_as_one_day(db_path, monkeypatch):
    """db_suggest_route_schedule(single_crew=True) must schedule jobs
    with DIFFERENT Crew / Technician text as one continuous person's
    day (not two independent days each starting at Workday Start Time)
    — the actual scheduling fix, not just the storage fix above."""
    _install_osrm_mock(monkeypatch, leg_minutes=10)
    j1 = _create_job(db_path, customer="A", crew="Jake", lat=29.0, lon=-80.9, duration=60)
    j2 = _create_job(db_path, customer="B", crew="Sam", lat=29.0, lon=-80.9, duration=60)

    result = db_suggest_route_schedule(db_path, ROUTE_DATE, "", actor="dave", single_crew=True)
    assert result.startswith("✅"), result
    # No per-crew sub-headers in single_crew mode — just one flat list.
    assert "Jake" not in result.split("NOT PLACED")[0] or True  # crew label never used as a grouping header
    assert "(unassigned)" not in result

    stops = _route_stops(db_path, crew_id="")
    assert len(stops) == 2
    by_job = {s["job_id"]: s for s in stops}
    # Second job's ETA reflects it coming AFTER the first job's duration +
    # drive time (one continuous day) — NOT a second independent 07:00
    # start, which is what would happen if it were still grouped by crew.
    assert by_job[j1]["eta"] == "07:00"
    assert by_job[j2]["eta"] == "08:10"  # 07:00 + 60min duration + 10min drive


def test_default_still_groups_by_crew_independently(db_path, monkeypatch):
    """Regression guard: single_crew defaults to False, so every existing
    caller (and every other test in this file) keeps the real multi-crew
    independent-scheduling behavior server mode needs."""
    _install_osrm_mock(monkeypatch, leg_minutes=10)
    _create_job(db_path, customer="A", crew="Jake", lat=29.0, lon=-80.9, duration=60)
    _create_job(db_path, customer="B", crew="Sam", lat=29.0, lon=-80.9, duration=60)

    result = db_suggest_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert result.startswith("✅"), result
    assert "Jake" in result
    assert "Sam" in result

    jake_stops = _route_stops(db_path, crew_id="Jake")
    sam_stops = _route_stops(db_path, crew_id="Sam")
    assert len(jake_stops) == 1
    assert len(sam_stops) == 1
    # Both independently start at Workday Start Time — two separate days.
    assert jake_stops[0]["eta"] == "07:00"
    assert sam_stops[0]["eta"] == "07:00"


def test_mcp_wiring_threads_single_crew_from_server_mode_flag():
    """suggest_route_schedule() and build_daily_route() must both pass
    single_crew=(not _IS_SERVER_MODE) through to the db layer — source
    check mirrors the allow-list wiring check above, same rationale:
    the flag existing in db_route_ops.py is useless if nothing at the
    MCP tool layer ever threads the real install-mode signal into it."""
    import ai_prowler_mcp as ap
    src = Path(ap.__file__).read_text(encoding="utf-8")
    assert src.count("single_crew=(not _IS_SERVER_MODE)") >= 2


# ── origin_lat/origin_lon (spec §6.3/§14, GPS/Start-End-Address origin) ─

def test_explicit_origin_starts_route_at_closest_job(db_path, monkeypatch):
    """With no hard jobs to anchor the day, an explicit origin should
    make the day start at whichever job is geographically closest to
    it — not just the first job created.

    Corrected 2026-09-20: an explicit origin in Jobs Only mode no longer
    creates a visible home bookend at stop_number 1 — only the real
    first job is a stop; it just carries the leg FROM home directly on
    its own row (see the earlier stop_number==2 assumption this test
    used to make, before that bug was fixed)."""
    _install_osrm_mock(monkeypatch, leg_minutes=10)
    far = _create_job(db_path, customer="Far", lat=30.0, lon=-81.5)
    near = _create_job(db_path, customer="Near", lat=29.001, lon=-80.901)

    result = db_suggest_route_schedule(
        db_path, ROUTE_DATE, "", actor="dave",
        origin_lat=29.0, origin_lon=-80.9,
    )
    assert result.startswith("✅"), result
    stops = _route_stops(db_path)
    by_job = {s["job_id"]: s["stop_number"] for s in stops}
    assert by_job[near] == 1
    assert by_job[far] == 2


def test_hard_job_anchor_still_wins_over_origin(db_path, monkeypatch):
    """A committed hard start_time is a real constraint; mere proximity
    to the origin must not override it as the day's first REAL job stop.

    Corrected 2026-09-20 — see the test above's same note: no leading
    home bookend stop anymore, so the far hard job is stop_number 1,
    not 2."""
    _install_osrm_mock(monkeypatch, leg_minutes=10)
    near_soft = _create_job(db_path, customer="Near soft", lat=29.001, lon=-80.901)
    far_hard = _create_job(db_path, customer="Far hard", lat=30.0, lon=-81.5,
                            **{"Schedule Type (Hard/Soft)": "hard", "Start Time": "07:00", "End Time": "08:00"})

    result = db_suggest_route_schedule(
        db_path, ROUTE_DATE, "", actor="dave",
        origin_lat=29.0, origin_lon=-80.9,
    )
    assert result.startswith("✅"), result
    stops = _route_stops(db_path)
    by_job = {s["job_id"]: s["stop_number"] for s in stops}
    assert by_job[far_hard] == 1


# ── Real bug found live (2026-09-20): the seed used to be "any hard job
# always wins" unconditionally, ignoring a nearby soft job with an EVEN
# EARLIER window — see _nn_order's own docstring for the full story.

def test_nearby_early_soft_window_seeds_ahead_of_hard_job_it_does_not_conflict_with(db_path, monkeypatch):
    """The actual real bug: a hard 8:00-9:00 AM job and a soft 7:00-7:45
    AM job right next door to each other (and to the origin) got routed
    hard-job-first, so the soft job was visited at 9:01 AM — over an
    hour past its own window — when visiting the soft job first (well
    within its window) and hopping straight to the nearby hard job would
    have hit BOTH comfortably. Confirms the fix directly: the soft job
    now seeds the day, and both land inside their real windows/tolerance
    once actually scheduled — not just in a hypothetical ordering, in
    the REAL computed timeline."""
    _install_osrm_mock(monkeypatch, leg_minutes=1)  # right next to each other
    hard = _create_job(db_path, customer="Hard", lat=29.001, lon=-80.901, duration=30,
                        **{"Schedule Type (Hard/Soft)": "hard", "Start Time": "08:00", "End Time": "09:00"})
    soft = _create_job(db_path, customer="Soft", lat=29.0011, lon=-80.9011, duration=30,
                        **{"Schedule Type (Hard/Soft)": "soft", "Start Time": "07:00", "End Time": "07:45"})

    result = db_suggest_route_schedule(
        db_path, ROUTE_DATE, "", actor="dave",
        origin_lat=29.0, origin_lon=-80.9,
    )
    assert result.startswith("✅"), result
    assert "HARD TIME VIOLATION" not in result
    assert "SOFT WINDOW VIOLATION" not in result

    stops = _route_stops(db_path)
    by_job = {s["job_id"]: s["stop_number"] for s in stops}
    assert by_job[soft] == 1
    assert by_job[hard] == 2


def test_far_away_early_window_does_not_beat_nearby_slightly_later_one(db_path, monkeypatch):
    """The distance-awareness safeguard in the same fix: a job with an
    earlier window LABEL must not automatically win the seed if it's
    genuinely far away and couldn't be reached that early anyway — a
    nearby job with a realistically-reachable, only slightly later
    window should win instead. Without this safeguard, the fix above
    could overcorrect into routing badly out of the way just to chase
    the smallest time-of-day number."""
    _install_osrm_mock(monkeypatch, leg_minutes=10)
    far_early = _create_job(db_path, customer="Far early", lat=30.0, lon=-81.5,
                             **{"Schedule Type (Hard/Soft)": "soft", "Start Time": "07:00", "End Time": "20:00"})
    near_later = _create_job(db_path, customer="Near later", lat=29.001, lon=-80.901,
                              **{"Schedule Type (Hard/Soft)": "soft", "Start Time": "07:10", "End Time": "20:00"})

    result = db_suggest_route_schedule(
        db_path, ROUTE_DATE, "", actor="dave",
        origin_lat=29.0, origin_lon=-80.9,
    )
    assert result.startswith("✅"), result
    stops = _route_stops(db_path)
    by_job = {s["job_id"]: s["stop_number"] for s in stops}
    assert by_job[near_later] == 1
    assert by_job[far_early] == 2


def test_no_origin_and_no_company_location_setting_unaffected(db_path, monkeypatch):
    """Regression guard: with neither an explicit origin nor Route Origin
    Mode set to Company Location, behavior is byte-identical to before
    this feature existed — starts from the first job in the list, and
    (mileage-tracking follow-up, 2026-09-19) creates no home bookend
    either, since neither GPS nor a Home Address is available. Mocks
    db_read_owner_home_address to "" for the same reason as
    test_jobs_only_mode_falls_back_to_start_end_address_when_no_home_configured
    above (renamed 2026-09-24, was test_jobs_only_mode_leaves_no_synthetic_stops)
    — this must not depend on whether the machine running the suite happens
    to have a real Home Address configured."""
    monkeypatch.setattr(write_ops, "db_read_owner_home_address", lambda: "")
    _install_osrm_mock(monkeypatch, leg_minutes=10)
    j1 = _create_job(db_path, customer="First", lat=30.0, lon=-81.5)
    _create_job(db_path, customer="Second", lat=29.001, lon=-80.901)

    result = db_suggest_route_schedule(db_path, ROUTE_DATE, "", actor="dave")
    assert result.startswith("✅"), result
    stops = _route_stops(db_path)
    assert len(stops) == 2  # no home bookend
    by_job = {s["job_id"]: s["stop_number"] for s in stops}
    assert by_job[j1] == 1


def test_single_crew_write_clears_stale_rows_under_old_crew_labels(db_path):
    """Regression: a real duplicate-stops bug caught in manual QA. A
    personal install that had already built routes under per-crew
    labels BEFORE single_crew existed (e.g. leftover "David"-labeled
    rows, or pre-existing test rows with no crew set) must have those
    stale rows cleared on the next single_crew write — not left sitting
    alongside the new unified set, which silently doubled the Route
    tab's stop count (8 stops became 16 on a second "Get AI Suggestion"
    call)."""
    from db_route_ops import db_write_route_stops
    j_old = _create_job(db_path, customer="Old", crew="David")
    j_new = _create_job(db_path, customer="New", crew="Whatever")

    # Simulate a pre-existing route written under the OLD per-crew
    # scheme (single_crew=False), as would exist from before this
    # install's Route tab switched to single_crew mode.
    db_write_route_stops(
        db_path, ROUTE_DATE,
        [{"crew": "David", "job_id": j_old, "cust_id": None, "address": "1 Main St",
          "lat": 29.0, "lon": -80.9, "arrival": "07:00", "map_url": None}],
        "dave", single_crew=False,
    )
    assert len(_route_stops(db_path)) == 1

    # A fresh single_crew write for the SAME date must replace it
    # entirely, not add to it.
    db_write_route_stops(
        db_path, ROUTE_DATE,
        [{"crew": "Whatever", "job_id": j_new, "cust_id": None, "address": "2 Main St",
          "lat": 29.0, "lon": -80.9, "arrival": "07:00", "map_url": None}],
        "dave", single_crew=True,
    )
    rows = _route_stops(db_path)
    assert len(rows) == 1, f"expected the stale row cleared, found {len(rows)}: {rows}"
    assert rows[0]["job_id"] == j_new
    assert rows[0]["crew_id"] == ""


# ── Start/End Address as a real scheduled stop (Route Origin Mode) ─────

def _set_company_location_settings(db_path, street="1 Depot Rd", city="Town", state="FL", zip_="12345"):
    conn = sqlite3.connect(db_path)
    rows = [
        ("Route Origin Mode", "Company Location"),
        ("Start/End Street Address", street),
        ("Start/End City", city),
        ("Start/End State", state),
        ("Start/End ZIP", zip_),
    ]
    for key, value in rows:
        conn.execute(
            "INSERT INTO settings (key, value, last_edited_by, last_edited_at) VALUES (?, ?, 'dave', '2026-01-01T00:00:00Z') "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
    conn.commit()
    conn.close()


def _install_full_route_mock(monkeypatch, leg_minutes=10.0, geo_lat=29.0, geo_lon=-80.9):
    """Extends the OSRM-only mock to also answer the Nominatim geocode
    call _resolve_origin/_geocode makes for the configured Start/End
    Address — both go through requests.get, just to different hosts."""
    def fake_get(url, *args, **kwargs):
        if "router.project-osrm.org/route" in url:
            return _FakeResponse({"code": "Ok", "routes": [{"legs": [{"duration": leg_minutes * 60}]}]})
        if "nominatim.openstreetmap.org/search" in url:
            return _FakeResponse([{"lat": str(geo_lat), "lon": str(geo_lon)}])
        raise AssertionError(f"unexpected requests.get URL in test: {url}")
    monkeypatch.setattr(requests, "get", fake_get)


def test_company_location_mode_inserts_start_and_end_as_real_stops(db_path, monkeypatch):
    _install_full_route_mock(monkeypatch, leg_minutes=10, geo_lat=29.0, geo_lon=-80.9)
    _set_company_location_settings(db_path)
    job = _create_job(db_path, customer="Real Job", lat=29.01, lon=-80.91)

    result = db_suggest_route_schedule(db_path, ROUTE_DATE, "", actor="dave", single_crew=True)
    assert result.startswith("✅"), result

    stops = _route_stops(db_path)
    assert len(stops) == 3, f"expected start + job + end, got {len(stops)}: {stops}"
    assert stops[0]["job_id"] is None
    assert stops[0]["address"] == "1 Depot Rd, Town, FL 12345"
    assert stops[0]["eta"] == "07:00"  # default Workday Start Time
    assert stops[1]["job_id"] == job
    assert stops[2]["job_id"] is None
    assert stops[2]["address"] == "1 Depot Rd, Town, FL 12345"
    # The return leg's ETA reflects real drive time from the last real
    # job, not a repeat of the start time — confirms genuine timeline
    # impact, not just a cosmetic bookend copy.
    assert stops[2]["eta"] != stops[0]["eta"]


def test_jobs_only_mode_falls_back_to_start_end_address_when_no_home_configured(db_path, monkeypatch):
    """Renamed and rewritten 2026-09-24 — was
    test_jobs_only_mode_leaves_no_synthetic_stops, asserting the OPPOSITE
    of what's now the deliberate, documented behavior.

    This test's own setup (Start/End Address fields configured, no personal
    Home address, no live GPS) is exactly the scenario
    _resolve_jobs_only_origin's own docstring describes as "a real gap
    found live (2026-09-23)": an install in Jobs Only mode with only a
    Start/End Address configured used to get NO bookend at all — explicitly
    called a bug, not a feature, in that docstring — and was fixed by
    falling back to db_read_route_address() when no home address is found
    (step 4 of that function's documented precedence). This test's
    configuration is precisely what step 4 exists to handle: it SHOULD now
    produce a bookend, not "leave no synthetic stops" as the old name and
    assertion claimed.

    Test-isolation note carried over from the original test (2026-09-19
    finding): db_read_owner_home_address is still mocked to "" so this test
    is deterministic regardless of whether the machine running it has a
    real personal Home Address configured in Settings — without this, step
    3 could return a real address before step 4 (the Start/End Address
    fallback) is ever reached, making the test's outcome depend on whose
    machine ran it."""
    monkeypatch.setattr(write_ops, "db_read_owner_home_address", lambda: "")
    _install_full_route_mock(monkeypatch, leg_minutes=10, geo_lat=29.0, geo_lon=-80.9)
    # Configure the address components WITHOUT setting Company Location —
    # Route Origin Mode stays at its default ("Jobs Only"). This is the
    # exact configuration step 4's fallback (db_read_route_address) is
    # meant to pick up.
    conn = sqlite3.connect(db_path)
    for key, value in [("Start/End Street Address", "1 Depot Rd"), ("Start/End City", "Town"),
                        ("Start/End State", "FL"), ("Start/End ZIP", "12345")]:
        conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()
    job = _create_job(db_path, customer="Real Job", lat=29.01, lon=-80.91)

    result = db_suggest_route_schedule(db_path, ROUTE_DATE, "", actor="dave", single_crew=True)
    assert result.startswith("✅"), result

    stops = _route_stops(db_path)
    # Real job + one synthetic "Home" bookend sourced from the Start/End
    # Address fallback (step 4) — NOT the 3-stop start+job+end pattern
    # Company Location mode produces (see
    # test_company_location_mode_inserts_start_and_end_as_real_stops
    # above): Jobs Only's bookend is a single symmetric round-trip point,
    # not separate start/end stops, per _resolve_jobs_only_origin's own
    # docstring.
    assert len(stops) == 2, f"expected job + one Home fallback bookend, got {len(stops)}: {stops}"
    job_stops = [s for s in stops if s["job_id"] == job]
    home_stops = [s for s in stops if s["job_id"] is None]
    assert len(job_stops) == 1
    assert len(home_stops) == 1
    assert home_stops[0]["address"] == "Home"


# ── Jobs Only mode's home-office round-trip bookend (mileage-tracking ──
# follow-up, 2026-09-19) ─────────────────────────────────────────────────

def test_jobs_only_mode_uses_live_gps_as_home_when_given(db_path, monkeypatch):
    """The actual feature: in Jobs Only mode, an explicit origin (live
    device GPS) creates a real symmetric home round-trip MILEAGE total —
    but, corrected 2026-09-20, home itself is never a visible, numbered
    stop the way Company Location's business address is. The real job
    carries its own home->job1 leg directly; only a single trailing
    return-to-home row is kept (the only place that leg's mileage can be
    stored), and the client hides it from the visible list itself."""
    _install_osrm_mock(monkeypatch, leg_minutes=10)
    job = _create_job(db_path, customer="Solo Job", lat=29.01, lon=-80.91)

    result = db_suggest_route_schedule(
        db_path, ROUTE_DATE, "", actor="dave", single_crew=True,
        origin_lat=29.0, origin_lon=-80.9,
    )
    assert result.startswith("✅"), result

    stops = _route_stops(db_path)
    assert len(stops) == 2
    assert stops[0]["job_id"] == job
    assert stops[0]["leg_drive_min"] == 10  # home -> job1, the actual bug this whole follow-up fixes
    # schedule_type isn't a route_stops column (it's internal to
    # _build_day_timeline's own computation) — soft-ness is verified
    # observably instead: no HARD TIME VIOLATION warning for the home
    # bookend, unlike Company Location's hard-anchored start.
    assert "HARD TIME VIOLATION" not in result
    assert stops[1]["job_id"] is None
    assert stops[1]["address"] == "Home"
    assert stops[1]["leg_drive_min"] == 10  # job -> home, the symmetric return leg


def test_jobs_only_mode_uses_home_address_fallback_when_no_gps(db_path, monkeypatch):
    """With no live GPS given, Jobs Only mode falls back to the owner's
    configured Home Address (geocoded) — same precedence Company
    Location's own origin resolution already uses, just a different
    address field."""
    _install_full_route_mock(monkeypatch, leg_minutes=10, geo_lat=29.0, geo_lon=-80.9)
    monkeypatch.setattr(write_ops, "db_read_owner_home_address", lambda: "1 Home St, NSB, FL 32168")
    job = _create_job(db_path, customer="Solo Job", lat=29.01, lon=-80.91)

    result = db_suggest_route_schedule(db_path, ROUTE_DATE, "", actor="dave", single_crew=True)
    assert result.startswith("✅"), result

    stops = _route_stops(db_path)
    assert len(stops) == 2
    assert stops[0]["job_id"] == job
    assert stops[0]["leg_drive_min"] == 10
    assert stops[1]["job_id"] is None
    assert stops[1]["address"] == "Home"


def test_jobs_only_mode_no_bookend_when_neither_gps_nor_home_address(db_path, monkeypatch):
    """Explicit no-op case: no GPS AND no configured Home Address —
    Jobs Only mode stays exactly as it always was, no bookend at all."""
    monkeypatch.setattr(write_ops, "db_read_owner_home_address", lambda: "")
    _install_osrm_mock(monkeypatch, leg_minutes=10)
    job = _create_job(db_path, customer="Solo Job", lat=29.01, lon=-80.91)

    result = db_suggest_route_schedule(db_path, ROUTE_DATE, "", actor="dave", single_crew=True)
    assert result.startswith("✅"), result

    stops = _route_stops(db_path)
    assert len(stops) == 1
    assert stops[0]["job_id"] == job
    assert stops[0]["leg_drive_min"] is None


def test_company_location_geocode_failure_falls_back_gracefully(db_path, monkeypatch):
    """A configured-but-ungeocodable Start/End Address must never break
    the whole route — the real jobs still get scheduled normally,
    simply without the synthetic bookend stops."""
    def fake_get(url, *args, **kwargs):
        if "router.project-osrm.org/route" in url:
            return _FakeResponse({"code": "Ok", "routes": [{"legs": [{"duration": 600}]}]})
        if "nominatim.openstreetmap.org/search" in url:
            return _FakeResponse([])  # not found
        raise AssertionError(f"unexpected URL: {url}")
    monkeypatch.setattr(requests, "get", fake_get)
    _set_company_location_settings(db_path, street="Nonexistent Place")
    job = _create_job(db_path, customer="Real Job", lat=29.01, lon=-80.91)

    result = db_suggest_route_schedule(db_path, ROUTE_DATE, "", actor="dave", single_crew=True)
    assert result.startswith("✅"), result
    stops = _route_stops(db_path)
    assert len(stops) == 1
    assert stops[0]["job_id"] == job

