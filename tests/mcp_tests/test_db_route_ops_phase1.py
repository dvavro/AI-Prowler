"""
tests/mcp_tests/test_db_route_ops_phase1.py
=========================================
Job Board Architecture Spec — Phase 1 (spec §4.2, §5, §6.4, §11).

Direct unit tests for db_route_ops.py's storage helpers. The routing
computation itself (geocoding, OSRM TSP, savings/late/overlap checks)
stays in ai_prowler_mcp.py and is exercised separately in
test_job_board_phase1_route_wiring.py with requests.get mocked out.

The single most important test in this file is
test_two_crews_same_date_do_not_clobber_each_other — this is the exact
regression test spec §6.4/§11 calls out by name: "explicit regression
test that two different crews building routes for the same date do not
affect each other's stops — this is the direct fix for a real bug found
this session, so it should be asserted, not assumed fixed by virtue of
the new schema."

Run with:
    run_tests.bat tests\\mcp\\test_db_route_ops_phase1.py -v
"""
import sqlite3

import pytest

from db_access import init_db
from db_route_ops import (
    db_get_jobs_for_route,
    db_update_job_geocode,
    db_update_job_route_url,
    db_write_route_stops,
)
from db_write_ops import db_create_customer, db_create_job, db_schedule_next_recurring_job


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _cust_id(db_path, name="A"):
    """Job Board Architecture Spec §5.1 (2026-09-22): create_job now
    requires a real, existing CustomerID."""
    result = db_create_customer(db_path, {"Company Name": name}, actor="dave")
    return result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()


# ══════════════════════════════════════════════════════════════════════════
# db_get_jobs_for_route
# ══════════════════════════════════════════════════════════════════════════

def test_get_jobs_for_route_matches_date(db_path):
    db_create_job(db_path, {
        "CustomerID (Customers!A)": _cust_id(db_path, "A"), "Customer Name / Company": "A", "Service Date": "2026-04-05",
        "Street Address": "1 Main St", "City": "NSB", "State": "FL",
    }, actor="dave")
    db_create_job(db_path, {
        "CustomerID (Customers!A)": _cust_id(db_path, "B"), "Customer Name / Company": "B", "Service Date": "2026-04-06",
        "Street Address": "2 Main St", "City": "NSB", "State": "FL",
    }, actor="dave")
    jobs = db_get_jobs_for_route(db_path, "2026-04-05")
    assert len(jobs) == 1
    assert jobs[0]["cust_name"] == "A"


def test_get_jobs_for_route_filters_by_crew(db_path):
    db_create_job(db_path, {
        "CustomerID (Customers!A)": _cust_id(db_path, "A"), "Customer Name / Company": "A", "Service Date": "2026-04-05", "Crew / Technician": "Jake R",
        "Street Address": "1 Main St", "City": "NSB", "State": "FL",
    }, actor="dave")
    db_create_job(db_path, {
        "CustomerID (Customers!A)": _cust_id(db_path, "B"), "Customer Name / Company": "B", "Service Date": "2026-04-05", "Crew / Technician": "Maria S",
        "Street Address": "2 Main St", "City": "NSB", "State": "FL",
    }, actor="dave")
    jobs = db_get_jobs_for_route(db_path, "2026-04-05", crew="Jake R")
    assert len(jobs) == 1
    assert jobs[0]["cust_name"] == "A"


def test_get_jobs_for_route_skips_jobs_with_no_address(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "NoAddr"), "Customer Name / Company": "NoAddr", "Service Date": "2026-04-05"}, actor="dave")
    jobs = db_get_jobs_for_route(db_path, "2026-04-05")
    assert jobs == []


def test_get_jobs_for_route_returns_existing_geocode(db_path):
    db_create_job(db_path, {
        "CustomerID (Customers!A)": _cust_id(db_path, "A"), "Customer Name / Company": "A", "Service Date": "2026-04-05",
        "Street Address": "1 Main St", "City": "NSB", "State": "FL",
        "Latitude (AI Geocode)": 29.02, "Longitude (AI Geocode)": -80.92,
    }, actor="dave")
    jobs = db_get_jobs_for_route(db_path, "2026-04-05")
    assert jobs[0]["lat"] == 29.02
    assert jobs[0]["lon"] == -80.92


# ══════════════════════════════════════════════════════════════════════════
# db_update_job_geocode / db_update_job_route_url
# ══════════════════════════════════════════════════════════════════════════

def test_update_job_geocode_writes_back(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "A"), "Customer Name / Company": "A"}, actor="dave")
    db_update_job_geocode(db_path, "JOB-0001", 29.02, -80.92, actor="dave")
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT latitude, longitude FROM jobs WHERE job_id = 'JOB-0001'").fetchone()
    conn.close()
    assert row == (29.02, -80.92)


def test_update_job_route_url_writes_back(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "A"), "Customer Name / Company": "A"}, actor="dave")
    db_update_job_route_url(db_path, "JOB-0001", "https://maps.google.com/xyz", actor="dave")
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT route_map_url FROM jobs WHERE job_id = 'JOB-0001'").fetchone()
    conn.close()
    assert row[0] == "https://maps.google.com/xyz"


# ══════════════════════════════════════════════════════════════════════════
# db_write_route_stops — THE regression test spec §6.4/§11 calls out
# ══════════════════════════════════════════════════════════════════════════

def _seed_job(db_path, job_id_num, cust_id_num, crew=""):
    """Creates a real customer + job row so route_stops' FK references
    (job_id, customer_id) resolve to something that actually exists —
    route_stops always originates from real job rows in production via
    db_get_jobs_for_route, so these tests should too."""
    cust_result = db_create_customer(db_path, {"Company Name": f"Cust {cust_id_num}"}, actor="dave")
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    job_result = db_create_job(db_path, {
        "CustomerID (Customers!A)": cust_id, "Customer Name / Company": f"Cust {cust_id_num}",
        "Crew / Technician": crew,
    }, actor="dave")
    job_id = job_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()
    return job_id, cust_id


def test_route_stops_written_correctly(db_path):
    j1, c1 = _seed_job(db_path, 1, 1, "Jake R")
    j2, c2 = _seed_job(db_path, 2, 2, "Jake R")
    stops = [
        {"crew": "Jake R", "job_id": j1, "cust_id": c1, "address": "1 Main St",
         "lat": 29.0, "lon": -80.9, "arrival": "08:00", "map_url": "https://x.test/a"},
        {"crew": "Jake R", "job_id": j2, "cust_id": c2, "address": "2 Main St",
         "lat": 29.1, "lon": -80.8, "arrival": "09:00", "map_url": "https://x.test/a"},
    ]
    cleared = db_write_route_stops(db_path, "2026-04-05", stops, actor="dave")
    assert cleared == 0

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM route_stops WHERE route_date = '2026-04-05' AND crew_id = 'Jake R' ORDER BY stop_number"
    ).fetchall()
    conn.close()
    assert len(rows) == 2
    assert rows[0]["stop_number"] == 1
    assert rows[0]["job_id"] == j1
    assert rows[1]["stop_number"] == 2


def test_two_crews_same_date_do_not_clobber_each_other(db_path):
    """THE explicit regression test called out in spec §6.4/§11: building
    one crew's route for a date must never clear or overwrite another
    crew's already-built route for that SAME date — the exact bug the
    old single shared Route_Planner sheet had."""
    j1, c1 = _seed_job(db_path, 1, 1, "Jake R")
    j2, c2 = _seed_job(db_path, 2, 2, "Vicki V")

    jake_stops = [
        {"crew": "Jake R", "job_id": j1, "cust_id": c1, "address": "1 Main St",
         "lat": 29.0, "lon": -80.9, "arrival": "08:00", "map_url": "https://x.test/jake"},
    ]
    db_write_route_stops(db_path, "2026-04-05", jake_stops, actor="dave")

    # Now build Vicki's route for the SAME date — must not touch Jake's rows.
    vicki_stops = [
        {"crew": "Vicki V", "job_id": j2, "cust_id": c2, "address": "2 Main St",
         "lat": 29.1, "lon": -80.8, "arrival": "09:00", "map_url": "https://x.test/vicki"},
    ]
    cleared = db_write_route_stops(db_path, "2026-04-05", vicki_stops, actor="dave")
    assert cleared == 0  # nothing previously stored for Vicki on this date

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    jake_rows = conn.execute(
        "SELECT * FROM route_stops WHERE route_date = '2026-04-05' AND crew_id = 'Jake R'"
    ).fetchall()
    vicki_rows = conn.execute(
        "SELECT * FROM route_stops WHERE route_date = '2026-04-05' AND crew_id = 'Vicki V'"
    ).fetchall()
    conn.close()

    # Jake's route is STILL THERE, completely untouched by Vicki's build.
    assert len(jake_rows) == 1
    assert jake_rows[0]["job_id"] == j1
    # Vicki's route was written correctly alongside it.
    assert len(vicki_rows) == 1
    assert vicki_rows[0]["job_id"] == j2


def test_rebuilding_same_crew_same_date_clears_only_that_crew(db_path):
    j1, c1 = _seed_job(db_path, 1, 1, "Jake R")
    j2, c2 = _seed_job(db_path, 2, 2, "Vicki V")
    j3, c3 = _seed_job(db_path, 3, 3, "Jake R")
    j4, c4 = _seed_job(db_path, 4, 4, "Jake R")

    stops_v1 = [
        {"crew": "Jake R", "job_id": j1, "cust_id": c1, "address": "1 Main St",
         "lat": 29.0, "lon": -80.9, "arrival": "08:00", "map_url": None},
    ]
    other_crew_stops = [
        {"crew": "Vicki V", "job_id": j2, "cust_id": c2, "address": "2 Main St",
         "lat": 29.1, "lon": -80.8, "arrival": "09:00", "map_url": None},
    ]
    db_write_route_stops(db_path, "2026-04-05", stops_v1, actor="dave")
    db_write_route_stops(db_path, "2026-04-05", other_crew_stops, actor="dave")

    # Rebuild Jake's route with 2 stops now — should clear his old 1 row
    # and write 2 new ones, WITHOUT touching Vicki's row.
    stops_v2 = [
        {"crew": "Jake R", "job_id": j3, "cust_id": c3, "address": "3 Main St",
         "lat": 29.2, "lon": -80.7, "arrival": "08:00", "map_url": None},
        {"crew": "Jake R", "job_id": j4, "cust_id": c4, "address": "4 Main St",
         "lat": 29.3, "lon": -80.6, "arrival": "09:00", "map_url": None},
    ]
    cleared = db_write_route_stops(db_path, "2026-04-05", stops_v2, actor="dave")
    assert cleared == 1  # Jake's one old row

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    jake_rows = conn.execute(
        "SELECT * FROM route_stops WHERE route_date = '2026-04-05' AND crew_id = 'Jake R' ORDER BY stop_number"
    ).fetchall()
    vicki_rows = conn.execute(
        "SELECT * FROM route_stops WHERE route_date = '2026-04-05' AND crew_id = 'Vicki V'"
    ).fetchall()
    conn.close()
    assert [r["job_id"] for r in jake_rows] == [j3, j4]
    assert len(vicki_rows) == 1  # untouched


def test_mixed_crew_build_partitions_by_each_jobs_own_crew(db_path):
    """A build with no crew filter (crew="") routes every job on the date
    together, but storage still partitions each stop under its OWN job's
    crew, per-crew-numbered — never one shared bucket for the whole
    mixed-crew build."""
    j1, c1 = _seed_job(db_path, 1, 1, "Jake R")
    j2, c2 = _seed_job(db_path, 2, 2, "Vicki V")
    j3, c3 = _seed_job(db_path, 3, 3, "Jake R")

    mixed_stops = [
        {"crew": "Jake R", "job_id": j1, "cust_id": c1, "address": "1 Main St",
         "lat": 29.0, "lon": -80.9, "arrival": "08:00", "map_url": None},
        {"crew": "Vicki V", "job_id": j2, "cust_id": c2, "address": "2 Main St",
         "lat": 29.1, "lon": -80.8, "arrival": "09:00", "map_url": None},
        {"crew": "Jake R", "job_id": j3, "cust_id": c3, "address": "3 Main St",
         "lat": 29.2, "lon": -80.7, "arrival": "10:00", "map_url": None},
    ]
    db_write_route_stops(db_path, "2026-04-05", mixed_stops, actor="dave")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    jake_rows = conn.execute(
        "SELECT * FROM route_stops WHERE route_date = '2026-04-05' AND crew_id = 'Jake R' ORDER BY stop_number"
    ).fetchall()
    vicki_rows = conn.execute(
        "SELECT * FROM route_stops WHERE route_date = '2026-04-05' AND crew_id = 'Vicki V'"
    ).fetchall()
    conn.close()

    # Jake's two stops are independently numbered 1, 2 (not 1, 3, preserving
    # global position) — each crew's subsequence is its own clean sequence.
    assert [r["stop_number"] for r in jake_rows] == [1, 2]
    assert [r["job_id"] for r in jake_rows] == [j1, j3]
    assert len(vicki_rows) == 1
    assert vicki_rows[0]["stop_number"] == 1


def test_blank_crew_falls_back_to_unassigned(db_path):
    j1, c1 = _seed_job(db_path, 1, 1, "")
    stops = [
        {"crew": "", "job_id": j1, "cust_id": c1, "address": "1 Main St",
         "lat": 29.0, "lon": -80.9, "arrival": "08:00", "map_url": None},
    ]
    db_write_route_stops(db_path, "2026-04-05", stops, actor="dave")
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT crew_id FROM route_stops WHERE route_date = '2026-04-05'"
    ).fetchone()
    conn.close()
    assert row[0] == "(unassigned)"


# ══════════════════════════════════════════════════════════════════════════
# db_schedule_next_recurring_job (db_write_ops.py)
# ══════════════════════════════════════════════════════════════════════════

def test_schedule_next_weekly(db_path):
    db_create_customer(db_path, {"Company Name": "Weekly Co", "Frequency": "Weekly"}, actor="dave")
    db_create_job(db_path, {
        "CustomerID (Customers!A)": "CUST-0001", "Customer Name / Company": "Weekly Co",
        "Service Date": "2026-04-05",
    }, actor="dave")
    result = db_schedule_next_recurring_job(db_path, "JOB-0001", actor="dave")
    assert result.startswith("✅"), result
    assert "04/12/2026" in result  # +7 days


def test_schedule_next_monthly_handles_month_end_overflow(db_path):
    db_create_customer(db_path, {"Company Name": "Monthly Co", "Frequency": "Monthly"}, actor="dave")
    db_create_job(db_path, {
        "CustomerID (Customers!A)": "CUST-0001", "Customer Name / Company": "Monthly Co",
        "Service Date": "2026-01-31",
    }, actor="dave")
    result = db_schedule_next_recurring_job(db_path, "JOB-0001", actor="dave")
    assert result.startswith("✅"), result
    assert "02/28/2026" in result  # Jan 31 + 1 month -> Feb 28 (2026 not a leap year)


def test_schedule_next_one_time_customer_no_job_created(db_path):
    db_create_customer(db_path, {"Company Name": "OneTime Co", "Frequency": "One-time"}, actor="dave")
    db_create_job(db_path, {
        "CustomerID (Customers!A)": "CUST-0001", "Customer Name / Company": "OneTime Co",
        "Service Date": "2026-04-05",
    }, actor="dave")
    result = db_schedule_next_recurring_job(db_path, "JOB-0001", actor="dave")
    assert result.startswith("ℹ️")
    assert "one-time customer" in result


def _legacy_weird_frequency_customer(db_path):
    """A customer whose stored Frequency is unrecognisable. R-057 refuses such a
    value on save (and reads "Fortnightly" as Biweekly), so it can only be
    legacy data — written straight into the table."""
    import sqlite3
    db_create_customer(db_path, {"Company Name": "Weird Co", "Frequency": "Weekly"}, actor="dave")
    c = sqlite3.connect(db_path)
    c.execute("UPDATE customers SET frequency = 'Whenever convenient' WHERE customer_id = 'CUST-0001'")
    c.commit()
    c.close()


def test_schedule_next_unrecognized_frequency_rejected(db_path):
    _legacy_weird_frequency_customer(db_path)
    db_create_job(db_path, {
        "CustomerID (Customers!A)": "CUST-0001", "Customer Name / Company": "Weird Co",
        "Service Date": "2026-04-05",
    }, actor="dave")
    result = db_schedule_next_recurring_job(db_path, "JOB-0001", actor="dave")
    assert result.startswith("❌")
    assert "Unrecognised frequency" in result


def test_schedule_next_no_service_date_rejected(db_path):
    db_create_customer(db_path, {"Company Name": "X", "Frequency": "Weekly"}, actor="dave")
    db_create_job(db_path, {"CustomerID (Customers!A)": "CUST-0001", "Customer Name / Company": "X"}, actor="dave")
    result = db_schedule_next_recurring_job(db_path, "JOB-0001", actor="dave")
    assert result.startswith("❌")
    assert "no Service Date" in result or "Service Date" in result


def test_schedule_next_ambiguous_job_rejected(db_path):
    cust_id = _cust_id(db_path, "Ambiguous")
    db_create_job(db_path, {"CustomerID (Customers!A)": cust_id, "Customer Name / Company": "Ambiguous"}, actor="dave")
    db_create_job(db_path, {"CustomerID (Customers!A)": cust_id, "Customer Name / Company": "Ambiguous"}, actor="dave")
    result = db_schedule_next_recurring_job(db_path, "Ambiguous", actor="dave")
    assert result.startswith("❌")
    assert "matches 2 jobs" in result


def test_schedule_next_no_match_rejected(db_path):
    result = db_schedule_next_recurring_job(db_path, "NOPE", actor="dave")
    assert result.startswith("❌")


def test_schedule_next_date_range_restricts_search(db_path):
    db_create_customer(db_path, {"Company Name": "X", "Frequency": "Weekly"}, actor="dave")
    db_create_job(db_path, {
        "CustomerID (Customers!A)": "CUST-0001", "Customer Name / Company": "X",
        "Service Date": "2026-04-05",
    }, actor="dave")
    # Range that doesn't include 2026-04-05 -> no match.
    result = db_schedule_next_recurring_job(
        db_path, "JOB-0001", actor="dave", range_start="2026-05-01", range_end="2026-05-01",
    )
    assert result.startswith("❌")
    assert "Try when='any'" in result


def test_schedule_next_field_crew_restricted_to_own_job(db_path):
    db_create_customer(db_path, {"Company Name": "X", "Frequency": "Weekly"}, actor="dave")
    db_create_job(db_path, {
        "CustomerID (Customers!A)": "CUST-0001", "Customer Name / Company": "X",
        "Service Date": "2026-04-05", "Crew / Technician": "Someone Else",
    }, actor="dave")
    result = db_schedule_next_recurring_job(
        db_path, "JOB-0001", actor="jake", restrict=True, crew_name="jake r",
    )
    assert result.startswith("❌")
    assert "assigned to you" in result


def test_schedule_next_new_job_carries_over_fields(db_path):
    db_create_customer(db_path, {"Company Name": "Carry Co", "Frequency": "Biweekly"}, actor="dave")
    db_create_job(db_path, {
        "CustomerID (Customers!A)": "CUST-0001", "Customer Name / Company": "Carry Co",
        "Service Date": "2026-04-05", "Crew / Technician": "Jake R",
        "Service Type": "Window", "Street Address": "1 Main St",
    }, actor="dave")
    result = db_schedule_next_recurring_job(db_path, "JOB-0001", actor="dave")
    assert result.startswith("✅"), result

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM jobs WHERE job_id = 'JOB-0002'").fetchone()
    conn.close()
    assert row["customer_name"] == "Carry Co"
    assert row["crew"] == "Jake R"
    assert row["service_type"] == "Window"
    assert row["street_address"] == "1 Main St"
    assert row["job_status"] == "Scheduled"
    assert row["service_date"] == "2026-04-19"  # +14 days


# ══════════════════════════════════════════════════════════════════════════
# Expanded recurrence vocabulary — Bi-Monthly, Semi-Annually, Annually
# ══════════════════════════════════════════════════════════════════════════
# 2026-09-14: Weekly and Monthly's month-end-overflow case were the only
# frequencies exercised above. The rest of _FREQ_MAP (BM/Bi-Monthly,
# SA/Semi-Annually, A/Annually, plus Bi-Monthly's own overflow case) was
# never exercised at this layer -- ported from the pre-migration
# tests/unit/test_contractor_tools.py::TestScheduleNextRecurringJob
# ExpandedFrequencies suite, whose openpyxl fixtures no longer connect
# to the DB-backed tool.

def test_schedule_next_biweekly_plus_14_days(db_path):
    db_create_customer(db_path, {"Company Name": "BW Co", "Frequency": "Biweekly"}, actor="dave")
    db_create_job(db_path, {
        "CustomerID (Customers!A)": "CUST-0001", "Customer Name / Company": "BW Co",
        "Service Date": "2026-03-16",
    }, actor="dave")
    result = db_schedule_next_recurring_job(db_path, "JOB-0001", actor="dave")
    assert result.startswith("✅"), result
    assert "03/30/2026" in result  # +14 days


def test_schedule_next_bi_monthly_plus_two_months(db_path):
    db_create_customer(db_path, {"Company Name": "BM Co", "Frequency": "Bi-Monthly"}, actor="dave")
    db_create_job(db_path, {
        "CustomerID (Customers!A)": "CUST-0001", "Customer Name / Company": "BM Co",
        "Service Date": "2026-03-01",
    }, actor="dave")
    result = db_schedule_next_recurring_job(db_path, "JOB-0001", actor="dave")
    assert result.startswith("✅"), result
    assert "05/01/2026" in result


def test_schedule_next_bi_monthly_short_code_bm_also_works(db_path):
    db_create_customer(db_path, {"Company Name": "BM2 Co", "Frequency": "BM"}, actor="dave")
    db_create_job(db_path, {
        "CustomerID (Customers!A)": "CUST-0001", "Customer Name / Company": "BM2 Co",
        "Service Date": "2026-03-01",
    }, actor="dave")
    result = db_schedule_next_recurring_job(db_path, "JOB-0001", actor="dave")
    assert result.startswith("✅"), result
    assert "05/01/2026" in result


def test_schedule_next_bi_monthly_month_end_overflow_capped(db_path):
    """Same day-overflow protection as monthly, exercised through a
    2-month jump instead of 1 -- Dec 31 2025 + 2 months = Feb 28 2026
    (2026 is not a leap year), not a crash."""
    db_create_customer(db_path, {"Company Name": "BM3 Co", "Frequency": "Bi-Monthly"}, actor="dave")
    db_create_job(db_path, {
        "CustomerID (Customers!A)": "CUST-0001", "Customer Name / Company": "BM3 Co",
        "Service Date": "2025-12-31",
    }, actor="dave")
    result = db_schedule_next_recurring_job(db_path, "JOB-0001", actor="dave")
    assert result.startswith("✅"), result
    assert "02/28/2026" in result


def test_schedule_next_semi_annually_plus_six_months(db_path):
    db_create_customer(db_path, {"Company Name": "SA Co", "Frequency": "Semi-Annually"}, actor="dave")
    db_create_job(db_path, {
        "CustomerID (Customers!A)": "CUST-0001", "Customer Name / Company": "SA Co",
        "Service Date": "2026-01-15",
    }, actor="dave")
    result = db_schedule_next_recurring_job(db_path, "JOB-0001", actor="dave")
    assert result.startswith("✅"), result
    assert "07/15/2026" in result


def test_schedule_next_annually_plus_twelve_months(db_path):
    db_create_customer(db_path, {"Company Name": "A Co", "Frequency": "Annually"}, actor="dave")
    db_create_job(db_path, {
        "CustomerID (Customers!A)": "CUST-0001", "Customer Name / Company": "A Co",
        "Service Date": "2026-06-01",
    }, actor="dave")
    result = db_schedule_next_recurring_job(db_path, "JOB-0001", actor="dave")
    assert result.startswith("✅"), result
    assert "06/01/2027" in result


def test_schedule_next_unrecognized_frequency_lists_full_expanded_set(db_path):
    _legacy_weird_frequency_customer(db_path)
    db_create_job(db_path, {
        "CustomerID (Customers!A)": "CUST-0001", "Customer Name / Company": "Weird Co",
        "Service Date": "2026-04-05",
    }, actor="dave")
    result = db_schedule_next_recurring_job(db_path, "JOB-0001", actor="dave")
    assert result.startswith("❌")
    assert "Bi-Monthly" in result
    assert "Semi-Annually" in result
    assert "Annually" in result
