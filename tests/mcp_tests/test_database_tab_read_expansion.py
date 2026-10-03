"""
tests/mcp_tests/test_database_tab_read_expansion.py
=================================================
Job Board Architecture Spec — Database-tab expansion (2026-09-12).

Direct unit tests confirming TimeLog/Route_Planner/Settings/Services_
Pricing are correctly readable through db_read_ops.db_read_job_spreadsheet
and db_get_jobs_changed_since — the _READ_DISPATCH extension. Also
confirms Settings/Services_Pricing reads are NEVER crew-scoped (only the
write side locks field_crew out — seeing current config/pricing is fine).

Run with:
    run_tests.bat tests\\mcp\\test_database_tab_read_expansion.py -v
"""
import pytest

from db_access import init_db
from db_read_ops import db_get_jobs_changed_since, db_read_job_spreadsheet
from db_write_ops import (
    db_create_customer,
    db_create_job,
    db_create_service_pricing,
    db_create_setting,
    db_log_time_entry,
)


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _cust_id(db_path, name="X"):
    """Job Board Architecture Spec §5.1 (2026-09-22): create_job now
    requires a real, existing CustomerID."""
    result = db_create_customer(db_path, {"Company Name": name}, actor="dave")
    return result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()


def test_timelog_readable(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "X", "Crew / Technician": "Jake"}, actor="dave")
    db_log_time_entry(db_path, "JOB-0001", "start", user_id="", user_display_name="Jake", gps_coords="")
    result = db_read_job_spreadsheet(db_path, sheet_name="TimeLog")
    assert result.startswith("📋 TimeLog")
    assert "Jake" in result
    assert "1 row(s)" in result


def test_route_planner_readable(db_path):
    from db_route_ops import db_write_route_stops
    j = db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "X", "Crew / Technician": "Jake"}, actor="dave")
    job_id = j.split("NEW_JOB_ID=")[1].splitlines()[0].strip()
    db_write_route_stops(db_path, "2026-04-05", [
        {"crew": "Jake", "job_id": job_id, "cust_id": None, "address": "1 Main St",
         "lat": 29.0, "lon": -80.9, "arrival": "08:00", "map_url": None},
    ], actor="dave")
    result = db_read_job_spreadsheet(db_path, sheet_name="Route_Planner")
    assert result.startswith("📋 Route_Planner")
    assert "1 Main St" in result


def test_settings_readable(db_path):
    db_create_setting(db_path, {"Setting": "tax_rate", "Value": "0.07"}, actor="dave")
    result = db_read_job_spreadsheet(db_path, sheet_name="Settings")
    assert "tax_rate" in result
    assert "0.07" in result


def test_service_pricing_readable(db_path):
    db_create_service_pricing(db_path, {"Service Code": "WIN", "Name": "Window Cleaning"}, actor="dave")
    result = db_read_job_spreadsheet(db_path, sheet_name="Services_Pricing")
    assert "WIN" in result
    assert "Window Cleaning" in result


def test_timelog_crew_scoped_read(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "A"), "Customer Name / Company": "A", "Crew / Technician": "Jake R"}, actor="dave")
    db_log_time_entry(db_path, "JOB-0001", "start", user_id="", user_display_name="Jake R", gps_coords="")
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "B"), "Customer Name / Company": "B", "Crew / Technician": "Someone Else"}, actor="dave")
    db_log_time_entry(db_path, "JOB-0002", "start", user_id="", user_display_name="Someone Else", gps_coords="")

    result = db_read_job_spreadsheet(db_path, sheet_name="TimeLog", restrict=True, crew_name="jake r")
    assert "1 row(s)" in result


def test_route_planner_crew_scoped_read(db_path):
    from db_route_ops import db_write_route_stops
    j1 = db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "A"), "Customer Name / Company": "A", "Crew / Technician": "Jake R"}, actor="dave")
    j1_id = j1.split("NEW_JOB_ID=")[1].splitlines()[0].strip()
    j2 = db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "B"), "Customer Name / Company": "B", "Crew / Technician": "Someone Else"}, actor="dave")
    j2_id = j2.split("NEW_JOB_ID=")[1].splitlines()[0].strip()
    db_write_route_stops(db_path, "2026-04-05", [
        {"crew": "Jake R", "job_id": j1_id, "cust_id": None, "address": "1 Main St",
         "lat": 29.0, "lon": -80.9, "arrival": "08:00", "map_url": None},
        {"crew": "Someone Else", "job_id": j2_id, "cust_id": None, "address": "2 Main St",
         "lat": 29.1, "lon": -80.8, "arrival": "09:00", "map_url": None},
    ], actor="dave")
    result = db_read_job_spreadsheet(db_path, sheet_name="Route_Planner", restrict=True, crew_name="jake r")
    assert "1 Main St" in result
    assert "2 Main St" not in result


def test_settings_never_crew_scoped_on_read(db_path):
    """Even a restricted caller sees every setting — only WRITES are
    locked out for field_crew, matching Customers' own posture."""
    db_create_setting(db_path, {"Setting": "tax_rate", "Value": "0.07"}, actor="dave")
    result = db_read_job_spreadsheet(db_path, sheet_name="Settings", restrict=True, crew_name="jake r")
    assert "tax_rate" in result


def test_service_pricing_never_crew_scoped_on_read(db_path):
    db_create_service_pricing(db_path, {"Service Code": "WIN"}, actor="dave")
    result = db_read_job_spreadsheet(db_path, sheet_name="Services_Pricing", restrict=True, crew_name="jake r")
    assert "WIN" in result


def test_get_board_updates_covers_all_four_new_sheets(db_path):
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "X"}, actor="dave")
    db_log_time_entry(db_path, "JOB-0001", "start", user_id="", user_display_name="Jake", gps_coords="")
    db_create_setting(db_path, {"Setting": "tax_rate", "Value": "0.07"}, actor="dave")
    db_create_service_pricing(db_path, {"Service Code": "WIN"}, actor="dave")

    for sheet in ("TimeLog", "Settings", "Services_Pricing"):
        rows = db_get_jobs_changed_since(db_path, "2000-01-01T00:00:00", sheet_name=sheet)
        # internal_* rows are bookkeeping markers (e.g. R-057's one-time
        # cleanup marker) that the app hides — not user data
        rows = [r for r in rows if not str(r.get("Setting", "")).startswith("internal_")]
        assert len(rows) == 1, f"{sheet} expected 1 row, got {len(rows)}"
