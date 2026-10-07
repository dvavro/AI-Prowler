"""
tests/mcp_tests/test_database_tab_expansion.py
============================================
Job Board Architecture Spec — Database-tab expansion (2026-09-12).

Direct unit tests for the four newly-wired tables: TimeLog (time_entries),
Route_Planner (route_stops), Settings, and Services_Pricing. Covers:
  - Audit-column awareness (_table_columns): Settings has no created_by
    or version column at all — the write engine must gracefully skip
    those rather than erroring, while every OTHER table still gets full
    audit stamping.
  - Integer-PK-safe matching: route_stops' `id` is INTEGER, not TEXT —
    db_update_row's LIKE-match must work for it exactly as it does for
    text IDs.
  - Crew-scoping: TimeLog/Route_Planner restrict a field_crew caller to
    their own entries/stops; Settings/Services_Pricing lock field_crew
    out of writing entirely.
  - Creation semantics: TimeLog entries are auto-numbered (TE-####,
    reusing the existing generate_next_id scheme); Settings/Services_
    Pricing use a caller-supplied key and reject a duplicate.

Run with:
    run_tests.bat tests\\mcp\\test_database_tab_expansion.py -v
"""
import sqlite3

import pytest

from db_access import init_db
from db_write_ops import (
    db_create_customer,
    db_create_job,
    db_create_service_pricing,
    db_create_setting,
    db_update_route_stop,
    db_update_service_pricing,
    db_update_settings,
    db_update_time_entry,
)


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _col(db_path, table, col, where_col, where_val):
    conn = sqlite3.connect(db_path)
    row = conn.execute(f"SELECT {col} FROM {table} WHERE {where_col} = ?", (where_val,)).fetchone()
    conn.close()
    return row[0] if row else None


def _cust_id(db_path, name="X"):
    """Job Board Architecture Spec §5.1 (2026-09-22): create_job now
    requires a real, existing CustomerID."""
    result = db_create_customer(db_path, {"Company Name": name}, actor="dave")
    return result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()


def _seed_time_entry(db_path, crew="Jake R"):
    """Real time_entries row via the actual log_time_entry storage path
    (db_log_time_entry), not a hand-crafted INSERT, since entry_id/
    elapsed_min/version all need to be genuine."""
    from db_write_ops import db_log_time_entry
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "X", "Crew / Technician": crew}, actor="dave")
    result = db_log_time_entry(db_path, "JOB-0001", "start", user_id="", user_display_name=crew,
                                gps_coords="")
    assert result.startswith("⏱️"), result
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT entry_id FROM time_entries LIMIT 1").fetchone()
    conn.close()
    return row["entry_id"]


def _seed_route_stop(db_path, crew="Jake R"):
    from db_route_ops import db_write_route_stops
    j = db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "X", "Crew / Technician": crew}, actor="dave")
    job_id = j.split("NEW_JOB_ID=")[1].splitlines()[0].strip()
    stops = [{"crew": crew, "job_id": job_id, "cust_id": None, "address": "1 Main St",
              "lat": 29.0, "lon": -80.9, "arrival": "08:00", "map_url": None}]
    db_write_route_stops(db_path, "2026-04-05", stops, actor="dave")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT id FROM route_stops LIMIT 1").fetchone()
    conn.close()
    return row["id"]


# ══════════════════════════════════════════════════════════════════════════
# Audit-column awareness — the user's explicit "don't forget audit data" ask
# ══════════════════════════════════════════════════════════════════════════

def test_settings_create_has_no_created_by_or_version_but_does_get_last_edited(db_path):
    """Settings genuinely lacks created_by and version columns (see
    db_schema.py) — the write engine must not try to set them (would
    raise 'no such column'), but MUST still set last_edited_by/at since
    those columns do exist."""
    result = db_create_setting(db_path, {"Setting": "tax_rate", "Value": "0.07"}, actor="dave")
    assert result.startswith("✅"), result

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM settings WHERE key = 'tax_rate'").fetchone()
    conn.close()
    assert row["value"] == "0.07"
    assert row["last_edited_by"] == "dave"
    assert row["last_edited_at"] is not None
    assert "created_by" not in row.keys()  # column genuinely doesn't exist
    assert "version" not in row.keys()


def test_settings_update_does_not_crash_on_missing_version_column(db_path):
    db_create_setting(db_path, {"Setting": "tax_rate", "Value": "0.07"}, actor="dave")
    result = db_update_settings(db_path, "tax_rate", {"Value": "0.08"}, actor="dave")
    assert result.startswith("✅"), result
    assert "NEW_VERSION=" not in result  # no version column -> no version line
    assert _col(db_path, "settings", "value", "key", "tax_rate") == "0.08"


def test_time_entries_get_full_audit_trail(db_path):
    """Unlike Settings, time_entries HAS created_by/last_edited_by/
    last_edited_at/version — confirms those still get stamped correctly
    now that the engine checks column presence dynamically instead of
    assuming every table is the same shape."""
    from db_write_ops import db_log_time_entry
    db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path), "Customer Name / Company": "X", "Crew / Technician": "Jake"}, actor="dave")
    db_log_time_entry(db_path, "JOB-0001", "start", user_id="", user_display_name="Jake", gps_coords="")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM time_entries LIMIT 1").fetchone()
    conn.close()
    assert row["created_by"] == "Jake"
    assert row["last_edited_by"] == "Jake"
    assert row["last_edited_at"] is not None
    assert row["version"] == 1


def test_service_pricing_gets_full_audit_trail_on_create_and_update(db_path):
    """service_pricing has NO created_by column (see db_schema.py) —
    only last_edited_by/last_edited_at/version. Confirms those three
    get stamped correctly and that create doesn't try (and fail) to
    set a column that doesn't exist."""
    result = db_create_service_pricing(db_path, {"Service Code": "WIN", "Base Price ($)": 150}, actor="dave")
    assert result.startswith("✅"), result
    assert _col(db_path, "service_pricing", "last_edited_by", "service_code", "WIN") == "dave"
    assert _col(db_path, "service_pricing", "last_edited_at", "service_code", "WIN") is not None
    assert _col(db_path, "service_pricing", "version", "service_code", "WIN") == 1

    result2 = db_update_service_pricing(db_path, "WIN", {"Base Price ($)": 175}, actor="maria")
    assert result2.startswith("✅"), result2
    assert "NEW_VERSION=2" in result2
    assert _col(db_path, "service_pricing", "last_edited_by", "service_code", "WIN") == "maria"


# ══════════════════════════════════════════════════════════════════════════
# Integer-PK-safe matching — route_stops.id is INTEGER, not TEXT
# ══════════════════════════════════════════════════════════════════════════

def test_route_stop_update_by_integer_id_works(db_path):
    stop_id = _seed_route_stop(db_path)
    result = db_update_route_stop(db_path, str(stop_id), {"ETA": "09:15"}, actor="dave")
    assert result.startswith("✅"), result
    assert _col(db_path, "route_stops", "eta", "id", stop_id) == "09:15"


# ══════════════════════════════════════════════════════════════════════════
# Crew-scoping — TimeLog / Route_Planner restrict by crew; Settings /
# Services_Pricing lock field_crew out entirely
# ══════════════════════════════════════════════════════════════════════════

def test_time_entry_field_crew_denied_for_unassigned_entry(db_path):
    entry_id = _seed_time_entry(db_path, crew="Someone Else")
    result = db_update_time_entry(db_path, entry_id, {"Notes": "hacked"}, actor="jake",
                                   restrict=True, crew_name="jake r")
    assert result.startswith("❌")
    assert "assigned to you" in result


def test_time_entry_field_crew_allowed_for_own_entry(db_path):
    entry_id = _seed_time_entry(db_path, crew="Jake R")
    result = db_update_time_entry(db_path, entry_id, {"Notes": "fixed a typo"}, actor="jake",
                                   restrict=True, crew_name="jake r")
    assert result.startswith("✅"), result


def test_route_stop_field_crew_denied_for_other_crews_stop(db_path):
    stop_id = _seed_route_stop(db_path, crew="Someone Else")
    result = db_update_route_stop(db_path, str(stop_id), {"ETA": "10:00"}, actor="jake",
                                   restrict=True, crew_name="jake r")
    assert result.startswith("❌")


def test_route_stop_field_crew_allowed_for_own_stop(db_path):
    stop_id = _seed_route_stop(db_path, crew="Jake R")
    result = db_update_route_stop(db_path, str(stop_id), {"ETA": "10:00"}, actor="jake",
                                   restrict=True, crew_name="jake r")
    assert result.startswith("✅"), result


def test_settings_field_crew_denied_entirely(db_path):
    db_create_setting(db_path, {"Setting": "tax_rate", "Value": "0.07"}, actor="dave")
    result = db_update_settings(db_path, "tax_rate", {"Value": "0.10"}, actor="jake", restrict=True)
    assert result.startswith("❌")
    assert "staff/manager/owner" in result
    # Confirm nothing was actually written.
    assert _col(db_path, "settings", "value", "key", "tax_rate") == "0.07"


def test_settings_create_denied_for_field_crew(db_path):
    result = db_create_setting(db_path, {"Setting": "x", "Value": "y"}, actor="jake", restrict=True)
    assert result.startswith("❌")


def test_service_pricing_field_crew_denied_entirely(db_path):
    db_create_service_pricing(db_path, {"Service Code": "WIN", "Base Price ($)": 150}, actor="dave")
    result = db_update_service_pricing(db_path, "WIN", {"Base Price ($)": 999}, actor="jake", restrict=True)
    assert result.startswith("❌")
    assert _col(db_path, "service_pricing", "base_price", "service_code", "WIN") == 150


def test_service_pricing_create_denied_for_field_crew(db_path):
    result = db_create_service_pricing(db_path, {"Service Code": "X"}, actor="jake", restrict=True)
    assert result.startswith("❌")


def test_staff_unrestricted_for_settings_and_pricing(db_path):
    r1 = db_create_setting(db_path, {"Setting": "x", "Value": "1"}, actor="dave", restrict=False)
    assert r1.startswith("✅")
    r2 = db_create_service_pricing(db_path, {"Service Code": "WIN"}, actor="dave", restrict=False)
    assert r2.startswith("✅")


# ══════════════════════════════════════════════════════════════════════════
# Creation semantics: caller-supplied key (Settings/Services_Pricing) vs.
# duplicate rejection
# ══════════════════════════════════════════════════════════════════════════

def test_setting_duplicate_key_rejected(db_path):
    db_create_setting(db_path, {"Setting": "tax_rate", "Value": "0.07"}, actor="dave")
    result = db_create_setting(db_path, {"Setting": "tax_rate", "Value": "0.10"}, actor="dave")
    assert result.startswith("❌")
    assert "already exists" in result


def test_setting_blank_key_rejected(db_path):
    result = db_create_setting(db_path, {"Value": "0.07"}, actor="dave")
    assert result.startswith("❌")


def test_service_pricing_duplicate_code_rejected(db_path):
    db_create_service_pricing(db_path, {"Service Code": "WIN"}, actor="dave")
    result = db_create_service_pricing(db_path, {"Service Code": "WIN"}, actor="dave")
    assert result.startswith("❌")
    assert "already exists" in result


def test_service_pricing_blank_code_rejected(db_path):
    result = db_create_service_pricing(db_path, {"Category": "Cleaning"}, actor="dave")
    assert result.startswith("❌")


# ══════════════════════════════════════════════════════════════════════════
# Conflict detection (expected_version) still applies where a version
# column exists
# ══════════════════════════════════════════════════════════════════════════

def test_service_pricing_conflict_detection_works(db_path):
    db_create_service_pricing(db_path, {"Service Code": "WIN", "Base Price ($)": 150}, actor="dave")
    db_update_service_pricing(db_path, "WIN", {"Base Price ($)": 160}, actor="dave", expected_version=1)
    result = db_update_service_pricing(db_path, "WIN", {"Base Price ($)": 200}, actor="maria",
                                        expected_version=1)  # stale
    assert result.startswith("❌")
    assert "Conflict" in result
