"""
tests/mcp_tests/test_gps_map_url.py
=================================
GPS Google Maps hyperlink storage for clock in/out (user follow-up after
Job Board Architecture Spec Phase 8/8a). Requested: verify Jobs PWA
captures phone GPS (confirmed already correct, not changed here), and
that when GPS is captured, a Google Maps URL is ALSO computed and stored
in the database, renderable as a clickable hyperlink in the Jobs PWA.

Run with:
    run_tests.bat tests\\mcp\\test_gps_map_url.py -v
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

from db_access import init_db
from db_schema import _ensure_column, apply_schema
from db_write_ops import _gps_to_map_url, db_create_customer, db_create_job, db_log_time_entry

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _seed_job(db_path):
    cust_result = db_create_customer(db_path, {"Company Name": "Blue Wave Cafe"}, actor="dave")
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    result = db_create_job(db_path, {"CustomerID (Customers!A)": cust_id, "Customer Name / Company": "Blue Wave Cafe"}, actor="dave")
    return result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


# ══════════════════════════════════════════════════════════════════════════
# _gps_to_map_url helper
# ══════════════════════════════════════════════════════════════════════════

def test_gps_to_map_url_valid_coords():
    url = _gps_to_map_url("29.0386379,-80.9038091")
    assert url == "https://www.google.com/maps?q=29.0386379,-80.9038091"


def test_gps_to_map_url_blank_returns_empty():
    assert _gps_to_map_url("") == ""
    assert _gps_to_map_url(None) == ""


def test_gps_to_map_url_malformed_returns_empty():
    assert _gps_to_map_url("not coordinates") == ""
    assert _gps_to_map_url("29.03,not-a-number") == ""


# ══════════════════════════════════════════════════════════════════════════
# db_log_time_entry stores the URL alongside raw GPS
# ══════════════════════════════════════════════════════════════════════════

def test_clock_in_stores_map_url(db_path):
    job_id = _seed_job(db_path)
    db_log_time_entry(db_path, job_id, "start", user_id="", user_display_name="Dave",
                       gps_coords="29.0386379,-80.9038091")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT clock_in_gps, clock_in_map_url FROM time_entries WHERE job_id = ?",
                        (job_id,)).fetchone()
    conn.close()

    assert row["clock_in_gps"] == "29.0386379,-80.9038091"
    assert row["clock_in_map_url"] == "https://www.google.com/maps?q=29.0386379,-80.9038091"


def test_clock_out_stores_map_url(db_path):
    job_id = _seed_job(db_path)
    db_log_time_entry(db_path, job_id, "start", user_id="", user_display_name="Dave",
                       gps_coords="29.0,-80.9")
    db_log_time_entry(db_path, job_id, "stop", user_id="", user_display_name="Dave",
                       gps_coords="29.1,-81.0")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT clock_out_gps, clock_out_map_url FROM time_entries WHERE job_id = ?",
                        (job_id,)).fetchone()
    conn.close()

    assert row["clock_out_gps"] == "29.1,-81.0"
    assert row["clock_out_map_url"] == "https://www.google.com/maps?q=29.1,-81.0"


def test_no_gps_means_no_map_url(db_path):
    """A crew member who denies location permission still clocks in fine
    — no GPS, no error, and no map URL (nothing to link to)."""
    job_id = _seed_job(db_path)
    db_log_time_entry(db_path, job_id, "start", user_id="", user_display_name="Dave", gps_coords="")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT clock_in_gps, clock_in_map_url FROM time_entries WHERE job_id = ?",
                        (job_id,)).fetchone()
    conn.close()

    assert not row["clock_in_gps"]
    assert not row["clock_in_map_url"]


def test_read_job_spreadsheet_exposes_map_url_columns(db_path):
    """The new columns must be readable through the same path the Jobs
    PWA Database tab uses (read_job_spreadsheet -> _TIME_ENTRIES_DISPLAY),
    not just directly via SQL."""
    job_id = _seed_job(db_path)
    db_log_time_entry(db_path, job_id, "start", user_id="", user_display_name="Dave",
                       gps_coords="29.0386379,-80.9038091")

    from db_read_ops import db_read_job_spreadsheet
    result = db_read_job_spreadsheet(db_path, "TimeLog", filter_date="", max_rows=10)
    assert "Clock In Map URL: https://www.google.com/maps?q=29.0386379,-80.9038091" in result


# ══════════════════════════════════════════════════════════════════════════
# Schema migration — existing databases get the new columns retroactively
# ══════════════════════════════════════════════════════════════════════════

def test_ensure_column_adds_missing_column(tmp_path):
    """Simulates an existing database created BEFORE these columns existed
    — apply_schema() must add them via migration, not just at CREATE TABLE
    time (which only affects brand-new databases)."""
    db_path = str(tmp_path / "old.db")
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE time_entries (entry_id TEXT PRIMARY KEY)")
    conn.commit()

    before = {row[1] for row in conn.execute("PRAGMA table_info(time_entries)").fetchall()}
    assert "clock_in_map_url" not in before

    _ensure_column(conn, "time_entries", "clock_in_map_url", "TEXT")
    _ensure_column(conn, "time_entries", "clock_out_map_url", "TEXT")
    conn.commit()

    after = {row[1] for row in conn.execute("PRAGMA table_info(time_entries)").fetchall()}
    conn.close()
    assert "clock_in_map_url" in after
    assert "clock_out_map_url" in after


def test_ensure_column_is_idempotent(tmp_path):
    """Calling it twice (e.g. two app startups) must not raise — SQLite
    has no native ADD COLUMN IF NOT EXISTS, so this is the whole point of
    the helper's own existence check."""
    db_path = str(tmp_path / "old.db")
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE time_entries (entry_id TEXT PRIMARY KEY)")
    conn.commit()

    _ensure_column(conn, "time_entries", "clock_in_map_url", "TEXT")
    _ensure_column(conn, "time_entries", "clock_in_map_url", "TEXT")  # no error
    conn.close()


def test_apply_schema_on_fresh_db_includes_new_columns(tmp_path):
    """A brand-new database (via the normal init_db path) already has the
    columns from SCHEMA_SQL directly — the migration should be a no-op
    for it, not fail or duplicate anything."""
    db_path = str(tmp_path / "fresh.db")
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    cols = {row[1] for row in conn.execute("PRAGMA table_info(time_entries)").fetchall()}
    conn.close()
    assert "clock_in_map_url" in cols
    assert "clock_out_map_url" in cols
