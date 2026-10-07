"""
tests/mcp_tests/test_route_schedule_advisor_phase9.py
================================================
Job Board Architecture Spec §14 — Route & Schedule Advisor, Phase 9
(schema & hard/soft time foundation).

Covers:
  - jobs.schedule_type: schema migration (idempotent, existing rows
    default to 'soft'), round-trip via db_create_job/db_update_job under
    both display-header aliases ("Schedule Type (Hard/Soft)" and bare
    "Schedule Type"), and the regression that a job with no schedule_type
    specified behaves exactly as before.
  - The five new Settings readers in db_write_ops.py: each falls back to
    its documented default when unset, and reads back a set value
    correctly, mirroring the existing db_read_settings_tax_rate tests.

Run with:
    run_tests.bat tests\\mcp\\test_route_schedule_advisor_phase9.py -v
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

import pytest

from db_access import init_db
from db_schema import apply_schema
from db_write_ops import (
    db_create_customer,
    db_create_job,
    db_update_job,
    db_read_settings_hard_time_tolerance_min,
    db_read_settings_lunch_break_duration_min,
    db_read_settings_lunch_break_start,
    db_read_settings_workday_end,
    db_read_settings_workday_start,
)

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _extract_job_id(result: str) -> str:
    return result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _schedule_type(db_path, job_id):
    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT schedule_type FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    conn.close()
    # R-057: a saved value is stored as the Jobs app's own spelling ("Hard" /
    # "Soft"); the untouched schema default is "soft". Compare the meaning.
    return (row[0] or "").lower()


def _start_end_times(db_path, job_id):
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT start_time, end_time FROM jobs WHERE job_id = ?", (job_id,)
    ).fetchone()
    conn.close()
    return row


def _set_setting(db_path, key, value):
    conn = sqlite3.connect(db_path)
    conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()


def _cust_id(db_path, name="A"):
    """Job Board Architecture Spec §5.1 (2026-09-22): create_job now
    requires a real, existing CustomerID."""
    result = db_create_customer(db_path, {"Company Name": name}, actor="dave")
    return result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()


# ── schedule_type: schema + migration ───────────────────────────────────

def test_new_job_defaults_to_soft_with_no_schedule_type_given(db_path):
    result = db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "Acme Co"), "Customer Name / Company": "Acme Co"}, actor="dave")
    assert result.startswith("✅")
    job_id = _extract_job_id(result)
    assert _schedule_type(db_path, job_id) == "soft"


def test_schema_migration_adds_schedule_type_default_soft_for_existing_rows():
    """Simulates a database created before schedule_type existed: a jobs
    table with the full pre-Phase-9 column set (everything schedule_type
    was added alongside) but no schedule_type column itself. Running
    apply_schema() must add the column via _ensure_column and leave the
    pre-existing row defaulted to 'soft' — the exact scenario spec §14.2's
    migration note describes. Uses the real pre-existing column list (not
    a stripped-down stub) so apply_schema's CREATE INDEX statements for
    customer_id/invoice_id/etc. resolve against real columns, matching
    what an actual pre-Phase-9 database looks like."""
    import tempfile
    import os

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    try:
        conn = sqlite3.connect(path)
        conn.execute("""
            CREATE TABLE jobs (
                job_id                  TEXT PRIMARY KEY,
                customer_id             TEXT,
                customer_name           TEXT,
                customer_type           TEXT,
                street_address          TEXT,
                city                    TEXT,
                state                   TEXT,
                zip                     TEXT,
                latitude                REAL,
                longitude               REAL,
                service_date            TEXT,
                end_date                TEXT,
                day_of_week             TEXT,
                start_time              TEXT,
                end_time                TEXT,
                service_type            TEXT,
                service_details         TEXT,
                crew                    TEXT,
                crew_user_id            TEXT,
                est_duration            REAL,
                est_duration_unit       TEXT,
                actual_duration         REAL,
                actual_duration_unit    TEXT,
                route_stop_number       INTEGER,
                route_map_url           TEXT,
                weather_check           TEXT,
                job_status              TEXT,
                quote_amount            REAL,
                discount_applied        REAL,
                recurrence              TEXT,
                invoice_id              TEXT,
                invoice_sent_date       TEXT,
                payment_status          TEXT,
                created_by              TEXT,
                last_edited_by          TEXT,
                last_edited_at          TEXT,
                version                 INTEGER NOT NULL DEFAULT 1
            )
        """)
        conn.execute(
            "INSERT INTO jobs (job_id, customer_name, start_time, end_time) "
            "VALUES ('JOB-0001', 'Pre-Migration Co', '09:00', '10:00')"
        )
        conn.commit()
        conn.close()

        conn2 = sqlite3.connect(path)
        apply_schema(conn2)
        row = conn2.execute(
            "SELECT schedule_type, start_time, end_time FROM jobs WHERE job_id = 'JOB-0001'"
        ).fetchone()
        conn2.close()

        assert row[0] == "soft"
        # start_time/end_time are untouched — they become the soft job's
        # window bounds, not wiped or reinterpreted, per spec §14.2.
        assert row[1] == "09:00"
        assert row[2] == "10:00"
    finally:
        os.remove(path)


def test_schema_migration_is_idempotent(db_path):
    conn = sqlite3.connect(db_path)
    apply_schema(conn)
    apply_schema(conn)  # second call must not raise or change anything
    row = conn.execute("PRAGMA table_info(jobs)").fetchall()
    conn.close()
    col_names = [r[1] for r in row]
    assert col_names.count("schedule_type") == 1


# ── schedule_type: round-trip via create/update, both header aliases ───

def test_schedule_type_roundtrip_hard_via_create_decorated_header(db_path):
    result = db_create_job(
        db_path,
        {
            "CustomerID (Customers!A)": _cust_id(db_path, "Hard Slot Co"),
            "Customer Name / Company": "Hard Slot Co",
            "Schedule Type (Hard/Soft)": "hard",
            "Start Time": "11:00",
            "End Time": "12:00",
        },
        actor="dave",
    )
    job_id = _extract_job_id(result)
    assert _schedule_type(db_path, job_id) == "hard"
    assert _start_end_times(db_path, job_id) == ("11:00", "12:00")


def test_schedule_type_roundtrip_via_create_bare_header(db_path):
    result = db_create_job(
        db_path,
        {"CustomerID (Customers!A)": _cust_id(db_path, "Bare Header Co"), "Customer Name / Company": "Bare Header Co", "Schedule Type": "hard"},
        actor="dave",
    )
    job_id = _extract_job_id(result)
    assert _schedule_type(db_path, job_id) == "hard"


def test_schedule_type_roundtrip_via_update(db_path):
    result = db_create_job(db_path, {"CustomerID (Customers!A)": _cust_id(db_path, "Flip Co"), "Customer Name / Company": "Flip Co"}, actor="dave")
    job_id = _extract_job_id(result)
    assert _schedule_type(db_path, job_id) == "soft"

    db_update_job(
        db_path, job_id, {"Schedule Type (Hard/Soft)": "hard"}, actor="dave"
    )
    assert _schedule_type(db_path, job_id) == "hard"

    db_update_job(db_path, job_id, {"Schedule Type": "soft"}, actor="dave")
    assert _schedule_type(db_path, job_id) == "soft"


def test_regression_job_with_start_end_time_and_no_schedule_type_is_unaffected(db_path):
    """A job created with Start/End Time but no Schedule Type at all must
    behave exactly as it did before this phase — schedule_type silently
    defaults to 'soft', and start_time/end_time round-trip unchanged."""
    result = db_create_job(
        db_path,
        {
            "CustomerID (Customers!A)": _cust_id(db_path, "No Opinion Co"),
            "Customer Name / Company": "No Opinion Co",
            "Start Time": "14:00",
            "End Time": "15:30",
        },
        actor="dave",
    )
    job_id = _extract_job_id(result)
    assert _schedule_type(db_path, job_id) == "soft"
    assert _start_end_times(db_path, job_id) == ("14:00", "15:30")


# ── New Settings readers: default fallback + set-value round trip ──────

def test_workday_start_default_and_override(db_path):
    assert db_read_settings_workday_start(db_path) == "07:00"
    _set_setting(db_path, "Workday Start Time", "08:30")
    assert db_read_settings_workday_start(db_path) == "08:30"


def test_workday_end_default_and_override(db_path):
    assert db_read_settings_workday_end(db_path) == "17:00"
    _set_setting(db_path, "Workday End Time", "18:00")
    assert db_read_settings_workday_end(db_path) == "18:00"


def test_lunch_break_start_default_and_override(db_path):
    assert db_read_settings_lunch_break_start(db_path) == "12:00"
    _set_setting(db_path, "Lunch Break Start", "12:30")
    assert db_read_settings_lunch_break_start(db_path) == "12:30"


def test_lunch_break_duration_default_and_override(db_path):
    assert db_read_settings_lunch_break_duration_min(db_path) == 60
    _set_setting(db_path, "Lunch Break Duration (min)", "45")
    assert db_read_settings_lunch_break_duration_min(db_path) == 45


def test_lunch_break_duration_malformed_value_falls_back(db_path):
    _set_setting(db_path, "Lunch Break Duration (min)", "not-a-number")
    assert db_read_settings_lunch_break_duration_min(db_path) == 60


def test_hard_time_tolerance_default_and_override(db_path):
    assert db_read_settings_hard_time_tolerance_min(db_path) == 10
    _set_setting(db_path, "Hard Time Tolerance (min)", "15")
    assert db_read_settings_hard_time_tolerance_min(db_path) == 15


def test_hard_time_tolerance_missing_db_falls_back_not_raises(tmp_path):
    """A nonexistent/garbage db_path must fall back rather than raise —
    every new reader wraps its query in try/except like
    db_read_settings_tax_rate does, so route building never crashes over
    a Settings read."""
    bogus_path = str(tmp_path / "does_not_exist.db")
    assert db_read_settings_hard_time_tolerance_min(bogus_path) == 10
    assert db_read_settings_workday_start(bogus_path) == "07:00"
