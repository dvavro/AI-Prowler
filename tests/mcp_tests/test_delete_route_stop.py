"""
Tests for delete_route_stop / db_delete_route_stop — added 2026-09-16 at
the owner's request: once a job is done, its route stop has no further
use. Unlike delete_customer/delete_quote/delete_service_pricing, no
status pre-condition gate (route stops have no "retire first" concept)
and no cascade (nothing references route_stops by foreign key). Crew-
scoping mirrors db_update_route_stop's own ownership rule (crew_id match)
rather than the staff+-only posture the other delete_* tools use.

Run: py -m pytest tests\\mcp\\test_delete_route_stop.py -v
"""

import os

import pytest

from db_access import get_connection, init_db, transaction
from db_write_ops import db_delete_route_stop


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _make_stop(db_path, route_date="2026-09-16", crew_id="jake-r", stop_number=1,
                address="1 Main St, NSB, FL"):
    with transaction(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO route_stops (route_date, crew_id, stop_number, address, "
            "created_by, last_edited_by, last_edited_at) "
            "VALUES (?, ?, ?, ?, 'test', 'test', '2026-09-16T00:00:00')",
            (route_date, crew_id, stop_number, address),
        )
        return cur.lastrowid


# ── Not found ────────────────────────────────────────────────────────────

def test_not_found_returns_error(db_path):
    result = db_delete_route_stop(db_path, 9999, confirm=True)
    assert result.startswith("❌")
    assert "No route stop found" in result


# ── Guard: confirm required ─────────────────────────────────────────────

def test_preview_without_confirm_deletes_nothing(db_path):
    stop_id = _make_stop(db_path)
    result = db_delete_route_stop(db_path, stop_id, confirm=False)
    assert result.startswith("❌")
    assert "confirm=True" in result
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM route_stops WHERE id = ?", (stop_id,)).fetchone()
    conn.close()
    assert row is not None


def test_preview_reports_date_and_stop_number(db_path):
    stop_id = _make_stop(db_path, route_date="2026-09-20", stop_number=3,
                          address="42 Beachside Dr")
    result = db_delete_route_stop(db_path, stop_id, confirm=False)
    assert "2026-09-20" in result
    assert "3" in result


# ── No status gate — a fresh, unretired stop deletes directly ───────────

def test_deletes_stop_with_no_precondition(db_path):
    """Unlike delete_customer/delete_quote, no Inactive/Declined gate —
    a route stop is eligible for deletion the moment it exists."""
    stop_id = _make_stop(db_path)
    result = db_delete_route_stop(db_path, stop_id, confirm=True)
    assert result.startswith("✅")
    assert "Safety backup saved first" in result
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM route_stops WHERE id = ?", (stop_id,)).fetchone()
    conn.close()
    assert row is None


def test_safety_backup_file_actually_created(db_path):
    stop_id = _make_stop(db_path)
    result = db_delete_route_stop(db_path, stop_id, confirm=True)
    backup_line = [l for l in result.splitlines() if "Safety backup saved first" in l][0]
    backup_path = backup_line.split(":", 1)[1].strip()
    assert os.path.exists(backup_path)


# ── No cascade needed — deleting a stop never touches the job/customer ──

def test_deleting_stop_does_not_affect_the_job_it_pointed_at(db_path):
    from db_write_ops import db_create_customer, db_create_job
    cust_result = db_create_customer(db_path, {"Company Name": "ZTEST Whoever"}, actor="test")
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    job_result = db_create_job(
        db_path,
        {"CustomerID (Customers!A)": cust_id, "Customer Name / Company": "ZTEST Whoever", "Service Date": "2026-09-16"},
        actor="test",
    )
    job_id = job_result.split("NEW_JOB_ID=")[1].strip()

    stop_id = _make_stop(db_path)
    with transaction(db_path) as conn:
        conn.execute("UPDATE route_stops SET job_id = ? WHERE id = ?", (job_id, stop_id))

    result = db_delete_route_stop(db_path, stop_id, confirm=True)
    assert result.startswith("✅")

    conn = get_connection(db_path)
    job_row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    conn.close()
    assert job_row is not None  # untouched


# ── Crew-scoping: mirrors db_update_route_stop's own ownership rule ─────

def test_field_crew_can_delete_own_stop(db_path):
    stop_id = _make_stop(db_path, crew_id="Jake R")
    result = db_delete_route_stop(db_path, stop_id, confirm=True, restrict=True, crew_name="jake r")
    assert result.startswith("✅")


def test_field_crew_cannot_delete_coworkers_stop(db_path):
    stop_id = _make_stop(db_path, crew_id="Jake R")
    result = db_delete_route_stop(db_path, stop_id, confirm=True, restrict=True, crew_name="vicki vavro")
    assert result.startswith("❌")
    assert "your own route" in result
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM route_stops WHERE id = ?", (stop_id,)).fetchone()
    conn.close()
    assert row is not None  # untouched


def test_owner_unrestricted_regardless_of_crew(db_path):
    """restrict=False (owner/manager/staff) bypasses the crew check
    entirely — same as every other crew-scoped table in this codebase."""
    stop_id = _make_stop(db_path, crew_id="Jake R")
    result = db_delete_route_stop(db_path, stop_id, confirm=True, restrict=False, crew_name="")
    assert result.startswith("✅")
