"""
Tests for delete_route / db_delete_route — added 2026-09-23 at the owner's
request: deleting a route one stop at a time never made sense, since the
stops are one coherent plan, not independent rows. Whole-route sibling of
delete_route_stop (same file, same no-cascade/no-retire-first posture).

Also locks in a real bug found the same day: the Route sheet's "Delete
Route" button was wired off the SHEET'S OWN DISPLAY VALUE for Route Date,
which is formatted MM/DD/YYYY (db_read_ops.py formats every "date" column
that way) — but route_stops.route_date is stored as ISO 'YYYY-MM-DD'. A
straight equality match against the display string silently found nothing
("No route found for 09/19/2026") even though the route was right there.
_normalize_route_date fixes this by accepting either shape.

Run: py -m pytest tests\\mcp\\test_delete_route.py -v
"""

import os

import pytest

from db_access import get_connection, init_db, transaction
from db_write_ops import db_create_customer, db_create_job, db_delete_route


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _make_stop(db_path, route_date="2026-09-19", crew_id="", stop_number=1,
               address="1 Main St, NSB, FL"):
    with transaction(db_path) as conn:
        cur = conn.execute(
            "INSERT INTO route_stops (route_date, crew_id, stop_number, address, "
            "created_by, last_edited_by, last_edited_at) "
            "VALUES (?, ?, ?, ?, 'test', 'test', '2026-09-19T00:00:00')",
            (route_date, crew_id, stop_number, address),
        )
        return cur.lastrowid


# ── Not found ────────────────────────────────────────────────────────────

def test_not_found_returns_error(db_path):
    result = db_delete_route(db_path, "2026-09-19", confirm=True)
    assert result.startswith("❌")
    assert "No route found" in result


def test_missing_route_date_rejected(db_path):
    result = db_delete_route(db_path, "", confirm=True)
    assert result.startswith("❌")
    assert "route_date is required" in result


# ── Regression: display-formatted MM/DD/YYYY date must still match ──────

def test_mm_dd_yyyy_display_format_still_finds_the_route(db_path):
    """The real bug: the Route sheet displays Route Date as MM/DD/YYYY
    (db_read_ops.py's generic date formatting), so a "Delete Route" button
    wired straight off that cell sends "09/19/2026", not the stored ISO
    "2026-09-19". Must still find and delete the route."""
    _make_stop(db_path, route_date="2026-09-19")
    preview = db_delete_route(db_path, "09/19/2026", confirm=False)
    assert preview.startswith("❌ This permanently deletes"), preview
    assert "2026-09-19" in preview

    result = db_delete_route(db_path, "09/19/2026", confirm=True)
    assert result.startswith("✅"), result
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM route_stops WHERE route_date = '2026-09-19'").fetchone()
    conn.close()
    assert row is None


def test_iso_format_also_works(db_path):
    _make_stop(db_path, route_date="2026-09-19")
    result = db_delete_route(db_path, "2026-09-19", confirm=True)
    assert result.startswith("✅"), result


# ── Guard: confirm required ─────────────────────────────────────────────

def test_preview_without_confirm_deletes_nothing(db_path):
    _make_stop(db_path)
    result = db_delete_route(db_path, "2026-09-19", confirm=False)
    assert result.startswith("❌")
    assert "confirm=True" in result
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM route_stops WHERE route_date = '2026-09-19'").fetchone()
    conn.close()
    assert row is not None


def test_preview_reports_stop_count_and_crews(db_path):
    _make_stop(db_path, crew_id="Jake R", stop_number=1)
    _make_stop(db_path, crew_id="Jake R", stop_number=2)
    _make_stop(db_path, crew_id="Maria S", stop_number=1)
    result = db_delete_route(db_path, "2026-09-19", confirm=False)
    assert "3 stop(s)" in result
    assert "Jake R" in result and "Maria S" in result


# ── Deletes the WHOLE route, not one row ────────────────────────────────

def test_deletes_every_stop_for_the_date(db_path):
    _make_stop(db_path, stop_number=1)
    _make_stop(db_path, stop_number=2)
    _make_stop(db_path, stop_number=3)
    result = db_delete_route(db_path, "2026-09-19", confirm=True)
    assert result.startswith("✅"), result
    assert "3 stop(s) removed" in result
    conn = get_connection(db_path)
    remaining = conn.execute("SELECT COUNT(*) AS n FROM route_stops WHERE route_date = '2026-09-19'").fetchone()
    conn.close()
    assert remaining["n"] == 0


def test_other_dates_left_untouched(db_path):
    _make_stop(db_path, route_date="2026-09-19")
    _make_stop(db_path, route_date="2026-09-20")
    db_delete_route(db_path, "2026-09-19", confirm=True)
    conn = get_connection(db_path)
    remaining = conn.execute("SELECT COUNT(*) AS n FROM route_stops WHERE route_date = '2026-09-20'").fetchone()
    conn.close()
    assert remaining["n"] == 1


def test_crew_argument_scopes_to_just_that_crew(db_path):
    """Passing crew deletes only that crew's stops for the date, leaving
    any other crew's stops on the same date untouched."""
    _make_stop(db_path, crew_id="Jake R", stop_number=1)
    _make_stop(db_path, crew_id="Maria S", stop_number=1)
    result = db_delete_route(db_path, "2026-09-19", crew="Jake R", confirm=True)
    assert result.startswith("✅"), result
    conn = get_connection(db_path)
    remaining = conn.execute(
        "SELECT crew_id FROM route_stops WHERE route_date = '2026-09-19'"
    ).fetchall()
    conn.close()
    assert [r["crew_id"] for r in remaining] == ["Maria S"]


def test_safety_backup_file_actually_created(db_path):
    _make_stop(db_path)
    result = db_delete_route(db_path, "2026-09-19", confirm=True)
    backup_line = [l for l in result.splitlines() if "Safety backup saved first" in l][0]
    backup_path = backup_line.split(":", 1)[1].strip()
    assert os.path.exists(backup_path)


# ── No cascade needed — deleting a route never touches jobs/customers ───

def test_deleting_route_does_not_affect_the_jobs_it_pointed_at(db_path):
    cust_result = db_create_customer(db_path, {"Company Name": "ZTEST Whoever"}, actor="test")
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    job_result = db_create_job(
        db_path,
        {"CustomerID (Customers!A)": cust_id, "Customer Name / Company": "ZTEST Whoever", "Service Date": "2026-09-19"},
        actor="test",
    )
    job_id = job_result.split("NEW_JOB_ID=")[1].strip()

    stop_id = _make_stop(db_path)
    with transaction(db_path) as conn:
        conn.execute("UPDATE route_stops SET job_id = ? WHERE id = ?", (job_id, stop_id))

    result = db_delete_route(db_path, "2026-09-19", confirm=True)
    assert result.startswith("✅")

    conn = get_connection(db_path)
    job_row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    conn.close()
    assert job_row is not None  # untouched


# ── Crew-scoping: mirrors db_delete_route_stop's own ownership rule ─────

def test_field_crew_can_delete_own_route(db_path):
    _make_stop(db_path, crew_id="Jake R")
    result = db_delete_route(db_path, "2026-09-19", confirm=True, restrict=True, crew_name="jake r")
    assert result.startswith("✅")


def test_field_crew_cannot_delete_route_with_a_coworkers_stop(db_path):
    _make_stop(db_path, crew_id="Jake R", stop_number=1)
    _make_stop(db_path, crew_id="Maria S", stop_number=2)
    result = db_delete_route(db_path, "2026-09-19", confirm=True, restrict=True, crew_name="jake r")
    assert result.startswith("❌")
    assert "your own" in result
    conn = get_connection(db_path)
    remaining = conn.execute("SELECT COUNT(*) AS n FROM route_stops WHERE route_date = '2026-09-19'").fetchone()
    conn.close()
    assert remaining["n"] == 2  # untouched


def test_owner_unrestricted_regardless_of_crew(db_path):
    _make_stop(db_path, crew_id="Jake R", stop_number=1)
    _make_stop(db_path, crew_id="Maria S", stop_number=2)
    result = db_delete_route(db_path, "2026-09-19", confirm=True, restrict=False)
    assert result.startswith("✅")
