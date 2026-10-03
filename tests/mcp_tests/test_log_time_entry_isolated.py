"""
test_log_time_entry_isolated.py
================================
Functional tests for _log_time_entry_impl() (clock in/out, GPS logging,
crew-name reporting) that exercise the REAL production function — not a
reimplemented copy — while staying fully isolated from:

  1. The real production job database (or dev-folder copy). Every test
     builds its own scratch SQLite database inside pytest's tmp_path,
     which pytest deletes automatically after the test. Nothing here
     ever opens a file under Documents/AI-Prowler or the dev-folder
     install.

     2026-09-14 migration note: this file originally built a scratch
     .xlsx workbook with openpyxl, matching the pre-Job-Board-migration
     spreadsheet store. Since Phase 1 (Job Board Architecture Spec),
     _log_time_entry_impl() reads/writes the SQLite job database via
     db_write_ops.db_log_time_entry instead — an .xlsx fixture is no
     longer read by the tool at all. Rewritten to build the scratch
     fixture directly against the real db_schema.py schema instead, the
     same way test_job_board_phase1_mcp_wiring.py already does. GPS
     "hyperlink" columns are now plain map-URL text columns
     (clock_in_map_url/clock_out_map_url) rather than openpyxl Hyperlink
     objects, so the two read-back helpers below read those columns
     directly instead of inspecting a cell's `.hyperlink` attribute.

  2. A live AI-Prowler server process, if one happens to be running.
     Importing ai_prowler_mcp.py normally opens
     ~/.ai-prowler/logs/mcp_server.log in truncate ("w") mode at import
     time — if a live server already has that file open, the two
     processes fight over it and can corrupt the log (this actually
     happened during manual testing on 2026-08-13). To avoid that, each
     test runs the real function in a SEPARATE SUBPROCESS with USERPROFILE
     (Windows' equivalent of $HOME) redirected to a scratch directory
     inside tmp_path — so Path.home() inside that subprocess resolves to
     the scratch dir, and mcp_server.log gets created there instead of
     under the real ~/.ai-prowler. The live server's log is never touched.

Safe to run at any time, including while AI-Prowler is running live.

Run with:
    pytest tests/mcp_tests/test_log_time_entry_isolated.py -v
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
MCP_FILE = SRC_ROOT / "ai_prowler_mcp.py"


def _build_scratch_tracker(path: Path, jobs=None):
    """Build a minimal but realistic scratch SQLite job database at
    `path`. `jobs` is a list of (job_id, customer, crew) tuples;
    defaults to one test job. Uses the real db_schema.apply_schema, the
    same schema the production tool reads/writes."""
    jobs = jobs or [("JOB-TEST-01", "Test Customer LLC", "Test Crew")]

    sys.path.insert(0, str(SRC_ROOT))
    from db_access import get_connection
    from db_schema import apply_schema

    conn = get_connection(str(path))
    try:
        apply_schema(conn)
        for jid, cust, crew in jobs:
            conn.execute(
                "INSERT INTO jobs (job_id, customer_name, crew) VALUES (?, ?, ?)",
                (jid, cust, crew),
            )
        conn.commit()
    finally:
        conn.close()


def _run_clock_action(tmp_path: Path, db_path: Path, job_identifier: str,
                       action: str, gps_coords: str = "") -> str:
    """
    Run the REAL _log_time_entry_impl() in an isolated subprocess.
    Returns the function's string result. Raises AssertionError with full
    stderr on any subprocess-level failure (import error, exception, etc.)
    so failures are legible in pytest output rather than a bare timeout.
    """
    scratch_home = tmp_path / "scratch_home"
    scratch_home.mkdir(exist_ok=True)

    script = textwrap.dedent(f"""
        import sys, json
        sys.path.insert(0, {str(SRC_ROOT)!r})
        import ai_prowler_mcp as m
        result = m._log_time_entry_impl(
            {job_identifier!r}, {action!r}, {str(db_path)!r}, None,
            gps_coords={gps_coords!r},
        )
        print("RESULT_JSON_START" + json.dumps(result) + "RESULT_JSON_END")
    """)

    env = os.environ.copy()
    env["USERPROFILE"] = str(scratch_home)
    env["HOME"] = str(scratch_home)

    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(SRC_ROOT), env=env,
        capture_output=True, text=True, timeout=90,
    )

    if "RESULT_JSON_START" not in proc.stdout:
        raise AssertionError(
            f"Subprocess did not return a result.\n"
            f"--- stdout ---\n{proc.stdout}\n"
            f"--- stderr ---\n{proc.stderr}\n"
            f"--- returncode --- {proc.returncode}"
        )

    payload = proc.stdout.split("RESULT_JSON_START", 1)[1].split("RESULT_JSON_END", 1)[0]
    return json.loads(payload)


def _read_row(db_path: Path, entry_id: str) -> dict:
    """Read back a time_entries row by EntryID as a plain dict, keyed by
    the real SQLite column names (job_id, clock_in, clock_out, etc.)."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM time_entries WHERE entry_id = ?", (entry_id,)
    ).fetchone()
    conn.close()
    if row is None:
        raise AssertionError(f"EntryID {entry_id!r} not found in time_entries.")
    return dict(row)


# ══════════════════════════════════════════════════════════════════════════
# TESTS
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def tracker(tmp_path):
    """Fresh scratch job database per test — never the real one."""
    path = tmp_path / "scratch_job_board.db"
    _build_scratch_tracker(path)
    return path


def _read_map_url(db_path: Path, entry_id: str, column: str) -> str | None:
    """Read back a clock_in_map_url / clock_out_map_url value directly —
    these are plain text columns in the SQLite schema (db_write_ops
    writes a real Google Maps URL string, or leaves the column NULL when
    no GPS was given), unlike the openpyxl-era cell hyperlink object."""
    row = _read_row(db_path, entry_id)
    return row.get(column) or None


def test_source_exists():
    assert MCP_FILE.exists(), f"ai_prowler_mcp.py not found at {MCP_FILE}"


def test_clock_in_writes_expected_fields(tmp_path, tracker):
    result = _run_clock_action(tmp_path, tracker, "JOB-TEST-01", "start",
                                gps_coords="29.0219,-80.9270")
    assert "Clocked IN" in result

    row = _read_row(tracker, "TE-0001")
    assert row["job_id"] == "JOB-TEST-01"
    assert row["customer_name"] == "Test Customer LLC"
    assert row["clock_in"] not in (None, "")
    assert row["clock_in_gps"] == "29.0219,-80.9270"
    assert row["clock_out_gps"] in (None, "")  # not set yet


def test_clock_out_writes_elapsed_and_gps(tmp_path, tracker):
    _run_clock_action(tmp_path, tracker, "JOB-TEST-01", "start",
                       gps_coords="29.0219,-80.9270")
    result = _run_clock_action(tmp_path, tracker, "JOB-TEST-01", "stop",
                                gps_coords="29.0221,-80.9268")
    assert "❌" not in result, f"Unexpected error: {result}"

    row = _read_row(tracker, "TE-0001")
    assert row["clock_out"] not in (None, "")
    assert row["elapsed_min"] is not None
    assert row["clock_in_gps"] == "29.0219,-80.9270"
    assert row["clock_out_gps"] == "29.0221,-80.9268"


def test_clock_out_without_gps_leaves_field_blank(tmp_path, tracker):
    """GPS must stay optional — denied/unavailable location on the phone
    should never block or break a clock action."""
    _run_clock_action(tmp_path, tracker, "JOB-TEST-01", "start", gps_coords="")
    result = _run_clock_action(tmp_path, tracker, "JOB-TEST-01", "stop", gps_coords="")
    assert "❌" not in result, f"Unexpected error: {result}"

    row = _read_row(tracker, "TE-0001")
    assert row["clock_out"] not in (None, "")
    assert row["clock_in_gps"] in (None, "")
    assert row["clock_out_gps"] in (None, "")


def test_duplicate_clock_in_blocked(tmp_path, tracker):
    _run_clock_action(tmp_path, tracker, "JOB-TEST-01", "start")
    result = _run_clock_action(tmp_path, tracker, "JOB-TEST-01", "start")
    assert "already open" in result


def test_clock_out_without_open_entry_errors_cleanly(tmp_path, tracker):
    result = _run_clock_action(tmp_path, tracker, "JOB-TEST-01", "stop")
    assert "❌" in result
    assert "No open clock-in" in result
    # THE ORIGINAL BUG this whole fix was for — must never reappear:
    assert "Could not parse Clock In time: None" not in result


def test_gps_columns_never_collide_with_base_columns(tmp_path, tracker):
    """Regression guard: GPS values must never land in the clock_in/
    clock_out timestamp columns or vice versa."""
    _run_clock_action(tmp_path, tracker, "JOB-TEST-01", "start",
                       gps_coords="1.111111,2.222222")
    _run_clock_action(tmp_path, tracker, "JOB-TEST-01", "stop",
                       gps_coords="3.333333,4.444444")
    row = _read_row(tracker, "TE-0001")

    # Clock In/Out timestamps must be real timestamp strings, not GPS coords
    assert "," not in str(row["clock_in"])
    assert "," not in str(row["clock_out"])
    # GPS columns must hold GPS coords, not timestamps
    assert row["clock_in_gps"] == "1.111111,2.222222"
    assert row["clock_out_gps"] == "3.333333,4.444444"


def test_unrelated_headers_untouched_by_canonicalization(tmp_path, tracker):
    """The job's crew name must be carried onto the time entry
    unchanged, distinct from any GPS/timestamp column."""
    _run_clock_action(tmp_path, tracker, "JOB-TEST-01", "start")
    row = _read_row(tracker, "TE-0001")
    assert row["crew"] == "Test Crew"


def test_nonexistent_job_returns_clear_error(tmp_path, tracker):
    result = _run_clock_action(tmp_path, tracker, "JOB-DOES-NOT-EXIST", "start")
    assert "❌" in result
    assert "No job found" in result


def test_scratch_tracker_never_touches_real_files(tmp_path, tracker):
    """Sanity check on the test design itself: confirm the scratch tracker
    is genuinely under tmp_path, nowhere near the real database."""
    assert "tmp" in str(tracker).lower() or str(tmp_path) in str(tracker)
    assert "Documents\\AI-Prowler" not in str(tracker)
    assert "AI-Prowler-V900_to_V910_work" not in str(tracker)


def test_clock_in_gps_gets_maps_hyperlink(tmp_path, tracker):
    _run_clock_action(tmp_path, tracker, "JOB-TEST-01", "start",
                       gps_coords="29.049377,-80.994279")
    link = _read_map_url(tracker, "TE-0001", "clock_in_map_url")
    assert link == "https://www.google.com/maps?q=29.049377,-80.994279"
    # Display value must be untouched — still the raw, copyable coordinates
    row = _read_row(tracker, "TE-0001")
    assert row["clock_in_gps"] == "29.049377,-80.994279"


def test_clock_out_gps_gets_maps_hyperlink(tmp_path, tracker):
    _run_clock_action(tmp_path, tracker, "JOB-TEST-01", "start")
    _run_clock_action(tmp_path, tracker, "JOB-TEST-01", "stop",
                       gps_coords="29.049385,-80.994275")
    link = _read_map_url(tracker, "TE-0001", "clock_out_map_url")
    assert link == "https://www.google.com/maps?q=29.049385,-80.994275"


def test_no_gps_means_no_hyperlink(tmp_path, tracker):
    """Blank GPS must not produce a broken/empty map URL."""
    _run_clock_action(tmp_path, tracker, "JOB-TEST-01", "start", gps_coords="")
    link = _read_map_url(tracker, "TE-0001", "clock_in_map_url")
    assert link is None

