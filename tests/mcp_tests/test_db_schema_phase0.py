"""
Phase 0 tests — Job Board Architecture Spec §11.

Covers the schema & data-access foundation only (db_schema.py /
db_access.py). No MCP tool calls yet — those land in Phase 1/2.
Fully isolated: every test uses tmp_path, never touches
~/.ai-prowler/ or the real AI-Prowler_Job_Tracker.xlsx, per the
project's testing discipline.

Run: py -m pytest tests\\mcp\\test_db_schema_phase0.py -v
"""

import json
import sqlite3
import threading

import pytest

from db_access import get_connection, import_users_json, init_db, transaction, touch_row
from db_schema import SCHEMA_VERSION, apply_schema


# ── Schema creation is idempotent ──────────────────────────────────────

def test_schema_creation_idempotent(tmp_path):
    db_path = str(tmp_path / "jobs.db")
    init_db(db_path)

    conn1 = get_connection(db_path)
    tables1 = {r["name"] for r in conn1.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    conn1.close()

    # Running it again on the same (now non-empty) file must be a no-op,
    # not an error, and must not change the table set.
    init_db(db_path)

    conn2 = get_connection(db_path)
    tables2 = {r["name"] for r in conn2.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    version = conn2.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'").fetchone()
    conn2.close()

    assert tables1 == tables2
    assert {"customers", "jobs", "invoices", "quotes", "time_entries",
            "route_stops", "settings", "service_pricing", "users"} <= tables1
    assert version["value"] == str(SCHEMA_VERSION)


def test_schema_creation_idempotent_on_empty_db(tmp_path):
    """Explicit empty-DB case called out in the spec: running schema
    creation twice on an empty DB produces identical structure, no
    errors."""
    db_path = str(tmp_path / "empty.db")
    conn = get_connection(db_path)
    apply_schema(conn)
    apply_schema(conn)  # must not raise
    conn.close()


# ── Generated columns compute correctly ────────────────────────────────

def _insert_customer(conn, customer_id="CUST-0001"):
    conn.execute(
        "INSERT INTO customers (customer_id, company_name, status) VALUES (?, 'Test Co', 'Active')",
        (customer_id,),
    )


def _insert_job(conn, job_id="JOB-0001", customer_id="CUST-0001"):
    conn.execute(
        "INSERT INTO jobs (job_id, customer_id) VALUES (?, ?)",
        (job_id, customer_id),
    )


def test_elapsed_min_generated_column(tmp_path):
    db_path = str(tmp_path / "jobs.db")
    init_db(db_path)
    with transaction(db_path) as conn:
        _insert_customer(conn)
        _insert_job(conn)
        conn.execute(
            """INSERT INTO time_entries (entry_id, job_id, entry_date, clock_in, clock_out)
               VALUES ('T1', 'JOB-0001', '2026-09-12', '08:00:00', '09:30:00')"""
        )

    conn = get_connection(db_path)
    row = conn.execute("SELECT elapsed_min FROM time_entries WHERE entry_id = 'T1'").fetchone()
    conn.close()
    assert row["elapsed_min"] == 90.0


def test_elapsed_min_null_while_clocked_in(tmp_path):
    """No clock_out yet -> elapsed_min must be NULL, not an error or 0."""
    db_path = str(tmp_path / "jobs.db")
    init_db(db_path)
    with transaction(db_path) as conn:
        _insert_customer(conn)
        _insert_job(conn)
        conn.execute(
            """INSERT INTO time_entries (entry_id, job_id, entry_date, clock_in)
               VALUES ('T2', 'JOB-0001', '2026-09-12', '08:00:00')"""
        )

    conn = get_connection(db_path)
    row = conn.execute("SELECT elapsed_min FROM time_entries WHERE entry_id = 'T2'").fetchone()
    conn.close()
    assert row["elapsed_min"] is None


def test_elapsed_min_cannot_be_written_directly(tmp_path):
    """Generated columns are read-only by construction — SQLite itself
    rejects an explicit write to elapsed_min."""
    db_path = str(tmp_path / "jobs.db")
    init_db(db_path)
    with transaction(db_path) as conn:
        _insert_customer(conn)
        _insert_job(conn)
        with pytest.raises(sqlite3.OperationalError):
            conn.execute(
                """INSERT INTO time_entries (entry_id, job_id, entry_date, elapsed_min)
                   VALUES ('T3', 'JOB-0001', '2026-09-12', 999)"""
            )


# ── Foreign key constraints are enforced ───────────────────────────────

def test_fk_violation_rejected_cleanly(tmp_path):
    """Inserting a job with a nonexistent customer_id must fail cleanly,
    not silently."""
    db_path = str(tmp_path / "jobs.db")
    init_db(db_path)
    with pytest.raises(sqlite3.IntegrityError):
        with transaction(db_path) as conn:
            conn.execute(
                "INSERT INTO jobs (job_id, customer_id) VALUES ('JOB-0099', 'CUST-DOES-NOT-EXIST')"
            )
    # And the failed insert must not have partially landed.
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM jobs WHERE job_id = 'JOB-0099'").fetchone()
    conn.close()
    assert row is None


def test_fk_valid_insert_succeeds(tmp_path):
    db_path = str(tmp_path / "jobs.db")
    init_db(db_path)
    with transaction(db_path) as conn:
        _insert_customer(conn)
        _insert_job(conn)
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM jobs WHERE job_id = 'JOB-0001'").fetchone()
    conn.close()
    assert row is not None
    assert row["version"] == 1


# ── Row versioning helper ───────────────────────────────────────────────

def test_touch_row_bumps_version_and_stamps(tmp_path):
    db_path = str(tmp_path / "jobs.db")
    init_db(db_path)
    with transaction(db_path) as conn:
        _insert_customer(conn)
        _insert_job(conn)
        touch_row(conn, "jobs", "job_id", "JOB-0001", actor="david")

    conn = get_connection(db_path)
    row = conn.execute("SELECT version, last_edited_by, last_edited_at FROM jobs WHERE job_id = 'JOB-0001'").fetchone()
    conn.close()
    assert row["version"] == 2
    assert row["last_edited_by"] == "david"
    assert row["last_edited_at"] is not None


# ── Concurrent-write smoke test (the core promise of the redesign) ─────

def test_concurrent_writes_to_different_rows_do_not_block_or_corrupt(tmp_path):
    """Two threads, each writing to a DIFFERENT row in the same table,
    must both complete without blocking each other or corrupting either
    row. This is the core promise of the whole redesign (spec §11,
    Phase 0) — test it explicitly, don't assume it from documentation."""
    db_path = str(tmp_path / "jobs.db")
    init_db(db_path)
    with transaction(db_path) as conn:
        _insert_customer(conn, "CUST-0001")
        _insert_job(conn, "JOB-0001", "CUST-0001")
        _insert_job(conn, "JOB-0002", "CUST-0001")

    errors = []

    def writer(job_id, status):
        try:
            with transaction(db_path) as conn:
                conn.execute(
                    "UPDATE jobs SET job_status = ? WHERE job_id = ?", (status, job_id)
                )
                touch_row(conn, "jobs", "job_id", job_id, actor=f"thread-{status}")
        except Exception as e:  # pragma: no cover - failure path surfaced via errors list
            errors.append(e)

    t1 = threading.Thread(target=writer, args=("JOB-0001", "Completed"))
    t2 = threading.Thread(target=writer, args=("JOB-0002", "In Progress"))
    t1.start()
    t2.start()
    t1.join(timeout=10)
    t2.join(timeout=10)

    assert not errors, f"concurrent writes raised: {errors}"

    conn = get_connection(db_path)
    j1 = conn.execute("SELECT job_status, version FROM jobs WHERE job_id = 'JOB-0001'").fetchone()
    j2 = conn.execute("SELECT job_status, version FROM jobs WHERE job_id = 'JOB-0002'").fetchone()
    conn.close()
    assert j1["job_status"] == "Completed" and j1["version"] == 2
    assert j2["job_status"] == "In Progress" and j2["version"] == 2


# ── users.json importer round-trip ──────────────────────────────────────

def test_users_json_importer_round_trips_realistic_roster(tmp_path):
    db_path = str(tmp_path / "jobs.db")
    init_db(db_path)

    users_json_path = tmp_path / "users.json"
    roster = [
        {
            "id": "u_david",
            "email": "david.vavro1@gmail.com",
            "phone": "555-0100",
            "first_name": "David",
            "last_name": "Vavro",
            "role": "owner",
            "scopes": ["shared"],
            "home_address": "New Smyrna Beach, FL",
            "private_collection_enabled": True,
        },
        {
            # exercises the dict-key-as-id fallback path and a
            # single 'name' field instead of first/last
            "email": "samantha@example.com",
            "name": "Samantha Crew",
            "role": "field_crew",
            "cell_phone": "555-0101",
            "some_future_field": "should not be dropped",
        },
    ]
    users_json_path.write_text(json.dumps(roster), encoding="utf-8")

    count = import_users_json(db_path, str(users_json_path))
    assert count == 2

    conn = get_connection(db_path)
    david = conn.execute("SELECT * FROM users WHERE id = 'u_david'").fetchone()
    assert david["email"] == "david.vavro1@gmail.com"
    assert david["first_name"] == "David"
    assert david["last_name"] == "Vavro"
    assert david["role"] == "owner"
    assert json.loads(david["scopes_json"]) == ["shared"]
    assert david["private_collection_enabled"] == 1

    sam = conn.execute("SELECT * FROM users WHERE email = 'samantha@example.com'").fetchone()
    assert sam is not None
    assert sam["first_name"] == "Samantha"
    assert sam["last_name"] == "Crew"
    assert sam["phone"] == "555-0101"
    extra = json.loads(sam["extra_json"])
    assert extra.get("some_future_field") == "should not be dropped"
    conn.close()

    # Re-running (e.g. after users.json changes) must upsert, not duplicate.
    roster[0]["role"] = "owner"  # unchanged
    roster[1]["cell_phone"] = "555-9999"  # changed
    users_json_path.write_text(json.dumps(roster), encoding="utf-8")
    count2 = import_users_json(db_path, str(users_json_path))
    assert count2 == 2

    conn = get_connection(db_path)
    total = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    sam2 = conn.execute("SELECT phone FROM users WHERE email = 'samantha@example.com'").fetchone()
    conn.close()
    assert total == 2  # upsert, not duplicate rows
    assert sam2["phone"] == "555-9999"


def test_wal_mode_enabled(tmp_path):
    """Sanity check that every connection actually gets WAL journal
    mode — this is what lets the admin's Job Board stay open all day
    without blocking crew writes (spec §4.1, §6.1)."""
    db_path = str(tmp_path / "jobs.db")
    init_db(db_path)
    conn = get_connection(db_path)
    mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    conn.close()
    assert mode.lower() == "wal"
