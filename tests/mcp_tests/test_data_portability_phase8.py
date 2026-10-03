"""
tests/mcp_tests/test_data_portability_phase8.py
=============================================
Job Board Architecture Spec Phase 8 (spec §12) — Data Portability:
backup_database(), restore_database(), export_to_csv().

Run with:
    run_tests.bat tests\\mcp\\test_data_portability_phase8.py -v
"""
from __future__ import annotations

import csv
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path

import pytest

from db_access import init_db
from db_backup_ops import (
    _ALL_TABLES,
    db_backup_database,
    db_export_to_csv,
    db_restore_database,
)
from db_write_ops import db_create_customer, db_create_job

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _seed_some_data(db_path):
    # Job Board Architecture Spec §5.1 (2026-09-22): create_job now requires
    # a real, existing CustomerID.
    cust_result = db_create_customer(db_path, {"Company Name": "Blue Wave Cafe"}, actor="dave")
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    db_create_job(db_path, {"CustomerID (Customers!A)": cust_id, "Customer Name / Company": "Blue Wave Cafe"}, actor="dave")


def _row_count(db_path, table):
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


# ══════════════════════════════════════════════════════════════════════════
# backup_database
# ══════════════════════════════════════════════════════════════════════════

def test_backup_creates_a_real_file(db_path, tmp_path):
    _seed_some_data(db_path)
    dest = str(tmp_path / "backup.db")
    result = db_backup_database(db_path, dest)
    assert result.startswith("✅"), result
    assert os.path.exists(dest)


def test_backup_row_counts_match_source(db_path, tmp_path):
    _seed_some_data(db_path)
    dest = str(tmp_path / "backup.db")
    db_backup_database(db_path, dest)
    for table in _ALL_TABLES:
        assert _row_count(dest, table) == _row_count(db_path, table), table


def test_backup_default_destination_when_omitted(db_path):
    result = db_backup_database(db_path, destination_path="")
    assert result.startswith("✅"), result
    assert "backup" in result
    assert os.path.exists(os.path.dirname(db_path) + os.sep + "backup") or "backup" in result


def test_backup_nonexistent_source_fails_cleanly(tmp_path):
    result = db_backup_database(str(tmp_path / "nonexistent.db"), str(tmp_path / "out.db"))
    assert result.startswith("❌")
    assert not os.path.exists(str(tmp_path / "out.db"))


def test_backup_survives_concurrent_writer(db_path, tmp_path):
    """The whole reason this uses SQLite's Backup API instead of a raw
    file copy — a backup taken while another connection is actively
    writing must not corrupt either side."""
    stop = threading.Event()
    errors = []

    def _writer():
        i = 0
        conn = sqlite3.connect(db_path, timeout=5)
        try:
            while not stop.is_set():
                try:
                    conn.execute(
                        "INSERT INTO customers (customer_id, company_name) VALUES (?, ?)",
                        (f"CUST-W{i}", f"Writer Co {i}"),
                    )
                    conn.commit()
                    i += 1
                except Exception as e:
                    errors.append(e)
                time.sleep(0.01)
        finally:
            conn.close()

    t = threading.Thread(target=_writer)
    t.start()
    try:
        time.sleep(0.05)
        dest = str(tmp_path / "concurrent_backup.db")
        result = db_backup_database(db_path, dest)
    finally:
        stop.set()
        t.join(timeout=5)

    assert result.startswith("✅"), result
    assert not errors, errors
    # The backup itself must be a valid, readable database.
    conn = sqlite3.connect(dest)
    conn.execute("SELECT COUNT(*) FROM customers").fetchone()
    conn.close()


# ══════════════════════════════════════════════════════════════════════════
# restore_database
# ══════════════════════════════════════════════════════════════════════════

def test_restore_without_confirm_does_nothing(db_path, tmp_path):
    _seed_some_data(db_path)
    backup_path = str(tmp_path / "backup.db")
    db_backup_database(db_path, backup_path)

    before = _row_count(db_path, "customers")
    result = db_restore_database(db_path, backup_path, confirm=False)
    assert result.startswith("❌")
    assert "confirm=True" in result
    assert _row_count(db_path, "customers") == before  # unchanged


def test_restore_rejects_non_ai_prowler_file(db_path, tmp_path):
    garbage_path = tmp_path / "garbage.db"
    garbage_path.write_text("not a real database")
    result = db_restore_database(db_path, str(garbage_path), confirm=True)
    assert result.startswith("❌")
    assert "does not look like an AI-Prowler database" in result


def test_restore_rejects_missing_backup_file(db_path, tmp_path):
    result = db_restore_database(db_path, str(tmp_path / "nonexistent.db"), confirm=True)
    assert result.startswith("❌")
    assert "not found" in result


def test_restore_takes_safety_backup_of_current_data_first(db_path, tmp_path):
    _seed_some_data(db_path)
    original_customer_count = _row_count(db_path, "customers")

    # Build a DIFFERENT backup with different data.
    other_db = str(tmp_path / "other.db")
    init_db(other_db)
    db_create_customer(other_db, {"Company Name": "Totally Different Co"}, actor="dave")
    db_create_customer(other_db, {"Company Name": "Another Co"}, actor="dave")

    result = db_restore_database(db_path, other_db, confirm=True)
    assert result.startswith("✅"), result
    assert "safety" in result.lower() or "backed up first" in result.lower()

    # The live db_path now has the OTHER data.
    assert _row_count(db_path, "customers") == 2

    # A safety backup of the ORIGINAL data must exist and be restorable.
    backups_dir = os.path.join(os.path.dirname(db_path), "backup")
    assert os.path.exists(backups_dir)
    safety_files = os.listdir(backups_dir)
    assert len(safety_files) >= 1
    safety_path = os.path.join(backups_dir, safety_files[0])
    assert _row_count(safety_path, "customers") == original_customer_count


def test_full_round_trip_backup_then_restore(db_path, tmp_path):
    _seed_some_data(db_path)
    original_counts = {t: _row_count(db_path, t) for t in _ALL_TABLES}

    backup_path = str(tmp_path / "roundtrip.db")
    backup_result = db_backup_database(db_path, backup_path)
    assert backup_result.startswith("✅")

    # Mutate the live db so restore has something real to reverse.
    db_create_customer(db_path, {"Company Name": "Extra Co"}, actor="dave")
    assert _row_count(db_path, "customers") == original_counts["customers"] + 1

    restore_result = db_restore_database(db_path, backup_path, confirm=True)
    assert restore_result.startswith("✅"), restore_result

    for table in _ALL_TABLES:
        assert _row_count(db_path, table) == original_counts[table], table


# ══════════════════════════════════════════════════════════════════════════
# export_to_csv
# ══════════════════════════════════════════════════════════════════════════

def test_csv_export_writes_all_eight_files_by_default(db_path, tmp_path):
    _seed_some_data(db_path)
    out_dir = str(tmp_path / "csv_out")
    result = db_export_to_csv(db_path, out_dir)
    assert result.startswith("✅"), result
    files = os.listdir(out_dir)
    assert len(files) == 8
    assert "Customers.csv" in files
    assert "Jobs_Schedule.csv" in files


def test_csv_export_scoped_to_one_table(db_path, tmp_path):
    _seed_some_data(db_path)
    out_dir = str(tmp_path / "csv_scoped")
    result = db_export_to_csv(db_path, out_dir, tables=["customers"])
    assert result.startswith("✅"), result
    files = os.listdir(out_dir)
    assert files == ["Customers.csv"]


def test_csv_export_content_is_correct(db_path, tmp_path):
    _seed_some_data(db_path)
    out_dir = str(tmp_path / "csv_content")
    db_export_to_csv(db_path, out_dir, tables=["customers"])
    with open(os.path.join(out_dir, "Customers.csv"), newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    assert rows[0][0] == "CustomerID (CUST-####)"  # header row present
    assert any("Blue Wave Cafe" in row for row in rows[1:])


def test_csv_export_unknown_table_rejected(db_path, tmp_path):
    result = db_export_to_csv(db_path, str(tmp_path / "out"), tables=["not_a_real_table"])
    assert result.startswith("❌")
    assert "Unknown table" in result


def test_csv_export_handles_commas_in_values_correctly(db_path, tmp_path):
    """A company name containing a comma must not corrupt the CSV
    structure — csv.writer handles quoting automatically, this just
    confirms it round-trips correctly."""
    db_create_customer(db_path, {"Company Name": "Smith, Jones & Co"}, actor="dave")
    out_dir = str(tmp_path / "csv_commas")
    db_export_to_csv(db_path, out_dir, tables=["customers"])
    with open(os.path.join(out_dir, "Customers.csv"), newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    assert any("Smith, Jones & Co" in row for row in rows[1:])
