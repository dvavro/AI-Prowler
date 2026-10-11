"""CUST-YEAR-N scheme tests (2026-10-04 — David: CUST-2026-1, no padding).

Customer IDs are now CUST-{YYYY}-{N}: year from the server clock at
creation, N auto-increments per year (restarts every January), unpadded,
never reused within a year (R-044). The number (not the year) is
user-editable via db_rename_customer_number / rename_customer.

Run: pytest test_year_scheme.py -v   (with db_access/db_schema/db_write_ops importable)
"""
import pytest

import db_write_ops
from db_access import get_connection, init_db, transaction
from db_write_ops import (
    db_create_customer,
    db_create_job,
    db_rename_customer_number,
    generate_next_id,
)


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


@pytest.fixture
def y2026(monkeypatch):
    monkeypatch.setattr(db_write_ops, "_current_year", lambda: 2026)


def _new_id(result, key="NEW_CUST_ID"):
    return result.split(f"{key}=")[1].splitlines()[0].strip()


def _cust(db_path, name="Y Customer"):
    return _new_id(db_create_customer(db_path, {"Company Name": name}, actor="dave"))


# ── Year-aware generation ────────────────────────────────────────────────

def test_first_customer_gets_year_one(db_path, y2026):
    assert _cust(db_path) == "CUST-2026-1"


def test_numbers_increment_unpadded(db_path, y2026):
    assert _cust(db_path, "A") == "CUST-2026-1"
    assert _cust(db_path, "B") == "CUST-2026-2"


def test_max_is_numeric_not_lexical(db_path, y2026):
    """Unpadded: CUST-2026-10 must beat CUST-2026-2 (lexical MAX is wrong)."""
    with transaction(db_path) as conn:
        conn.execute("INSERT INTO customers (customer_id) VALUES ('CUST-2026-2')")
        conn.execute("INSERT INTO customers (customer_id) VALUES ('CUST-2026-10')")
    assert _cust(db_path) == "CUST-2026-11"


def test_year_rollover_restarts_at_one(db_path, monkeypatch):
    monkeypatch.setattr(db_write_ops, "_current_year", lambda: 2026)
    assert _cust(db_path, "A") == "CUST-2026-1"
    assert _cust(db_path, "B") == "CUST-2026-2"
    monkeypatch.setattr(db_write_ops, "_current_year", lambda: 2027)
    assert _cust(db_path, "C") == "CUST-2027-1"
    assert _cust(db_path, "D") == "CUST-2027-2"


def test_legacy_ids_do_not_feed_year_max(db_path, y2026):
    """Old-scheme CUST-1643 must not push the 2026 sequence to 1644."""
    with transaction(db_path) as conn:
        conn.execute("INSERT INTO customers (customer_id) VALUES ('CUST-1643')")
    assert _cust(db_path) == "CUST-2026-1"


def test_old_plain_counter_row_is_ignored(db_path, y2026):
    """The pre-year id_counters 'CUST' row must not affect CUST-2026-N."""
    with transaction(db_path) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS id_counters (prefix TEXT PRIMARY KEY, last_num INTEGER NOT NULL)")
        conn.execute("INSERT INTO id_counters (prefix, last_num) VALUES ('CUST', 1673)")
    assert _cust(db_path) == "CUST-2026-1"


def test_counter_monotonic_after_delete(db_path, y2026):
    """R-044 per year: deleting the newest customer never frees its number."""
    c1 = _cust(db_path, "A")
    assert c1 == "CUST-2026-1"
    c2 = _cust(db_path, "B")
    assert c2 == "CUST-2026-2"
    with transaction(db_path) as conn:
        conn.execute("DELETE FROM customers WHERE customer_id = ?", (c2,))
    assert _cust(db_path, "C") == "CUST-2026-3"


def test_other_prefixes_unchanged(db_path, y2026):
    cust = _cust(db_path)
    res = db_create_job(db_path, {"CustomerID": cust, "Customer Name / Company": "Y"}, actor="dave")
    assert "NEW_JOB_ID=JOB-0001" in res


def test_generate_next_id_direct(db_path, y2026):
    conn = get_connection(db_path)
    try:
        assert generate_next_id(conn, "customers", "customer_id", "CUST", 0) == "CUST-2026-1"
    finally:
        conn.close()


# ── Rename ───────────────────────────────────────────────────────────────

def _job(db_path, cust):
    return _new_id(db_create_job(db_path, {"CustomerID": cust,
                                           "Customer Name / Company": "Y"}, actor="dave"), "NEW_JOB_ID")


def test_rename_moves_customer_and_job(db_path, y2026):
    cust = _cust(db_path, "A")          # CUST-2026-1
    job = _job(db_path, cust)
    out = db_rename_customer_number(db_path, cust, 9, actor="dave")
    assert out.startswith("✅"), out
    assert "NEW_CUSTOMER_ID=CUST-2026-9" in out
    conn = get_connection(db_path)
    try:
        assert conn.execute("SELECT 1 FROM customers WHERE customer_id='CUST-2026-9'").fetchone()
        assert not conn.execute("SELECT 1 FROM customers WHERE customer_id=?", (cust,)).fetchone()
        row = conn.execute("SELECT customer_id FROM jobs WHERE job_id=?", (job,)).fetchone()
        assert row["customer_id"] == "CUST-2026-9"
    finally:
        conn.close()


def test_rename_duplicate_rejected_names_conflict(db_path, y2026):
    c1 = _cust(db_path, "A")           # CUST-2026-1
    c2 = _cust(db_path, "B")           # CUST-2026-2
    out = db_rename_customer_number(db_path, c1, 2, actor="dave")
    assert out.startswith("❌"), out
    assert "CUST-2026-2" in out and "already exists" in out
    conn = get_connection(db_path)
    try:
        assert conn.execute("SELECT 1 FROM customers WHERE customer_id=?", (c1,)).fetchone()
        assert conn.execute("SELECT 1 FROM customers WHERE customer_id=?", (c2,)).fetchone()
    finally:
        conn.close()


def test_rename_rejects_bad_numbers(db_path, y2026):
    cust = _cust(db_path, "A")
    for bad in (0, -5, "abc", "", "3.5"):
        out = db_rename_customer_number(db_path, cust, bad, actor="dave")
        assert out.startswith("❌"), (bad, out)
    # string digits are fine
    out = db_rename_customer_number(db_path, cust, "7", actor="dave")
    assert "NEW_CUSTOMER_ID=CUST-2026-7" in out, out


def test_rename_legacy_id_adopts_current_year(db_path, y2026):
    with transaction(db_path) as conn:
        conn.execute("INSERT INTO customers (customer_id, company_name) VALUES ('CUST-1643', 'Legacy')")
    out = db_rename_customer_number(db_path, "CUST-1643", 5, actor="dave")
    assert "NEW_CUSTOMER_ID=CUST-2026-5" in out, out


def test_rename_same_number_is_noop(db_path, y2026):
    cust = _cust(db_path, "A")
    out = db_rename_customer_number(db_path, cust, 1, actor="dave")
    assert out.startswith("✅") and "nothing to change" in out
    assert "NEW_CUSTOMER_ID=CUST-2026-1" in out


def test_rename_unknown_customer(db_path, y2026):
    out = db_rename_customer_number(db_path, "CUST-2026-99", 1, actor="dave")
    assert out.startswith("❌") and "No customer found" in out


def test_rename_raises_year_counter(db_path, y2026):
    """R-044 across renames: renaming to 50 burns 1..50 for the year."""
    cust = _cust(db_path, "A")          # CUST-2026-1
    db_rename_customer_number(db_path, cust, 50, actor="dave")
    assert _cust(db_path, "B") == "CUST-2026-51"


def test_rename_updates_all_referencing_tables(db_path, y2026):
    cust = _cust(db_path, "A")
    job = _job(db_path, cust)
    conn = get_connection(db_path)
    try:
        conn.execute("INSERT INTO invoices (invoice_id, customer_id, job_id) VALUES ('INV-0001', ?, ?)",
                     (cust, job))
        conn.execute("INSERT INTO quotes (quote_id, customer_id) VALUES ('QTE-0001', ?)", (cust,))
        conn.execute("INSERT INTO route_stops (route_date, crew_id, stop_number, job_id, customer_id) "
                     "VALUES ('2026-10-05', 'Sam', 1, ?, ?)", (job, cust))
        conn.commit()
    finally:
        conn.close()
    out = db_rename_customer_number(db_path, cust, 4, actor="dave")
    assert out.startswith("✅"), out
    conn = get_connection(db_path)
    try:
        for tbl in ("jobs", "invoices", "quotes", "route_stops"):
            n = conn.execute(f"SELECT COUNT(*) n FROM {tbl} WHERE customer_id='CUST-2026-4'").fetchone()["n"]
            assert n == 1, tbl
            n_old = conn.execute(f"SELECT COUNT(*) n FROM {tbl} WHERE customer_id=?", (cust,)).fetchone()["n"]
            assert n_old == 0, tbl
    finally:
        conn.close()
