"""
R-044 (was gap G-11, 2026-09-27 — David: "never reuse a job number, that way
you can review a cancelled job").

generate_next_id used to be "highest existing + 1": delete the newest job and
the next job got its number — and the old job's JobPhotos folder with it.
Now the highest number ever issued is remembered per prefix (id_counters) and
never handed out again. Applies to every id this module makes (jobs,
customers, quotes, invoices, time entries).

Run: run_tests.bat tests\\mcp\\test_r044_ids_never_reused.py -v
"""
import pytest

from db_access import get_connection, init_db, transaction
from db_write_ops import (
    db_create_customer,
    db_create_job,
    db_delete_customer,
    db_delete_job,
    db_update_job,
    generate_next_id,
)


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _new_id(result: str, key: str) -> str:
    return result.split(f"{key}=")[1].splitlines()[0].strip()


def _customer(db_path, name="R044 Customer"):
    return _new_id(db_create_customer(db_path, {"Company Name": name}, actor="dave"), "NEW_CUST_ID")


def _job(db_path, cust):
    return _new_id(db_create_job(db_path, {"CustomerID (Customers!A)": cust,
                                           "Customer Name / Company": "R044"}, actor="dave"), "NEW_JOB_ID")


def _cancel_and_delete(db_path, jid):
    db_update_job(db_path, jid, {"Job Status": "Cancelled"}, actor="dave")
    out = db_delete_job(db_path, jid, confirm=True)
    assert "deleted" in out.lower() or out.startswith("✅"), out


def test_R044_01_deleting_the_newest_job_does_not_free_its_number(db_path):
    cust = _customer(db_path)
    assert _job(db_path, cust) == "JOB-0001"
    j2 = _job(db_path, cust)
    assert j2 == "JOB-0002"
    _cancel_and_delete(db_path, j2)
    assert _job(db_path, cust) == "JOB-0003", "JOB-0002 was handed out again after being deleted"


def test_R044_02_deleting_every_job_still_never_restarts_at_one(db_path):
    cust = _customer(db_path)
    ids = [_job(db_path, cust) for _ in range(3)]
    for j in ids:
        _cancel_and_delete(db_path, j)
    assert _job(db_path, cust) == "JOB-0004"


def test_R044_03_customer_numbers_are_not_reused_either(db_path):
    _customer(db_path, "A")
    c2 = _customer(db_path, "B")
    out = db_delete_customer(db_path, c2, confirm=True)
    assert "CUST" in out or out.startswith("✅"), out
    assert _customer(db_path, "C") == "CUST-0003"


def test_R044_04_existing_database_without_a_counter_continues_from_highest(db_path):
    """An install that predates R-044 has no id_counters row: numbering
    carries on from the highest existing id, exactly as before."""
    with transaction(db_path) as conn:
        conn.execute("INSERT INTO customers (customer_id) VALUES ('CUST-0001')")
        conn.execute("INSERT INTO jobs (job_id, customer_id) VALUES ('JOB-0007', 'CUST-0001')")
    assert generate_next_id(get_connection(db_path), "jobs", "job_id", "JOB", 4) == "JOB-0008"


def test_R044_05_a_row_added_behind_the_counters_back_is_never_collided_with(db_path):
    cust = _customer(db_path)
    assert _job(db_path, cust) == "JOB-0001"
    with transaction(db_path) as conn:            # e.g. an import, or a restored backup
        conn.execute("INSERT INTO jobs (job_id, customer_id) VALUES ('JOB-0050', ?)", (cust,))
    assert _job(db_path, cust) == "JOB-0051"


def test_R044_06_a_rolled_back_create_does_not_burn_a_number(db_path):
    cust = _customer(db_path)
    with pytest.raises(RuntimeError):
        with transaction(db_path) as conn:
            assert generate_next_id(conn, "jobs", "job_id", "JOB", 4) == "JOB-0001"
            raise RuntimeError("create failed after the id was picked")
    assert _job(db_path, cust) == "JOB-0001"


def test_R044_07_each_prefix_counts_on_its_own(db_path):
    cust = _customer(db_path)            # CUST-0001
    _job(db_path, cust)                  # JOB-0001
    _job(db_path, cust)                  # JOB-0002
    assert _customer(db_path, "Second") == "CUST-0002"
