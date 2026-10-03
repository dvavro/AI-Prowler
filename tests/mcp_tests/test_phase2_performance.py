"""
tests/mcp_tests/test_phase2_performance.py
========================================
Job Board Architecture Spec — Phase 2 (spec §5, §11).

Performance sanity check on a realistically large dataset, per Phase 2's
own stated testing requirement: "Performance sanity check on a
realistically large dataset (hundreds of jobs) — this is also where the
DB approach should visibly outperform the old whole-sheet scan, worth
confirming rather than assuming."

Not a strict regression test (no old openpyxl code path remains to
compare against directly in-process), so this asserts a generous wall-
clock ceiling rather than a tight benchmark — its purpose is to catch a
gross regression (e.g. an accidental N+1 query or a missing index), not
to micro-benchmark SQLite itself.

Run with:
    run_tests.bat tests\\mcp\\test_phase2_performance.py -v
"""
import time

import pytest

from db_access import init_db
from db_read_ops import db_get_ar_aging_report, db_read_job_spreadsheet
from db_write_ops import db_create_customer, db_create_invoice, db_create_job

N_CUSTOMERS = 50
N_JOBS = 500


@pytest.fixture(scope="module")
def large_db(tmp_path_factory):
    """One shared large dataset for every test in this file — building
    it (500 jobs + invoices) is the expensive part; reads against it
    are what's actually being timed."""
    db_path = str(tmp_path_factory.mktemp("perf") / "jobs.db")
    init_db(db_path)

    customer_ids = []
    for i in range(N_CUSTOMERS):
        result = db_create_customer(db_path, {"Company Name": f"Customer {i}"}, actor="dave")
        customer_ids.append(result.split("NEW_CUST_ID=")[1].splitlines()[0].strip())

    crews = ["Jake R", "Maria S", "Tom B", "Vicki V"]
    for i in range(N_JOBS):
        cust_id = customer_ids[i % N_CUSTOMERS]
        month = (i % 12) + 1
        day = (i % 28) + 1
        db_create_job(db_path, {
            "CustomerID (Customers!A)": cust_id,
            "Customer Name / Company": f"Customer {i % N_CUSTOMERS}",
            "Service Date": f"2026-{month:02d}-{day:02d}",
            "Crew / Technician": crews[i % len(crews)],
            "Quote Amount ($)": 100 + (i % 50) * 10,
            "Job Status": "Scheduled" if i % 3 else "Complete",
        }, actor="dave")

    # A few hundred invoices too, for the AR aging report benchmark.
    for i in range(0, N_JOBS, 2):
        job_id = f"JOB-{i + 1:04d}"
        db_create_invoice(db_path, job_id, actor="dave")

    return db_path


def test_read_job_spreadsheet_full_scan_completes_quickly(large_db):
    start = time.perf_counter()
    result = db_read_job_spreadsheet(large_db, max_rows=500)
    elapsed = time.perf_counter() - start
    assert "500 row(s)" in result
    assert elapsed < 2.0, f"Full 500-row read took {elapsed:.3f}s — expected well under 2s"


def test_read_job_spreadsheet_date_filter_completes_quickly(large_db):
    start = time.perf_counter()
    result = db_read_job_spreadsheet(large_db, filter_date="03/15/2026", max_rows=500)
    elapsed = time.perf_counter() - start
    assert "row(s)" in result
    assert elapsed < 2.0, f"Date-filtered read took {elapsed:.3f}s — expected well under 2s"


def test_read_job_spreadsheet_crew_scoped_completes_quickly(large_db):
    start = time.perf_counter()
    result = db_read_job_spreadsheet(large_db, restrict=True, crew_name="jake r", max_rows=500)
    elapsed = time.perf_counter() - start
    assert "row(s)" in result
    assert elapsed < 2.0, f"Crew-scoped read took {elapsed:.3f}s — expected well under 2s"
    # Sanity: crew scoping actually narrowed the result set.
    assert "500 row(s)" not in result


def test_ar_aging_report_completes_quickly(large_db):
    start = time.perf_counter()
    result = db_get_ar_aging_report(large_db)
    elapsed = time.perf_counter() - start
    assert "AR AGING REPORT" in result
    assert elapsed < 2.0, f"AR aging report over ~250 invoices took {elapsed:.3f}s — expected well under 2s"


def test_id_generation_still_fast_with_many_existing_rows(large_db):
    """generate_next_id scans the whole id column (spec-documented
    behavior, not a bug) — confirms that scan still completes quickly
    even with 500 existing jobs, since this runs on every single create_job
    call."""
    cust_result = db_create_customer(large_db, {"Company Name": "One More"}, actor="dave")
    cust_id = cust_result.split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    start = time.perf_counter()
    result = db_create_job(large_db, {"CustomerID (Customers!A)": cust_id, "Customer Name / Company": "One More"}, actor="dave")
    elapsed = time.perf_counter() - start
    assert result.startswith("✅")
    assert f"NEW_JOB_ID=JOB-{N_JOBS + 1:04d}" in result
    assert elapsed < 1.0, f"create_job against {N_JOBS} existing rows took {elapsed:.3f}s — expected well under 1s"
