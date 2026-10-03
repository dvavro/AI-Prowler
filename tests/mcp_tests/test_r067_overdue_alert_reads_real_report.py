"""
R-067 (2026-09-29, found by the time-machine E2E TM-07): the Overdue Invoice
Alert and the morning briefing's overdue section looked for "31-60"/"61-90" on
a line, but the real AR aging report writes "31 – 60 days overdue" (en dash)
as a header with the invoices on their own lines below — so a 31–90-day
overdue invoice never raised the alert. These tests feed the REAL report text
(db_get_ar_aging_report on a temp database), not a hand-written string.

Run:  run_tests.bat tests\\mcp\\test_r067_overdue_alert_reads_real_report.py -v
"""
from __future__ import annotations

import sqlite3
from unittest.mock import patch

import pytest

from db_access import init_db
from db_read_ops import db_get_ar_aging_report
from db_write_ops import db_create_customer, db_create_invoice, db_create_job

import scheduler_jobs as sj


@pytest.fixture
def db_path(tmp_path):
    p = str(tmp_path / "jobs.db")
    init_db(p)
    return p


def _invoice(db_path, name, amount, due_date):
    cid = db_create_customer(db_path, {"Company Name": name}, actor="t") \
        .split("NEW_CUST_ID=")[1].splitlines()[0].strip()
    db_create_job(db_path, {"CustomerID (Customers!A)": cid, "Customer Name / Company": name,
                            "Quote Amount ($)": amount}, actor="t")
    conn = sqlite3.connect(db_path)
    n = conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
    conn.close()
    db_create_invoice(db_path, f"JOB-{n:04d}", actor="t", due_days=30)
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE invoices SET due_date = ? WHERE customer_name = ?", (due_date, name))
    conn.commit()
    conn.close()


def _report(db_path, as_of):
    return db_get_ar_aging_report(db_path, as_of_date=as_of)


def test_real_report_31_60_raises_alert_with_invoice_row(db_path):
    _invoice(db_path, "Late38 Co", 95, "2026-10-06")
    rep = _report(db_path, "2026-11-13")           # 38 days overdue
    assert "31 – 60 days overdue" in rep        # the real layout
    with patch("ai_prowler_mcp.get_ar_aging_report", return_value=rep):
        out = sj.job_overdue_invoice_alert({})
    assert out is not None, "a 38-day-overdue invoice raised no alert"
    subject, body = out
    assert "Late38 Co" in body and "38d overdue" in body
    assert "Subtotal" not in body and "Balance" not in body   # rows only, no table furniture


def test_real_report_61_90_and_90_plus(db_path):
    _invoice(db_path, "Late70 Co", 50, "2026-09-04")
    _invoice(db_path, "Late120 Co", 60, "2026-07-16")
    rep = _report(db_path, "2026-11-13")
    lines = sj._overdue_ar_lines(rep)
    joined = "\n".join(lines)
    assert "Late70 Co" in joined and "Late120 Co" in joined


def test_1_30_and_current_stay_silent(db_path):
    _invoice(db_path, "Late10 Co", 95, "2026-11-03")
    _invoice(db_path, "NotDue Co", 95, "2026-12-01")
    rep = _report(db_path, "2026-11-13")
    with patch("ai_prowler_mcp.get_ar_aging_report", return_value=rep):
        assert sj.job_overdue_invoice_alert({}) is None
    assert sj._overdue_ar_lines(rep) == []


def test_mixed_buckets_only_31_plus_rows(db_path):
    _invoice(db_path, "Late10 Co", 95, "2026-11-03")
    _invoice(db_path, "Late45 Co", 95, "2026-09-29")
    rep = _report(db_path, "2026-11-13")
    joined = "\n".join(sj._overdue_ar_lines(rep))
    assert "Late45 Co" in joined
    assert "Late10 Co" not in joined


def test_one_line_form_still_works():
    assert sj._overdue_ar_lines("31-60 days: Johnson $450") == ["31-60 days: Johnson $450"]
    assert sj._overdue_ar_lines("Current: $1500Total: $1500") == []
