"""R-034 (2026-09-26, E2E DB-06): Customers / Quotes / Invoices reads must
show each row's Version, so the Jobs app's Database-tab Edit form can send it
back as expected_version and a stale edit is refused instead of silently
overwriting another device's change. Version can never be set by a caller.

Run: py -m pytest tests\\mcp\\test_r034_version_on_reads.py -v
"""
import re

import pytest

from db_access import init_db
from db_read_ops import db_get_sheet_columns, db_read_job_spreadsheet
from db_write_ops import (
    db_create_customer,
    db_create_quote,
    db_update_customer,
    db_update_quote,
)


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _version(text):
    m = re.search(r"^\s*Version:\s*(\d+)", text, re.M)
    return int(m.group(1)) if m else None


def _new_customer_id(db_path, name):
    """Create a customer and return its real ID (CUST-YYYY-N year scheme)."""
    result = db_create_customer(db_path, {"Company Name": name}, actor="david")
    assert result.startswith("✅"), result
    return re.search(r"NEW_CUST_ID=(\S+)", result).group(1)


@pytest.mark.parametrize("sheet", ["Customers", "Quotes", "Invoices"])
def test_sheet_columns_include_version(db_path, sheet):
    assert "Version" in [c.strip() for c in db_get_sheet_columns(db_path, sheet).splitlines()[0]
                         .split(":", 1)[1].split("|")]


def test_customer_read_shows_version_and_it_moves(db_path):
    cust_id = _new_customer_id(db_path, "Blue Wave Cafe")
    assert _version(db_read_job_spreadsheet(db_path, "Customers")) == 1
    db_update_customer(db_path, cust_id, {"Phone": "555"}, actor="david")
    assert _version(db_read_job_spreadsheet(db_path, "Customers")) == 2


def test_stale_customer_edit_is_refused(db_path):
    cust_id = _new_customer_id(db_path, "Blue Wave Cafe")
    loaded = _version(db_read_job_spreadsheet(db_path, "Customers"))
    db_update_customer(db_path, cust_id, {"On-Site Contact": "Pat"}, actor="other")
    out = db_update_customer(db_path, cust_id, {"Phone": "555", "On-Site Contact": ""},
                             actor="david", expected_version=loaded)
    assert out.startswith("❌") and "reload" in out
    assert "On-Site Contact: Pat" in db_read_job_spreadsheet(db_path, "Customers")


def test_stale_quote_edit_is_refused(db_path):
    cust_id = _new_customer_id(db_path, "Blue Wave Cafe")
    db_create_quote(db_path, {"CustomerID": cust_id, "Subtotal ($)": 100}, actor="david")
    loaded = _version(db_read_job_spreadsheet(db_path, "Quotes"))
    assert loaded == 1
    db_update_quote(db_path, "QTE-0001", {"Service Type": "Window"}, actor="other")
    out = db_update_quote(db_path, "QTE-0001", {"Subtotal ($)": 150}, actor="david",
                          expected_version=loaded)
    assert out.startswith("❌") and "reload" in out


def test_version_cannot_be_set_by_a_caller(db_path):
    # A caller-supplied Version on create is ignored - the row starts at 1
    result = db_create_customer(db_path, {"Company Name": "A", "Version": 99}, actor="david")
    assert result.startswith("✅"), result
    cust_id = re.search(r"NEW_CUST_ID=(\S+)", result).group(1)
    assert _version(db_read_job_spreadsheet(db_path, "Customers")) == 1
    # ...and on update it is ignored too (normal bump to 2, not 50)
    db_update_customer(db_path, cust_id, {"Version": 50, "Phone": "1"}, actor="david")
    assert _version(db_read_job_spreadsheet(db_path, "Customers")) == 2
