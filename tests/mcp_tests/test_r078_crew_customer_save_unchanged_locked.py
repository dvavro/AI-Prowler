"""R-078 (2026-10-09, E2E SRV-FR-02): the Jobs app's customer editor sends
every column on Save. Field crew must be able to save a customer they work
for when the four business fields come along UNCHANGED; a CHANGED business
field is still refused with nothing written.

Run: py -m pytest tests\\mcp_tests\\test_r078_crew_customer_save_unchanged_locked.py -v
"""
import sqlite3

import pytest

import db_write_ops
from db_access import init_db
from db_write_ops import db_create_customer, db_create_job, db_update_customer

CID = "CUST-2026-1"


@pytest.fixture
def db_path(tmp_path, monkeypatch):
    monkeypatch.setattr(db_write_ops, "_current_year", lambda: 2026)
    path = str(tmp_path / "jobs.db")
    init_db(path)
    db_create_customer(path, {"Company Name": "Linked Co", "Frequency": "Monthly",
                              "Standard Quote ($)": "120", "Discount (%)": "10",
                              "Status Active/Inactive": "Active"}, actor="owner")
    db_create_job(path, {"CustomerID (Customers!A)": CID, "Crew / Technician": "samuel"}, actor="owner")
    return path


def _crew(db_path, updates):
    return db_update_customer(db_path, CID, updates, actor="samuel", restrict=True, crew_name="samuel")


ALL_UNCHANGED = {"CustomerID (CUST-####)": CID, "Frequency": "Monthly", "Standard Quote ($)": "120.00",
                 "Discount (%)": "10", "Status Active/Inactive": "active"}


def test_unchanged_locked_fields_do_not_block_a_contact_fix(db_path):
    out = _crew(db_path, dict(ALL_UNCHANGED, Phone="555-0101"))
    assert out.startswith("✅"), out


@pytest.mark.parametrize("field,value", [("Frequency", "Weekly"), ("Standard Quote ($)", "999"),
                                         ("Discount (%)", "0"), ("Status Active/Inactive", "Inactive")])
def test_a_changed_locked_field_is_refused_and_nothing_written(db_path, field, value):
    out = _crew(db_path, dict(ALL_UNCHANGED, Phone="555-0102", **{field: value}))
    assert out.startswith("❌") and field in out, out
    # nothing written — not even the harmless Phone change
    col = db_write_ops.CUSTOMERS_HEADER_MAP["Phone"]
    with sqlite3.connect(db_path) as c:
        phone = c.execute(f"SELECT {col} FROM customers WHERE customer_id=?", (CID,)).fetchone()[0]
    assert phone in (None, ""), phone


def test_blank_to_value_counts_as_a_change(db_path):
    db_update_customer(db_path, CID, {"Discount (%)": ""}, actor="owner")
    out = _crew(db_path, {"Discount (%)": "5"})
    assert out.startswith("❌"), out


def test_owner_unaffected(db_path):
    out = db_update_customer(db_path, CID, {"Standard Quote ($)": "999"}, actor="owner")
    assert out.startswith("✅"), out
