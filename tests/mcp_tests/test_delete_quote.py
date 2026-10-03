"""
Tests for delete_quote / db_delete_quote — added 2026-09-15 alongside
delete_customer/delete_service_pricing, at the owner's request, so a
quote can actually be removed instead of piling up forever. Updated
2026-09-23 (at the owner's request) to drop the original Declined-first
gate — any quote, in any status, can now be deleted directly. Needs no
cascade either way — nothing in the schema references quotes by foreign
key.

Run: py -m pytest tests\\mcp\\test_delete_quote.py -v
"""

import os

import pytest

from db_access import get_connection, init_db
from db_write_ops import (
    db_create_quote,
    db_delete_quote,
    db_update_quote,
)


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "jobs.db")
    init_db(path)
    return path


def _make_quote(db_path, customer_name="ZTEST Quote Customer", status="Open", **extra):
    updates = {"Customer Name / Company": customer_name, "Status (Open/Approved/Declined)": status}
    updates.update(extra)
    result = db_create_quote(db_path, updates, actor="david")
    return result.split("NEW_QTE_ID=")[1].strip()


# ── Any status is deletable (gate removed 2026-09-23) ───────────────────

def test_deletes_open_quote(db_path):
    quote_id = _make_quote(db_path, status="Open")
    result = db_delete_quote(db_path, quote_id, confirm=True)
    assert result.startswith("✅"), result
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM quotes WHERE quote_id = ?", (quote_id,)).fetchone()
    conn.close()
    assert row is None


def test_deletes_approved_quote(db_path):
    quote_id = _make_quote(db_path, status="Approved")
    result = db_delete_quote(db_path, quote_id, confirm=True)
    assert result.startswith("✅"), result
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM quotes WHERE quote_id = ?", (quote_id,)).fetchone()
    conn.close()
    assert row is None


def test_deletes_declined_quote(db_path):
    quote_id = _make_quote(db_path, status="Declined")
    result = db_delete_quote(db_path, quote_id, confirm=True)
    assert result.startswith("✅")
    assert "Safety backup saved first" in result
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM quotes WHERE quote_id = ?", (quote_id,)).fetchone()
    conn.close()
    assert row is None


def test_reapproved_quote_still_deletable(db_path):
    """A quote that was Declined, then re-approved by someone else, is
    still eligible — there's no status gate left to trip."""
    quote_id = _make_quote(db_path, status="Declined")
    db_update_quote(db_path, quote_id, {"Status (Open/Approved/Declined)": "Approved"}, actor="someone_else")
    result = db_delete_quote(db_path, quote_id, confirm=True)
    assert result.startswith("✅"), result
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM quotes WHERE quote_id = ?", (quote_id,)).fetchone()
    conn.close()
    assert row is None


def test_preview_reports_status(db_path):
    quote_id = _make_quote(db_path, status="Open")
    result = db_delete_quote(db_path, quote_id, confirm=False)
    assert "status: Open" in result


# ── Guard: confirm required ───────────────────────────────────────────

def test_preview_without_confirm_deletes_nothing(db_path):
    quote_id = _make_quote(db_path, status="Declined")
    result = db_delete_quote(db_path, quote_id, confirm=False)
    assert result.startswith("❌")
    assert "confirm=True" in result
    conn = get_connection(db_path)
    row = conn.execute("SELECT * FROM quotes WHERE quote_id = ?", (quote_id,)).fetchone()
    conn.close()
    assert row is not None


def test_preview_reports_customer_and_amount(db_path):
    quote_id = _make_quote(db_path, customer_name="ZTEST Preview Co", status="Declined",
                            **{"Subtotal ($)": 225})
    result = db_delete_quote(db_path, quote_id, confirm=False)
    assert "ZTEST Preview Co" in result
    assert "225" in result


# ── Not found / ambiguous ───────────────────────────────────────────────

def test_not_found_returns_error(db_path):
    result = db_delete_quote(db_path, "QTE-9999", confirm=True)
    assert result.startswith("❌")
    assert "No quote found" in result


def test_ambiguous_match_refused_nothing_deleted(db_path):
    _make_quote(db_path, customer_name="ZTEST Ambig Alpha", status="Declined")
    _make_quote(db_path, customer_name="ZTEST Ambig Alphb", status="Declined")
    result = db_delete_quote(db_path, "ZTEST Ambig Alph", confirm=True)
    assert result.startswith("❌")
    assert "matches 2 quotes" in result
    conn = get_connection(db_path)
    count = conn.execute("SELECT COUNT(*) AS n FROM quotes").fetchone()["n"]
    conn.close()
    assert count == 2


# ── Safety backup ────────────────────────────────────────────────────────

def test_safety_backup_file_actually_created(db_path):
    quote_id = _make_quote(db_path, status="Declined")
    result = db_delete_quote(db_path, quote_id, confirm=True)
    backup_line = [l for l in result.splitlines() if "Safety backup saved first" in l][0]
    backup_path = backup_line.split(":", 1)[1].strip()
    assert os.path.exists(backup_path)
