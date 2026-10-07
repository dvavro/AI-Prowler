"""
tests/mcp_tests/test_invoice_receipt_openpyxl_removal.py
======================================================
Real, previously-undiscovered bug found while tracing where the Database
tab's Settings screen actually gets used: _find_invoice_row() (shared by
email_invoice, text_invoice, email_receipt, text_receipt) was still fully
openpyxl-based, opening the .xlsx Job Tracker directly. Since
create_invoice() (and everything else) moved to SQLite-only, these four
tools could not reliably find ANY invoice created after the migration —
a genuine break in the whole invoice/receipt-sending pipeline.

This tests the fix: _find_invoice_row() and _lookup_customer_email() are
now fully DB-backed, and email_invoice()/email_receipt()/text_invoice()/
text_receipt() are wired to them with zero openpyxl left in the chain.

Run with:
    run_tests.bat tests\\mcp\\test_invoice_receipt_openpyxl_removal.py -v
"""
from __future__ import annotations

import smtplib
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


def _make_ctx(user):
    if user is None:
        return None
    ctx = MagicMock()
    ctx.request_context.request.state.user = user
    return ctx


def _field_crew(uid="jake-r", name="Jake R"):
    return {"id": uid, "name": name, "role": "field_crew", "status": "active", "scopes": []}


def _owner(uid="dave"):
    return {"id": uid, "name": "Dave Owner", "role": "owner", "status": "active", "scopes": []}


def _job_id(create_result: str) -> str:
    return create_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _inv_id(create_result: str) -> str:
    return create_result.split("NEW_INVOICE_ID=")[1].splitlines()[0].strip()


# ══════════════════════════════════════════════════════════════════════════
# Personal mode — _find_invoice_row / _lookup_customer_email direct tests
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def personal_env(tmp_path, monkeypatch, mcp_mod):
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"  # deliberately never created
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    return tmp_path / "ai_prowler_jobs.db"


def _seed_invoiced_job(mcp_mod, cust_email="jane@example.com"):
    mcp_mod.create_customer({"Company Name": "Blue Wave Cafe", "Email": cust_email},
                             filepath="", backup=False, ctx=None)
    job_result = mcp_mod.create_job(
        {"Customer Name / Company": "Blue Wave Cafe", "CustomerID (Customers!A)": "CUST-0001",
         "Quote Amount ($)": 150.0}, filepath="", backup=False, ctx=None)
    job_id = _job_id(job_result)
    inv_result = mcp_mod.create_invoice(job_id, filepath="", backup=False, ctx=None)
    return job_id, _inv_id(inv_result)


def test_find_invoice_row_never_touches_the_old_xlsx_file(personal_env, mcp_mod):
    """The .xlsx is never created anywhere in this test — if _find_invoice_
    row still depended on openpyxl/the old file at all, this would fail
    outright rather than just returning wrong data."""
    job_id, inv_id = _seed_invoiced_job(mcp_mod)
    result = mcp_mod._find_invoice_row(inv_id, "", None)
    assert "error" not in result, result
    assert result["inv_row"]["InvoiceID (INV-####)"] == inv_id
    assert result["inv_row"]["JobID (JOB-####)"] == job_id
    assert result["inv_row"]["Customer Name / Company"] == "Blue Wave Cafe"
    assert result["inv_row"]["TOTAL DUE ($)"] == pytest.approx(160.50)


def test_find_invoice_row_matches_by_customer_name(personal_env, mcp_mod):
    job_id, inv_id = _seed_invoiced_job(mcp_mod)
    result = mcp_mod._find_invoice_row("Blue Wave", "", None)
    assert "error" not in result, result
    assert result["inv_row"]["InvoiceID (INV-####)"] == inv_id


def test_find_invoice_row_matches_by_job_id(personal_env, mcp_mod):
    job_id, inv_id = _seed_invoiced_job(mcp_mod)
    result = mcp_mod._find_invoice_row(job_id, "", None)
    assert "error" not in result, result
    assert result["inv_row"]["InvoiceID (INV-####)"] == inv_id


def test_find_invoice_row_blank_identifier_rejected(personal_env, mcp_mod):
    _seed_invoiced_job(mcp_mod)
    result = mcp_mod._find_invoice_row("   ", "", None)
    assert "error" in result
    assert "blank" in result["error"]


def test_find_invoice_row_not_found_rejected_cleanly(personal_env, mcp_mod):
    _seed_invoiced_job(mcp_mod)
    result = mcp_mod._find_invoice_row("INV-9999", "", None)
    assert "error" in result
    assert "No invoice found" in result["error"]


def test_lookup_customer_email_by_customer_id(personal_env, mcp_mod):
    _seed_invoiced_job(mcp_mod, cust_email="jane@example.com")
    email = mcp_mod._lookup_invoice_customer_email(str(personal_env), "CUST-0001", "")
    assert email == "jane@example.com"


def test_lookup_customer_email_falls_back_to_name_match(personal_env, mcp_mod):
    _seed_invoiced_job(mcp_mod, cust_email="jane@example.com")
    email = mcp_mod._lookup_invoice_customer_email(str(personal_env), "", "Blue Wave")
    assert email == "jane@example.com"


def test_lookup_customer_email_no_match_returns_blank(personal_env, mcp_mod):
    _seed_invoiced_job(mcp_mod)
    email = mcp_mod._lookup_invoice_customer_email(str(personal_env), "CUST-9999", "Nobody Here")
    assert email == ""


# ══════════════════════════════════════════════════════════════════════════
# End-to-end: email_invoice / email_receipt / text_invoice / text_receipt,
# with only the actual send functions mocked out (SMTP/SMS credentials
# aren't part of this fix) — everything else (lookup, customer-email
# resolution, business info, HTML build) runs for real against SQLite.
# ══════════════════════════════════════════════════════════════════════════

def test_email_invoice_end_to_end_auto_resolves_recipient(personal_env, mcp_mod, monkeypatch):
    job_id, inv_id = _seed_invoiced_job(mcp_mod, cust_email="jane@example.com")
    monkeypatch.setattr(mcp_mod, "_email_config_load", lambda: {"configured": True})
    sent = {}
    def _fake_send_smtp(to, subject, body, body_html=None):
        sent["to"] = to
        sent["subject"] = subject
        return True, "ok"
    monkeypatch.setattr(mcp_mod, "_send_smtp", _fake_send_smtp)

    result = mcp_mod.email_invoice(inv_id, filepath="", ctx=None)
    assert result.startswith("✅"), result
    assert sent["to"] == "jane@example.com"
    assert inv_id in sent["subject"]


def test_email_invoice_no_recipient_found_fails_cleanly(personal_env, mcp_mod, monkeypatch):
    mcp_mod.create_customer({"Company Name": "No Email Co"}, filepath="", backup=False, ctx=None)
    job_result = mcp_mod.create_job(
        {"Customer Name / Company": "No Email Co", "CustomerID (Customers!A)": "CUST-0001",
         "Quote Amount ($)": 100.0}, filepath="", backup=False, ctx=None)
    inv_result = mcp_mod.create_invoice(_job_id(job_result), filepath="", backup=False, ctx=None)
    inv_id = _inv_id(inv_result)

    result = mcp_mod.email_invoice(inv_id, filepath="", ctx=None)
    assert result.startswith("❌")
    assert "could not auto-find" in result


def test_email_receipt_end_to_end(personal_env, mcp_mod, monkeypatch):
    job_id, inv_id = _seed_invoiced_job(mcp_mod, cust_email="jane@example.com")
    monkeypatch.setattr(mcp_mod, "_email_config_load", lambda: {"configured": True})
    sent = {}
    def _fake_send_smtp(to, subject, body, body_html=None):
        sent["to"] = to
        return True, "ok"
    monkeypatch.setattr(mcp_mod, "_send_smtp", _fake_send_smtp)

    result = mcp_mod.email_receipt(inv_id, payment_method="Cash", filepath="", ctx=None)
    assert result.startswith("✅"), result
    assert sent["to"] == "jane@example.com"


def test_text_invoice_end_to_end(personal_env, mcp_mod, monkeypatch):
    job_id, inv_id = _seed_invoiced_job(mcp_mod)
    sent = {}
    def _fake_send_sms(to, message, ctx=None):
        sent["to"] = to
        sent["message"] = message
        return "✅ sent"
    monkeypatch.setattr(mcp_mod, "send_sms", _fake_send_sms)

    result = mcp_mod.text_invoice(inv_id, filepath="", ctx=None)
    assert result.startswith("✅"), result
    assert sent["to"] == "Blue Wave Cafe"
    assert "160.50" in sent["message"]


def test_text_receipt_end_to_end(personal_env, mcp_mod, monkeypatch):
    job_id, inv_id = _seed_invoiced_job(mcp_mod)
    sent = {}
    def _fake_send_sms(to, message, ctx=None):
        sent["to"] = to
        return "✅ sent"
    monkeypatch.setattr(mcp_mod, "send_sms", _fake_send_sms)

    result = mcp_mod.text_receipt(inv_id, payment_method="Check", filepath="", ctx=None)
    assert result.startswith("✅"), result
    assert sent["to"] == "Blue Wave Cafe"


# ══════════════════════════════════════════════════════════════════════════
# Server mode — crew scoping on invoice/receipt access
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def server_env(tmp_path, monkeypatch, mcp_mod):
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    return tmp_path / "ai_prowler_jobs.db"


def test_server_mode_field_crew_denied_for_unassigned_jobs_invoice(server_env, monkeypatch, mcp_mod):
    owner = _owner()
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: owner)
    mcp_mod.create_customer({"Company Name": "X"}, filepath="", backup=False, ctx=_make_ctx(owner))
    job_result = mcp_mod.create_job(
        {"Customer Name / Company": "X", "CustomerID (Customers!A)": "CUST-0001",
         "Crew / Technician": "Someone Else", "Quote Amount ($)": 100.0},
        filepath="", backup=False, ctx=_make_ctx(owner))
    inv_result = mcp_mod.create_invoice(_job_id(job_result), filepath="", backup=False, ctx=_make_ctx(owner))
    inv_id = _inv_id(inv_result)

    crew = _field_crew()
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: crew)
    result = mcp_mod._find_invoice_row(inv_id, "", _make_ctx(crew))
    assert "error" in result
    assert "assigned to you" in result["error"]


def test_server_mode_field_crew_allowed_for_own_jobs_invoice(server_env, monkeypatch, mcp_mod):
    owner = _owner()
    crew = _field_crew()
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: owner)
    mcp_mod.create_customer({"Company Name": "X"}, filepath="", backup=False, ctx=_make_ctx(owner))
    job_result = mcp_mod.create_job(
        {"Customer Name / Company": "X", "CustomerID (Customers!A)": "CUST-0001",
         "Crew / Technician": crew["name"], "Quote Amount ($)": 100.0},
        filepath="", backup=False, ctx=_make_ctx(owner))
    inv_result = mcp_mod.create_invoice(_job_id(job_result), filepath="", backup=False, ctx=_make_ctx(owner))
    inv_id = _inv_id(inv_result)

    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: crew)
    result = mcp_mod._find_invoice_row(inv_id, "", _make_ctx(crew))
    assert "error" not in result, result


# ══════════════════════════════════════════════════════════════════════════
# SMTP transport correctness -- ported from tests/unit/test_contractor_
# tools.py::TestEmailInvoice (CT_01/01b/01c/04/05). Those tests mock
# smtplib.SMTP directly (one layer below the _send_smtp wrapper the tests
# above mock away) to verify email_invoice's OWN transport code -- real
# login credentials, real envelope-from address -- rather than trusting
# _send_smtp blindly. Not redundant with the personal_env tests above,
# which mock _send_smtp itself and so never exercise this layer. Ported
# onto a real DB-seeded invoice instead of the openpyxl fixture that no
# longer connects to _find_invoice_row.
# ══════════════════════════════════════════════════════════════════════════

_SMTP_CFG = {
    "smtp_host": "smtp.test.com", "smtp_port": 587,
    "username": "u@test.com", "password": "realpassword123",
    "from_address": "me@test.com", "from_name": "Test",
}


def test_email_invoice_by_invoice_id_smtp_layer(personal_env, mcp_mod, monkeypatch):
    job_id, inv_id = _seed_invoiced_job(mcp_mod, cust_email="karen@sunshine.com")
    smtp_mock = MagicMock()
    smtp_mock.__enter__ = MagicMock(return_value=smtp_mock)
    smtp_mock.__exit__ = MagicMock(return_value=False)
    monkeypatch.setattr(mcp_mod, "_email_config_load", lambda: _SMTP_CFG)
    monkeypatch.setattr(smtplib, "SMTP", MagicMock(return_value=smtp_mock))

    result = mcp_mod.email_invoice(inv_id, to="karen@sunshine.com", filepath="", ctx=None)
    assert result.startswith("✅"), result
    assert inv_id in result


def test_email_invoice_uses_real_username_and_password(personal_env, mcp_mod, monkeypatch):
    """Regression guard: login() must be called with the real configured
    username/password, not a blank default from a key that doesn't
    exist in the saved config (a real bug found pre-migration)."""
    job_id, inv_id = _seed_invoiced_job(mcp_mod, cust_email="karen@sunshine.com")
    smtp_mock = MagicMock()
    smtp_mock.__enter__ = MagicMock(return_value=smtp_mock)
    smtp_mock.__exit__ = MagicMock(return_value=False)
    monkeypatch.setattr(mcp_mod, "_email_config_load", lambda: _SMTP_CFG)
    monkeypatch.setattr(smtplib, "SMTP", MagicMock(return_value=smtp_mock))

    mcp_mod.email_invoice(inv_id, to="karen@sunshine.com", filepath="", ctx=None)
    smtp_mock.login.assert_called_once_with("u@test.com", "realpassword123")


def test_email_invoice_uses_real_from_address_for_envelope(personal_env, mcp_mod, monkeypatch):
    job_id, inv_id = _seed_invoiced_job(mcp_mod, cust_email="karen@sunshine.com")
    smtp_mock = MagicMock()
    smtp_mock.__enter__ = MagicMock(return_value=smtp_mock)
    smtp_mock.__exit__ = MagicMock(return_value=False)
    monkeypatch.setattr(mcp_mod, "_email_config_load", lambda: _SMTP_CFG)
    monkeypatch.setattr(smtplib, "SMTP", MagicMock(return_value=smtp_mock))

    mcp_mod.email_invoice(inv_id, to="karen@sunshine.com", filepath="", ctx=None)
    assert smtp_mock.sendmail.call_args[0][0] == "me@test.com"


def test_email_invoice_no_smtp_config_returns_error(personal_env, mcp_mod, monkeypatch):
    job_id, inv_id = _seed_invoiced_job(mcp_mod)
    monkeypatch.setattr(mcp_mod, "_email_config_load", lambda: None)
    result = mcp_mod.email_invoice(inv_id, to="karen@sunshine.com", filepath="", ctx=None)
    assert any(w in result.lower() for w in ["configure", "email", "smtp", "setup"])


def test_email_invoice_missing_db_returns_error(personal_env, mcp_mod, monkeypatch):
    """Passing a nonexistent database path must return a clear error,
    not a crash -- the DB-era equivalent of CT_05's missing-spreadsheet
    check."""
    monkeypatch.setattr(mcp_mod, "_email_config_load", lambda: _SMTP_CFG)
    result = mcp_mod.email_invoice(
        "INV-0001", to="test@example.com",
        filepath=str(personal_env.parent / "does_not_exist.db"), ctx=None,
    )
    assert any(w in result.lower() for w in ["not found", "no spreadsheet", "no invoice", "error"])
