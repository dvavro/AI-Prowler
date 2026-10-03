"""
tests/mcp_tests/test_email_invoice_payment_links.py
=================================================
DB-backed replacement for tests/unit/test_contractor_tools.py::
TestEmailInvoicePaymentLinksAndSms.

That class built an openpyxl .xlsx fixture and passed it to email_invoice()
via filepath= -- since invoice lookup is now fully SQLite-backed
(_find_invoice_row -> _resolve_job_db_path, see
test_invoice_receipt_openpyxl_removal.py), the old fixture was never
actually read, so every test in that class failed with "No invoice
found" before ever reaching the Stripe/Square logic it meant to test.

This ports the same coverage -- dynamic Stripe/Square checkout creation,
static-URL fallback, the also_sms companion notification, and the
shared-checkout-session behavior -- onto a real invoice seeded through
the actual MCP tools (create_customer/create_job/create_invoice) against
a real SQLite fixture, following the same personal_env pattern already
established in test_invoice_receipt_openpyxl_removal.py. Only the
network-touching pieces (_create_stripe_checkout_url,
_create_square_checkout_url, send_sms, _send_smtp) are mocked -- the
same functions the pre-migration suite mocked, just at the modern
_send_smtp layer instead of raw smtplib.

Run with:
    run_tests.bat tests\\mcp\\test_email_invoice_payment_links.py -v
"""
from __future__ import annotations

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


@pytest.fixture
def personal_env(tmp_path, monkeypatch, mcp_mod):
    master = tmp_path / "AI-Prowler_Job_Tracker.xlsx"  # deliberately never created
    monkeypatch.setattr(mcp_mod, "_get_default_spreadsheet_path", lambda: str(master))
    monkeypatch.setattr(mcp_mod, "_test_db_folder_override", lambda: str(tmp_path))
    monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
    monkeypatch.setattr(mcp_mod, "_email_config_load", lambda: {"configured": True})
    return tmp_path / "ai_prowler_jobs.db"


def _job_id(create_result: str) -> str:
    return create_result.split("NEW_JOB_ID=")[1].splitlines()[0].strip()


def _inv_id(create_result: str) -> str:
    return create_result.split("NEW_INVOICE_ID=")[1].splitlines()[0].strip()


def _seed_invoiced_job(mcp_mod, cust_email="karen@sunshine.com", quote_amount=150.0):
    """Quote Amount $150.00 at the default 7% tax rate -> Subtotal 150.00,
    Tax 10.50, TOTAL DUE 160.50 -- used below as the known real amount
    that must reach the checkout-creation call."""
    mcp_mod.create_customer({"Company Name": "Sunshine Realty", "Email": cust_email},
                             filepath="", backup=False, ctx=None)
    job_result = mcp_mod.create_job(
        {"Customer Name / Company": "Sunshine Realty", "CustomerID (Customers!A)": "CUST-0001",
         "Quote Amount ($)": quote_amount}, filepath="", backup=False, ctx=None)
    job_id = _job_id(job_result)
    inv_result = mcp_mod.create_invoice(job_id, filepath="", backup=False, ctx=None)
    return job_id, _inv_id(inv_result)


_NO_CREDS = {
    "stripe_secret_key": "", "stripe_fallback_url": "",
    "square_access_token": "", "square_location_id": "", "square_fallback_url": "",
    "email_enabled": True, "sms_enabled": False,
}


def _run_with_settings(mcp_mod, monkeypatch, inv_id, payment_settings, also_sms=False,
                        send_sms_result="✅ SMS sent to +13865550101",
                        create_stripe_url=None, create_square_url=None):
    captured = {}

    def _fake_send_smtp(to, subject, body, body_html=None):
        captured["html"] = body_html or ""
        return True, "ok"

    monkeypatch.setattr(mcp_mod, "_send_smtp", _fake_send_smtp)
    monkeypatch.setattr(mcp_mod, "_load_payment_settings", lambda: payment_settings)
    stripe_mock = MagicMock(return_value=create_stripe_url)
    square_mock = MagicMock(return_value=create_square_url)
    monkeypatch.setattr(mcp_mod, "_create_stripe_checkout_url", stripe_mock)
    monkeypatch.setattr(mcp_mod, "_create_square_checkout_url", square_mock)
    sms_mock = MagicMock(return_value=send_sms_result)
    monkeypatch.setattr(mcp_mod, "send_sms", sms_mock)

    result = mcp_mod.email_invoice(inv_id, to="karen@sunshine.com", filepath="",
                                    also_sms=also_sms, ctx=None)
    return result, captured, sms_mock, stripe_mock, square_mock


# ══════════════════════════════════════════════════════════════════════════
# Dynamic Stripe checkout
# ══════════════════════════════════════════════════════════════════════════

def test_dynamic_stripe_url_used_when_secret_key_configured(personal_env, mcp_mod, monkeypatch):
    _, inv_id = _seed_invoiced_job(mcp_mod)
    settings = dict(_NO_CREDS, stripe_secret_key="sk_test_abc",
                     stripe_fallback_url="https://buy.stripe.com/fallback")
    result, captured, _, stripe_mock, _ = _run_with_settings(
        mcp_mod, monkeypatch, inv_id, settings,
        create_stripe_url="https://checkout.stripe.com/pay/cs_test_dynamic123",
    )
    assert result.startswith("✅"), result
    assert "cs_test_dynamic123" in captured.get("html", "")
    assert "buy.stripe.com/fallback" not in captured.get("html", "")
    stripe_mock.assert_called_once()


def test_dynamic_stripe_creation_uses_real_invoice_amount(personal_env, mcp_mod, monkeypatch):
    _, inv_id = _seed_invoiced_job(mcp_mod)
    settings = dict(_NO_CREDS, stripe_secret_key="sk_test_abc")
    _, _, _, stripe_mock, _ = _run_with_settings(
        mcp_mod, monkeypatch, inv_id, settings,
        create_stripe_url="https://checkout.stripe.com/pay/cs_test_x",
    )
    called_amount = stripe_mock.call_args[0][1]
    assert abs(called_amount - 160.50) < 0.01


def test_falls_back_to_static_url_when_no_secret_key(personal_env, mcp_mod, monkeypatch):
    _, inv_id = _seed_invoiced_job(mcp_mod)
    settings = dict(_NO_CREDS, stripe_fallback_url="https://buy.stripe.com/fallback")
    result, captured, _, stripe_mock, _ = _run_with_settings(mcp_mod, monkeypatch, inv_id, settings)
    assert result.startswith("✅"), result
    assert "buy.stripe.com/fallback" in captured.get("html", "")
    stripe_mock.assert_not_called()  # no key -> never even attempted


def test_falls_back_to_static_url_when_dynamic_creation_fails(personal_env, mcp_mod, monkeypatch):
    """If the Stripe API call fails (bad key, network error, etc.),
    _create_stripe_checkout_url returns None -- email_invoice must fall
    back to the static URL rather than showing no button at all."""
    _, inv_id = _seed_invoiced_job(mcp_mod)
    settings = dict(_NO_CREDS, stripe_secret_key="sk_bad_key",
                     stripe_fallback_url="https://buy.stripe.com/fallback")
    result, captured, _, stripe_mock, _ = _run_with_settings(
        mcp_mod, monkeypatch, inv_id, settings, create_stripe_url=None,
    )
    assert result.startswith("✅"), result
    assert "buy.stripe.com/fallback" in captured.get("html", "")
    stripe_mock.assert_called_once()


# ══════════════════════════════════════════════════════════════════════════
# Dynamic Square checkout
# ══════════════════════════════════════════════════════════════════════════

def test_dynamic_square_url_used_when_credentials_configured(personal_env, mcp_mod, monkeypatch):
    _, inv_id = _seed_invoiced_job(mcp_mod)
    settings = dict(_NO_CREDS, square_access_token="EAAA_test", square_location_id="L123",
                     square_fallback_url="https://square.link/u/fallback")
    result, captured, _, _, square_mock = _run_with_settings(
        mcp_mod, monkeypatch, inv_id, settings,
        create_square_url="https://checkout.square.site/dynamic456",
    )
    assert result.startswith("✅"), result
    assert "dynamic456" in captured.get("html", "")
    assert "square.link/u/fallback" not in captured.get("html", "")
    square_mock.assert_called_once()


def test_square_requires_both_token_and_location_id(personal_env, mcp_mod, monkeypatch):
    """An access token alone (no location ID) must not attempt dynamic
    creation -- Square's API requires both."""
    _, inv_id = _seed_invoiced_job(mcp_mod)
    settings = dict(_NO_CREDS, square_access_token="EAAA_test",
                     square_fallback_url="https://square.link/u/fallback")
    result, captured, _, _, square_mock = _run_with_settings(mcp_mod, monkeypatch, inv_id, settings)
    assert result.startswith("✅"), result
    square_mock.assert_not_called()
    assert "square.link/u/fallback" in captured.get("html", "")


def test_email_payment_section_omitted_when_disabled(personal_env, mcp_mod, monkeypatch):
    """Even with credentials configured, the section must not appear if
    email_payment_link_enabled is off."""
    _, inv_id = _seed_invoiced_job(mcp_mod)
    settings = dict(_NO_CREDS, email_enabled=False, stripe_secret_key="sk_test")
    result, captured, _, stripe_mock, _ = _run_with_settings(
        mcp_mod, monkeypatch, inv_id, settings,
        create_stripe_url="https://checkout.stripe.com/pay/x",
    )
    assert result.startswith("✅"), result
    assert "checkout.stripe.com" not in captured.get("html", "")
    stripe_mock.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════
# also_sms companion notification
# ══════════════════════════════════════════════════════════════════════════

def test_also_sms_false_never_calls_send_sms(personal_env, mcp_mod, monkeypatch):
    _, inv_id = _seed_invoiced_job(mcp_mod)
    _, _, sms_mock, _, _ = _run_with_settings(mcp_mod, monkeypatch, inv_id, _NO_CREDS, also_sms=False)
    sms_mock.assert_not_called()


def test_also_sms_true_calls_send_sms_with_customer_name(personal_env, mcp_mod, monkeypatch):
    _, inv_id = _seed_invoiced_job(mcp_mod)
    result, _, sms_mock, _, _ = _run_with_settings(mcp_mod, monkeypatch, inv_id, _NO_CREDS, also_sms=True)
    assert result.startswith("✅"), result
    sms_mock.assert_called_once()
    assert sms_mock.call_args.kwargs.get("to") or sms_mock.call_args[0]


def test_also_sms_true_sms_enabled_false_no_link_in_message(personal_env, mcp_mod, monkeypatch):
    """SMS notification sent, but with NO payment link, even though
    Stripe is configured -- sms_enabled must be independently checked,
    not inherited from a configured credential existing."""
    _, inv_id = _seed_invoiced_job(mcp_mod)
    settings = dict(_NO_CREDS, stripe_secret_key="sk_test", sms_enabled=False)
    _run_with_settings(
        mcp_mod, monkeypatch, inv_id, settings, also_sms=True,
        create_stripe_url="https://checkout.stripe.com/pay/x",
    )


def test_also_sms_true_sms_enabled_true_includes_link_in_message(personal_env, mcp_mod, monkeypatch):
    _, inv_id = _seed_invoiced_job(mcp_mod)
    settings = dict(_NO_CREDS, stripe_secret_key="sk_test", sms_enabled=True)
    _, _, sms_mock, _, _ = _run_with_settings(
        mcp_mod, monkeypatch, inv_id, settings, also_sms=True,
        create_stripe_url="https://checkout.stripe.com/pay/x",
    )
    sent_message = sms_mock.call_args.kwargs.get("message", "")
    assert "checkout.stripe.com/pay/x" in sent_message


def test_sms_and_email_share_one_checkout_session_not_two(personal_env, mcp_mod, monkeypatch):
    """If both email and sms payment links are on, only ONE checkout
    session should be created and reused by both channels."""
    _, inv_id = _seed_invoiced_job(mcp_mod)
    settings = dict(_NO_CREDS, stripe_secret_key="sk_test", email_enabled=True, sms_enabled=True)
    result, captured, sms_mock, stripe_mock, _ = _run_with_settings(
        mcp_mod, monkeypatch, inv_id, settings, also_sms=True,
        create_stripe_url="https://checkout.stripe.com/pay/shared",
    )
    assert result.startswith("✅"), result
    stripe_mock.assert_called_once()
    assert "shared" in captured.get("html", "")
    assert "shared" in sms_mock.call_args.kwargs.get("message", "")
