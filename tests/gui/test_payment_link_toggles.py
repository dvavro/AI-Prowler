"""
tests/gui/test_payment_link_toggles.py
=========================================
Structural tests for Settings → Small Business → Online Payment Links
(rag_gui.py):

  - The two toggle checkboxes: "Include Pay Now buttons in emailed
    invoices" (email_payment_link_enabled, default ON) and "Include
    payment link when texting invoice notifications"
    (sms_payment_link_enabled, default OFF).
  - Stripe Secret Key + Square Access Token/Location ID fields, which
    enable dynamic per-invoice checkout (correct amount automatically),
    each with a static fallback URL field used only when no credentials
    are configured.
  - Xero fully removed — no fields, no fallback, nothing. Its API
    requires full OAuth 2.0 (registered redirect URI, refresh token
    management, tenant ID), judged too complex for this feature's
    target users.

Both toggles and both providers must be present regardless of mode —
this section is NOT gated by any server-mode conditional, unlike several
other settings in this file.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
GUI_FILE = SRC_ROOT / "rag_gui.py"


@pytest.fixture(scope="module")
def source():
    return GUI_FILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def pay_section(source):
    """Isolates the Online Payment Links LabelFrame section for scoped
    assertions, rather than searching the entire multi-megabyte file."""
    start = source.index('text="💳 Online Payment Links')
    end = source.index("ttk.Separator(f, orient='horizontal')", start)
    return source[start:end]


class TestXeroFullyRemoved:
    def test_no_xero_variable_anywhere_in_section(self, pay_section):
        assert "_xero_var" not in pay_section

    def test_no_xero_config_key_anywhere_in_section(self, pay_section):
        assert "xero_payment_url" not in pay_section

    def test_no_xero_text_anywhere_in_section(self, pay_section):
        assert "xero" not in pay_section.lower()


class TestStripeFields:
    def test_secret_key_field_present(self, pay_section):
        assert "_stripe_secret_var" in pay_section
        assert "stripe_secret_key" in pay_section

    def test_fallback_url_field_present(self, pay_section):
        assert "_stripe_var" in pay_section
        assert "stripe_payment_url" in pay_section

    def test_secret_key_field_is_masked(self, pay_section):
        idx = pay_section.index("_stripe_secret_var")
        nearby = pay_section[idx:idx + 400]
        assert "_masked_row" in nearby


class TestSquareFields:
    def test_access_token_field_present(self, pay_section):
        assert "_square_token_var" in pay_section
        assert "square_access_token" in pay_section

    def test_location_id_field_present(self, pay_section):
        assert "_square_location_var" in pay_section
        assert "square_location_id" in pay_section

    def test_fallback_url_field_present(self, pay_section):
        assert "_square_var" in pay_section
        assert "square_payment_url" in pay_section

    def test_access_token_field_is_masked(self, pay_section):
        idx = pay_section.index("_square_token_var")
        nearby = pay_section[idx:idx + 400]
        assert "_masked_row" in nearby


class TestCheckboxesExist:
    def test_email_link_checkbox_present(self, pay_section):
        assert "_email_link_var" in pay_section
        assert "Include Pay Now buttons in emailed invoices" in pay_section

    def test_sms_link_checkbox_present(self, pay_section):
        assert "_sms_link_var" in pay_section
        assert "Include payment link when texting invoice notifications" in pay_section

    def test_both_are_checkbuttons_not_entries(self, pay_section):
        """Regression guard — these must be actual toggleable checkboxes,
        not accidentally left as another widget type."""
        assert "ttk.Checkbutton(pay_lf" in pay_section
        assert pay_section.count("ttk.Checkbutton(pay_lf") == 2


class TestDefaults:
    def test_email_link_defaults_true(self, pay_section):
        """Preserves the feature's original, pre-toggle behavior — it
        already worked unconditionally whenever a URL was configured."""
        idx = pay_section.index("_email_link_var")
        nearby = pay_section[idx:idx + 150]
        assert "email_payment_link_enabled" in nearby
        assert ", True))" in nearby

    def test_sms_link_defaults_false(self, pay_section):
        """A newer, more exposed channel — off until the toll-free
        registration's sample message is updated to include a link."""
        idx = pay_section.index("_sms_link_var")
        nearby = pay_section[idx:idx + 150]
        assert "sms_payment_link_enabled" in nearby
        assert ", False))" in nearby


class TestSaveWritesAllExpectedKeys:
    def test_save_pay_links_writes_stripe_secret_key(self, pay_section):
        idx = pay_section.index("def _save_pay_links()")
        nearby = pay_section[idx:idx + 600]
        assert '"stripe_secret_key"' in nearby

    def test_save_pay_links_writes_square_credentials(self, pay_section):
        idx = pay_section.index("def _save_pay_links()")
        nearby = pay_section[idx:idx + 600]
        assert '"square_access_token"' in nearby
        assert '"square_location_id"' in nearby

    def test_save_pay_links_writes_email_toggle(self, pay_section):
        idx = pay_section.index("def _save_pay_links()")
        nearby = pay_section[idx:idx + 600]
        assert '"email_payment_link_enabled": _email_link_var.get()' in nearby

    def test_save_pay_links_writes_sms_toggle(self, pay_section):
        idx = pay_section.index("def _save_pay_links()")
        nearby = pay_section[idx:idx + 600]
        assert '"sms_payment_link_enabled":   _sms_link_var.get()' in nearby

    def test_save_pay_links_writes_no_xero_key(self, pay_section):
        idx = pay_section.index("def _save_pay_links()")
        nearby = pay_section[idx:idx + 600]
        assert "xero" not in nearby.lower()


class TestNotGatedByServerMode:
    """Explicit requirement from the request that introduced this feature:
    both toggles and both providers must apply to server and personal
    mode identically."""

    def test_section_has_no_server_mode_conditional_immediately_before_it(self, source):
        start = source.index('text="💳 Online Payment Links')
        # Look at a window before the section starts for a mode-gating
        # 'if' statement guarding this LabelFrame's creation.
        preceding = source[max(0, start - 400):start]
        assert "_settings_is_server_mode" not in preceding

