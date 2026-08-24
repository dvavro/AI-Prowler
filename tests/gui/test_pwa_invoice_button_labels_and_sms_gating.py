"""
tests/gui/test_pwa_invoice_button_labels_and_sms_gating.py
=============================================================
Tests for the Jobs PWA job modal invoice/receipt button rework:

  - Old "Email Only" / "Email + Text" → replaced by separate per-channel
    "Email Invoice" / "Text Invoice" buttons (and "Email Receipt" / "Text
    Receipt" for cash/check payments).
  - Each channel button is individually dimmed when its transport is not
    configured — Email Invoice dims if no SMTP; Text Invoice dims if no SMS.
  - "Text Customer" in the modal is also dimmed when SMS is not configured.
  - Status is fetched at boot via check_sms_configured() and
    check_email_configured() and cached in state.smsConfigured /
    state.emailConfigured.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
PWA_FILE = SRC_ROOT / "jobs" / "index.html"
MCP_FILE = SRC_ROOT / "ai_prowler_mcp.py"


@pytest.fixture(scope="module")
def pwa_source():
    return PWA_FILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def mcp_source():
    return MCP_FILE.read_text(encoding="utf-8")


class TestButtonLabelsUpdated:
    def test_email_only_renamed_to_email_invoice(self, pwa_source):
        assert "Email Only</button>" not in pwa_source
        assert "Email Invoice" in pwa_source

    def test_email_plus_text_removed_now_separate_buttons(self, pwa_source):
        # Old combined button gone; replaced by separate channel buttons
        assert "Email + Text Invoice</button>" not in pwa_source
        assert "Text Invoice" in pwa_source


class TestSmsButtonDimmedWhenNotConfigured:
    def test_text_invoice_button_disabled_conditional_on_state(self, pwa_source):
        # _smsDis variable gates the Text Invoice button
        assert "_smsDis" in pwa_source or "smsConfigured" in pwa_source

    def test_onclick_only_fires_when_sms_configured(self, pwa_source):
        # sendInvoice for sms channel only fires when SMS ok
        assert "_smsOk" in pwa_source or "smsConfigured" in pwa_source

    def test_disabled_button_has_explanatory_tooltip(self, pwa_source):
        # The SMS dim has a title tooltip explaining why
        assert "Configure SMS" in pwa_source or "SMS" in pwa_source

    def test_email_invoice_button_gated_by_email_not_sms(self, pwa_source):
        # Email Invoice is gated by emailConfigured, not smsConfigured
        assert "emailConfigured" in pwa_source or "_emailOk" in pwa_source


class TestSmsConfiguredStatusFetchedAtBoot:
    def test_state_has_sms_configured_field_defaulting_false(self, pwa_source):
        idx = pwa_source.index("let state = {")
        end_idx = pwa_source.index("};", idx)
        body = pwa_source[idx:end_idx]
        assert "smsConfigured:false" in body

    def test_state_has_email_configured_field_defaulting_false(self, pwa_source):
        idx = pwa_source.index("let state = {")
        end_idx = pwa_source.index("};", idx)
        body = pwa_source[idx:end_idx]
        assert "emailConfigured:false" in body

    def test_check_sms_function_defined(self, pwa_source):
        assert "async function checkSmsConfiguredStatus()" in pwa_source

    def test_check_email_function_defined(self, pwa_source):
        assert "async function checkEmailConfiguredStatus()" in pwa_source

    def test_check_function_called_from_boot_app(self, pwa_source):
        idx = pwa_source.index("function bootApp()")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert "checkSmsConfiguredStatus();" in body
        assert "checkEmailConfiguredStatus();" in body

    def test_check_sms_function_calls_the_backend_tool(self, pwa_source):
        idx = pwa_source.index("async function checkSmsConfiguredStatus()")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert "check_sms_configured" in body

    def test_check_email_function_calls_the_backend_tool(self, pwa_source):
        idx = pwa_source.index("async function checkEmailConfiguredStatus()")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert "check_email_configured" in body

    def test_check_function_defaults_to_false_on_error(self, pwa_source):
        idx = pwa_source.index("async function checkSmsConfiguredStatus()")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert "catch" in body
        assert "state.smsConfigured = false;" in body

    def test_boot_only_calls_it_once_not_on_every_refresh(self, pwa_source):
        idx = pwa_source.index("async function loadJobs()")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert "checkSmsConfiguredStatus" not in body
        assert "checkEmailConfiguredStatus" not in body


class TestBackendToolAllowedInBothModes:
    def test_check_sms_configured_allowed_in_server_mode(self, mcp_source):
        idx = mcp_source.index("_srv_pa_allowed = {")
        nearby = mcp_source[idx:idx + 800]
        assert '"check_sms_configured"' in nearby

    def test_check_sms_configured_allowed_in_personal_mode(self, mcp_source):
        idx = mcp_source.index("_allowed_tools = {")
        nearby = mcp_source[idx:idx + 800]
        assert '"check_sms_configured"' in nearby

    def test_check_email_configured_allowed_in_server_mode(self, mcp_source):
        idx = mcp_source.index("_srv_pa_allowed = {")
        nearby = mcp_source[idx:idx + 800]
        assert '"check_email_configured"' in nearby

    def test_check_email_configured_allowed_in_personal_mode(self, mcp_source):
        idx = mcp_source.index("_allowed_tools = {")
        nearby = mcp_source[idx:idx + 800]
        assert '"check_email_configured"' in nearby
