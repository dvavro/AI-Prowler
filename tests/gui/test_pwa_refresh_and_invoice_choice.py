"""
tests/gui/test_pwa_refresh_and_invoice_choice.py
===================================================
Structural tests for two Jobs PWA additions:

  1. A manual refresh control on the Jobs tab (previously loadJobs() only
     ran once at login, or via the error-state "Retry" button — no way to
     pull in new/changed jobs while the app stayed open).

  2. A choice between "Email Only" and "Email + Text" when sending an
     invoice — SMS carries a short notification only (the formatted HTML
     invoice can't be attached to a text), and the email always goes out
     regardless of which option is chosen.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
PWA_FILE = SRC_ROOT / "jobs" / "index.html"


@pytest.fixture(scope="module")
def pwa_source():
    return PWA_FILE.read_text(encoding="utf-8")


class TestJobsRefreshButton:
    def test_refresh_button_present_in_jobs_screen(self, pwa_source):
        idx = pwa_source.index('id="screen-jobs"')
        nearby = pwa_source[idx:idx + 600]
        assert 'id="refreshJobsBtn"' in nearby
        assert 'onclick="loadJobs()"' in nearby

    def test_refresh_disables_button_and_spins_icon(self, pwa_source):
        idx = pwa_source.index("async function loadJobs()")
        nearby = pwa_source[idx:idx + 500]
        assert "refreshBtn.disabled = true" in nearby
        assert "classList.add('spinning')" in nearby

    def test_refresh_button_re_enabled_on_both_success_and_failure(self, pwa_source):
        """Must use finally, not just the success path — a failed refresh
        must not leave the button permanently disabled."""
        idx = pwa_source.index("async function loadJobs()")
        end_idx = pwa_source.index("\n}", idx)
        nearby = pwa_source[idx:end_idx]
        assert "} finally {" in nearby
        assert "refreshBtn.disabled = false" in nearby
        assert "classList.remove('spinning')" in nearby

    def test_spin_animation_css_defined(self, pwa_source):
        assert ".spinning{animation:spin" in pwa_source
        assert "@keyframes spin{" in pwa_source


class TestInvoiceSendChoice:
    """sendInvoice(jobId, channel) dispatches to email_invoice or text_invoice
    via a single mcpCall using a channel parameter ('email'/'sms'). The old
    also_sms / alsoText design was replaced by separate per-channel buttons,
    each making its own targeted tool call."""

    def test_two_buttons_replace_single_send_invoice_button(self, pwa_source):
        # Both Email Invoice and Text Invoice buttons must exist
        assert "Email Invoice" in pwa_source
        assert "Text Invoice" in pwa_source
        # Old combined button is gone
        assert "Email + Text" not in pwa_source

    def test_send_invoice_accepts_channel_parameter(self, pwa_source):
        idx = pwa_source.index("async function sendInvoice(jobId")
        nearby = pwa_source[idx:idx + 200]
        assert "channel" in nearby

    def test_single_tool_call_dispatches_on_channel(self, pwa_source):
        """sendInvoice must call email_invoice or text_invoice based on
        the channel param — one call, not a separate send_sms call."""
        idx = pwa_source.index("async function sendInvoice(jobId")
        nearby = pwa_source[idx:idx + 1800]
        assert "email_invoice" in nearby
        assert "text_invoice" in nearby
        assert "channel" in nearby

    def test_no_client_side_send_sms_call_remains(self, pwa_source):
        """sendInvoice() must not make its own send_sms call — that
        duplicated logic has been removed; text_invoice handles it."""
        idx = pwa_source.index("async function sendInvoice(jobId")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert "send_sms" not in body

    def test_confirm_dialog_still_distinguishes_the_two_choices(self, pwa_source):
        idx = pwa_source.index("async function sendInvoice(jobId")
        nearby = pwa_source[idx:idx + 600]
        assert "confirmMsg" in nearby
        assert "channel" in nearby


class TestInvoiceIdentifierUsesReliableJobId:
    """Regression guard for a real production bug: sendInvoice() used to
    pass `j.invoiceId || j.customer` as the invoice identifier. j.invoiceId
    never existed in parseJobs()'s output at all (always undefined), and
    j.customer comes from a regex match that silently returns '' on any
    parse miss. A blank identifier reaching the backend's substring search
    matched the FIRST row in the entire Invoices sheet unconditionally
    (Python: "" is a substring of everything) — silently emailing an
    unrelated customer's invoice with no error. Fixed by using j.id (the
    JobID) instead, which is guaranteed non-empty for any job that made it
    into state.jobs at all, since parseJobs() splits job blocks on it."""

    def test_uses_job_id_not_customer_name_fallback_chain(self, pwa_source):
        idx = pwa_source.index("async function sendInvoice(jobId")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert "invoice_identifier: j.id" in body
        assert "j.invoiceId || j.customer" not in body

    def test_guards_against_missing_job_id_before_calling_backend(self, pwa_source):
        idx = pwa_source.index("async function sendInvoice(jobId")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert "if (!j.id)" in body
        # The guard must appear before the mcpCall
        guard_pos = body.index("if (!j.id)")
        call_pos  = body.index("mcpCall(")
        assert guard_pos < call_pos
