"""
tests/gui/test_pwa_sms_email_send_result_gating.py
=====================================================
Regression tests for a 2026-08-24 bug report: disabling SMS in Settings
while the Jobs PWA tab was already open let a text still "send" — no
"SMS is not configured" popup, and the UI reported success.

Root causes (two independent bugs, either one alone reproduces the report):

  1. state.smsConfigured / state.emailConfigured were fetched exactly once,
     at boot, and never refreshed. A tab left open across a Settings change
     kept gating on stale (now-wrong) cached values.
     Fix: _requireConfigured() is now async and re-runs
     checkSmsConfiguredStatus() / checkEmailConfiguredStatus() immediately
     before every gated action, so the cache can never be more than an
     instant stale.

  2. send_sms / text_invoice / text_receipt / email_invoice / email_receipt
     report failure (provider not configured, bad number, Twilio/SMTP
     error, etc.) as an ordinary "❌ ..." STRING return value with the
     transport-level {"ok": true} still set. mcpCall() only throws on an
     actual HTTP/transport failure — never on the tool's own reported
     outcome — so every send path was handing that failure string straight
     to a success toast, unchecked.
     Fix: a shared _isFailureResult(result) helper (checks for a leading
     "❌") is now called in sendSMS(), sendInvoice(), and sendReceipt()
     before any success toast/status update, routing to the error path
     instead when the backend reported failure.

Plain string-presence / substring-order checks against the source, matching
the existing structural-verification approach for this file (a JS file
can't be usefully unit-tested the way Python tool functions can without a
full browser/DOM harness — see test_pwa_invoice_button_labels_and_sms_gating.py).
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

_SRC = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parent.parent.parent
PWA_FILE = SRC_ROOT / "jobs" / "index.html"


@pytest.fixture(scope="module")
def pwa_source():
    return PWA_FILE.read_text(encoding="utf-8")


def _function_body(source: str, signature: str) -> str:
    """Extract a top-level function body from `signature` (e.g.
    'async function sendSMS()') through its closing '\\n}' line.
    Mirrors the pattern already used throughout this test suite."""
    idx = source.index(signature)
    end_idx = source.index("\n}", idx)
    return source[idx:end_idx]


# ══════════════════════════════════════════════════════════════════════════
# Bug 1 — _requireConfigured must re-check live status, not just boot cache
# ══════════════════════════════════════════════════════════════════════════

class TestRequireConfiguredRefetchesLiveStatus:
    def test_require_configured_is_async(self, pwa_source):
        assert "async function _requireConfigured(kind)" in pwa_source, (
            "_requireConfigured must be async so it can re-check live "
            "config status before gating — a sync function can only read "
            "the (possibly stale) cached state."
        )

    def test_require_configured_recalls_check_sms_status(self, pwa_source):
        body = _function_body(pwa_source, "async function _requireConfigured(kind)")
        assert "await checkSmsConfiguredStatus();" in body, (
            "_requireConfigured must re-run checkSmsConfiguredStatus() "
            "before reading state.smsConfigured, or a tab left open "
            "across a Settings change keeps gating on a stale cache."
        )

    def test_require_configured_recalls_check_email_status(self, pwa_source):
        body = _function_body(pwa_source, "async function _requireConfigured(kind)")
        assert "await checkEmailConfiguredStatus();" in body, (
            "_requireConfigured must re-run checkEmailConfiguredStatus() "
            "before reading state.emailConfigured, same as the SMS path."
        )

    def test_sms_recheck_happens_before_reading_state(self, pwa_source):
        body = _function_body(pwa_source, "async function _requireConfigured(kind)")
        recheck_idx = body.index("await checkSmsConfiguredStatus();")
        read_idx = body.index("if (!state.smsConfigured)")
        assert recheck_idx < read_idx, (
            "The live re-check must happen BEFORE state.smsConfigured is "
            "read — checking the stale value first defeats the fix."
        )

    def test_email_recheck_happens_before_reading_state(self, pwa_source):
        body = _function_body(pwa_source, "async function _requireConfigured(kind)")
        recheck_idx = body.index("await checkEmailConfiguredStatus();")
        read_idx = body.index("if (!state.emailConfigured)")
        assert recheck_idx < read_idx, (
            "The live re-check must happen BEFORE state.emailConfigured "
            "is read — checking the stale value first defeats the fix."
        )

    def test_still_alerts_when_sms_not_configured(self, pwa_source):
        body = _function_body(pwa_source, "async function _requireConfigured(kind)")
        assert "SMS is not configured yet." in body

    def test_still_alerts_when_email_not_configured(self, pwa_source):
        body = _function_body(pwa_source, "async function _requireConfigured(kind)")
        assert "Email is not configured yet." in body


class TestAllCallSitesAwaitRequireConfigured:
    """_requireConfigured() becoming async is a breaking change for every
    caller — a caller that forgot to add `await` would get a Promise
    object back, which is always truthy, silently defeating the gate
    entirely (worse than the original bug: it would never block anything,
    even on a fresh boot)."""

    @pytest.mark.parametrize(
        "signature",
        [
            "async function sendSMS()",
            "async function sendInvoice(jobId, channel)",
            "async function sendReceipt(jobId, channel, paymentMethod)",
            "async function goMessages(customerName)",
        ],
    )
    def test_call_site_awaits_require_configured(self, pwa_source, signature):
        body = _function_body(pwa_source, signature)
        assert re.search(r"await _requireConfigured\(", body), (
            f"{signature} must `await _requireConfigured(...)` now that "
            "it's async — an un-awaited call returns a Promise, which is "
            "always truthy and would silently disable the entire gate."
        )

    def test_go_messages_itself_is_async(self, pwa_source):
        # A caller can only `await` inside an async function.
        assert "async function goMessages(customerName)" in pwa_source


# ══════════════════════════════════════════════════════════════════════════
# Bug 2 — send paths must not report success on a backend ❌ failure string
# ══════════════════════════════════════════════════════════════════════════

class TestIsFailureResultHelperExists:
    def test_helper_is_defined(self, pwa_source):
        assert "function _isFailureResult(result)" in pwa_source

    def test_helper_checks_for_leading_cross_mark(self, pwa_source):
        body = _function_body(pwa_source, "function _isFailureResult(result)")
        assert "startsWith('❌')" in body

    def test_helper_guards_against_non_string_results(self, pwa_source):
        # Defensive: a non-string result (or an exception object) must not
        # throw inside the helper itself.
        body = _function_body(pwa_source, "function _isFailureResult(result)")
        assert "typeof result === 'string'" in body


class TestSendPathsCheckResultBeforeSuccessToast:
    @pytest.mark.parametrize(
        "signature, success_marker",
        [
            ("async function sendSMS()", "'✓ Sent'"),
            ("async function sendInvoice(jobId, channel)", "'Invoice sent!'"),
            ("async function sendReceipt(jobId, channel, paymentMethod)", "'Receipt sent!'"),
        ],
    )
    def test_calls_is_failure_result(self, pwa_source, signature, success_marker):
        body = _function_body(pwa_source, signature)
        assert "_isFailureResult(result)" in body, (
            f"{signature} must check _isFailureResult(result) — otherwise "
            "a backend '❌ ...' failure string is reported as success."
        )

    @pytest.mark.parametrize(
        "signature, success_marker",
        [
            ("async function sendSMS()", "'✓ Sent'"),
            ("async function sendInvoice(jobId, channel)", "'Invoice sent!'"),
            ("async function sendReceipt(jobId, channel, paymentMethod)", "'Receipt sent!'"),
        ],
    )
    def test_failure_check_precedes_success_toast(self, pwa_source, signature, success_marker):
        body = _function_body(pwa_source, signature)
        failure_check_idx = body.index("_isFailureResult(result)")
        success_idx = body.index(success_marker)
        assert failure_check_idx < success_idx, (
            f"{signature} must check _isFailureResult(result) BEFORE "
            "showing the success toast, or the check has no effect."
        )

    @pytest.mark.parametrize(
        "signature",
        [
            "async function sendSMS()",
            "async function sendInvoice(jobId, channel)",
            "async function sendReceipt(jobId, channel, paymentMethod)",
        ],
    )
    def test_failure_branch_shows_error_toast_and_returns(self, pwa_source, signature):
        body = _function_body(pwa_source, signature)
        failure_block_idx = body.index("_isFailureResult(result)")
        # Grab the small if-block immediately following the check.
        block_end = body.index("}", failure_block_idx)
        failure_block = body[failure_block_idx:block_end]
        assert "'error'" in failure_block, (
            f"{signature}: the _isFailureResult branch must show an "
            "error-styled toast, not a success one."
        )
        assert "return;" in failure_block, (
            f"{signature}: the _isFailureResult branch must return early "
            "so execution never reaches the success toast / closeModal()."
        )


class TestSendSmsResultCheckedInStatusTextToo:
    def test_failed_status_text_uses_backend_message(self, pwa_source):
        body = _function_body(pwa_source, "async function sendSMS()")
        assert "status.textContent = 'Failed: ' + result.split('\\n')[0];" in body, (
            "sendSMS's on-screen status line should surface the backend's "
            "actual failure reason (e.g. 'SMS not configured'), not just "
            "silently swap to a generic success message."
        )


class TestExistingGatingBehaviorUnchanged:
    """Sanity checks that the fix didn't regress the pre-existing,
    already-tested dimming/gating behavior from
    test_pwa_invoice_button_labels_and_sms_gating.py."""

    def test_state_still_has_sms_configured_field(self, pwa_source):
        idx = pwa_source.index("let state = {")
        end_idx = pwa_source.index("};", idx)
        body = pwa_source[idx:end_idx]
        assert "smsConfigured:false" in body

    def test_state_still_has_email_configured_field(self, pwa_source):
        idx = pwa_source.index("let state = {")
        end_idx = pwa_source.index("};", idx)
        body = pwa_source[idx:end_idx]
        assert "emailConfigured:false" in body

    def test_boot_still_fires_both_checks_for_first_paint(self, pwa_source):
        idx = pwa_source.index("function bootApp()")
        end_idx = pwa_source.index("\n}", idx)
        body = pwa_source[idx:end_idx]
        assert "checkSmsConfiguredStatus();" in body
        assert "checkEmailConfiguredStatus();" in body
