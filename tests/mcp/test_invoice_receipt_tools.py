"""
tests/mcp/test_invoice_receipt_tools.py
=========================================
Tests for the invoice/receipt button rework and new MCP tools added in v9.1:

  NEW MCP TOOLS
  -------------
  A  check_email_configured   — parallel to check_sms_configured; reports
                                 whether SMTP is set up so the PWA can dim
                                 the Email Invoice/Receipt button before tap.
  B  email_receipt            — HTML "Payment Received" receipt for cash/check
  C  text_receipt             — SMS "Payment Received" receipt for cash/check

  PWA STRUCTURAL CHANGES (pwa/index.html)
  ----------------------------------------
  D  emailConfigured state     — added alongside smsConfigured; both default false
  E  checkEmailConfiguredStatus() — boot function that calls check_email_configured
  F  sendReceipt()             — JS function calling email_receipt / text_receipt
  G  Button logic              — paid→badge; cash/check→Receipt buttons;
                                  unpaid→Invoice buttons; Text Customer dimmed
                                  if no SMS

  ALLOWED-TOOL LIST INTEGRITY
  ----------------------------
  H  All four new tools are in both the personal-mode and server-mode
     allowed lists; dangerous tools are still absent.

  RECEIPT TOOL STRUCTURE
  ----------------------
  I  email_receipt and text_receipt both call _find_invoice_row for consistent
     crew-scoping and path resolution (same as email_invoice / text_invoice).

All tests are OFFLINE (no running server required). They inspect source text
and the MCP module object where appropriate.

Run:
    pytest tests/mcp/test_invoice_receipt_tools.py -v
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_SRC     = os.environ.get("AI_PROWLER_SRC")
SRC_ROOT = Path(_SRC).resolve() if _SRC else Path(__file__).resolve().parents[2]
MCP_FILE = SRC_ROOT / "ai_prowler_mcp.py"
HTML_FILE = SRC_ROOT / "jobs" / "index.html"  # disk folder is jobs/ to match the /jobs/ URL route


def _find_line(lines: list[str], pattern: str, start: int = 0) -> int | None:
    for i in range(start, len(lines)):
        if pattern in lines[i]:
            return i
    return None


@pytest.fixture(scope="module")
def source() -> str:
    return MCP_FILE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def lines(source) -> list[str]:
    return source.splitlines()


@pytest.fixture(scope="module")
def html() -> str:
    assert HTML_FILE.exists(), f"pwa/index.html not found: {HTML_FILE}"
    return HTML_FILE.read_text(encoding="utf-8")


# ══════════════════════════════════════════════════════════════════════════
# Section A — check_email_configured MCP tool
# ══════════════════════════════════════════════════════════════════════════

class TestCheckEmailConfigured:
    """A.x — check_email_configured tool structure."""

    def test_A1_tool_function_exists(self, source):
        assert "def check_email_configured(" in source, \
            "check_email_configured function missing from ai_prowler_mcp.py"

    def test_A2_decorated_as_mcp_tool(self, lines):
        ln = _find_line(lines, "def check_email_configured(")
        assert ln is not None
        # @mcp.tool() decorator must be within 2 lines above the def
        nearby_above = "\n".join(lines[max(0, ln - 2):ln])
        assert "@mcp.tool()" in nearby_above, \
            "check_email_configured must be decorated with @mcp.tool()"

    def test_A3_calls_email_config_load(self, lines):
        ln = _find_line(lines, "def check_email_configured(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 20])
        assert "_email_config_load()" in body, \
            "check_email_configured must call _email_config_load() to probe SMTP config"

    def test_A4_returns_checkmark_string_on_success(self, lines):
        ln = _find_line(lines, "def check_email_configured(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 20])
        assert "✅ Email configured" in body, \
            "check_email_configured must return '✅ Email configured' on success"

    def test_A5_returns_x_string_on_failure(self, lines):
        ln = _find_line(lines, "def check_email_configured(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 20])
        assert "❌ Email not configured" in body, \
            "check_email_configured must return '❌ Email not configured' on failure"

    def test_A6_appears_after_check_sms_configured(self, lines):
        sms_ln   = _find_line(lines, "def check_sms_configured(")
        email_ln = _find_line(lines, "def check_email_configured(")
        assert sms_ln is not None and email_ln is not None
        assert sms_ln < email_ln, \
            "check_email_configured should appear after check_sms_configured (logical grouping)"

    def test_A7_appears_before_send_sms(self, lines):
        email_ln = _find_line(lines, "def check_email_configured(")
        sms_ln   = _find_line(lines, "def send_sms(")
        assert email_ln is not None and sms_ln is not None
        assert email_ln < sms_ln, \
            "check_email_configured should appear before send_sms in file"


# ══════════════════════════════════════════════════════════════════════════
# Section B — email_receipt MCP tool
# ══════════════════════════════════════════════════════════════════════════

class TestEmailReceiptTool:
    """B.x — email_receipt tool structure and implementation."""

    def test_B1_tool_function_exists(self, source):
        assert "def email_receipt(" in source, \
            "email_receipt function missing from ai_prowler_mcp.py"

    def test_B2_decorated_as_mcp_tool(self, lines):
        ln = _find_line(lines, "def email_receipt(")
        assert ln is not None
        nearby_above = "\n".join(lines[max(0, ln - 2):ln])
        assert "@mcp.tool()" in nearby_above

    def test_B3_takes_invoice_identifier_param(self, lines):
        ln = _find_line(lines, "def email_receipt(")
        assert ln is not None
        sig = "\n".join(lines[ln: ln + 8])
        assert "invoice_identifier" in sig

    def test_B4_takes_payment_method_param(self, lines):
        ln = _find_line(lines, "def email_receipt(")
        assert ln is not None
        sig = "\n".join(lines[ln: ln + 8])
        assert "payment_method" in sig, \
            "email_receipt must accept payment_method (Cash/Check/etc.)"

    def test_B5_uses_find_invoice_row_for_scoping(self, lines):
        ln = _find_line(lines, "def email_receipt(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 120])
        assert "_find_invoice_row(" in body, \
            "email_receipt must delegate to _find_invoice_row for crew-scoping/path"

    def test_B6_calls_email_config_load(self, lines):
        ln = _find_line(lines, "def email_receipt(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 220])
        assert "_email_config_load()" in body, \
            "email_receipt must call _email_config_load() to check/load SMTP config"

    def test_B7_sends_via_smtp(self, lines):
        ln = _find_line(lines, "def email_receipt(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 220])
        assert "smtp" in body.lower() or "SMTP" in body, \
            "email_receipt must use SMTP to send the email"

    def test_B8_receipt_subject_says_payment_received(self, lines):
        ln = _find_line(lines, "def email_receipt(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 220])
        assert "Receipt" in body or "Payment Received" in body, \
            "email_receipt HTML/subject must mention Receipt or Payment Received"

    def test_B9_returns_success_checkmark(self, lines):
        ln = _find_line(lines, "def email_receipt(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 250])
        assert "✅ Receipt emailed" in body, \
            "email_receipt must return '✅ Receipt emailed' on success"

    def test_B10_returns_error_on_no_email_config(self, lines):
        ln = _find_line(lines, "def email_receipt(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 250])
        assert "❌ Email not configured" in body or "configure_email" in body, \
            "email_receipt must return an error when SMTP not configured"

    def test_B11_appears_after_text_invoice(self, lines):
        text_inv_ln = _find_line(lines, "def text_invoice(")
        email_rec_ln = _find_line(lines, "def email_receipt(")
        assert text_inv_ln is not None and email_rec_ln is not None
        assert text_inv_ln < email_rec_ln, \
            "email_receipt must appear after text_invoice (Action Tool 8b section)"

    def test_B12_increments_telemetry(self, lines):
        ln = _find_line(lines, "def email_receipt(")
        assert ln is not None
        # The telemetry call is just after the docstring — use a 55-line window
        # to clear the multi-line docstring that precedes the function body.
        body = "\n".join(lines[ln: ln + 55])
        assert '_telemetry_increment_tool_count("email_receipt")' in body, \
            "email_receipt must call _telemetry_increment_tool_count"


# ══════════════════════════════════════════════════════════════════════════
# Section C — text_receipt MCP tool
# ══════════════════════════════════════════════════════════════════════════

class TestTextReceiptTool:
    """C.x — text_receipt tool structure and implementation."""

    def test_C1_tool_function_exists(self, source):
        assert "def text_receipt(" in source, \
            "text_receipt function missing from ai_prowler_mcp.py"

    def test_C2_decorated_as_mcp_tool(self, lines):
        ln = _find_line(lines, "def text_receipt(")
        assert ln is not None
        nearby_above = "\n".join(lines[max(0, ln - 2):ln])
        assert "@mcp.tool()" in nearby_above

    def test_C3_takes_invoice_identifier_param(self, lines):
        ln = _find_line(lines, "def text_receipt(")
        assert ln is not None
        sig = "\n".join(lines[ln: ln + 8])
        assert "invoice_identifier" in sig

    def test_C4_takes_payment_method_param(self, lines):
        ln = _find_line(lines, "def text_receipt(")
        assert ln is not None
        sig = "\n".join(lines[ln: ln + 8])
        assert "payment_method" in sig

    def test_C5_uses_find_invoice_row_for_scoping(self, lines):
        ln = _find_line(lines, "def text_receipt(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 80])
        assert "_find_invoice_row(" in body, \
            "text_receipt must delegate to _find_invoice_row for crew-scoping/path"

    def test_C6_calls_send_sms(self, lines):
        ln = _find_line(lines, "def text_receipt(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 80])
        assert "send_sms(" in body, \
            "text_receipt must call send_sms() to deliver the receipt"

    def test_C7_message_says_thank_you(self, lines):
        ln = _find_line(lines, "def text_receipt(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 80])
        assert "thank" in body.lower() or "Thank" in body, \
            "text_receipt SMS message must include a thank-you"

    def test_C8_message_includes_receipt_number(self, lines):
        ln = _find_line(lines, "def text_receipt(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 80])
        assert "Receipt #" in body or "inv_id" in body, \
            "text_receipt message must reference the receipt/invoice ID"

    def test_C9_returns_success_checkmark(self, lines):
        ln = _find_line(lines, "def text_receipt(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 80])
        assert "✅ Receipt texted" in body, \
            "text_receipt must return '✅ Receipt texted' on success"

    def test_C10_appears_after_email_receipt(self, lines):
        email_rec_ln = _find_line(lines, "def email_receipt(")
        text_rec_ln  = _find_line(lines, "def text_receipt(")
        assert email_rec_ln is not None and text_rec_ln is not None
        assert email_rec_ln < text_rec_ln, \
            "text_receipt must appear after email_receipt (same 8b section)"

    def test_C11_increments_telemetry(self, lines):
        ln = _find_line(lines, "def text_receipt(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 30])
        assert '_telemetry_increment_tool_count("text_receipt")' in body, \
            "text_receipt must call _telemetry_increment_tool_count"


# ══════════════════════════════════════════════════════════════════════════
# Section D/E — PWA state: emailConfigured + checkEmailConfiguredStatus
# ══════════════════════════════════════════════════════════════════════════

class TestPwaEmailConfiguredState:
    """D/E.x — emailConfigured state and boot check function in pwa/index.html."""

    def test_D1_email_configured_in_state(self, html):
        assert "emailConfigured" in html, \
            "emailConfigured missing from state object in pwa/index.html"

    def test_D2_email_configured_defaults_false(self, html):
        # Find the state block and confirm the default
        idx = html.find("emailConfigured")
        assert idx != -1
        snippet = html[idx: idx + 30]
        assert "false" in snippet, \
            "emailConfigured must default to false (safe-dim until confirmed)"

    def test_D3_sms_configured_still_present(self, html):
        assert "smsConfigured" in html, \
            "smsConfigured removed from state — must stay alongside emailConfigured"

    def test_E1_check_email_configured_status_function(self, html):
        assert "checkEmailConfiguredStatus" in html, \
            "checkEmailConfiguredStatus() function missing from pwa/index.html"

    def test_E2_calls_check_email_configured_mcp_tool(self, html):
        idx = html.find("checkEmailConfiguredStatus")
        assert idx != -1
        # Find the function body (search forward from definition)
        fn_idx = html.find("async function checkEmailConfiguredStatus")
        assert fn_idx != -1, "checkEmailConfiguredStatus must be an async function"
        body = html[fn_idx: fn_idx + 300]
        assert "check_email_configured" in body, \
            "checkEmailConfiguredStatus must call the 'check_email_configured' MCP tool"

    def test_E3_sets_state_email_configured(self, html):
        fn_idx = html.find("async function checkEmailConfiguredStatus")
        assert fn_idx != -1
        body = html[fn_idx: fn_idx + 300]
        assert "state.emailConfigured" in body, \
            "checkEmailConfiguredStatus must update state.emailConfigured"

    def test_E4_check_email_called_on_boot(self, html):
        assert "checkEmailConfiguredStatus()" in html, \
            "checkEmailConfiguredStatus() must be called during app boot"

    def test_E5_both_checks_called_at_boot(self, html):
        # Both SMS and email checks must be in the same boot section
        boot_idx = html.find("checkSmsConfiguredStatus()")
        email_boot_idx = html.find("checkEmailConfiguredStatus()")
        assert boot_idx != -1, "checkSmsConfiguredStatus() call missing"
        assert email_boot_idx != -1, "checkEmailConfiguredStatus() call missing"
        # They should be within 5 lines of each other
        boot_snippet = html[min(boot_idx, email_boot_idx): max(boot_idx, email_boot_idx) + 50]
        assert abs(boot_snippet.count("\n")) <= 6, \
            "Both SMS and email configured checks should be called together at boot"


# ══════════════════════════════════════════════════════════════════════════
# Section F — sendReceipt() JS function in pwa/index.html
# ══════════════════════════════════════════════════════════════════════════

class TestPwaSendReceiptFunction:
    """F.x — sendReceipt() in pwa/index.html."""

    def test_F1_send_receipt_function_exists(self, html):
        assert "async function sendReceipt(" in html, \
            "sendReceipt() function missing from pwa/index.html"

    def test_F2_calls_email_receipt_tool(self, html):
        fn_idx = html.find("async function sendReceipt(")
        assert fn_idx != -1
        body = html[fn_idx: fn_idx + 1200]
        assert "email_receipt" in body, \
            "sendReceipt must call the email_receipt MCP tool"

    def test_F3_calls_text_receipt_tool(self, html):
        fn_idx = html.find("async function sendReceipt(")
        assert fn_idx != -1
        body = html[fn_idx: fn_idx + 1200]
        assert "text_receipt" in body, \
            "sendReceipt must call the text_receipt MCP tool"

    def test_F4_accepts_channel_param(self, html):
        fn_idx = html.find("async function sendReceipt(")
        assert fn_idx != -1
        sig = html[fn_idx: fn_idx + 60]
        assert "channel" in sig, \
            "sendReceipt must accept a 'channel' parameter (email/sms)"

    def test_F5_accepts_payment_method_param(self, html):
        fn_idx = html.find("async function sendReceipt(")
        assert fn_idx != -1
        sig = html[fn_idx: fn_idx + 80]
        assert "paymentMethod" in sig or "payment_method" in sig, \
            "sendReceipt must accept a payment method parameter"

    def test_F6_shows_confirm_dialog(self, html):
        fn_idx = html.find("async function sendReceipt(")
        assert fn_idx != -1
        body = html[fn_idx: fn_idx + 1200]
        assert "confirm(" in body, \
            "sendReceipt must show a confirm() dialog before sending"

    def test_F7_shows_toast_on_success(self, html):
        fn_idx = html.find("async function sendReceipt(")
        assert fn_idx != -1
        body = html[fn_idx: fn_idx + 1200]
        assert "showToast" in body, \
            "sendReceipt must call showToast() to feedback the user"

    def test_F8_closes_modal_on_success(self, html):
        fn_idx = html.find("async function sendReceipt(")
        assert fn_idx != -1
        body = html[fn_idx: fn_idx + 1200]
        assert "closeModal()" in body, \
            "sendReceipt must close the job modal after successful send"

    def test_F9_appears_after_send_invoice(self, html):
        inv_idx = html.find("async function sendInvoice(")
        rec_idx = html.find("async function sendReceipt(")
        assert inv_idx != -1 and rec_idx != -1
        assert inv_idx < rec_idx, \
            "sendReceipt must appear after sendInvoice in the JS source"

    def test_F10_passes_payment_method_to_mcp_tool(self, html):
        fn_idx = html.find("async function sendReceipt(")
        assert fn_idx != -1
        body = html[fn_idx: fn_idx + 1200]
        assert "payment_method" in body, \
            "sendReceipt must pass payment_method to the MCP tool call"


# ══════════════════════════════════════════════════════════════════════════
# Section G — Job popup button logic
# ══════════════════════════════════════════════════════════════════════════

class TestPwaButtonLogic:
    """G.x — Invoice/receipt button logic in the job popup."""

    def test_G1_email_invoice_button_present(self, html):
        assert "Email Invoice" in html, \
            "Email Invoice button missing from job popup"

    def test_G2_text_invoice_button_present(self, html):
        assert "Text Invoice" in html, \
            "Text Invoice button missing from job popup"

    def test_G3_email_receipt_button_present(self, html):
        assert "Email Receipt" in html, \
            "Email Receipt button missing from job popup"

    def test_G4_text_receipt_button_present(self, html):
        assert "Text Receipt" in html, \
            "Text Receipt button missing from job popup"

    def test_G5_invoice_paid_badge_present(self, html):
        assert "Invoice Paid" in html, \
            "Invoice Paid badge missing — paid jobs must show this instead of send buttons"

    def test_G6_offline_payment_methods_covered(self, html):
        # The offline-paid check must include cash and check at minimum
        assert "'cash'" in html or '"cash"' in html, \
            "Button logic must recognize 'cash' as an offline payment method"
        assert "'check'" in html or '"check"' in html, \
            "Button logic must recognize 'check' as an offline payment method"

    def test_G7_email_invoice_dims_when_no_email(self, html):
        # _emailDis / emailOk check must gate the Email Invoice button
        assert "emailConfigured" in html or "_emailOk" in html or "_emailDis" in html, \
            "Email Invoice button must be conditioned on emailConfigured state"

    def test_G8_text_invoice_dims_when_no_sms(self, html):
        # _smsDis / smsOk check must gate the Text Invoice button
        assert "smsConfigured" in html or "_smsOk" in html or "_smsDis" in html, \
            "Text Invoice button must be conditioned on smsConfigured state"

    def test_G9_text_customer_button_guarded_when_no_sms(self, html):
        # The Text Customer button must be gated on SMS availability.
        # Design decision (2026-08-23, see _requireConfigured comment in
        # jobs/index.html): buttons are always tappable on mobile — disabling
        # them with `disabled` silently does nothing on a touchscreen because
        # there's no hover tooltip. Instead goMessages() calls
        # _requireConfigured('sms') first, which pops a real alert() with
        # setup instructions if SMS isn't configured.
        # So the correct assertion is that goMessages calls _requireConfigured,
        # NOT that the button itself has a disabled attribute.
        assert "function goMessages(" in html, \
            "goMessages function must exist"
        gm_idx = html.index("function goMessages(")
        gm_body = html[gm_idx: gm_idx + 300]
        assert "_requireConfigured('sms')" in gm_body, \
            "goMessages must call _requireConfigured('sms') to guard SMS access"

    def test_G10_send_receipt_called_for_offline_payments(self, html):
        assert "sendReceipt(" in html, \
            "sendReceipt() must be called from the popup button onclick handlers"

    def test_G11_send_invoice_called_for_unpaid(self, html):
        assert "sendInvoice(" in html, \
            "sendInvoice() must still be called for unpaid jobs"

    def test_G12_three_states_are_mutually_exclusive(self, html):
        # Verify the IIFE structure with if/else branches exists
        assert "_pm === 'paid'" in html or "_pm === \"paid\"" in html, \
            "Popup must check for 'paid' state (online payment)"
        assert "_offlinePaid" in html, \
            "Popup must check _offlinePaid for cash/check/etc. state"


# ══════════════════════════════════════════════════════════════════════════
# Section H — Allowed-tool list integrity
# ══════════════════════════════════════════════════════════════════════════

class TestAllowedToolLists:
    """H.x — All four new tools appear in both personal and server allowed lists."""

    NEW_TOOLS = [
        "check_email_configured",
        "email_receipt",
        "text_receipt",
    ]
    DANGEROUS_TOOLS = [
        "delete_learning", "reindex_all", "grant_write_access",
        "revoke_write_access", "write_file", "create_file",
    ]

    def _personal_mode_block(self, source: str) -> str:
        """Extract the personal-mode _allowed_tools block."""
        idx = source.rfind("_allowed_tools = {")  # last occurrence = personal mode
        assert idx != -1, "_allowed_tools block not found"
        return source[idx: idx + 1200]

    def _server_mode_block(self, source: str) -> str:
        """Extract the server-mode _srv_pa_allowed block (first occurrence)."""
        idx = source.find("_srv_pa_allowed = {")
        assert idx != -1, "_srv_pa_allowed block not found"
        return source[idx: idx + 1200]

    def test_H1_personal_mode_has_check_email_configured(self, source):
        block = self._personal_mode_block(source)
        assert '"check_email_configured"' in block, \
            "check_email_configured missing from personal-mode _allowed_tools"

    def test_H2_personal_mode_has_email_receipt(self, source):
        block = self._personal_mode_block(source)
        assert '"email_receipt"' in block, \
            "email_receipt missing from personal-mode _allowed_tools"

    def test_H3_personal_mode_has_text_receipt(self, source):
        block = self._personal_mode_block(source)
        assert '"text_receipt"' in block, \
            "text_receipt missing from personal-mode _allowed_tools"

    def test_H4_server_mode_has_check_email_configured(self, source):
        block = self._server_mode_block(source)
        assert '"check_email_configured"' in block, \
            "check_email_configured missing from server-mode _srv_pa_allowed"

    def test_H5_server_mode_has_email_receipt(self, source):
        block = self._server_mode_block(source)
        assert '"email_receipt"' in block, \
            "email_receipt missing from server-mode _srv_pa_allowed"

    def test_H6_server_mode_has_text_receipt(self, source):
        block = self._server_mode_block(source)
        assert '"text_receipt"' in block, \
            "text_receipt missing from server-mode _srv_pa_allowed"

    def test_H7_existing_invoice_tools_still_present(self, source):
        block = self._personal_mode_block(source)
        for tool in ("email_invoice", "text_invoice", "check_sms_configured"):
            assert f'"{tool}"' in block, \
                f"{tool} removed from personal-mode _allowed_tools — must stay"

    def test_H8_dangerous_tools_not_in_personal_list(self, source):
        block = self._personal_mode_block(source)
        for tool in self.DANGEROUS_TOOLS:
            assert f'"{tool}"' not in block, \
                f"Dangerous tool '{tool}' found in _allowed_tools — remove it!"

    def test_H9_dangerous_tools_not_in_server_list(self, source):
        block = self._server_mode_block(source)
        for tool in self.DANGEROUS_TOOLS:
            assert f'"{tool}"' not in block, \
                f"Dangerous tool '{tool}' found in _srv_pa_allowed — remove it!"

    def test_H10_all_new_tools_in_both_lists(self, source):
        personal = self._personal_mode_block(source)
        server   = self._server_mode_block(source)
        for tool in self.NEW_TOOLS:
            assert f'"{tool}"' in personal, \
                f"{tool} missing from personal _allowed_tools"
            assert f'"{tool}"' in server, \
                f"{tool} missing from server _srv_pa_allowed"


# ══════════════════════════════════════════════════════════════════════════
# Section I — Receipt tools use shared _find_invoice_row helper
# ══════════════════════════════════════════════════════════════════════════

class TestReceiptToolsUseSharedHelper:
    """I.x — email_receipt and text_receipt delegate to _find_invoice_row
    for consistent crew-scoping and path resolution."""

    def test_I1_find_invoice_row_helper_exists(self, source):
        assert "def _find_invoice_row(" in source, \
            "_find_invoice_row helper missing — receipt tools have nothing to delegate to"

    def test_I2_find_invoice_row_calls_resolve_spreadsheet_path(self, lines):
        ln = _find_line(lines, "def _find_invoice_row(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 30])
        assert "_resolve_job_spreadsheet_path(" in body, \
            "_find_invoice_row must call _resolve_job_spreadsheet_path for path/scope"

    def test_I3_email_receipt_delegates_to_find_invoice_row(self, lines):
        ln = _find_line(lines, "def email_receipt(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 120])
        assert "_find_invoice_row(" in body

    def test_I4_text_receipt_delegates_to_find_invoice_row(self, lines):
        ln = _find_line(lines, "def text_receipt(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 80])
        assert "_find_invoice_row(" in body

    def test_I5_email_receipt_checks_error_key(self, lines):
        """Crew scope check: if _find_invoice_row returns {"error": ...}, bail out."""
        ln = _find_line(lines, "def email_receipt(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 120])
        assert '"error"' in body or "'error'" in body, \
            "email_receipt must check the 'error' key from _find_invoice_row"

    def test_I6_text_receipt_checks_error_key(self, lines):
        ln = _find_line(lines, "def text_receipt(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 80])
        assert '"error"' in body or "'error'" in body, \
            "text_receipt must check the 'error' key from _find_invoice_row"

    def test_I7_all_four_invoice_tools_use_same_helper(self, source):
        """Regression guard: all four invoice/receipt tools must go through
        _find_invoice_row so crew scoping can't silently diverge between them."""
        for tool in ("email_invoice", "text_invoice", "email_receipt", "text_receipt"):
            fn_idx = source.find(f"def {tool}(")
            assert fn_idx != -1, f"def {tool}( not found"
            body = source[fn_idx: fn_idx + 5000]  # full function body
            helper_idx = body.find("_find_invoice_row(")
            assert helper_idx != -1, \
                f"{tool} does not call _find_invoice_row() — crew scoping may be broken"


# ══════════════════════════════════════════════════════════════════════════
# Section J — Syntax sanity
# ══════════════════════════════════════════════════════════════════════════

class TestSyntaxSanity:
    """J.x — Sanity checks that edits haven't broken syntax."""

    def test_J1_mcp_file_no_syntax_error(self):
        import py_compile, shutil, tempfile
        tmp = Path(tempfile.mkdtemp())
        try:
            dst = tmp / "ai_prowler_mcp.py"
            shutil.copy(MCP_FILE, dst)
            try:
                py_compile.compile(str(dst), doraise=True)
            except py_compile.PyCompileError as exc:
                pytest.fail(f"SyntaxError in ai_prowler_mcp.py:\n{exc}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_J2_pwa_html_has_balanced_script_tags(self, html):
        # Strip HTML comments first — a naive substring count of "<script"
        # false-positives on the word "script" appearing inside a comment
        # (e.g. "...and <script> below, closing at its own tag..."), which
        # isn't a real tag and shouldn't be counted.
        import re
        stripped = re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)
        opens  = stripped.count("<script")
        closes = stripped.count("</script>")
        assert opens == closes, \
            f"Unbalanced <script> tags: {opens} open vs {closes} close"

    def test_J3_send_receipt_function_has_closing_brace(self, html):
        fn_idx = html.find("async function sendReceipt(")
        assert fn_idx != -1
        # The function must have a closing brace within a reasonable range
        body = html[fn_idx: fn_idx + 800]
        assert body.count("{") > 0 and body.count("}") > 0, \
            "sendReceipt function body appears malformed"

    def test_J4_check_email_configured_has_return_statement(self, lines):
        ln = _find_line(lines, "def check_email_configured(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 25])
        assert "return " in body, \
            "check_email_configured must have a return statement"

    def test_J5_email_receipt_has_return_statement(self, lines):
        ln = _find_line(lines, "def email_receipt(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 250])
        assert "return " in body, \
            "email_receipt must have a return statement"

    def test_J6_text_receipt_has_return_statement(self, lines):
        ln = _find_line(lines, "def text_receipt(")
        assert ln is not None
        body = "\n".join(lines[ln: ln + 80])
        assert "return " in body, \
            "text_receipt must have a return statement"
