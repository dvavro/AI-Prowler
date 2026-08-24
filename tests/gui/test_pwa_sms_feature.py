"""
tests/gui/test_pwa_sms_feature.py
====================================
Structural tests for the Jobs PWA's SMS feature: a "Messages" tab (send +
check replies) plus a job-modal "Text Customer" shortcut, in both server
mode and personal mode.

Backend: send_sms and the mode-appropriate reply-checking tool
(check_sms_replies for server mode — already correctly per-user scoped;
check_sms_inbox for personal mode — server mode's scoping is meaningless
with a single user) were added to BOTH /pwa-api allowed-tools sets.

Frontend: a 5th bottom-nav tab, a compose form calling send_sms, a "Check"
button calling the mode-appropriate reply tool, and a job-modal shortcut
that pre-fills the customer's name.
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


class TestServerModeAllowedTools:
    def test_send_sms_allowed_in_server_mode(self, mcp_source):
        idx = mcp_source.index("_srv_pa_allowed = {")
        nearby = mcp_source[idx:idx + 1200]
        assert '"send_sms"' in nearby

    def test_check_sms_replies_allowed_in_server_mode_not_check_sms_inbox(self, mcp_source):
        """The whole point of using check_sms_replies here — server mode
        must use the per-user-scoped tool, never the unscoped inbox tool
        (which is deliberately unavailable in server mode entirely)."""
        idx = mcp_source.index("_srv_pa_allowed = {")
        nearby = mcp_source[idx:idx + 1200]
        assert '"check_sms_replies"' in nearby
        assert '"check_sms_inbox"' not in nearby


class TestPersonalModeAllowedTools:
    def test_send_sms_allowed_in_personal_mode(self, mcp_source):
        idx = mcp_source.index("_allowed_tools = {")
        nearby = mcp_source[idx:idx + 1200]
        assert '"send_sms"' in nearby

    def test_check_sms_inbox_allowed_in_personal_mode_not_check_sms_replies(self, mcp_source):
        """Inverse of the server-mode test — personal mode has no
        per-employee scoping concept, so it should use the simpler
        unscoped inbox tool, not the server-mode-oriented one."""
        idx = mcp_source.index("_allowed_tools = {")
        nearby = mcp_source[idx:idx + 1200]
        assert '"check_sms_inbox"' in nearby
        assert '"check_sms_replies"' not in nearby


class TestMessagesTabExists:
    def test_nav_button_present(self, pwa_source):
        assert "showScreen('messages',this)" in pwa_source
        idx = pwa_source.index("showScreen('messages',this)")
        nearby = pwa_source[idx:idx + 300]
        assert "Messages" in nearby

    def test_messages_screen_present(self, pwa_source):
        assert 'id="screen-messages"' in pwa_source

    def test_no_duplicate_profile_screen(self, pwa_source):
        """Regression guard for a real mistake made while inserting the
        new screen — a duplicate <div id="screen-profile"> opening tag
        was accidentally introduced and had to be removed."""
        assert pwa_source.count('id="screen-profile"') == 1

    def test_compose_fields_present(self, pwa_source):
        assert 'id="smsTo"' in pwa_source
        assert 'id="smsMessage"' in pwa_source

    def test_send_button_calls_send_sms_function(self, pwa_source):
        assert 'onclick="sendSMS()"' in pwa_source

    def test_check_button_calls_check_sms_replies_function(self, pwa_source):
        assert 'onclick="checkSMSReplies()"' in pwa_source


class TestSendSmsFunction:
    def test_send_sms_calls_mcp_call_with_send_sms_tool(self, pwa_source):
        idx = pwa_source.index("async function sendSMS()")
        nearby = pwa_source[idx:idx + 900]
        assert "mcpCall('send_sms'" in nearby

    def test_send_sms_requires_both_fields(self, pwa_source):
        idx = pwa_source.index("async function sendSMS()")
        nearby = pwa_source[idx:idx + 400]
        assert "!to || !message" in nearby

    def test_send_sms_clears_message_on_success_not_recipient(self, pwa_source):
        """Clearing the recipient too would be annoying if sending two
        messages to the same person in a row."""
        idx = pwa_source.index("async function sendSMS()")
        nearby = pwa_source[idx:idx + 900]
        assert "smsMessage').value = ''" in nearby
        assert "smsTo').value = ''" not in nearby


class TestCheckSmsRepliesFunction:
    def test_picks_tool_based_on_server_mode(self, pwa_source):
        idx = pwa_source.index("async function checkSMSReplies()")
        nearby = pwa_source[idx:idx + 600]
        assert "state.serverMode" in nearby
        assert "'check_sms_replies'" in nearby
        assert "'check_sms_inbox'" in nearby

    def test_output_is_html_escaped(self, pwa_source):
        """Reply content is real customer text and must not be inserted
        as raw HTML — a customer could otherwise inject markup via their
        own SMS reply."""
        idx = pwa_source.index("async function checkSMSReplies()")
        nearby = pwa_source[idx:idx + 900]
        assert "escapeHtml(result)" in nearby


class TestJobModalTextCustomerShortcut:
    def test_button_present_in_job_modal(self, pwa_source):
        idx = pwa_source.index("quickClock")  # unique to the job-detail modal template
        nearby = pwa_source[idx:idx + 900]
        assert "goMessages('${j.customer}')" in nearby
        assert "Text Customer" in nearby

    def test_go_messages_prefills_customer_name(self, pwa_source):
        idx = pwa_source.index("function goMessages(")
        nearby = pwa_source[idx:idx + 400]
        assert "smsTo').value = customerName" in nearby

    def test_go_messages_switches_to_correct_nav_index(self, pwa_source):
        """Nav order is Jobs(0), Clock(1), Photos(2), Messages(3),
        Profile(4) — goPhotos() already correctly uses index 2 for Photos
        elsewhere; this confirms Messages' index wasn't miscounted."""
        idx = pwa_source.index("function goMessages(")
        nearby = pwa_source[idx:idx + 300]
        assert "nav-btn')[3]" in nearby
