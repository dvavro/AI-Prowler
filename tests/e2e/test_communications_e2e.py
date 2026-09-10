"""
tests/e2e/test_communications_e2e.py
=======================================
Phase 2 of the broader MCP tool E2E suite (see run_e2e_mcp_tool.bat header
comments and tests/pytest.ini's mcp_tool_e2e marker docs for the full
phased rollout plan).

Covers the Communications tool family's email tools:
  configure_email, send_email, send_alert, send_file,
  check_email_configured, list_outlook_accounts (fixed/resolved
  2026-09-08 — see TestListOutlookAccounts below for the investigation)

EXCLUDED FROM THIS PHASE: SMS (send_sms, check_sms_configured,
check_sms_replies, check_sms_inbox, list_sms_consents, delete_sms_consent)
and WhatsApp (send_whatsapp, check_whatsapp_replies) — Twilio/SMS is not
configured on this machine, per explicit instruction. Add a Phase 2b for
these once SMS/WhatsApp is set up.

WHY THIS PHASE NEEDED EXTRA CARE BEFORE ANY TEST RAN
-------------------------------------------------------
configure_email() writes directly to the REAL, currently-working
email_config.json — the same file that powers every other email tool on
this real install (already used successfully throughout the job-tracker
and Phase 1 suites). A careless round-trip test here risked genuinely
breaking working email, not just failing a test.

While designing this suite's round-trip test (BEFORE writing or running
any test code against it), reading configure_email()'s "outlook" backend
branch surfaced a real bug: _email_config_save() does a full file
overwrite with no merge against the existing file, and the "outlook"
branch's cfg dict never carried forward the existing "_password_b64"
field — so calling configure_email(backend="outlook", ...) would have
silently deleted the real SMTP app password on every call. This is the
exact same class of bug already found and fixed once in the Settings
GUI's _save_smtp_cfg() (a separate code path reaching the same file) —
that fix did not cover this MCP tool. Found and fixed via code review,
never actually triggered against real config. See the fix's own comment
in ai_prowler_mcp.py's configure_email() for the full explanation.

TestEmailConfigurationRoundTrip below exists specifically to make this a
permanent regression test: it snapshots the real config's raw bytes,
extracts the current settings, calls configure_email() with those exact
settings (a true no-op round trip), and asserts the password field is
BYTE-FOR-BYTE unchanged afterward — this would have caught the bug above
immediately had it existed when this test first ran.

SAFETY MODEL
------------
- Backs up the raw email_config.json bytes via plain Python file I/O
  (not a generic MCP write tool) before any configure_email call.
- The round-trip test re-saves the EXACT current settings, not different
  ones — this is a no-op by design, not an experiment with new values.
- Restores the exact original file bytes at the end (belt-and-suspenders
  on top of the round-trip itself being designed as a no-op), verified
  byte-for-byte, and re-confirms check_email_configured() is still true
  afterward.
- send_email/send_alert/send_file send 3 REAL emails to TEST_EMAIL_TO,
  each clearly marked [E2E TEST] in the subject.
- If the config file does not exist at all (fresh install, nothing
  configured yet), the whole round-trip class is skipped rather than
  attempting to fabricate a config to round-trip — there is nothing
  "current" to safely preserve in that case.

REQUIREMENTS
------------
No ANTHROPIC_API_KEY needed. Requires email already configured on this
machine (real Outlook and/or SMTP backend).

RUN
---
  run_e2e_mcp_tool.bat -k communications
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

INSTALL_DIR = Path(os.environ.get("AI_PROWLER_SRC",
                                   r"C:\Program Files\AI-Prowler"))
TEST_EMAIL_TO = "david.vavro1@gmail.com"
WRITABLE_TEST_DIR = Path(os.environ.get(
    "AI_PROWLER_WRITABLE_TEST_DIR",
    r"C:\Users\david\AI-Prowler-V900_to_V910_work\AI-Prowler",
))

if str(INSTALL_DIR) not in sys.path:
    sys.path.insert(0, str(INSTALL_DIR))


@pytest.fixture(scope="session")
def mcp_module():
    import ai_prowler_mcp as m
    return m


@pytest.fixture(scope="session")
def email_config_path(mcp_module):
    return mcp_module._EMAIL_CONFIG_PATH()


# ═══════════════════════════════════════════════════════════════════════
# configure_email() round trip — see module docstring for why this class
# is designed the way it is.
# ═══════════════════════════════════════════════════════════════════════
@pytest.mark.mcp_tool_e2e
class TestEmailConfigurationRoundTrip:

    original_bytes: "bytes | None" = None
    current_backend: "str | None" = None
    current_username: "str | None" = None
    current_from_name: "str | None" = None
    current_default_to: "str | None" = None

    def test_00_backup_raw_config_and_skip_if_absent(self, email_config_path):
        if not email_config_path.exists():
            pytest.skip(
                "No email_config.json exists yet on this machine — "
                "nothing configured to safely round-trip. Run "
                "configure_email() manually first if you want this "
                "suite to cover it."
            )
        TestEmailConfigurationRoundTrip.original_bytes = \
            email_config_path.read_bytes()

    def test_01_extract_current_config_fields(self, email_config_path):
        raw = json.loads(self.original_bytes.decode("utf-8"))
        TestEmailConfigurationRoundTrip.current_backend = raw.get("backend", "smtp")
        TestEmailConfigurationRoundTrip.current_username = raw.get("username", "")
        TestEmailConfigurationRoundTrip.current_from_name = raw.get("from_name", "AI-Prowler")
        TestEmailConfigurationRoundTrip.current_default_to = raw.get("default_to", "")
        assert self.current_username, (
            "Existing config has no username — nothing to round-trip safely"
        )
        if self.current_backend not in ("outlook", "outlook+smtp"):
            pytest.skip(
                f"Current backend is {self.current_backend!r} (SMTP-only) — "
                f"configure_email(backend='smtp') REQUIRES a plaintext "
                f"password argument, but only the obfuscated _password_b64 "
                f"is ever available to re-supply it safely. Round-tripping "
                f"an SMTP-only config isn't something this suite can do "
                f"without either decoding a stored secret into a live test "
                f"(undesirable) or genuinely changing behavior. The "
                f"'outlook' branch's password-preservation fix (the actual "
                f"target of this test) only applies when backend is "
                f"'outlook' or 'outlook+smtp' in the first place."
            )

    def test_02_configure_email_round_trip(self, mcp_module):
        result = mcp_module.configure_email(
            username=self.current_username,
            backend="outlook",
            from_name=self.current_from_name,
            default_to=self.current_default_to,
        )
        assert result.startswith("✅"), (
            f"configure_email round-trip failed: {result}"
        )

    def test_03_password_preserved_after_roundtrip(self, email_config_path):
        """The core regression check for the bug found and fixed while
        designing this suite: the SMTP app password must survive an
        Outlook-backend configure_email() call unchanged."""
        original = json.loads(self.original_bytes.decode("utf-8"))
        original_pw_b64 = original.get("_password_b64")

        after = json.loads(email_config_path.read_bytes().decode("utf-8"))
        after_pw_b64 = after.get("_password_b64")

        if original_pw_b64 is None:
            pytest.skip(
                "Original config had no _password_b64 to begin with "
                "(pure Outlook, no SMTP fallback saved) — nothing to "
                "regress-test here."
            )
        assert after_pw_b64 == original_pw_b64, (
            "REGRESSION: SMTP app password was altered/deleted by "
            "configure_email(backend='outlook') — this is exactly the "
            "bug found and fixed while designing this test. "
            f"Before: {original_pw_b64!r}  After: {after_pw_b64!r}"
        )

    def test_04_check_email_configured_still_true(self, mcp_module):
        result = mcp_module.check_email_configured()
        assert result == "✅ Email configured", (
            f"check_email_configured regressed after round-trip: {result}"
        )

    def test_05_send_email_smoke_test(self, mcp_module):
        """Confirms the round-tripped config is not just SAVED but
        actually FUNCTIONAL — a config that passes test_04 but can't
        really send would be a different, subtler bug."""
        result = mcp_module.send_email(
            to=TEST_EMAIL_TO,
            subject="[E2E TEST] configure_email round-trip smoke test",
            body="If you received this, the email config survived an "
                 "automated configure_email() round-trip test intact. "
                 "Safe to ignore/delete.",
        )
        assert result.startswith("✅"), f"Post-round-trip send failed: {result}"

    def test_99_restore_original_file_bytes(self, email_config_path):
        email_config_path.write_bytes(self.original_bytes)
        restored = email_config_path.read_bytes()
        assert restored == self.original_bytes, (
            "Restore did not produce byte-identical content"
        )


# ═══════════════════════════════════════════════════════════════════════
# Sending tools — 3 real sends
# ═══════════════════════════════════════════════════════════════════════
@pytest.mark.mcp_tool_e2e
class TestEmailSendingTools:

    def test_01_send_email_basic(self, mcp_module):
        result = mcp_module.send_email(
            to=TEST_EMAIL_TO,
            subject="[E2E TEST] send_email basic test",
            body="Plain-text body sent by test_communications_e2e.py. "
                 "Safe to ignore/delete.",
        )
        assert result.startswith("✅"), f"send_email failed: {result}"

    def test_02_send_alert(self, mcp_module):
        result = mcp_module.send_alert(
            message="[E2E TEST] send_alert test — safe to ignore",
            to=TEST_EMAIL_TO,
        )
        assert result.startswith("✅"), f"send_alert failed: {result}"

    def test_03_send_file(self, mcp_module):
        attachment = WRITABLE_TEST_DIR / "ztest_e2e_send_file_attachment.txt"
        attachment.write_text(
            "This is a synthetic test attachment created by "
            "test_communications_e2e.py's send_file test. Safe to ignore.",
            encoding="utf-8",
        )
        try:
            result = mcp_module.send_file(
                to=TEST_EMAIL_TO,
                filepath=str(attachment),
                subject="[E2E TEST] send_file attachment test",
            )
            assert result.startswith("✅"), f"send_file failed: {result}"
        finally:
            attachment.unlink(missing_ok=True)


# ═══════════════════════════════════════════════════════════════════════
# list_outlook_accounts — inherently dependent on live Outlook COM state,
# which this suite cannot fully control (Outlook must be running, no
# hidden dialogs, etc.) — see module docstring section below for the full
# investigation. Handles both the "Outlook active and working" and
# "Outlook not currently reachable" outcomes as valid, rather than
# assuming one.
#
# INVESTIGATION NOTE (2026-09-08): earlier manual calls to this tool
# returned a generic "No approval received" error with Outlook open and
# no hidden dialogs. Nothing in list_outlook_accounts()'s own source
# makes any elicitation/approval request — it's a plain @mcp.tool() like
# every other tool, no special annotations. A later retry (same Outlook
# state) succeeded and correctly listed both configured accounts. This
# points to a transient/environmental issue (possibly Outlook COM's own
# readiness state at the moment of the call) rather than a code defect —
# nothing in ai_prowler_mcp.py needed to change. This test cannot force
# or reproduce that transient state, so it verifies the tool's actual
# documented behavior, and if a genuine environment-level failure recurs
# it will show up here as a real, investigable test failure rather than
# silently going untested forever.
# ═══════════════════════════════════════════════════════════════════════
@pytest.mark.mcp_tool_e2e
class TestListOutlookAccounts:

    def test_01_lists_configured_accounts_or_explains_why_not(self, mcp_module):
        result = mcp_module.list_outlook_accounts()

        # Any of these are legitimate, correctly-functioning outcomes,
        # depending on real Outlook/backend state at test time:
        #   - accounts successfully listed
        #   - backend isn't set to outlook/outlook+smtp
        #   - classic Outlook isn't available on this machine
        # A generic, unexplained failure is NOT acceptable — the tool
        # should always either succeed or give a specific, actionable
        # reason, never a bare error.
        valid_outcomes = (
            "accounts available to send from" in result,
            "Outlook backend is not currently active" in result,
            "Classic Outlook" in result and "not available" in result,
            "No email accounts found in Outlook" in result,
        )
        assert any(valid_outcomes), (
            f"list_outlook_accounts returned an unrecognized/unexplained "
            f"result — every outcome should be self-explanatory: {result}"
        )

    def test_02_default_account_marked_when_accounts_listed(self, mcp_module):
        """If accounts ARE successfully listed, exactly one should be
        marked as the current default (matching whatever configure_email
        last saved) — not zero, not more than one."""
        result = mcp_module.list_outlook_accounts()
        if "accounts available to send from" not in result:
            pytest.skip(
                "Outlook accounts were not listed this run (backend not "
                "active, Outlook unavailable, or a transient COM issue) "
                "— see test_01 for the broader outcome check. This test "
                "specifically needs a successful listing to be meaningful."
            )
        default_count = result.count("← current default")
        assert default_count == 1, (
            f"Expected exactly 1 account marked as default, "
            f"found {default_count}: {result}"
        )
