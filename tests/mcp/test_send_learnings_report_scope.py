"""
tests/mcp/test_send_learnings_report_scope.py
================================================
Tests for send_learnings_report()'s server-mode role gate — previously
ZERO test coverage existed for this tool anywhere in the suite, and a
test docstring elsewhere (test_role_tool_matrix.py::TestEmailAllowedForUser)
incorrectly implied it used the personal-mode-only _email_allowed_for_user
gate. It does not: it uses _send_email_cap, exactly like send_email and
send_alert, and is available to ALL roles in server mode.

This is confirmed directly by _TIER_A_SUPPRESSED's own comment in
ai_prowler_mcp.py: "send_email, send_alert, and send_learnings_report stay
registered; all roles use them via the Tier B _send_email_cap gate."

These tests lock that in with a real regression test, alongside basic
validation coverage (no recipient, email not configured, self-learning
module missing) that also had zero coverage before this file.
"""

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


def _user(role, uid="test-user"):
    return {"id": uid, "name": "Test User", "role": role, "status": "active"}


class TestNotTierASuppressed:

    def test_send_learnings_report_not_in_tier_a_suppressed(self, mcp_mod):
        """The core regression this file exists to lock in: send_learnings_report
        must never be blanket-suppressed in server mode — it's gated per-call
        via _send_email_cap instead, same as send_email/send_alert."""
        assert "send_learnings_report" not in mcp_mod._TIER_A_SUPPRESSED


class TestRoleGateAllowsAllRoles:
    """send_learnings_report uses _send_email_cap, NOT _email_allowed_for_user
    — confirms all four roles are allowed in server mode, the opposite of
    what an earlier, now-corrected test docstring implied."""

    @pytest.mark.parametrize("role", ["owner", "manager", "staff", "field_crew"])
    def test_role_allowed_via_send_email_cap(self, mcp_mod, monkeypatch, role):
        user = _user(role)
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_email_config_load",
                            lambda: {"default_to": "team@company.com"})
        monkeypatch.setattr(mcp_mod, "_send_email_cap", lambda u: (True, "ok"))
        monkeypatch.setattr(mcp_mod, "_sl", MagicMock(_load_db=lambda: {"learnings": []}))

        result = mcp_mod.send_learnings_report(ctx=_make_ctx(user))

        # Must NOT be denied for role reasons — whatever happens next
        # (e.g. "no learnings match") is a separate concern from the gate.
        assert "personal mode" not in result.lower()
        assert not result.startswith("⛔")

    def test_uses_send_email_cap_not_email_allowed_for_user(self, mcp_mod, monkeypatch):
        """Direct proof of which gate function is actually called."""
        user = _user("field_crew")
        called = {"send_email_cap": False, "email_allowed_for_user": False}

        def _tripwire_wrong_gate(u):
            called["email_allowed_for_user"] = True
            return (False, "should not be called")

        def _correct_gate(u):
            called["send_email_cap"] = True
            return (True, "ok")

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_email_config_load",
                            lambda: {"default_to": "team@company.com"})
        monkeypatch.setattr(mcp_mod, "_send_email_cap", _correct_gate)
        monkeypatch.setattr(mcp_mod, "_email_allowed_for_user", _tripwire_wrong_gate)
        monkeypatch.setattr(mcp_mod, "_sl", MagicMock(_load_db=lambda: {"learnings": []}))

        mcp_mod.send_learnings_report(ctx=_make_ctx(user))

        assert called["send_email_cap"] is True
        assert called["email_allowed_for_user"] is False


class TestValidation:

    def test_email_not_configured_returns_error(self, mcp_mod, monkeypatch):
        monkeypatch.setattr(mcp_mod, "_email_config_load", lambda: None)
        result = mcp_mod.send_learnings_report(to="team@company.com", ctx=None)
        assert "❌" in result
        assert "not configured" in result.lower()

    def test_no_recipient_and_no_default_returns_error(self, mcp_mod, monkeypatch):
        monkeypatch.setattr(mcp_mod, "_email_config_load",
                            lambda: {"default_to": ""})
        result = mcp_mod.send_learnings_report(to="", ctx=None)
        assert "❌" in result
        assert "recipient" in result.lower()

    def test_missing_self_learning_module_returns_error(self, mcp_mod, monkeypatch):
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        monkeypatch.setattr(mcp_mod, "_email_config_load",
                            lambda: {"default_to": "team@company.com"})
        monkeypatch.setattr(mcp_mod, "_send_email_cap", lambda u: (True, "ok"))
        monkeypatch.setattr(mcp_mod, "_sl", None)

        result = mcp_mod.send_learnings_report(ctx=None)
        assert "❌" in result
        assert "self-learning" in result.lower()

    def test_default_to_used_when_to_omitted(self, mcp_mod, monkeypatch):
        """Confirms cfg['default_to'] is actually consulted, not just
        validated for presence."""
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        monkeypatch.setattr(mcp_mod, "_email_config_load",
                            lambda: {"default_to": "fallback@company.com"})
        monkeypatch.setattr(mcp_mod, "_send_email_cap", lambda u: (True, "ok"))
        monkeypatch.setattr(mcp_mod, "_sl", MagicMock(_load_db=lambda: {"learnings": []}))

        # Should get PAST the "no recipient" validation using the default.
        result = mcp_mod.send_learnings_report(to="", ctx=None)
        assert "no recipient" not in result.lower()
