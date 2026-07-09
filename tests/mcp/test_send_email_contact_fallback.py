"""
tests/mcp/test_send_email_contact_fallback.py
================================================
Tests for send_email()'s third recipient-resolution tier: the caller's own
saved personal contacts (_contact_lookup), used when a name doesn't match
the Customers sheet or a registered user in users.json.

Background
----------
send_email() resolves a non-email 'to' argument in this order:
  1. Customers sheet (by name/company/CustomerID)
  2. users.json (registered server users, by name)
  3. The caller's own personal contacts_cache_<user_id>.json (by name) —
     this tier had ZERO test coverage before this file.

Since save_contact() isolates each server-mode user's contacts into a
separate file, this fallback must resolve against the CALLING user's own
contacts only — never a coworker's, even if both saved a contact under
the same name with different details.

Uses the real AIPROWLER_TEST_STATE_DIR sandbox (same mechanism
test_save_contact.py uses) plus a mocked _send_smtp so no real network
calls happen, while still exercising the real save_contact() /
_contact_lookup() code path end-to-end.
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


@pytest.fixture
def sandboxed_state(monkeypatch, tmp_path):
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))
    return tmp_path


def _make_ctx(user):
    if user is None:
        return None
    ctx = MagicMock()
    ctx.request_context.request.state.user = user
    return ctx


def _user(uid, name, role="field_crew"):
    return {"id": uid, "name": name, "role": role, "status": "active", "email": ""}


def _wire_common_mocks(mcp_mod, monkeypatch, captured):
    """Common send_email() dependencies, mocked so only the contact-lookup
    fallback tier is actually exercised for real."""
    monkeypatch.setattr(mcp_mod, "_email_config_load",
                        lambda: {"smtp_host": "smtp.test.com", "smtp_port": 587,
                                "username": "u@test.com", "password": "pw",
                                "from_addr": "u@test.com", "default_to": ""})
    monkeypatch.setattr(mcp_mod, "_lookup_customer_email", lambda name: None)
    monkeypatch.setattr(mcp_mod, "_load_users", lambda: {"users": {}})
    monkeypatch.setattr(mcp_mod, "_send_email_cap", lambda user: (True, "ok"))

    def _fake_send_smtp(to, subject, body, **kwargs):
        captured["to"] = to
        captured["subject"] = subject
        return (True, "sent")
    monkeypatch.setattr(mcp_mod, "_send_smtp", _fake_send_smtp)


class TestContactFallbackResolves:

    def test_personal_mode_resolves_via_saved_contact(self, mcp_mod, sandboxed_state, monkeypatch):
        mcp_mod.save_contact(name="Karen", email="karen@example.com", ctx=None)
        captured = {}
        _wire_common_mocks(mcp_mod, monkeypatch, captured)

        result = mcp_mod.send_email(to="Karen", subject="Hi", body="test body", ctx=None)

        assert "❌" not in result
        assert captured.get("to") == "karen@example.com"

    def test_server_mode_resolves_via_own_saved_contact(self, mcp_mod, sandboxed_state, monkeypatch):
        jake = _user("jake-r", "Jake R")
        mcp_mod.save_contact(name="Karen", email="karen-per-jake@example.com", ctx=_make_ctx(jake))

        captured = {}
        _wire_common_mocks(mcp_mod, monkeypatch, captured)

        result = mcp_mod.send_email(to="Karen", subject="Hi", body="test", ctx=_make_ctx(jake))

        assert "❌" not in result
        assert captured.get("to") == "karen-per-jake@example.com"

    def test_unresolvable_name_returns_clear_error(self, mcp_mod, sandboxed_state, monkeypatch):
        captured = {}
        _wire_common_mocks(mcp_mod, monkeypatch, captured)

        result = mcp_mod.send_email(to="TotallyUnknownPerson", subject="Hi", body="test", ctx=None)

        assert "❌" in result
        assert "to" not in captured  # _send_smtp must never have been called


class TestContactFallbackIsolation:
    """The actual leak this closes: one server-mode user's saved contact
    must never resolve for a DIFFERENT user's send_email() call, even when
    both have a contact saved under the exact same name."""

    def test_jakes_karen_is_not_vickis_karen(self, mcp_mod, sandboxed_state, monkeypatch):
        jake = _user("jake-r", "Jake R", role="field_crew")
        vicki = _user("vicki-vavro", "Vicki Vavro", role="manager")

        mcp_mod.save_contact(name="Karen", email="jakes-karen@example.com", ctx=_make_ctx(jake))
        mcp_mod.save_contact(name="Karen", email="vickis-karen@example.com", ctx=_make_ctx(vicki))

        captured = {}
        _wire_common_mocks(mcp_mod, monkeypatch, captured)

        jake_result = mcp_mod.send_email(to="Karen", subject="Hi", body="x", ctx=_make_ctx(jake))
        assert captured.get("to") == "jakes-karen@example.com"

        captured.clear()
        vicki_result = mcp_mod.send_email(to="Karen", subject="Hi", body="x", ctx=_make_ctx(vicki))
        assert captured.get("to") == "vickis-karen@example.com"

    def test_user_with_no_saved_contact_gets_no_resolution_even_if_coworker_has_one(
            self, mcp_mod, sandboxed_state, monkeypatch):
        """Jake saves 'Karen'; a brand-new user (no contacts file at all)
        asking for 'Karen' must NOT accidentally see Jake's contact."""
        jake = _user("jake-r", "Jake R")
        new_hire = _user("new-hire", "New Hire")

        mcp_mod.save_contact(name="Karen", email="jakes-karen@example.com", ctx=_make_ctx(jake))

        captured = {}
        _wire_common_mocks(mcp_mod, monkeypatch, captured)

        result = mcp_mod.send_email(to="Karen", subject="Hi", body="x", ctx=_make_ctx(new_hire))

        assert "❌" in result
        assert "to" not in captured
