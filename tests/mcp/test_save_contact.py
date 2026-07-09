"""
tests/mcp/test_save_contact.py
=================================
Tests for save_contact() / _contact_save() / _contacts_cache_load() /
_contacts_cache_save() — previously ZERO test coverage existed for this
tool anywhere in the suite.

Background
----------
save_contact() saves personal name -> phone/email lookups so send_sms /
send_email can resolve "text David" instead of a raw number. It is
explicitly NOT for customers (those live in the Customers spreadsheet
sheet and take priority automatically).

Storage: ~/.ai-prowler/contacts_cache.json in personal mode (single
shared file); ~/.ai-prowler/contacts_cache_<username>.json per user in
server mode, where <username> comes from user['username'] or user['id']
or user['name'] (first one set), sanitised to [a-z0-9_-] only.

These tests use the AIPROWLER_TEST_STATE_DIR env var (the same sandbox
mechanism _state_dir() already supports) to redirect all file I/O into a
pytest tmp_path, so real files are read/written and verified — not just
mocked calls.
"""

import os
import sys
import json
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
    """Redirect _state_dir() to an isolated tmp_path for this test only."""
    monkeypatch.setenv("AIPROWLER_TEST_STATE_DIR", str(tmp_path))
    return tmp_path


def _make_ctx(user):
    if user is None:
        return None
    ctx = MagicMock()
    ctx.request_context.request.state.user = user
    return ctx


def _user(uid, name, role="field_crew"):
    return {"id": uid, "name": name, "role": role, "status": "active"}


class TestPersonalModeBasics:

    def test_save_creates_contacts_cache_json(self, mcp_mod, sandboxed_state):
        result = mcp_mod.save_contact(name="David", phone="386-555-0101", ctx=None)
        assert "✅" in result
        assert "David" in result

        p = sandboxed_state / "contacts_cache.json"
        assert p.exists()
        data = json.loads(p.read_text())
        assert data["contacts"]["david"]["phone"] == "3865550101"

    def test_save_email_only(self, mcp_mod, sandboxed_state):
        mcp_mod.save_contact(name="Vicki", email="vicki@example.com", ctx=None)
        p = sandboxed_state / "contacts_cache.json"
        data = json.loads(p.read_text())
        assert data["contacts"]["vicki"]["email"] == "vicki@example.com"

    def test_save_both_phone_and_email(self, mcp_mod, sandboxed_state):
        mcp_mod.save_contact(name="Jamie", phone="3865551234", email="jamie@x.com", ctx=None)
        p = sandboxed_state / "contacts_cache.json"
        data = json.loads(p.read_text())
        assert data["contacts"]["jamie"]["phone"] == "3865551234"
        assert data["contacts"]["jamie"]["email"] == "jamie@x.com"

    def test_name_lookup_is_case_insensitive(self, mcp_mod, sandboxed_state):
        mcp_mod.save_contact(name="DAVID", phone="3865550101", ctx=None)
        p = sandboxed_state / "contacts_cache.json"
        data = json.loads(p.read_text())
        assert "david" in data["contacts"]


class TestValidation:

    def test_empty_name_rejected(self, mcp_mod, sandboxed_state):
        result = mcp_mod.save_contact(name="", phone="3865550101", ctx=None)
        assert "❌" in result

    def test_whitespace_only_name_rejected(self, mcp_mod, sandboxed_state):
        result = mcp_mod.save_contact(name="   ", phone="3865550101", ctx=None)
        assert "❌" in result

    def test_no_phone_and_no_email_rejected(self, mcp_mod, sandboxed_state):
        result = mcp_mod.save_contact(name="David", ctx=None)
        assert "❌" in result


class TestPhoneNormalization:

    def test_dashes_and_parens_stripped(self, mcp_mod, sandboxed_state):
        mcp_mod.save_contact(name="Rick", phone="(386) 555-0199", ctx=None)
        p = sandboxed_state / "contacts_cache.json"
        data = json.loads(p.read_text())
        assert data["contacts"]["rick"]["phone"] == "3865550199"

    def test_leading_us_country_code_stripped(self, mcp_mod, sandboxed_state):
        mcp_mod.save_contact(name="Sam", phone="1-386-555-0199", ctx=None)
        p = sandboxed_state / "contacts_cache.json"
        data = json.loads(p.read_text())
        # 11 digits starting with '1' -> country code dropped -> 10 digits
        assert data["contacts"]["sam"]["phone"] == "3865550199"

    def test_ten_digit_number_unaffected(self, mcp_mod, sandboxed_state):
        mcp_mod.save_contact(name="Karen", phone="3865550199", ctx=None)
        p = sandboxed_state / "contacts_cache.json"
        data = json.loads(p.read_text())
        assert data["contacts"]["karen"]["phone"] == "3865550199"


class TestMergeBehavior:

    def test_saving_same_name_twice_merges_not_overwrites(self, mcp_mod, sandboxed_state):
        """Adding an email later must not wipe the phone saved earlier."""
        mcp_mod.save_contact(name="Rebecca", phone="3865550188", ctx=None)
        mcp_mod.save_contact(name="Rebecca", email="rebecca@x.com", ctx=None)

        p = sandboxed_state / "contacts_cache.json"
        data = json.loads(p.read_text())
        assert data["contacts"]["rebecca"]["phone"] == "3865550188"
        assert data["contacts"]["rebecca"]["email"] == "rebecca@x.com"

    def test_updating_phone_replaces_old_phone(self, mcp_mod, sandboxed_state):
        mcp_mod.save_contact(name="Christina", phone="3865550100", ctx=None)
        mcp_mod.save_contact(name="Christina", phone="3865559999", ctx=None)

        p = sandboxed_state / "contacts_cache.json"
        data = json.loads(p.read_text())
        assert data["contacts"]["christina"]["phone"] == "3865559999"


class TestServerModeIsolation:

    def test_two_users_get_separate_files(self, mcp_mod, sandboxed_state):
        jake = _user("jake-r", "Jake R")
        vicki = _user("vicki-vavro", "Vicki Vavro", role="manager")

        mcp_mod.save_contact(name="Crabby's", phone="3865550001", ctx=_make_ctx(jake))
        mcp_mod.save_contact(name="Crabby's", phone="3865559999", ctx=_make_ctx(vicki))

        jake_file = sandboxed_state / "contacts_cache_jake-r.json"
        vicki_file = sandboxed_state / "contacts_cache_vicki-vavro.json"
        assert jake_file.exists()
        assert vicki_file.exists()

        jake_data = json.loads(jake_file.read_text())
        vicki_data = json.loads(vicki_file.read_text())
        assert jake_data["contacts"]["crabby's"]["phone"] == "3865550001"
        assert vicki_data["contacts"]["crabby's"]["phone"] == "3865559999"

    def test_no_shared_contacts_cache_json_written_in_server_mode(self, mcp_mod, sandboxed_state):
        """Server-mode saves must never touch the personal-mode shared file."""
        jake = _user("jake-r", "Jake R")
        mcp_mod.save_contact(name="Test", phone="3865550001", ctx=_make_ctx(jake))
        shared_file = sandboxed_state / "contacts_cache.json"
        assert not shared_file.exists()

    def test_confirmation_message_shows_correct_filename(self, mcp_mod, sandboxed_state):
        jake = _user("jake-r", "Jake R")
        result = mcp_mod.save_contact(name="Test", phone="3865550001", ctx=_make_ctx(jake))
        assert "contacts_cache_jake-r.json" in result

    def test_username_sanitisation_for_unusual_ids(self, mcp_mod, sandboxed_state):
        """A user id with characters outside [a-z0-9_-] must be sanitised to
        a safe filename rather than producing a broken/unsafe path."""
        weird = _user("Jake.R+Test@Co", "Jake R")
        mcp_mod.save_contact(name="Test", phone="3865550001", ctx=_make_ctx(weird))
        matches = list(sandboxed_state.glob("contacts_cache_*.json"))
        assert len(matches) == 1
        assert all(c.isalnum() or c in "_-" for c in matches[0].stem.replace("contacts_cache_", ""))

    def test_personal_mode_still_uses_shared_file_when_ctx_none(self, mcp_mod, sandboxed_state):
        """Sanity check: personal mode (ctx=None) is unaffected by any of
        the server-mode isolation logic."""
        mcp_mod.save_contact(name="David", phone="3865550101", ctx=None)
        shared_file = sandboxed_state / "contacts_cache.json"
        assert shared_file.exists()
        data = json.loads(shared_file.read_text())
        assert data["contacts"]["david"]["phone"] == "3865550101"
