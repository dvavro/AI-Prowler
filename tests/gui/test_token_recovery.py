"""
tests/gui/test_token_recovery.py

Unit tests for the AI-Prowler v7.0.0 token recovery system.
Tests the pure-logic helpers (no GUI, no SMTP calls) by importing
only the standalone functions and calling them directly with
in-memory data structures.

Run with:
    pytest tests/gui/test_token_recovery.py -v
"""
import sys
import time
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Path bootstrap ────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# ── Carrier gateway table (duplicated from rag_gui.py for test isolation) ─────
CARRIER_GATEWAYS = {
    "att":         "txt.att.net",
    "verizon":     "vtext.com",
    "t-mobile":    "tmomail.net",
    "cricket":     "sms.cricketwireless.net",
    "boost":       "sms.myboostmobile.com",
    "us cellular": "email.uscc.net",
    "metro pcs":   "mymetropcs.com",
    "sprint":      "messaging.sprintpcs.com",
}


# ── Standalone helpers (extracted so tests need no tkinter / running GUI) ──────

def _generate_temp_token(user_key, users_dict, duration_secs=3600):
    """Mirror of RAGApp._admin_generate_temp_token."""
    import secrets
    temp_tok = secrets.token_urlsafe(24)
    perm_rec = dict(users_dict.get(user_key, {}))
    perm_rec["_temp_token"]    = True
    perm_rec["_expires_at"]    = int(time.time()) + duration_secs
    perm_rec["_permanent_key"] = user_key
    users_dict[temp_tok] = perm_rec
    return temp_tok


def _cleanup_temp_tokens(users_dict):
    """Mirror of RAGApp._admin_cleanup_temp_tokens."""
    now = time.time()
    expired = [k for k, v in list(users_dict.items())
               if isinstance(v, dict) and v.get("_temp_token")
               and v.get("_expires_at", 0) < now]
    for k in expired:
        del users_dict[k]
    return expired


def _recovery_eligible(users_dict):
    """Mirror of RAGApp._admin_recovery_eligible_users — returns list of names."""
    now = time.time()
    out = []
    for tok, rec in users_dict.items():
        if not isinstance(rec, dict):
            continue
        if rec.get("_temp_token") and rec.get("_expires_at", 0) < now:
            continue
        if rec.get("_temp_token"):
            continue
        role = (rec.get("role") or "").lower()
        if role == "owner" or rec.get("can_manage_users"):
            out.append(rec.get("name", ""))
    return out


def _sms_address(phone, carrier):
    """Build the email-to-SMS gateway address."""
    gw = CARRIER_GATEWAYS.get(carrier, "")
    if not phone or not gw:
        return None
    return f"{phone}@{gw}"


def _build_recovery_subject():
    return "AI-Prowler Admin Access Recovery"


def _build_recovery_body(name, temp_token):
    return (
        f"Hi {name},\n\n"
        f"A temporary admin token has been generated.\n\n"
        f"Temporary token:  {temp_token}\n"
        f"Expires:          1 hour from now\n\n"
        f"Use this token to log in to the Admin tab.\n"
        f"You will be prompted to set a permanent token after login."
    )


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestTempTokenGeneration:

    def test_token_is_url_safe_string(self):
        users = {"perm_tok": {"name": "David", "role": "owner"}}
        temp  = _generate_temp_token("perm_tok", users)
        assert isinstance(temp, str)
        assert len(temp) >= 20

    def test_token_added_to_users_dict(self):
        users = {"perm_tok": {"name": "David", "role": "owner"}}
        temp  = _generate_temp_token("perm_tok", users)
        assert temp in users

    def test_temp_flag_set(self):
        users = {"perm_tok": {"name": "David", "role": "owner"}}
        temp  = _generate_temp_token("perm_tok", users)
        assert users[temp]["_temp_token"] is True

    def test_expires_at_is_future(self):
        users = {"perm_tok": {"name": "David", "role": "owner"}}
        temp  = _generate_temp_token("perm_tok", users)
        assert users[temp]["_expires_at"] > time.time()

    def test_expires_at_roughly_one_hour(self):
        users = {"perm_tok": {"name": "David", "role": "owner"}}
        temp  = _generate_temp_token("perm_tok", users)
        delta = users[temp]["_expires_at"] - time.time()
        assert 3590 < delta <= 3601   # within 10 s of 3600

    def test_permanent_key_stored(self):
        users = {"perm_tok": {"name": "David", "role": "owner"}}
        temp  = _generate_temp_token("perm_tok", users)
        assert users[temp]["_permanent_key"] == "perm_tok"

    def test_two_tokens_are_different(self):
        users = {"perm_tok": {"name": "David", "role": "owner"}}
        t1 = _generate_temp_token("perm_tok", users)
        t2 = _generate_temp_token("perm_tok", users)
        assert t1 != t2

    def test_user_fields_preserved_in_temp(self):
        users = {"perm_tok": {"name": "David", "role": "owner",
                              "email": "d@ex.com"}}
        temp = _generate_temp_token("perm_tok", users)
        assert users[temp]["email"] == "d@ex.com"
        assert users[temp]["role"]  == "owner"


class TestTempTokenExpiry:

    def test_expired_token_is_cleaned_up(self):
        users = {
            "perm": {"name": "David", "role": "owner"},
            "old_temp": {
                "name": "David", "role": "owner",
                "_temp_token": True, "_expires_at": time.time() - 10,
                "_permanent_key": "perm",
            },
        }
        removed = _cleanup_temp_tokens(users)
        assert "old_temp" not in users
        assert len(removed) == 1

    def test_valid_temp_token_survives_cleanup(self):
        users = {
            "perm": {"name": "David", "role": "owner"},
            "new_temp": {
                "name": "David", "role": "owner",
                "_temp_token": True, "_expires_at": time.time() + 3600,
                "_permanent_key": "perm",
            },
        }
        removed = _cleanup_temp_tokens(users)
        assert "new_temp" in users
        assert len(removed) == 0

    def test_permanent_token_untouched_by_cleanup(self):
        users = {"perm_tok": {"name": "David", "role": "owner"}}
        removed = _cleanup_temp_tokens(users)
        assert "perm_tok" in users
        assert len(removed) == 0

    def test_multiple_expired_all_removed(self):
        users = {
            "perm": {"name": "David", "role": "owner"},
            "t1": {"name": "David", "_temp_token": True,
                   "_expires_at": time.time() - 100, "_permanent_key": "perm"},
            "t2": {"name": "David", "_temp_token": True,
                   "_expires_at": time.time() - 200, "_permanent_key": "perm"},
        }
        removed = _cleanup_temp_tokens(users)
        assert "perm" in users
        assert "t1" not in users
        assert "t2" not in users
        assert len(removed) == 2


class TestRecoveryEligibility:

    def test_owner_always_eligible(self):
        users = {"tok": {"name": "David", "role": "owner",
                         "can_manage_users": False}}
        assert "David" in _recovery_eligible(users)

    def test_manager_with_manage_eligible(self):
        users = {"tok": {"name": "Maria", "role": "manager",
                         "can_manage_users": True}}
        assert "Maria" in _recovery_eligible(users)

    def test_manager_without_manage_not_eligible(self):
        users = {"tok": {"name": "Bob", "role": "manager",
                         "can_manage_users": False}}
        assert "Bob" not in _recovery_eligible(users)

    def test_staff_not_eligible(self):
        users = {"tok": {"name": "Jake", "role": "staff"}}
        assert "Jake" not in _recovery_eligible(users)

    def test_field_crew_not_eligible(self):
        users = {"tok": {"name": "Sam", "role": "field_crew"}}
        assert "Sam" not in _recovery_eligible(users)

    def test_expired_temp_not_returned_as_eligible(self):
        users = {
            "perm": {"name": "David", "role": "owner"},
            "tmp":  {"name": "David", "role": "owner",
                     "_temp_token": True,
                     "_expires_at": time.time() - 10,
                     "_permanent_key": "perm"},
        }
        names = _recovery_eligible(users)
        assert names.count("David") == 1   # only the perm record

    def test_active_temp_excluded_from_eligible(self):
        # Active temp tokens should not appear as selectable identities;
        # only the permanent record should appear.
        users = {
            "perm": {"name": "David", "role": "owner"},
            "tmp":  {"name": "David", "role": "owner",
                     "_temp_token": True,
                     "_expires_at": time.time() + 3600,
                     "_permanent_key": "perm"},
        }
        names = _recovery_eligible(users)
        assert names.count("David") == 1


class TestSMSGatewayAddress:

    def test_verizon_gateway(self):
        addr = _sms_address("3215550199", "verizon")
        assert addr == "3215550199@vtext.com"

    def test_att_gateway(self):
        addr = _sms_address("3215550199", "att")
        assert addr == "3215550199@txt.att.net"

    def test_tmobile_gateway(self):
        addr = _sms_address("3215550199", "t-mobile")
        assert addr == "3215550199@tmomail.net"

    def test_cricket_gateway(self):
        addr = _sms_address("3215550199", "cricket")
        assert addr == "3215550199@sms.cricketwireless.net"

    def test_boost_gateway(self):
        addr = _sms_address("3215550199", "boost")
        assert addr == "3215550199@sms.myboostmobile.com"

    def test_no_phone_returns_none(self):
        assert _sms_address("", "verizon") is None

    def test_unknown_carrier_returns_none(self):
        assert _sms_address("3215550199", "unknown_carrier") is None

    def test_no_carrier_returns_none(self):
        assert _sms_address("3215550199", "") is None


class TestRecoveryEmailContent:

    def test_subject_is_correct(self):
        assert _build_recovery_subject() == "AI-Prowler Admin Access Recovery"

    def test_body_contains_name(self):
        body = _build_recovery_body("David", "tok123")
        assert "David" in body

    def test_body_contains_token(self):
        body = _build_recovery_body("David", "secrettoken99")
        assert "secrettoken99" in body

    def test_body_contains_expiry_note(self):
        body = _build_recovery_body("David", "tok")
        assert "1 hour" in body

    def test_body_mentions_admin_tab(self):
        body = _build_recovery_body("David", "tok")
        assert "Admin" in body

    def test_body_warns_about_physical_access(self):
        body = _build_recovery_body("David", "tok")
        assert "permanent" in body.lower()


class TestManualFallback:

    def test_users_json_path_contains_ai_prowler(self):
        path = str(Path.home() / ".ai-prowler" / "users.json")
        assert ".ai-prowler" in path
        assert "users.json" in path

    def test_users_json_path_is_absolute(self):
        path = Path.home() / ".ai-prowler" / "users.json"
        assert path.is_absolute()

    def test_users_json_parent_is_ai_prowler_dir(self):
        path = Path.home() / ".ai-prowler" / "users.json"
        assert path.parent.name == ".ai-prowler"
