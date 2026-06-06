"""
tests/mcp/test_role_tool_matrix.py
===================================
Unit tests for the v7.0.1 role-to-tool capability matrix.

Covers:
  Q1 -- DB-management tool gating  (_check_db_cap, updated _can_index)
  Q5 -- Email capability gating    (_send_email_cap, _email_allowed_for_user)

All tests are PURE: they call helper functions directly without starting the
MCP server or touching ChromaDB.

Role quick-reference (v7.0.1):
  owner      manage_db=full    can_write_shared=T  can_send_email=F
  manager    manage_db=full    can_write_shared=T  can_send_email=F
  staff      manage_db=limited can_write_shared=F  can_send_email=F
  field_crew manage_db=none    can_write_shared=F  can_send_email=T
"""

import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path bootstrap — only needed when the file is run in isolation; the
# tests/mcp/conftest.py already does this when run as part of the suite.
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# mcp_module fixture is provided by tests/mcp/conftest.py (session-scoped).
# Do NOT redefine it here — that would override the conftest version and
# bypass the proper import setup that makes ai_prowler_mcp importable.


# ---------------------------------------------------------------------------
# Shared user dicts (mirrors what _resolve_user produces at runtime).
# ---------------------------------------------------------------------------
def _user(role, uid="u0000000000001", scopes=None, private=True):
    return {
        "id": uid,
        "name": f"Test {role.title()}",
        "role": role,
        "scopes": scopes or [],
        "private_collection_enabled": private,
        "status": "active",
    }


OWNER   = _user("owner",     uid="owner0000000001", scopes=[])
MANAGER = _user("manager",   uid="mgr0000000000001", scopes=["scope:sales", "scope:office"])
STAFF   = _user("staff",     uid="staff0000000001",  scopes=["scope:office"])
FIELD   = _user("field_crew",uid="field0000000001",  scopes=["scope:field"], private=False)


# =============================================================================
# Section A -- _check_db_cap   (Q1)
# =============================================================================

class TestCheckDbCap:
    """_check_db_cap(user, level) gates DB-management tools:
        level='limited' -- index_path        (owner, manager, staff)
        level='full'    -- untrack/reindex   (owner, manager only)
    """

    # -- Personal mode (user=None): always open --------------------------------

    def test_A_DB_01_personal_mode_full_allowed(self, mcp_module):
        ok, reason = mcp_module._check_db_cap(None, "full")
        assert ok is True
        assert "personal" in reason.lower()

    def test_A_DB_02_personal_mode_limited_allowed(self, mcp_module):
        ok, _ = mcp_module._check_db_cap(None, "limited")
        assert ok is True

    # -- Owner ----------------------------------------------------------------

    def test_A_DB_03_owner_full_allowed(self, mcp_module):
        ok, _ = mcp_module._check_db_cap(OWNER, "full")
        assert ok is True

    def test_A_DB_04_owner_limited_allowed(self, mcp_module):
        ok, _ = mcp_module._check_db_cap(OWNER, "limited")
        assert ok is True

    # -- Manager --------------------------------------------------------------

    def test_A_DB_05_manager_full_allowed(self, mcp_module):
        ok, _ = mcp_module._check_db_cap(MANAGER, "full")
        assert ok is True

    def test_A_DB_06_manager_limited_allowed(self, mcp_module):
        ok, _ = mcp_module._check_db_cap(MANAGER, "limited")
        assert ok is True

    # -- Staff ----------------------------------------------------------------

    def test_A_DB_07_staff_full_denied(self, mcp_module):
        """staff has manage_db='limited' -- cannot call untrack/reindex."""
        ok, reason = mcp_module._check_db_cap(STAFF, "full")
        assert ok is False
        assert "staff" in reason.lower() or "limited" in reason.lower()

    def test_A_DB_08_staff_limited_allowed(self, mcp_module):
        """staff may call index_path (level='limited')."""
        ok, _ = mcp_module._check_db_cap(STAFF, "limited")
        assert ok is True

    # -- Field crew -----------------------------------------------------------

    def test_A_DB_09_field_full_denied(self, mcp_module):
        ok, _ = mcp_module._check_db_cap(FIELD, "full")
        assert ok is False

    def test_A_DB_10_field_limited_denied(self, mcp_module):
        """field_crew cannot index anything -- not even at 'limited' level."""
        ok, reason = mcp_module._check_db_cap(FIELD, "limited")
        assert ok is False
        assert "none" in reason.lower() or "field_crew" in reason.lower()

    # -- Unknown role defaults to field_crew (most restricted) ----------------

    def test_A_DB_11_unknown_role_denied(self, mcp_module):
        alien = _user("receptionist", uid="x")
        ok, _ = mcp_module._check_db_cap(alien, "limited")
        assert ok is False

    # -- Bad level argument ---------------------------------------------------

    def test_A_DB_12_unknown_level_denied(self, mcp_module):
        ok, reason = mcp_module._check_db_cap(OWNER, "superuser")
        assert ok is False
        assert "unknown level" in reason.lower()


# =============================================================================
# Section B -- _can_index  (Q1 -- staff now has limited write access)
# =============================================================================

class TestCanIndexV71:
    """v7.0.1 _can_index changes:
      - staff can_write=True but can_write_shared=False
      - field_crew unchanged (can_write=False)
    """

    # -- Staff: allowed -------------------------------------------------------

    def test_B_IDX_01_staff_assigned_scope_allowed(self, mcp_module):
        ok, _ = mcp_module._can_index(STAFF, "scope:office")
        assert ok is True

    def test_B_IDX_02_staff_own_private_allowed(self, mcp_module):
        ok, _ = mcp_module._can_index(STAFF, f"user:{STAFF['id']}")
        assert ok is True

    # -- Staff: denied --------------------------------------------------------

    def test_B_IDX_03_staff_shared_denied(self, mcp_module):
        ok, reason = mcp_module._can_index(STAFF, "shared")
        assert ok is False
        assert "staff" in reason.lower() or "shared" in reason.lower()

    def test_B_IDX_04_staff_unassigned_scope_denied(self, mcp_module):
        ok, _ = mcp_module._can_index(STAFF, "scope:sales")
        assert ok is False

    def test_B_IDX_05_staff_others_private_denied(self, mcp_module):
        ok, _ = mcp_module._can_index(STAFF, "user:someone_else")
        assert ok is False

    # -- Field crew: nothing allowed ------------------------------------------

    def test_B_IDX_06_field_denied_everywhere(self, mcp_module):
        for tgt in ("shared", "scope:field", f"user:{FIELD['id']}", "scope:office"):
            ok, _ = mcp_module._can_index(FIELD, tgt)
            assert ok is False, f"field_crew must not index '{tgt}'"

    # -- Manager: shared still open -------------------------------------------

    def test_B_IDX_07_manager_shared_allowed(self, mcp_module):
        ok, _ = mcp_module._can_index(MANAGER, "shared")
        assert ok is True

    def test_B_IDX_08_manager_assigned_scope_allowed(self, mcp_module):
        ok, _ = mcp_module._can_index(MANAGER, "scope:sales")
        assert ok is True

    def test_B_IDX_09_manager_unassigned_scope_denied(self, mcp_module):
        ok, _ = mcp_module._can_index(MANAGER, "scope:field")
        assert ok is False

    # -- Owner: unrestricted --------------------------------------------------

    def test_B_IDX_10_owner_any_target_allowed(self, mcp_module):
        for tgt in ("shared", "scope:anything", "user:anyone", "scope:office"):
            ok, _ = mcp_module._can_index(OWNER, tgt)
            assert ok is True, f"owner must index '{tgt}'"

    # -- Vocabulary tolerance: legacy role: == new scope: ---------------------

    def test_B_IDX_11_legacy_role_prefix_treated_same_as_scope(self, mcp_module):
        ok_new, _ = mcp_module._can_index(STAFF, "scope:office")
        ok_old, _ = mcp_module._can_index(STAFF, "role:office")
        assert ok_new is True
        assert ok_old is True


# =============================================================================
# Section C -- _send_email_cap   (Q5)
# =============================================================================

class TestSendEmailCap:
    """send_email and send_alert use _send_email_cap.
    field_crew: allowed (no personal install available).
    owner/manager/staff: denied (use personal install for email).
    Personal mode (user=None): always allowed.
    """

    def test_C_EMAIL_01_personal_mode_allowed(self, mcp_module):
        ok, reason = mcp_module._send_email_cap(None)
        assert ok is True
        assert "personal" in reason.lower()

    def test_C_EMAIL_02_field_crew_allowed(self, mcp_module):
        ok, reason = mcp_module._send_email_cap(FIELD)
        assert ok is True
        assert "field_crew" in reason.lower()

    def test_C_EMAIL_03_owner_denied(self, mcp_module):
        ok, reason = mcp_module._send_email_cap(OWNER)
        assert ok is False
        assert "personal" in reason.lower() or "owner" in reason.lower()

    def test_C_EMAIL_04_manager_denied(self, mcp_module):
        ok, _ = mcp_module._send_email_cap(MANAGER)
        assert ok is False

    def test_C_EMAIL_05_staff_denied(self, mcp_module):
        ok, _ = mcp_module._send_email_cap(STAFF)
        assert ok is False


# =============================================================================
# Section D -- _email_allowed_for_user  (personal-only gate)
# =============================================================================

class TestEmailAllowedForUser:
    """configure_email, send_file, and send_learnings_report use this gate.
    Blocked in server mode for ALL roles, including field_crew -- field crew
    can SEND (via _send_email_cap) but cannot CONFIGURE or ATTACH arbitrary files.
    """

    def test_D_CFG_01_personal_mode_allowed(self, mcp_module):
        ok, _ = mcp_module._email_allowed_for_user(None)
        assert ok is True

    def test_D_CFG_02_all_server_roles_blocked(self, mcp_module):
        for user in (OWNER, MANAGER, STAFF, FIELD):
            ok, reason = mcp_module._email_allowed_for_user(user)
            assert ok is False, f"expected blocked for {user['role']}"
            assert "personal" in reason.lower()


# =============================================================================
# Section E -- _role_caps matrix sanity  (new fields)
# =============================================================================

class TestRoleCapsMatrix:
    """Spot-check every role's new capability fields are wired correctly."""

    @pytest.mark.parametrize("role,expected", [
        ("owner",      {"manage_db": "full",    "can_send_email": False, "can_write_shared": True}),
        ("manager",    {"manage_db": "full",    "can_send_email": False, "can_write_shared": True}),
        ("staff",      {"manage_db": "limited", "can_send_email": False, "can_write_shared": False}),
        ("field_crew", {"manage_db": "none",    "can_send_email": True,  "can_write_shared": False}),
    ])
    def test_E_CAP_matrix(self, mcp_module, role, expected):
        caps = mcp_module._role_caps(role)
        for key, val in expected.items():
            assert caps.get(key) == val, (
                f"_role_caps({role!r})[{key!r}] = {caps.get(key)!r}, want {val!r}"
            )

    def test_E_CAP_unknown_role_defaults_to_field_crew(self, mcp_module):
        caps = mcp_module._role_caps("receptionist")
        assert caps["manage_db"] == "none"
        assert caps["can_send_email"] is True
        assert caps["can_write_shared"] is False

    def test_E_CAP_staff_can_write_is_true(self, mcp_module):
        """staff gained can_write=True in v7.0.1 for limited indexing."""
        assert mcp_module._role_caps("staff")["can_write"] is True

    def test_E_CAP_field_crew_can_write_is_false(self, mcp_module):
        assert mcp_module._role_caps("field_crew")["can_write"] is False
