"""
tests/mcp/test_hr_role_based_auth.py
=====================================
Tests for the HR module's real role-based auth in server mode (replaces the
earlier MVP simplification that granted HR admin to ANY recognized
server-mode token regardless of role). Covers:
  - the new "can_manage_hr" capability added to _ROLE_CAPS (owner/manager
    True, staff/field_crew False)
  - the server-mode /hr-api/* auth-resolution block in ai_prowler_mcp.py that
    now resolves the real user and gates on that capability instead of
    "any valid token = admin"
  - personal mode is intentionally UNCHANGED (single-user desktop install —
    there are no owner/manager/staff/field_crew roles in personal mode, so
    "any valid token = admin" there is correct, not a gap)

SAFETY (per explicit user requirement): these tests do NOT import
ai_prowler_mcp.py, do NOT start a server, and do NOT touch any real
users.json / hr_db.json. Behavioral assertions run against a local mirror of
the role-capability matrix and the auth-resolution decision tree, driven
with synthetic user/token data. Everything else is a read-only structural
check against the real source, matching the established convention (see
tests/mcp/test_pwa_api_route.py, tests/analysis/test_hr_scheduler.py,
tests/mcp/test_hr_document_upload.py).

Run:
    run_tests.bat tests\\mcp\\test_hr_role_based_auth.py -v
"""

import os
import re
import pytest

SRC_ROOT = os.environ.get(
    "AI_PROWLER_SRC",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)
AI_PROWLER_MCP_PATH = os.path.join(SRC_ROOT, "ai_prowler_mcp.py")

_USER_ROLES = ("owner", "manager", "staff", "field_crew")

# Local mirror of _ROLE_CAPS's can_manage_hr column — deliberately duplicated
# rather than imported (importing ai_prowler_mcp.py would pull in its full
# module-level side effects: ChromaDB init, MCP tool registration, etc.).
_CAN_MANAGE_HR = {
    "owner": True,
    "manager": True,
    "staff": False,
    "field_crew": False,
}


def _mirror_role_caps(role: str) -> dict:
    """Mirrors _role_caps()'s fallback behavior: unknown roles get the
    most-restricted (field_crew) capability set."""
    return {"can_manage_hr": _CAN_MANAGE_HR.get(role, _CAN_MANAGE_HR["field_crew"])}


# ── Local mirror of the server-mode HR auth-resolution decision tree ───────

def _mirror_resolve_hr_auth(resolved_user, employee_session_valid, employee_id=None):
    """Mirrors the exact decision tree now in ai_prowler_mcp.py's server-mode
    /hr-api/* block:
        1. If a real user was resolved (valid bearer token) AND their role's
           can_manage_hr capability is True -> {"role": "admin"}.
        2. Else, fall through to the X-Employee-Session check -> {"role":
           "employee", "employee_id": ...} if that session verifies.
        3. Else -> {"role": None} (unauthorized on every protected route).
    """
    if resolved_user and _mirror_role_caps(resolved_user.get("role")).get("can_manage_hr"):
        return {"role": "admin"}
    if employee_session_valid:
        return {"role": "employee", "employee_id": employee_id}
    return {"role": None}


class TestCanManageHrCapabilityMatrix:
    @pytest.mark.parametrize("role,expected", [
        ("owner", True), ("manager", True), ("staff", False), ("field_crew", False),
    ])
    def test_matrix_values(self, role, expected):
        assert _mirror_role_caps(role)["can_manage_hr"] is expected

    def test_unknown_role_defaults_to_most_restricted(self):
        assert _mirror_role_caps("not-a-real-role")["can_manage_hr"] is False

    def test_all_four_roles_covered(self):
        assert set(_CAN_MANAGE_HR.keys()) == set(_USER_ROLES)


class TestHrAuthResolutionLogic:
    def test_owner_gets_admin(self):
        auth = _mirror_resolve_hr_auth({"role": "owner"}, employee_session_valid=False)
        assert auth == {"role": "admin"}

    def test_manager_gets_admin(self):
        auth = _mirror_resolve_hr_auth({"role": "manager"}, employee_session_valid=False)
        assert auth == {"role": "admin"}

    def test_staff_does_not_get_admin(self):
        auth = _mirror_resolve_hr_auth({"role": "staff"}, employee_session_valid=False)
        assert auth != {"role": "admin"}
        assert auth == {"role": None}

    def test_field_crew_does_not_get_admin(self):
        auth = _mirror_resolve_hr_auth({"role": "field_crew"}, employee_session_valid=False)
        assert auth != {"role": "admin"}
        assert auth == {"role": None}

    def test_unresolved_user_falls_through(self):
        auth = _mirror_resolve_hr_auth(None, employee_session_valid=False)
        assert auth == {"role": None}

    def test_staff_with_valid_employee_session_gets_employee_role(self):
        # A staff-role server user who ALSO happens to be a named HR employee
        # (separate email+PIN /auth/employee flow) still gets scoped
        # employee access — they're just never granted blanket HR admin.
        auth = _mirror_resolve_hr_auth(
            {"role": "staff"}, employee_session_valid=True, employee_id="EMP-00007")
        assert auth == {"role": "employee", "employee_id": "EMP-00007"}

    def test_owner_bearer_token_takes_priority_over_employee_session(self):
        # If somehow both a valid owner/manager bearer token AND an
        # X-Employee-Session header are present, admin wins (matches the
        # if/else — not elif-chained-after — structure in the real code).
        auth = _mirror_resolve_hr_auth(
            {"role": "owner"}, employee_session_valid=True, employee_id="EMP-00007")
        assert auth == {"role": "admin"}

    def test_no_token_and_no_session_is_fully_unauthorized(self):
        auth = _mirror_resolve_hr_auth(None, employee_session_valid=False)
        assert auth["role"] is None


# ── Structural checks — real source read as text, read-only ────────────────

@pytest.fixture(scope="module")
def ai_prowler_source():
    with open(AI_PROWLER_MCP_PATH, "r", encoding="utf-8") as f:
        return f.read()


class TestRoleCapsMatrixInSource:
    def test_can_manage_hr_key_present_for_all_four_roles(self, ai_prowler_source):
        caps_block = ai_prowler_source.split("_ROLE_CAPS = {", 1)[1].split("\n}\n", 1)[0]
        for role in _USER_ROLES:
            role_block = caps_block.split(f'"{role}":', 1)[1].split("},", 1)[0]
            assert "can_manage_hr" in role_block, f"can_manage_hr missing from '{role}' entry"

    @pytest.mark.parametrize("role,expected", [
        ("owner", "True"), ("manager", "True"), ("staff", "False"), ("field_crew", "False"),
    ])
    def test_can_manage_hr_values_match_expected(self, ai_prowler_source, role, expected):
        caps_block = ai_prowler_source.split("_ROLE_CAPS = {", 1)[1].split("\n}\n", 1)[0]
        role_block = caps_block.split(f'"{role}":', 1)[1].split("},", 1)[0]
        assert re.search(rf'"can_manage_hr":\s*{expected}', role_block), (
            f"expected can_manage_hr: {expected} for role '{role}', "
            f"got block: {role_block.strip()[:200]}"
        )


class TestMvpSimplificationIsGone:
    """Regression guard: the old 'any recognized server-mode token = HR
    admin' MVP simplification must not reappear — assert its exact old
    unconditional assignment pattern is absent from the server-mode block."""

    def test_no_longer_grants_admin_unconditionally_on_any_token(self, ai_prowler_source):
        hr_srv_block = ai_prowler_source.split(
            'if path.startswith("/hr-api"):', 2)[1].split("# ── end HR", 1)[0]
        # The old bug pattern: "if ... in _srv_access_tokens:" immediately
        # followed (next non-comment line) by an unconditional
        # `_hrsrv_auth = {"role": "admin"}` with no role check in between.
        assert '_role_caps(_hrsrv_resolved_user.get("role")).get("can_manage_hr")' in hr_srv_block, (
            "server-mode HR auth no longer gates on can_manage_hr — the MVP "
            "any-token-is-admin simplification may have regressed"
        )

    def test_resolve_user_and_load_users_are_used_for_hr_auth(self, ai_prowler_source):
        hr_srv_block = ai_prowler_source.split(
            'if path.startswith("/hr-api"):', 2)[1].split("# ── end HR", 1)[0]
        assert "_resolve_user(_load_users()" in hr_srv_block


class TestPersonalModeUnaffected:
    """Personal mode is single-user by design — 'any valid token = admin'
    there is correct behavior, not a gap, and must remain untouched."""

    def test_personal_mode_hr_block_still_grants_admin_on_valid_token(self, ai_prowler_source):
        hrp_block = ai_prowler_source.split(
            'if path.startswith("/hr-api"):', 2)[2].split("# ── end HR", 1)[0]
        assert '_hrp_auth = {"role": "admin"}' in hrp_block
        # Must NOT have been accidentally changed to require role resolution —
        # personal mode has no users.json / role concept at all.
        assert "_resolve_user" not in hrp_block
