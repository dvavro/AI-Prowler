"""
Tests for _allowed_scopes() -- Phase 2 of the single-collection scope
redesign (see SCOPE_SIMPLIFICATION_SPEC.md at the repo root).

ADDITIVE-PHASE test: _allowed_scopes() is not yet called by any read tool
(_allowed_collections() remains the live enforcement mechanism until the
single-collection query path replaces the multi-collection fan-out). This
file locks in the function's behavior now, against realistic user shapes,
ahead of that switch -- per the incremental build-and-test-each-phase plan.

Uses the session-scoped `mcp_module` fixture from tests/mcp/conftest.py so
the (side-effecting) engine import happens once.

    pytest tests/mcp/test_allowed_scopes.py -v
"""
import pytest

import scope_lookup as sl


def _get(mcp_module):
    fn = getattr(mcp_module, "_allowed_scopes", None)
    if fn is None:
        pytest.skip("engine _allowed_scopes not present")
    return fn


# ── Delegation: the engine wrapper must agree with scope_lookup exactly ──
OWNER = {"id": "david-vavro", "role": "owner",
         "scopes": ["scope:office"], "private_collection_enabled": True}
MANAGER = {"id": "vicki-vavro", "role": "manager",
           "scopes": ["scope:sales", "scope:office"],
           "private_collection_enabled": True}
STAFF = {"id": "samantha-vavro", "role": "staff",
         "scopes": ["scope:sales"], "private_collection_enabled": True}
FIELD_CREW = {"id": "jamie-vavro", "role": "field_crew",
              "scopes": ["scope:field"], "private_collection_enabled": False}
NO_SCOPES_USER = {"id": "new-hire", "role": "staff"}


@pytest.mark.parametrize("user", [
    None, OWNER, MANAGER, STAFF, FIELD_CREW, NO_SCOPES_USER,
])
def test_engine_matches_scope_lookup_exactly(mcp_module, user):
    """The engine wrapper must be a pure passthrough -- no additional
    logic, no drift, for every realistic user shape."""
    fn = _get(mcp_module)
    assert fn(user) == sl.allowed_scopes_for_user(user)


# ── The decision this phase locks in: NO role elevation, anyone ─────────
def test_owner_gets_no_elevation_beyond_own_assigned_scopes(mcp_module):
    """CRITICAL: direct product decision (2026-07-16) -- owner does NOT
    automatically see every business scope. Owner's search visibility is
    exactly {"shared"} + their own assigned scopes + their own private
    scope, same formula as everyone else. If this ever starts returning
    office/sales/ops/field for an owner who was only assigned 'office',
    someone has reintroduced the read_all_role_scopes-style elevation
    that was deliberately rejected for the new design."""
    fn = _get(mcp_module)
    result = fn(OWNER)
    assert result == {"shared", "office", "private:david-vavro"}
    assert "sales" not in result
    assert "ops" not in result
    assert "field" not in result


def test_manager_gets_no_elevation_either(mcp_module):
    fn = _get(mcp_module)
    result = fn(MANAGER)
    assert result == {"shared", "sales", "office", "private:vicki-vavro"}
    assert "ops" not in result
    assert "field" not in result


def test_staff_and_owner_use_the_identical_formula(mcp_module):
    """Same shape of scopes/private_collection_enabled -> same result,
    regardless of role. Role must not appear anywhere in the computation
    -- this test would catch a role branch being reintroduced even if the
    specific OWNER/STAFF fixtures above didn't happen to exercise it."""
    fn = _get(mcp_module)
    owner_shaped = {"id": "x", "role": "owner",
                     "scopes": ["scope:field"],
                     "private_collection_enabled": False}
    staff_shaped = {"id": "x", "role": "staff",
                     "scopes": ["scope:field"],
                     "private_collection_enabled": False}
    assert fn(owner_shaped) == fn(staff_shaped) == {"shared", "field"}


def test_no_user_gets_no_scopes(mcp_module):
    """Mirrors _allowed_collections(None) -> [] -- no resolved token means
    no access; the auth middleware 401s before this is ever reached."""
    fn = _get(mcp_module)
    assert fn(None) == set()


def test_private_never_leaks_across_users_via_the_engine_wrapper(mcp_module):
    fn = _get(mcp_module)
    owner_scopes = fn(OWNER)
    manager_scopes = fn(MANAGER)
    assert "private:vicki-vavro" not in owner_scopes
    assert "private:david-vavro" not in manager_scopes
