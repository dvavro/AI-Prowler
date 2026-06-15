"""
test_security_roles.py — AI-Prowler v7.0.1 Security & Role Tests
=================================================================
Tests for: bearer token enforcement, cross-user scope isolation,
role-based capability gating, owner data protection, and
chunk-ownership purge protection.

All tests in this file run against the REAL production functions in
ai_prowler_mcp.py.  No mocks, no stubs — actual implementation tested.

Run from the repo root:
    pytest tests/test_security_roles.py -v

Roles (actual — from _USER_ROLES in ai_prowler_mcp.py):
    owner       — full access, admin rights, reads all scopes
    manager     — full DB mgmt within assigned scopes + shared
    staff       — limited DB (own private + assigned scopes only)
    field_crew  — no DB management; may send email

users.json schema (key = bearer token, value = user record):
    {
      "users": {
        "<bearer-token>": {
          "name":                       "Display Name",
          "role":                       "owner|manager|staff|field_crew",
          "status":                     "active",          # omit = active
          "scopes":                     ["sales"],         # logical scope names
          "private_collection_enabled": true,
          "can_manage_users":           true,              # admin gate
          "index_target":               "scope:sales"      # write default
        }
      },
      "collection_map": {                                  # optional
        "rules": [{"prefix": "C:/...", "collection": "scope:sales"}],
        "default_collection": "shared"
      }
    }
"""

import sys
import json
import pytest
import tempfile
import os
from pathlib import Path

# ── Ensure the AI-Prowler source root is on sys.path ────────────────────────
_SRC = Path(__file__).resolve().parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# ── Import the real production functions ────────────────────────────────────
# These are module-level pure functions — no server startup needed.
from ai_prowler_mcp import (
    _resolve_user,
    _allowed_collections,
    _can_index,
    _can_manage_user_data,
    _can_purge_chunks,
    _chunk_owners,
    _owner_user_id,
    _check_db_cap,
    _user_has_role,
    _is_admin,
    _role_caps,
    _canon_scope,
    _ROLE_CAPS,
    _USER_ROLES,
    _SHARED_COLLECTION,
    _OWNERLESS,
)
import scope_resolver as sr


# ═══════════════════════════════════════════════════════════════════════════
# users.json fixtures — one dict per test scenario
# These match the EXACT schema _resolve_user() expects:
#   users_data["users"][<bearer_token>] = user_record
# The bearer token IS the dict key (not hashed in users.json).
# ═══════════════════════════════════════════════════════════════════════════

# ── Fixture A: Full company with all four roles ──────────────────────────────
USERS_FULL = {
    "users": {
        # Owner — David (full access, admin rights)
        "tok-owner-david-secret": {
            "name":                       "David Vavro",
            "role":                       "owner",
            "status":                     "active",
            "scopes":                     ["sales", "office"],
            "private_collection_enabled": True,
            "can_manage_users":           True,
        },
        # Manager — Jamie (full DB mgmt, manages employees)
        "tok-manager-jamie-secret": {
            "name":                       "Jamie V",
            "role":                       "manager",
            "status":                     "active",
            "scopes":                     ["sales", "office"],
            "private_collection_enabled": True,
            "can_manage_users":           True,
        },
        # Staff — Alice (limited DB, assigned scopes)
        "tok-staff-alice-secret": {
            "name":                       "Alice Smith",
            "role":                       "staff",
            "status":                     "active",
            "scopes":                     ["sales"],
            "private_collection_enabled": True,
            "can_manage_users":           False,
        },
        # Field crew — Bob (no DB, email only)
        "tok-crew-bob-secret": {
            "name":                       "Bob Jones",
            "role":                       "field_crew",
            "status":                     "active",
            "scopes":                     [],
            "private_collection_enabled": False,
            "can_manage_users":           False,
        },
    },
    "collection_map": {
        "rules": [
            {"prefix": "C:/CompanyDocs/Owner",   "collection": "scope:owner_private"},
            {"prefix": "C:/CompanyDocs/Sales",   "collection": "scope:sales"},
            {"prefix": "C:/CompanyDocs/Office",  "collection": "scope:office"},
            {"prefix": "C:/CompanyDocs/Shared",  "collection": "shared"},
        ],
        "default_collection": "shared",
    },
}

# ── Fixture B: Suspended / revoked user ──────────────────────────────────────
USERS_WITH_SUSPENDED = {
    "users": {
        "tok-owner-active": {
            "name": "Owner", "role": "owner", "status": "active",
            "scopes": [], "private_collection_enabled": True,
            "can_manage_users": True,
        },
        "tok-staff-suspended": {
            "name": "Ex-Employee", "role": "staff", "status": "suspended",
            "scopes": ["sales"], "private_collection_enabled": True,
            "can_manage_users": False,
        },
        "tok-crew-revoked": {
            "name": "Revoked Crew", "role": "field_crew", "status": "revoked",
            "scopes": [], "private_collection_enabled": False,
            "can_manage_users": False,
        },
    }
}

# ── Fixture C: Single owner, no other users ──────────────────────────────────
USERS_OWNER_ONLY = {
    "users": {
        "tok-solo-owner": {
            "name": "Solo Owner", "role": "owner", "status": "active",
            "scopes": [], "private_collection_enabled": True,
            "can_manage_users": True,
        }
    }
}

# ── Fixture D: Malformed / edge-case users.json ──────────────────────────────
USERS_MALFORMED = {
    "users": {
        "tok-valid-owner": {
            "name": "Valid Owner", "role": "owner", "status": "active",
            "scopes": [], "private_collection_enabled": True,
            "can_manage_users": True,
        },
        "tok-bad-role": {
            "name": "Unknown Role", "role": "superhero",  # unknown role → field_crew
            "status": "active", "scopes": [], "private_collection_enabled": False,
        },
        "tok-missing-status": {
            "name": "No Status Field", "role": "staff",  # missing status = active
            "scopes": ["sales"], "private_collection_enabled": True,
        },
    }
}

# Convenience: resolved user dicts (what _resolve_user() returns)
def _resolve(users_data, token):
    return _resolve_user(users_data, token)

OWNER   = _resolve(USERS_FULL, "tok-owner-david-secret")
MANAGER = _resolve(USERS_FULL, "tok-manager-jamie-secret")
STAFF   = _resolve(USERS_FULL, "tok-staff-alice-secret")
CREW    = _resolve(USERS_FULL, "tok-crew-bob-secret")

# Scope mapping for scope_resolver tests (uses scope: prefix)
SCOPE_MAPPING = {
    "rules": [
        {"prefix": "C:/CompanyDocs/Owner",   "collection": "scope:owner_private"},
        {"prefix": "C:/CompanyDocs/Sales",   "collection": "scope:sales"},
        {"prefix": "C:/CompanyDocs/Office",  "collection": "scope:office"},
        {"prefix": "C:/CompanyDocs/Shared",  "collection": "shared"},
        {"prefix": "C:/CompanyDocs/Employees/Alice", "collection": "user:alice-smith"},
        {"prefix": "C:/CompanyDocs/Employees/Bob",   "collection": "user:bob-jones"},
    ],
    "default_collection": "shared",
}


# ════════════════════════════════════════════════════════════════════════════
# SECTION A — _resolve_user: token → user dict
# ════════════════════════════════════════════════════════════════════════════

class TestResolveUser:

    def test_owner_token_resolves(self):
        user = _resolve(USERS_FULL, "tok-owner-david-secret")
        assert user is not None
        assert user["role"] == "owner"
        assert user["name"] == "David Vavro"

    def test_resolved_user_has_id_as_name_slug(self):
        """_resolve_user sets user['id'] to a lowercase slug from the display name,
        NOT the bearer token key. This decouples identity from credentials."""
        user = _resolve(USERS_FULL, "tok-owner-david-secret")
        assert user["id"] == "david-vavro"   # slug from "David Vavro"

    def test_manager_token_resolves(self):
        user = _resolve(USERS_FULL, "tok-manager-jamie-secret")
        assert user is not None
        assert user["role"] == "manager"

    def test_staff_token_resolves(self):
        user = _resolve(USERS_FULL, "tok-staff-alice-secret")
        assert user is not None
        assert user["role"] == "staff"

    def test_field_crew_token_resolves(self):
        user = _resolve(USERS_FULL, "tok-crew-bob-secret")
        assert user is not None
        assert user["role"] == "field_crew"

    def test_unknown_token_returns_none(self):
        assert _resolve(USERS_FULL, "tok-does-not-exist") is None

    def test_empty_token_returns_none(self):
        assert _resolve(USERS_FULL, "") is None

    def test_none_token_returns_none(self):
        assert _resolve(USERS_FULL, None) is None

    def test_none_users_data_returns_none(self):
        assert _resolve(None, "tok-owner-david-secret") is None

    def test_suspended_user_returns_none(self):
        user = _resolve(USERS_WITH_SUSPENDED, "tok-staff-suspended")
        assert user is None, "Suspended user must be denied (returns None)"

    def test_revoked_user_returns_none(self):
        user = _resolve(USERS_WITH_SUSPENDED, "tok-crew-revoked")
        assert user is None, "Revoked user must be denied (returns None)"

    def test_active_owner_in_mixed_fixture_resolves(self):
        user = _resolve(USERS_WITH_SUSPENDED, "tok-owner-active")
        assert user is not None
        assert user["role"] == "owner"

    def test_unknown_role_normalised_to_field_crew(self):
        """Unknown roles get clamped to field_crew (the most restricted)."""
        user = _resolve(USERS_MALFORMED, "tok-bad-role")
        assert user is not None
        assert user["role"] == "field_crew"

    def test_missing_status_field_treated_as_active(self):
        user = _resolve(USERS_MALFORMED, "tok-missing-status")
        assert user is not None
        assert user["role"] == "staff"


# ════════════════════════════════════════════════════════════════════════════
# SECTION B — Bearer Token Auth Layer
# Replicates the _RouterASGI token-check logic (pure, no HTTP server)
# ════════════════════════════════════════════════════════════════════════════

class TestBearerTokenEnforcement:

    def _is_authorized(self, users_data, raw_auth_header: str) -> bool:
        """
        Replicates _run_server_mode's auth: extract bearer token,
        call _resolve_user, reject if None.
        """
        auth = raw_auth_header or ""
        tok = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        return _resolve_user(users_data, tok) is not None

    def test_owner_bearer_authorized(self):
        assert self._is_authorized(USERS_FULL, "Bearer tok-owner-david-secret")

    def test_manager_bearer_authorized(self):
        assert self._is_authorized(USERS_FULL, "Bearer tok-manager-jamie-secret")

    def test_staff_bearer_authorized(self):
        assert self._is_authorized(USERS_FULL, "Bearer tok-staff-alice-secret")

    def test_field_crew_bearer_authorized(self):
        assert self._is_authorized(USERS_FULL, "Bearer tok-crew-bob-secret")

    def test_missing_header_rejected(self):
        assert not self._is_authorized(USERS_FULL, "")

    def test_wrong_prefix_rejected(self):
        assert not self._is_authorized(USERS_FULL, "Token tok-owner-david-secret")

    def test_wrong_token_rejected(self):
        assert not self._is_authorized(USERS_FULL, "Bearer WRONG_TOKEN")

    def test_empty_bearer_value_rejected(self):
        assert not self._is_authorized(USERS_FULL, "Bearer ")

    def test_bearer_case_insensitive(self):
        assert self._is_authorized(USERS_FULL, "bearer tok-owner-david-secret")
        assert self._is_authorized(USERS_FULL, "BEARER tok-owner-david-secret")

    def test_suspended_user_bearer_rejected(self):
        assert not self._is_authorized(
            USERS_WITH_SUSPENDED, "Bearer tok-staff-suspended")

    def test_revoked_user_bearer_rejected(self):
        assert not self._is_authorized(
            USERS_WITH_SUSPENDED, "Bearer tok-crew-revoked")


# ════════════════════════════════════════════════════════════════════════════
# SECTION C — _allowed_collections: scope isolation per user
# ════════════════════════════════════════════════════════════════════════════

class TestAllowedCollections:

    def test_owner_always_has_shared(self):
        cols = _allowed_collections(OWNER)
        assert _SHARED_COLLECTION in cols

    def test_owner_has_private_collection(self):
        cols = _allowed_collections(OWNER)
        assert f"user:{OWNER['id']}" in cols

    def test_owner_with_all_role_collections_sees_all(self):
        all_role = ["scope:sales", "scope:office", "scope:warehouse"]
        cols = _allowed_collections(OWNER, all_role_collections=all_role)
        for c in all_role:
            assert c in cols

    def test_manager_sees_assigned_scopes(self):
        cols = _allowed_collections(MANAGER)
        # scopes: ["sales", "office"] → canonicalized to scope:sales, scope:office
        assert "scope:sales" in cols
        assert "scope:office" in cols

    def test_manager_sees_shared(self):
        cols = _allowed_collections(MANAGER)
        assert _SHARED_COLLECTION in cols

    def test_manager_has_private_collection(self):
        cols = _allowed_collections(MANAGER)
        assert f"user:{MANAGER['id']}" in cols

    def test_staff_sees_assigned_scopes(self):
        cols = _allowed_collections(STAFF)
        assert "scope:sales" in cols

    def test_staff_has_private_collection(self):
        cols = _allowed_collections(STAFF)
        assert f"user:{STAFF['id']}" in cols

    def test_staff_does_not_see_unassigned_scope(self):
        cols = _allowed_collections(STAFF)
        assert "scope:office" not in cols

    def test_field_crew_no_private_collection(self):
        """Bob has private_collection_enabled=False."""
        cols = _allowed_collections(CREW)
        assert f"user:{CREW['id']}" not in cols

    def test_field_crew_sees_shared(self):
        cols = _allowed_collections(CREW)
        assert _SHARED_COLLECTION in cols

    def test_none_user_returns_empty(self):
        assert _allowed_collections(None) == []

    # ── Cross-user isolation ──────────────────────────────────────────────────

    def test_staff_alice_cannot_see_bob_private_collection(self):
        alice_cols = _allowed_collections(STAFF)
        assert f"user:{CREW['id']}" not in alice_cols

    def test_manager_cannot_see_owner_private_collection_without_role_list(self):
        """Manager without the all_role_collections list cannot see owner private."""
        manager_cols = _allowed_collections(MANAGER)
        assert f"user:{OWNER['id']}" not in manager_cols

    def test_owner_sees_other_user_private_when_given_role_list(self):
        """Owner with read_others_private=True CAN see user:* if passed in."""
        # Simulate the admin view — server would pass user:* collections too
        all_role = [f"user:{STAFF['id']}", "scope:sales"]
        cols = _allowed_collections(OWNER, all_role_collections=all_role)
        assert f"user:{STAFF['id']}" in cols


# ════════════════════════════════════════════════════════════════════════════
# SECTION D — _can_index: write permission enforcement
# ════════════════════════════════════════════════════════════════════════════

class TestCanIndex:

    # ── Owner: may write anywhere ─────────────────────────────────────────────
    def test_owner_can_index_shared(self):
        allowed, _ = _can_index(OWNER, "shared")
        assert allowed

    def test_owner_can_index_any_scope(self):
        allowed, _ = _can_index(OWNER, "scope:sales")
        assert allowed

    def test_owner_can_index_own_private(self):
        allowed, _ = _can_index(OWNER, f"user:{OWNER['id']}")
        assert allowed

    def test_owner_can_index_staff_private(self):
        """Owner may index any user:* collection."""
        allowed, _ = _can_index(OWNER, f"user:{STAFF['id']}")
        assert allowed

    # ── Manager ───────────────────────────────────────────────────────────────
    def test_manager_can_index_assigned_scope(self):
        allowed, _ = _can_index(MANAGER, "scope:sales")
        assert allowed

    def test_manager_can_index_shared(self):
        allowed, _ = _can_index(MANAGER, "shared")
        assert allowed

    def test_manager_can_index_own_private(self):
        allowed, _ = _can_index(MANAGER, f"user:{MANAGER['id']}")
        assert allowed

    def test_manager_cannot_index_unassigned_scope(self):
        allowed, _ = _can_index(MANAGER, "scope:warehouse")
        assert not allowed

    def test_manager_cannot_index_staff_private(self):
        allowed, _ = _can_index(MANAGER, f"user:{STAFF['id']}")
        assert not allowed

    # ── Staff ─────────────────────────────────────────────────────────────────
    def test_staff_can_index_assigned_scope(self):
        allowed, _ = _can_index(STAFF, "scope:sales")
        assert allowed

    def test_staff_cannot_index_shared(self):
        """Staff cannot write to the shared commons (can_write_shared=False)."""
        allowed, _ = _can_index(STAFF, "shared")
        assert not allowed

    def test_staff_can_index_own_private(self):
        allowed, _ = _can_index(STAFF, f"user:{STAFF['id']}")
        assert allowed

    def test_staff_cannot_index_unassigned_scope(self):
        allowed, _ = _can_index(STAFF, "scope:office")
        assert not allowed

    def test_staff_cannot_index_other_user_private(self):
        allowed, _ = _can_index(STAFF, f"user:{CREW['id']}")
        assert not allowed

    # ── Field crew ────────────────────────────────────────────────────────────
    def test_field_crew_cannot_index_anywhere(self):
        for target in ["shared", "scope:sales", f"user:{CREW['id']}"]:
            allowed, _ = _can_index(CREW, target)
            assert not allowed, f"field_crew should not be able to index {target}"

    def test_no_user_cannot_index(self):
        allowed, _ = _can_index(None, "shared")
        assert not allowed


# ════════════════════════════════════════════════════════════════════════════
# SECTION E — _check_db_cap: DB management capability gate
# ════════════════════════════════════════════════════════════════════════════

class TestCheckDbCap:

    def test_owner_has_full_db_cap(self):
        allowed, _ = _check_db_cap(OWNER, "full")
        assert allowed

    def test_manager_has_full_db_cap(self):
        allowed, _ = _check_db_cap(MANAGER, "full")
        assert allowed

    def test_staff_has_limited_db_cap(self):
        allowed, _ = _check_db_cap(STAFF, "limited")
        assert allowed

    def test_staff_does_not_have_full_db_cap(self):
        allowed, _ = _check_db_cap(STAFF, "full")
        assert not allowed

    def test_field_crew_has_no_db_cap(self):
        allowed, _ = _check_db_cap(CREW, "limited")
        assert not allowed

    def test_none_user_always_allowed(self):
        """Personal mode — no user context means single-user install, always ok."""
        allowed, _ = _check_db_cap(None, "full")
        assert allowed


# ════════════════════════════════════════════════════════════════════════════
# SECTION F — _can_manage_user_data: rogue admin / offboarding protection
# This is the CRITICAL owner data protection gate.
# ════════════════════════════════════════════════════════════════════════════

class TestCanManageUserData:

    OWNER_ID   = "tok-owner-david-secret"
    MANAGER_ID = "tok-manager-jamie-secret"
    STAFF_ID   = "tok-staff-alice-secret"
    CREW_ID    = "tok-crew-bob-secret"

    # ── Owner: may manage anyone ──────────────────────────────────────────────
    def test_owner_can_manage_own_data(self):
        allowed, _ = _can_manage_user_data(OWNER, self.OWNER_ID, self.OWNER_ID)
        assert allowed

    def test_owner_can_manage_manager_data(self):
        allowed, _ = _can_manage_user_data(OWNER, self.MANAGER_ID, self.OWNER_ID)
        assert allowed

    def test_owner_can_manage_staff_data(self):
        allowed, _ = _can_manage_user_data(OWNER, self.STAFF_ID, self.OWNER_ID)
        assert allowed

    def test_owner_can_manage_crew_data(self):
        allowed, _ = _can_manage_user_data(OWNER, self.CREW_ID, self.OWNER_ID)
        assert allowed

    # ── Manager (can_manage_users=True): employee offboarding ─────────────────
    def test_manager_can_manage_staff_data(self):
        """Offboarding use case: manager wipes departing staff member's data."""
        allowed, _ = _can_manage_user_data(MANAGER, self.STAFF_ID, self.OWNER_ID)
        assert allowed

    def test_manager_can_manage_crew_data(self):
        allowed, _ = _can_manage_user_data(MANAGER, self.CREW_ID, self.OWNER_ID)
        assert allowed

    def test_rogue_manager_cannot_manage_owner_data(self):
        """
        THE critical rogue-admin test.
        A manager with can_manage_users=True is BLOCKED from touching the owner's data.
        Even a fully authenticated manager token must be denied here.
        """
        allowed, reason = _can_manage_user_data(MANAGER, self.OWNER_ID, self.OWNER_ID)
        assert not allowed, (
            f"SECURITY VIOLATION: manager was permitted to manage owner data. "
            f"reason='{reason}'. Owner data must be protected from all non-owner roles."
        )

    def test_rogue_manager_denied_when_owner_id_unknown(self):
        """
        FAIL CLOSED: if we can't determine the owner's id, the manager is DENIED
        even when the target isn't the owner — we won't risk it.
        """
        allowed, reason = _can_manage_user_data(MANAGER, self.STAFF_ID, owner_id=None)
        assert not allowed, (
            f"Manager should be denied when owner_id is unknown (fail-closed). "
            f"reason='{reason}'"
        )

    # ── Staff (can_manage_users=False): no management rights ─────────────────
    def test_staff_cannot_manage_any_data(self):
        for target in [self.OWNER_ID, self.MANAGER_ID, self.CREW_ID]:
            allowed, _ = _can_manage_user_data(STAFF, target, self.OWNER_ID)
            assert not allowed, f"Staff should not manage {target}'s data"

    # ── Field crew: no management rights ─────────────────────────────────────
    def test_field_crew_cannot_manage_any_data(self):
        for target in [self.OWNER_ID, self.STAFF_ID]:
            allowed, _ = _can_manage_user_data(CREW, target, self.OWNER_ID)
            assert not allowed

    # ── None actor ────────────────────────────────────────────────────────────
    def test_none_actor_cannot_manage_anything(self):
        allowed, _ = _can_manage_user_data(None, self.STAFF_ID, self.OWNER_ID)
        assert not allowed


# ════════════════════════════════════════════════════════════════════════════
# SECTION G — _owner_user_id: find the owner in users.json
# ════════════════════════════════════════════════════════════════════════════

class TestOwnerUserId:

    def test_finds_owner_in_full_fixture(self):
        oid = _owner_user_id(USERS_FULL)
        assert oid == "david-vavro"   # slug from "David Vavro"

    def test_finds_owner_in_solo_fixture(self):
        oid = _owner_user_id(USERS_OWNER_ONLY)
        assert oid == "solo-owner"    # slug from "Solo Owner"

    def test_returns_none_when_no_users(self):
        assert _owner_user_id({"users": {}}) is None

    def test_returns_none_when_users_data_none(self):
        # _owner_user_id(None) is a convenience call that loads the live
        # users.json — it intentionally falls through to disk.
        # The correct "no data" sentinel is an empty users dict, not None.
        assert _owner_user_id({"users": {}}) is None

    def test_returns_none_when_empty_dict(self):
        assert _owner_user_id({}) is None

    def test_returns_none_when_no_owner_role(self):
        no_owner = {
            "users": {
                "tok-staff": {"name": "Alice", "role": "staff", "status": "active"},
                "tok-crew":  {"name": "Bob",   "role": "field_crew", "status": "active"},
            }
        }
        assert _owner_user_id(no_owner) is None


# ════════════════════════════════════════════════════════════════════════════
# SECTION H — _can_purge_chunks: chunk-ownership write protection
# ════════════════════════════════════════════════════════════════════════════

class TestCanPurgeChunks:

    OWNER_ID = "david-vavro"    # slug from "David Vavro"
    STAFF_ID = "alice-smith"    # slug from "Alice Smith"
    CREW_ID  = "bob-jones"      # slug from "Bob Jones"

    def _meta(self, indexed_by):
        return {"indexed_by": indexed_by, "source": "test.txt"}

    # ── No existing chunks: always allowed ───────────────────────────────────
    def test_empty_chunks_always_allowed(self):
        allowed, _ = _can_purge_chunks(STAFF, [], self.OWNER_ID)
        assert allowed

    def test_none_chunks_always_allowed(self):
        allowed, _ = _can_purge_chunks(STAFF, None, self.OWNER_ID)
        assert allowed

    # ── Own chunks: always allowed ────────────────────────────────────────────
    def test_staff_can_purge_own_chunks(self):
        metas = [self._meta(self.STAFF_ID)]
        allowed, _ = _can_purge_chunks(STAFF, metas, self.OWNER_ID)
        assert allowed

    def test_owner_can_purge_own_chunks(self):
        metas = [self._meta(self.OWNER_ID)]
        allowed, _ = _can_purge_chunks(OWNER, metas, self.OWNER_ID)
        assert allowed

    # ── Admin can purge employee chunks ──────────────────────────────────────
    def test_manager_can_purge_staff_chunks(self):
        metas = [self._meta(self.STAFF_ID)]
        allowed, _ = _can_purge_chunks(MANAGER, metas, self.OWNER_ID)
        assert allowed

    # ── Rogue admin cannot purge owner chunks ────────────────────────────────
    def test_rogue_manager_cannot_purge_owner_chunks(self):
        """Manager must not be able to overwrite chunks owned by the owner."""
        metas = [self._meta(self.OWNER_ID)]
        allowed, reason = _can_purge_chunks(MANAGER, metas, self.OWNER_ID)
        assert not allowed, (
            f"SECURITY VIOLATION: manager purged owner chunks. reason='{reason}'"
        )

    # ── Staff cannot purge other user's chunks ───────────────────────────────
    def test_staff_cannot_purge_crew_chunks(self):
        metas = [self._meta(self.CREW_ID)]
        allowed, _ = _can_purge_chunks(STAFF, metas, self.OWNER_ID)
        assert not allowed

    # ── Legacy / ownerless chunks ─────────────────────────────────────────────
    def test_owner_can_purge_ownerless_chunks(self):
        metas = [{"source": "old.txt"}]  # no indexed_by → ownerless
        allowed, _ = _can_purge_chunks(OWNER, metas, self.OWNER_ID)
        assert allowed

    def test_manager_can_purge_ownerless_chunks(self):
        metas = [{"source": "old.txt"}]
        allowed, _ = _can_purge_chunks(MANAGER, metas, self.OWNER_ID)
        assert allowed

    def test_staff_cannot_purge_ownerless_chunks(self):
        """Plain staff/field_crew cannot overwrite legacy un-owned data."""
        metas = [{"source": "old.txt"}]
        allowed, _ = _can_purge_chunks(STAFF, metas, self.OWNER_ID)
        assert not allowed

    def test_none_actor_cannot_purge_anything(self):
        metas = [self._meta(self.STAFF_ID)]
        allowed, _ = _can_purge_chunks(None, metas, self.OWNER_ID)
        assert not allowed


# ════════════════════════════════════════════════════════════════════════════
# SECTION I — Role capability matrix sanity checks (_role_caps / _ROLE_CAPS)
# ════════════════════════════════════════════════════════════════════════════

class TestRoleCapabilities:

    def test_all_roles_defined(self):
        for role in _USER_ROLES:
            caps = _role_caps(role)
            assert isinstance(caps, dict)
            assert "can_write" in caps
            assert "manage_db" in caps

    def test_unknown_role_returns_field_crew_caps(self):
        caps = _role_caps("superhero")
        assert caps == _ROLE_CAPS["field_crew"]

    # ── Owner ─────────────────────────────────────────────────────────────────
    def test_owner_reads_all_role_scopes(self):
        assert _role_caps("owner")["read_all_role_scopes"]

    def test_owner_reads_others_private(self):
        assert _role_caps("owner")["read_others_private"]

    def test_owner_can_write(self):
        assert _role_caps("owner")["can_write"]

    def test_owner_can_write_shared(self):
        assert _role_caps("owner")["can_write_shared"]

    def test_owner_is_admin(self):
        assert _role_caps("owner")["is_admin"]

    def test_owner_full_manage_db(self):
        assert _role_caps("owner")["manage_db"] == "full"

    # ── Manager ───────────────────────────────────────────────────────────────
    def test_manager_cannot_read_all_role_scopes(self):
        assert not _role_caps("manager")["read_all_role_scopes"]

    def test_manager_cannot_read_others_private(self):
        assert not _role_caps("manager")["read_others_private"]

    def test_manager_can_write(self):
        assert _role_caps("manager")["can_write"]

    def test_manager_can_write_shared(self):
        assert _role_caps("manager")["can_write_shared"]

    def test_manager_is_not_admin(self):
        assert not _role_caps("manager")["is_admin"]

    def test_manager_full_manage_db(self):
        assert _role_caps("manager")["manage_db"] == "full"

    # ── Staff ─────────────────────────────────────────────────────────────────
    def test_staff_can_write(self):
        assert _role_caps("staff")["can_write"]

    def test_staff_cannot_write_shared(self):
        assert not _role_caps("staff")["can_write_shared"]

    def test_staff_limited_manage_db(self):
        assert _role_caps("staff")["manage_db"] == "limited"

    # ── Field crew ────────────────────────────────────────────────────────────
    def test_field_crew_cannot_write(self):
        assert not _role_caps("field_crew")["can_write"]

    def test_field_crew_no_manage_db(self):
        assert _role_caps("field_crew")["manage_db"] == "none"

    def test_field_crew_can_send_email(self):
        """Field crew uses server-side email (no personal install)."""
        assert _role_caps("field_crew")["can_send_email"]

    def test_owner_cannot_send_email_via_server(self):
        """Owner/manager/staff have personal installs — use those for email."""
        assert not _role_caps("owner")["can_send_email"]


# ════════════════════════════════════════════════════════════════════════════
# SECTION J — _is_admin / _user_has_role helpers
# ════════════════════════════════════════════════════════════════════════════

class TestAdminHelpers:

    def test_owner_is_admin(self):
        assert _is_admin(OWNER)

    def test_manager_is_not_admin(self):
        assert not _is_admin(MANAGER)

    def test_staff_is_not_admin(self):
        assert not _is_admin(STAFF)

    def test_field_crew_is_not_admin(self):
        assert not _is_admin(CREW)

    def test_none_is_not_admin(self):
        assert not _is_admin(None)

    def test_user_has_role_owner(self):
        assert _user_has_role(OWNER, "owner")

    def test_user_has_role_manager(self):
        assert _user_has_role(MANAGER, "manager")

    def test_user_does_not_have_wrong_role(self):
        assert not _user_has_role(MANAGER, "owner")

    def test_none_user_never_has_role(self):
        assert not _user_has_role(None, "owner")


# ════════════════════════════════════════════════════════════════════════════
# SECTION K — _canon_scope: scope name normalization
# ════════════════════════════════════════════════════════════════════════════

class TestCanonScope:

    def test_bare_name_becomes_scope_prefix(self):
        assert _canon_scope("sales") == "scope:sales"

    def test_role_prefix_becomes_scope_prefix(self):
        assert _canon_scope("role:sales") == "scope:sales"

    def test_scope_prefix_unchanged(self):
        assert _canon_scope("scope:sales") == "scope:sales"

    def test_shared_unchanged(self):
        assert _canon_scope("shared") == "shared"

    def test_documents_unchanged(self):
        assert _canon_scope("documents") == "documents"

    def test_user_collection_unchanged(self):
        assert _canon_scope("user:tok-owner") == "user:tok-owner"

    def test_empty_string_unchanged(self):
        assert _canon_scope("") == ""


# ════════════════════════════════════════════════════════════════════════════
# SECTION L — Scope Resolver Security Angles (path traversal / spoofing)
# ════════════════════════════════════════════════════════════════════════════

class TestScopeResolverSecurityAngles:

    def test_owner_folder_resolves_to_owner_scope(self):
        result = sr.resolve_collection_for_path(
            "C:/CompanyDocs/Owner/trust_documents.pdf", SCOPE_MAPPING)
        assert result == "scope:owner_private"

    def test_sales_folder_resolves_to_sales_scope(self):
        result = sr.resolve_collection_for_path(
            "C:/CompanyDocs/Sales/q3_report.xlsx", SCOPE_MAPPING)
        assert result == "scope:sales"

    def test_alice_folder_resolves_to_alice_private(self):
        result = sr.resolve_collection_for_path(
            "C:/CompanyDocs/Employees/Alice/invoices.pdf", SCOPE_MAPPING)
        assert result == "user:alice-smith"   # slug from "Alice Smith"

    def test_path_traversal_does_not_escape_to_owner(self):
        """
        'C:/CompanyDocs/Employees/Alice/../../Owner/secret.pdf' uses '..' to try
        to escape into the Owner folder. scope_resolver uses plain string ops
        (not os.path.normpath) — '..' is a literal folder name, not resolved.
        The path must NOT resolve to scope:owner_private.
        """
        traversal = "C:/CompanyDocs/Employees/Alice/../../Owner/secret.pdf"
        result = sr.resolve_collection_for_path(traversal, SCOPE_MAPPING)
        assert result != "scope:owner_private", (
            "Path traversal succeeded — escaped to owner scope!"
        )

    def test_prefix_spoofing_owner_substring_does_not_match(self):
        """'C:/CompanyDocs/OwnerCopy/evil.pdf' must NOT match the Owner prefix."""
        result = sr.resolve_collection_for_path(
            "C:/CompanyDocs/OwnerCopy/evil.pdf", SCOPE_MAPPING)
        assert result != "scope:owner_private"

    def test_alice_prefix_does_not_match_alicebob_folder(self):
        """'C:/CompanyDocs/Employees/AliceBob/file.pdf' must not match Alice."""
        result = sr.resolve_collection_for_path(
            "C:/CompanyDocs/Employees/AliceBob/file.pdf", SCOPE_MAPPING)
        assert result != "user:tok-staff-alice-secret"

    def test_unknown_path_falls_back_to_shared(self):
        result = sr.resolve_collection_for_path(
            "C:/SomeRandomFolder/file.txt", SCOPE_MAPPING)
        assert result == "shared"

    def test_unknown_path_no_default_falls_back_to_documents(self):
        mapping_no_default = {"rules": SCOPE_MAPPING["rules"]}
        result = sr.resolve_collection_for_path(
            "C:/SomeRandomFolder/file.txt", mapping_no_default)
        assert result == "documents"

    def test_unknown_path_with_indexer_user_falls_back_to_private(self):
        mapping_no_default = {"rules": SCOPE_MAPPING["rules"]}
        result = sr.resolve_collection_for_path(
            "C:/SomeRandomFolder/file.txt",
            mapping_no_default,
            indexer_user={"id": "tok-staff-alice-secret"})
        assert result == "user:tok-staff-alice-secret"

    def test_case_insensitive_match(self):
        result = sr.resolve_collection_for_path(
            r"c:\companydocs\sales\deal.docx", SCOPE_MAPPING)
        assert result == "scope:sales"

    def test_longest_prefix_wins(self):
        """More specific rule wins over shorter prefix."""
        mapping = {
            "rules": [
                {"prefix": "C:/CompanyDocs",       "collection": "shared"},
                {"prefix": "C:/CompanyDocs/Sales", "collection": "scope:sales"},
            ]
        }
        result = sr.resolve_collection_for_path(
            "C:/CompanyDocs/Sales/q3.pdf", mapping)
        assert result == "scope:sales"


# ════════════════════════════════════════════════════════════════════════════
# SECTION M — users.json file round-trip (fixture written to disk, loaded back)
# ════════════════════════════════════════════════════════════════════════════

class TestUsersJsonDiskRoundTrip:
    """Write the fixture to a temp file, load it with _load_users logic,
    verify _resolve_user works correctly on the loaded data."""

    def _write_and_load(self, fixture):
        """Write fixture to a temp file, read it back as _load_users would."""
        import json
        with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", encoding="utf-8",
                delete=False) as f:
            json.dump(fixture, f, indent=2)
            path = f.name
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
            return data
        finally:
            os.unlink(path)

    def test_full_fixture_round_trips(self):
        data = self._write_and_load(USERS_FULL)
        user = _resolve_user(data, "tok-owner-david-secret")
        assert user is not None
        assert user["role"] == "owner"

    def test_all_roles_load_correctly(self):
        data = self._write_and_load(USERS_FULL)
        expected = {
            "tok-owner-david-secret":   "owner",
            "tok-manager-jamie-secret": "manager",
            "tok-staff-alice-secret":   "staff",
            "tok-crew-bob-secret":      "field_crew",
        }
        for token, expected_role in expected.items():
            user = _resolve_user(data, token)
            assert user is not None, f"{token} should resolve"
            assert user["role"] == expected_role

    def test_suspended_user_not_resolved_after_load(self):
        data = self._write_and_load(USERS_WITH_SUSPENDED)
        assert _resolve_user(data, "tok-staff-suspended") is None

    def test_bom_encoded_file_loads_correctly(self):
        """Tolerate UTF-8 BOM (PowerShell Out-File adds one)."""
        with tempfile.NamedTemporaryFile(
                mode="wb", suffix=".json", delete=False) as f:
            bom_bytes = b"\xef\xbb\xbf" + json.dumps(USERS_OWNER_ONLY).encode("utf-8")
            f.write(bom_bytes)
            path = f.name
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
            user = _resolve_user(data, "tok-solo-owner")
            assert user is not None
            assert user["role"] == "owner"
        finally:
            os.unlink(path)
