"""
tests/mcp/test_private_dir_isolation.py
========================================
Regression tests for private-directory access isolation in server mode.

WHY THESE TESTS EXIST
---------------------
The "Vicki bug" (found June 13 2026): Vicki Vavro (role=manager) was able to
call search_within_directory() and get results from David's private directory
(David-Vavro-Private), even though the access-control logic in
_scoped_collections_for_ctx() is designed to block this.

ROOT CAUSE — testing layer mismatch
------------------------------------
The 100+ unit tests in test_security_roles.py are PURE unit tests. They test
Python helper functions (_allowed_collections, _can_index, _can_purge_chunks,
etc.) in isolation with mock fixture data. They never attach a user identity
to a live MCP tool call.

When MCP tools are called directly (as all existing tests do), ctx=None, so
_current_user(ctx) returns None, which triggers the PERSONAL-MODE path —
single shared collection, no scope enforcement at all. The server-mode access
control code was never exercised by any test.

WHAT THESE TESTS DO DIFFERENTLY
---------------------------------
They monkey-patch _current_user() to return a specific user dict, then call
the MCP tool functions directly. This exercises the FULL code path:
  _current_user() -> _scoped_collections_for_ctx() -> ChromaDB query

This is the missing "integration shim" layer between:
  - Unit tests (pure Python, no DB)             <- existed
  - Live HTTP tests (real subprocess + token)   <- too heavy for CI
  - THIS FILE: in-process with identity mock    <- was missing

WHAT SHOULD PASS vs FAIL
--------------------------
  OK  David (owner) CAN read David-Vavro-Private
  OK  David (owner) CAN read Vicki-Vavro-Private   (owner sees all)
  BUG Vicki (manager) CANNOT read David-Vavro-Private
  OK  Vicki (manager) CAN read Vicki-Vavro-Private  (her own private)
  BUG Field crew CANNOT read David-Vavro-Private    (no private access)

Before the fix, the BUG tests FAIL (unauthorized access silently permitted).
After the fix, all tests PASS.
"""
from __future__ import annotations

import pytest
from unittest.mock import patch

# ── User fixtures ─────────────────────────────────────────────────────────────

DAVID_USER = {
    "id": "david-vavro",        # slug from "David Vavro" via _make_user_id()
    "name": "David Vavro",
    "role": "owner",
    "status": "active",
    "scopes": ["scope:office"],
    "private_collection_enabled": True,
}

VICKI_USER = {
    "id": "vicki-vavro",        # slug from "Vicki Vavro" via _make_user_id()
    "name": "Vicki Vavro",
    "role": "manager",
    "status": "active",
    "scopes": ["scope:sales", "scope:ops", "scope:office"],
    "private_collection_enabled": True,
}

FIELD_CREW_USER = {
    "id": "field-crew-member",  # slug from "Field Crew Member" via _make_user_id()
    "name": "Field Crew Member",
    "role": "field_crew",
    "status": "active",
    "scopes": ["field"],
    "private_collection_enabled": False,
}


@pytest.fixture(scope="module")
def mcp_mod():
    """Import ai_prowler_mcp once for this module. Uses the live DB."""
    import ai_prowler_mcp as m
    return m


def _call_search_as(mcp_mod, user_dict: dict, directory: str) -> str:
    """
    Call search_within_directory() with a mocked user identity.

    This is the key testing shim: we patch _current_user so that when
    _scoped_collections_for_ctx() asks 'who is this request?', it gets
    back our test user — exactly as the auth middleware would set it in
    production via request.state.user.
    """
    with patch.object(mcp_mod, "_current_user", return_value=user_dict):
        return mcp_mod.search_within_directory(
            query="any content",
            directory=directory,
            n_results=5,
            ctx=object(),  # non-None ctx triggers server-mode path
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section A — Owner access (David should see everything)
# ══════════════════════════════════════════════════════════════════════════════

class TestOwnerAccess:
    """Owner (David) must be able to read both private directories."""

    def test_owner_can_read_own_private_directory(self, mcp_mod):
        """David reads David-Vavro-Private — must succeed."""
        result = _call_search_as(mcp_mod, DAVID_USER, "David-Vavro-Private")
        assert "David-Vavro-Private" in result, (
            "Owner could not read their own private directory.\n"
            f"Got: {result[:300]}"
        )

    def test_owner_can_read_other_user_private_directory(self, mcp_mod):
        """David reads Vicki-Vavro-Private — owner sees all privates, must succeed."""
        result = _call_search_as(mcp_mod, DAVID_USER, "Vicki-Vavro-Private")
        assert "Vicki-Vavro-Private" in result, (
            "Owner could not read another user's private directory.\n"
            f"Got: {result[:300]}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section B — Manager access (Vicki must be blocked from David's private dir)
# ══════════════════════════════════════════════════════════════════════════════

class TestManagerAccessIsolation:
    """
    Manager (Vicki) must NOT be able to read the owner's private directory.
    This is the exact scenario that exposed the bug.
    """

    def test_manager_cannot_read_owner_private_directory(self, mcp_mod):
        """
        REGRESSION TEST — the Vicki bug.

        Vicki (manager) calls search_within_directory targeting
        David-Vavro-Private. She must get zero results, not David's content.

        Before the fix: this test FAILS (Vicki gets David's private docs).
        After the fix:  this test PASSES (zero results returned).
        """
        result = _call_search_as(mcp_mod, VICKI_USER, "David-Vavro-Private")
        assert "Test Private docs for David Vavro" not in result, (
            "SECURITY BUG: Manager (Vicki) can read owner's private directory!\n"
            f"Got: {result[:300]}"
        )
        assert (
            "0 chunk" in result.lower()
            or "no results" in result.lower()
            or "no document" in result.lower()
            or "access denied" in result.lower()
            or "Returning 0" in result
        ), (
            "Expected zero results or access-denied response.\n"
            f"Got: {result[:300]}"
        )

    def test_manager_can_read_own_private_directory(self, mcp_mod):
        """Vicki CAN read her own private directory — must succeed."""
        result = _call_search_as(mcp_mod, VICKI_USER, "Vicki-Vavro-Private")
        assert "Vicki-Vavro-Private" in result, (
            "Manager could not read their own private directory.\n"
            f"Got: {result[:300]}"
        )

    def test_manager_cannot_read_other_user_private_directory(self, mcp_mod):
        """General case: no manager should ever read another user's private dir."""
        result = _call_search_as(mcp_mod, VICKI_USER, "David-Vavro-Private")
        # Must not contain actual document content from David's private dir
        assert "Test Private docs for David Vavro" not in result, (
            "Manager can read another user's private directory — access leak!\n"
            f"Got: {result[:300]}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section C — Field crew access (no private collections at all)
# ══════════════════════════════════════════════════════════════════════════════

class TestFieldCrewAccessIsolation:
    """Field crew must not access ANY private directory."""

    def test_field_crew_cannot_read_owner_private_directory(self, mcp_mod):
        """Field crew targeting David-Vavro-Private must get zero results."""
        result = _call_search_as(mcp_mod, FIELD_CREW_USER, "David-Vavro-Private")
        assert "Test Private docs for David Vavro" not in result, (
            "SECURITY BUG: Field crew can read owner's private directory!\n"
            f"Got: {result[:300]}"
        )

    def test_field_crew_cannot_read_manager_private_directory(self, mcp_mod):
        """Field crew targeting Vicki-Vavro-Private must get zero results."""
        result = _call_search_as(mcp_mod, FIELD_CREW_USER, "Vicki-Vavro-Private")
        assert "Test Private docs for Vicki Vavro" not in result, (
            "SECURITY BUG: Field crew can read manager's private directory!\n"
            f"Got: {result[:300]}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section D — Verify the mock shim itself works (meta-tests)
# ══════════════════════════════════════════════════════════════════════════════

class TestMockShimVerification:
    """
    Confirm that _current_user is being correctly patched.
    If these fail, the test architecture is broken, not the production code.
    """

    def test_patch_returns_correct_user_for_david(self, mcp_mod):
        with patch.object(mcp_mod, "_current_user", return_value=DAVID_USER):
            result = mcp_mod._current_user(ctx=object())
            assert result["id"] == "david-vavro"
            assert result["role"] == "owner"

    def test_patch_returns_correct_user_for_vicki(self, mcp_mod):
        with patch.object(mcp_mod, "_current_user", return_value=VICKI_USER):
            result = mcp_mod._current_user(ctx=object())
            assert result["id"] == "vicki-vavro"
            assert result["role"] == "manager"

    def test_ctx_none_still_returns_none(self, mcp_mod):
        """Without patch, ctx=None must return None (personal mode)."""
        result = mcp_mod._current_user(None)
        assert result is None
