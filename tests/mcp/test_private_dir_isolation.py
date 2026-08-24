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

SANDBOXED, NOT LIVE-DB (rewritten 2026-08-23)
-----------------------------------------------
This module used to be marked `@pytest.mark.live_db` and connect to the
REAL production ChromaDB at ~/AI-Prowler/rag_database, because it needed
real seeded "David-Vavro-Private" / "Vicki-Vavro-Private" sentinel
documents to assert against. That exposed it to an upstream chromadb/HNSW
race (documented in get_chroma_client()'s "Cold-init settle delay" —
confirmed capable of hanging the whole process with a native access
violation when anything else touches the live DB at the same moment —
found 2026-08-22, reproduced again 2026-08-23 while a live test run
collided with normal AI-Prowler usage).

Now uses the same isolated_env sandbox (tests/conftest.py) every other
test in this suite already relies on, with the two sentinel documents
seeded directly into it per-test via the seeded_env fixture below —
_scoped_collections_for_ctx()'s actual private-scope routing rules
(scope string "private:<user id>", per scope_lookup.allowed_scopes_for_user)
and search_within_directory()'s actual directory-matching metadata fields
(parent_directory / directory_chain, per its own docstring) are used
exactly as production does, just against sandboxed data instead of live.
No more live-DB hazard, and no more dependency on hand-maintained sentinel
documents living in the real production database.
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


@pytest.fixture
def mcp_mod():
    """Import ai_prowler_mcp. No DB access on its own — safe for the
    mock-shim-only tests in TestMockShimVerification."""
    import ai_prowler_mcp as m
    return m


@pytest.fixture
def seeded_env(isolated_env):
    """Sandboxed ChromaDB (isolated_env, tests/conftest.py) seeded with the
    same two sentinel documents the old live-DB version of this suite
    depended on finding already indexed in production. Function-scoped —
    re-seeds per test — to stay simple and fully isolated; the embedding
    cost of two short documents per test is negligible next to the
    correctness and safety this buys over sharing state across tests.

    Metadata mirrors exactly what production indexing/scoping produces:
      scope            -- "private:<user id>", per
                           scope_lookup.allowed_scopes_for_user()'s own
                           f"private:{user['id']}" convention
      parent_directory / directory_chain
                        -- what search_within_directory() actually
                           filters on (see its docstring/implementation)

    Returns the ai_prowler_mcp module (same role as the old live mcp_mod
    fixture), so _call_search_as() below needs no changes.
    """
    import ai_prowler_mcp as m
    rag = isolated_env.rag
    client, embedding_func = rag.get_chroma_client()
    coll = client.get_or_create_collection(
        name=rag.COLLECTION_NAME, embedding_function=embedding_func)
    coll.add(
        ids=["david-private-sentinel-1", "vicki-private-sentinel-1"],
        documents=[
            "Test Private docs for David Vavro",
            "Test Private docs for Vicki Vavro",
        ],
        metadatas=[
            {
                "scope": f"private:{DAVID_USER['id']}",
                "parent_directory": "David-Vavro-Private",
                "directory_chain": "David-Vavro-Private",
                "filepath": "David-Vavro-Private/note.txt",
            },
            {
                "scope": f"private:{VICKI_USER['id']}",
                "parent_directory": "Vicki-Vavro-Private",
                "directory_chain": "Vicki-Vavro-Private",
                "filepath": "Vicki-Vavro-Private/note.txt",
            },
        ],
    )
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

    def test_owner_can_read_own_private_directory(self, seeded_env):
        """David reads David-Vavro-Private — must succeed."""
        result = _call_search_as(seeded_env, DAVID_USER, "David-Vavro-Private")
        assert "David-Vavro-Private" in result, (
            "Owner could not read their own private directory.\n"
            f"Got: {result[:300]}"
        )

    def test_owner_can_read_other_user_private_directory(self, seeded_env):
        """David reads Vicki-Vavro-Private — owner sees all privates, must succeed."""
        result = _call_search_as(seeded_env, DAVID_USER, "Vicki-Vavro-Private")
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

    def test_manager_cannot_read_owner_private_directory(self, seeded_env):
        """
        REGRESSION TEST — the Vicki bug.

        Vicki (manager) calls search_within_directory targeting
        David-Vavro-Private. She must get zero results, not David's content.

        Before the fix: this test FAILS (Vicki gets David's private docs).
        After the fix:  this test PASSES (zero results returned).
        """
        result = _call_search_as(seeded_env, VICKI_USER, "David-Vavro-Private")
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

    def test_manager_can_read_own_private_directory(self, seeded_env):
        """Vicki CAN read her own private directory — must succeed."""
        result = _call_search_as(seeded_env, VICKI_USER, "Vicki-Vavro-Private")
        assert "Vicki-Vavro-Private" in result, (
            "Manager could not read their own private directory.\n"
            f"Got: {result[:300]}"
        )

    def test_manager_cannot_read_other_user_private_directory(self, seeded_env):
        """General case: no manager should ever read another user's private dir."""
        result = _call_search_as(seeded_env, VICKI_USER, "David-Vavro-Private")
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

    def test_field_crew_cannot_read_owner_private_directory(self, seeded_env):
        """Field crew targeting David-Vavro-Private must get zero results."""
        result = _call_search_as(seeded_env, FIELD_CREW_USER, "David-Vavro-Private")
        assert "Test Private docs for David Vavro" not in result, (
            "SECURITY BUG: Field crew can read owner's private directory!\n"
            f"Got: {result[:300]}"
        )

    def test_field_crew_cannot_read_manager_private_directory(self, seeded_env):
        """Field crew targeting Vicki-Vavro-Private must get zero results."""
        result = _call_search_as(seeded_env, FIELD_CREW_USER, "Vicki-Vavro-Private")
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
    No DB access needed — uses the plain mcp_mod fixture.
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
