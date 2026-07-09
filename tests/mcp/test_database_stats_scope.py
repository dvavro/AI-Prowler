"""
tests/mcp/test_database_stats_scope.py
========================================
Tests for get_database_stats()'s server-mode scoping fix.

Background
----------
get_database_stats() previously always enumerated EVERY ChromaDB collection
via client.list_collections(), regardless of caller or mode — the one read
tool that didn't respect per-user scoping at all. In server mode, any role
(including field_crew) saw company-wide chunk/document totals covering
every other employee's private collection and every scope combined.

Personal mode is untouched (see test_database_stats_collections.py) — it
still enumerates ALL collections via client.list_collections(), which is
required to match check_ai_prowler_status() exactly and catch orphaned
scope collections left over from switching modes.

Server mode now uses _scoped_collections_for_ctx(ctx) instead — the same
function search_documents() and get_knowledge_base_overview() already use.
Owners (and managers with read_all_role_scopes) still see the full
company-wide total via their real entitlement inside that function;
staff/field_crew see only their own private + assigned scopes + shared.
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


def _fake_collection(n_chunks, ext="pdf", filepath="C:/docs/a.pdf"):
    col = MagicMock()
    col.count.return_value = n_chunks
    col.get.return_value = {
        "metadatas": [
            {"filepath": filepath, "extension": ext} for _ in range(n_chunks)
        ]
    }
    return col


class TestServerModeScoping:

    def test_server_mode_uses_scoped_collections_not_list_collections(self, mcp_mod, monkeypatch):
        """Core fix: server mode must call _scoped_collections_for_ctx(ctx),
        NOT client.list_collections() (which would be company-wide)."""
        user = {"id": "jake-r", "name": "Jake R", "role": "field_crew"}
        scoped_col = _fake_collection(3, filepath="C:/scope/jake_file.pdf")

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_scoped_collections_for_ctx",
                            lambda ctx: [scoped_col])

        # If get_database_stats still called client.list_collections()
        # under the hood, this fake client would be hit and the test would
        # see a totally different (and wrong) result — so patch it to
        # something that would obviously fail the assertions if called.
        fake_client = MagicMock()
        fake_client.list_collections.return_value = [MagicMock(name="scope-user-vicki-vavro")]
        import rag_preprocessor
        monkeypatch.setattr(rag_preprocessor, "get_chroma_client",
                            lambda: (fake_client, MagicMock()))

        result = mcp_mod.get_database_stats(ctx=_make_ctx(user))
        assert "Total chunks     : 3" in result
        fake_client.list_collections.assert_not_called()

    def test_server_mode_shows_scoped_note(self, mcp_mod, monkeypatch):
        """Server-mode output is labeled so it's clear the total isn't
        necessarily company-wide."""
        user = {"id": "jake-r", "name": "Jake R", "role": "field_crew"}
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_scoped_collections_for_ctx",
                            lambda ctx: [_fake_collection(1)])
        result = mcp_mod.get_database_stats(ctx=_make_ctx(user))
        assert "scoped to your accessible collections" in result

    def test_personal_mode_no_scoped_note(self, mcp_mod, monkeypatch):
        """Personal mode output must NOT carry the server-mode scoped
        label — it always covers the whole database."""
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        fake_client = MagicMock()
        fake_col = MagicMock()
        fake_col.name = "documents"
        fake_client.list_collections.return_value = [fake_col]
        fake_client.get_collection.return_value = _fake_collection(1)
        import rag_preprocessor
        monkeypatch.setattr(rag_preprocessor, "get_chroma_client",
                            lambda: (fake_client, MagicMock()))
        result = mcp_mod.get_database_stats(ctx=None)
        assert "scoped to your accessible collections" not in result

    def test_two_users_different_scopes_see_different_totals(self, mcp_mod, monkeypatch):
        """The actual leak this fix closes: two different server-mode users
        must be able to see DIFFERENT totals, proving neither sees the
        other's (or the whole company's) data by default."""
        user_a = {"id": "jake-r", "name": "Jake R", "role": "field_crew"}
        user_b = {"id": "vicki-vavro", "name": "Vicki Vavro", "role": "manager"}

        def _scoped(ctx):
            u = mcp_mod._current_user(ctx)
            if u["id"] == "jake-r":
                return [_fake_collection(3)]
            return [_fake_collection(9)]

        monkeypatch.setattr(mcp_mod, "_scoped_collections_for_ctx", _scoped)

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user_a)
        result_a = mcp_mod.get_database_stats(ctx=_make_ctx(user_a))

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user_b)
        result_b = mcp_mod.get_database_stats(ctx=_make_ctx(user_b))

        assert "Total chunks     : 3" in result_a
        assert "Total chunks     : 9" in result_b
        assert result_a != result_b

    def test_server_mode_empty_scope_returns_friendly_message(self, mcp_mod, monkeypatch):
        """A user with no accessible collections at all (e.g. no private dir,
        no assigned scopes) gets a clean empty message, not an error."""
        user = {"id": "new-hire", "name": "New Hire", "role": "field_crew"}
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_scoped_collections_for_ctx", lambda ctx: [])
        result = mcp_mod.get_database_stats(ctx=_make_ctx(user))
        assert "📭" in result
