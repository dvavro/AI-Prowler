"""
tests/mcp/test_index_path_private_only.py
============================================
Tests for the "private-only indexing" grant in index_path().

Background
----------
Previously, index_path() required manage_db capability at 'limited' or
above (staff+) — field_crew (manage_db='none') could never index,
regardless of whether they had a private collection configured.

Per an explicit design decision: any role with manage_db='none' but a
WORKING private collection should still be able to index — but only:
  1. Files/folders located inside their own personal directory
     (same containment check as the write-scoping feature).
  2. Content is force-routed to their own user:<id> collection, bypassing
     any company collection_map path→scope rule entirely.

A user with manage_db='none' and NO private collection configured still
cannot index at all — this grant does not create a new capability out of
nothing, it only extends an *existing* private collection to also accept
indexing, not just search/read/write.

Once indexed, content becomes semantically searchable via search_documents
like anything else — that's the whole point of allowing this at all.
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


def _field_crew(uid="jake-r"):
    return {"id": uid, "name": "Jake R", "role": "field_crew", "status": "active"}


def _staff(uid="karen-s"):
    return {"id": uid, "name": "Karen S", "role": "staff", "status": "active"}


class TestNoPrivateCollectionStillBlocked:
    """The grant only EXTENDS an existing private collection — it must not
    create indexing ability out of nothing."""

    def test_field_crew_no_private_dir_still_denied(self, mcp_mod, monkeypatch, tmp_path):
        user = _field_crew()
        target_file = tmp_path / "notes.txt"
        target_file.write_text("hello")

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_check_db_cap", lambda u, level: (False, "role 'field_crew' (manage_db='none') cannot index documents."))
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir", lambda ctx: ("blocked", None))
        monkeypatch.setattr(mcp_mod, "load_config", lambda: None)

        result = mcp_mod.index_path(directory=str(target_file), ctx=_make_ctx(user))
        assert "⛔" in result
        assert "cannot index" in result.lower() or "no db-management" in result.lower()


class TestPrivateOnlyGrant:

    def test_field_crew_with_private_dir_inside_allowed(self, mcp_mod, monkeypatch, tmp_path):
        """Core fix: field_crew WITH a private collection can index a file
        that's inside their own personal directory."""
        user = _field_crew()
        private_dir = tmp_path / "jake-r-private"
        private_dir.mkdir()
        target_file = private_dir / "field_notes.txt"
        target_file.write_text("job 1042 notes")

        captured = {}

        def _fake_index_file_list(paths, **kwargs):
            captured["paths"] = paths
            captured["resolver"] = kwargs.get("collection_resolver")
            return {"chunks": 3}

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_check_db_cap", lambda u, level: (False, "manage_db=none"))
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir", lambda ctx: ("scoped", private_dir))
        monkeypatch.setattr(mcp_mod, "load_config", lambda: None)
        monkeypatch.setattr(mcp_mod, "add_to_auto_update_list", lambda p: True)
        import rag_preprocessor
        monkeypatch.setattr(rag_preprocessor, "index_file_list", _fake_index_file_list)

        result = mcp_mod.index_path(directory=str(target_file), ctx=_make_ctx(user))

        assert "⛔" not in result
        assert captured.get("resolver") is not None
        # The forced resolver must route to the user's OWN collection,
        # regardless of the actual filepath passed to it.
        assert captured["resolver"]("C:/anything/at/all.txt") == "user:jake-r"

    def test_field_crew_with_private_dir_outside_denied(self, mcp_mod, monkeypatch, tmp_path):
        """A private collection does NOT grant indexing rights to files
        OUTSIDE that user's own personal directory."""
        user = _field_crew()
        private_dir = tmp_path / "jake-r-private"
        private_dir.mkdir()
        shared_dir = tmp_path / "shared"
        shared_dir.mkdir()
        target_file = shared_dir / "company_manual.pdf"
        target_file.write_text("company-wide content")

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_check_db_cap", lambda u, level: (False, "manage_db=none"))
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir", lambda ctx: ("scoped", private_dir))
        monkeypatch.setattr(mcp_mod, "load_config", lambda: None)

        result = mcp_mod.index_path(directory=str(target_file), ctx=_make_ctx(user))
        assert "⛔" in result
        assert "personal directory" in result.lower()

    def test_forced_resolver_bypasses_company_scope_rules(self, mcp_mod, monkeypatch, tmp_path):
        """Even if a company collection_map rule WOULD route this exact path
        to a shared/role scope, the private-only grant forces it to the
        user's own private collection instead — never company-wide."""
        user = _field_crew()
        private_dir = tmp_path / "jake-r-private"
        private_dir.mkdir()
        target_file = private_dir / "notes.txt"
        target_file.write_text("x")

        captured = {}

        def _fake_index_file_list(paths, **kwargs):
            captured["resolver"] = kwargs.get("collection_resolver")
            return {"chunks": 1}

        # A company rule that would normally route this path to a shared
        # scope — must NEVER be consulted for the private-only grant.
        def _company_resolver_that_should_not_be_used(fp):
            return "scope:sales"

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_check_db_cap", lambda u, level: (False, "manage_db=none"))
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir", lambda ctx: ("scoped", private_dir))
        monkeypatch.setattr(mcp_mod, "_build_collection_resolver",
                            lambda u: _company_resolver_that_should_not_be_used)
        monkeypatch.setattr(mcp_mod, "load_config", lambda: None)
        monkeypatch.setattr(mcp_mod, "add_to_auto_update_list", lambda p: True)
        import rag_preprocessor
        monkeypatch.setattr(rag_preprocessor, "index_file_list", _fake_index_file_list)

        mcp_mod.index_path(directory=str(target_file), ctx=_make_ctx(user))

        resolved = captured["resolver"](str(target_file))
        assert resolved == "user:jake-r"
        assert resolved != "scope:sales"


class TestExistingTiersUnaffected:

    def test_staff_still_uses_normal_resolver_not_private_only_path(self, mcp_mod, monkeypatch, tmp_path):
        """Staff (manage_db='limited') must take the EXISTING code path —
        _check_db_cap succeeds directly, the private-only branch never
        triggers, even if they happen to also have a private collection."""
        user = _staff()
        target_file = tmp_path / "doc.txt"
        target_file.write_text("x")

        _build_resolver_called = {"count": 0}

        def _normal_resolver(u):
            _build_resolver_called["count"] += 1
            return lambda fp: "scope:sales"

        captured = {}

        def _fake_index_file_list(paths, **kwargs):
            captured["resolver"] = kwargs.get("collection_resolver")
            return {"chunks": 1}

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_check_db_cap", lambda u, level: (True, "role 'staff' may index"))
        monkeypatch.setattr(mcp_mod, "_build_collection_resolver", _normal_resolver)
        # If the private-only branch were mistakenly entered, this being
        # called at all (staff already passed _check_db_cap) would be a bug —
        # ensure it's simply never consulted.
        monkeypatch.setattr(mcp_mod, "_user_private_write_dir",
                            lambda ctx: (_ for _ in ()).throw(AssertionError(
                                "should not be called when _check_db_cap already succeeded")))
        monkeypatch.setattr(mcp_mod, "load_config", lambda: None)
        monkeypatch.setattr(mcp_mod, "add_to_auto_update_list", lambda p: True)
        import rag_preprocessor
        monkeypatch.setattr(rag_preprocessor, "index_file_list", _fake_index_file_list)

        result = mcp_mod.index_path(directory=str(target_file), ctx=_make_ctx(user))

        assert "⛔" not in result
        assert _build_resolver_called["count"] == 1
        assert captured["resolver"]("anything") == "scope:sales"
