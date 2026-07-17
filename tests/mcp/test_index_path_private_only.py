"""
tests/mcp/test_index_path_private_only.py
============================================
Tests for who is allowed to call index_path() via MCP.

HISTORY: originally written for the "private-only indexing" grant —
manage_db='none' roles (field_crew) could only index if they had a
private collection configured, and only inside their own personal
directory, with every chunk force-routed to their own user:<id>
collection bypassing any company collection_map rule.

SUPERSEDED 2026-07-16/17 (SCOPE_SIMPLIFICATION_SPEC.md section 3.7, Phase
7 cutover): direct product decision — indexing is not a data leak (only
search is), and every directory that can be indexed was already created
and tracked by an admin/owner in the first place, so there's no
arbitrary-path risk in letting any authenticated user trigger indexing.
The role-based manage_db gate (_check_db_cap) is removed from index_path
entirely, along with the narrower "private collection = indexing confined
to own directory, force-routed to own collection" carve-out that
depended on it. Any authenticated (or personal-mode) caller may now index
any path. Content always lands in the single unified index;
build_scope_resolver() (tested separately in
tests/unit/test_build_scope_resolver.py) still automatically tags
anything under a <slug>-private folder as "private:<their own id>" via
path-convention detection, so a user's own private content stays exactly
as private as before at SEARCH time (allowed_scopes()) — nothing here
weakens that, since the write-time role gate was never the actual
confidentiality boundary.
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


class TestAnyRoleCanIndexAnyPath:
    """The role-based gate is gone entirely -- field_crew, staff, whoever,
    can all trigger indexing, on any path, with no confinement and no
    forced collection routing. This is the direct replacement for the
    old TestNoPrivateCollectionStillBlocked / TestPrivateOnlyGrant /
    TestExistingTiersUnaffected classes."""

    def test_field_crew_with_no_private_dir_can_still_index(self, mcp_mod, monkeypatch, tmp_path):
        """The old grant required a private collection to be configured at
        all -- that requirement is gone too. field_crew can index even
        with no private collection set up."""
        user = _field_crew()
        target_file = tmp_path / "notes.txt"
        target_file.write_text("hello")

        captured = {}

        def _fake_index_file_list(paths, **kwargs):
            captured["paths"] = paths
            captured["kwargs"] = kwargs
            return {"chunks": 1}

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_config", lambda: None)
        monkeypatch.setattr(mcp_mod, "add_to_auto_update_list", lambda p: True)
        import rag_preprocessor
        monkeypatch.setattr(rag_preprocessor, "index_file_list", _fake_index_file_list)

        result = mcp_mod.index_path(directory=str(target_file), ctx=_make_ctx(user))

        assert "⛔" not in result
        assert captured.get("paths")

    def test_field_crew_can_index_outside_any_personal_directory(self, mcp_mod, monkeypatch, tmp_path):
        """The old grant explicitly denied indexing OUTSIDE the user's own
        personal directory. That confinement is gone -- field_crew can
        index a path with no relation to their own directory at all."""
        user = _field_crew()
        shared_dir = tmp_path / "shared"
        shared_dir.mkdir()
        target_file = shared_dir / "company_manual.pdf"
        target_file.write_text("company-wide content")

        captured = {}

        def _fake_index_file_list(paths, **kwargs):
            captured["kwargs"] = kwargs
            return {"chunks": 1}

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_config", lambda: None)
        monkeypatch.setattr(mcp_mod, "add_to_auto_update_list", lambda p: True)
        import rag_preprocessor
        monkeypatch.setattr(rag_preprocessor, "index_file_list", _fake_index_file_list)

        result = mcp_mod.index_path(directory=str(target_file), ctx=_make_ctx(user))

        assert "⛔" not in result

    def test_no_collection_resolver_is_ever_built_or_passed(self, mcp_mod, monkeypatch, tmp_path):
        """Regardless of role, index_file_list must never receive a
        collection_resolver kwarg at all -- there is only one physical
        collection now, and scope comes from chunk metadata instead."""
        user = _field_crew()
        target_file = tmp_path / "notes.txt"
        target_file.write_text("x")

        captured = {}

        def _fake_index_file_list(paths, **kwargs):
            captured["kwargs"] = kwargs
            return {"chunks": 1}

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_config", lambda: None)
        monkeypatch.setattr(mcp_mod, "add_to_auto_update_list", lambda p: True)
        import rag_preprocessor
        monkeypatch.setattr(rag_preprocessor, "index_file_list", _fake_index_file_list)

        mcp_mod.index_path(directory=str(target_file), ctx=_make_ctx(user))

        assert captured.get("kwargs", {}).get("collection_resolver") is None

    def test_staff_indexing_unaffected_in_shape(self, mcp_mod, monkeypatch, tmp_path):
        """Staff continue to be able to index, same as before -- just
        without any resolver being built for them either now."""
        user = _staff()
        target_file = tmp_path / "doc.txt"
        target_file.write_text("x")

        captured = {}

        def _fake_index_file_list(paths, **kwargs):
            captured["kwargs"] = kwargs
            return {"chunks": 1}

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_config", lambda: None)
        monkeypatch.setattr(mcp_mod, "add_to_auto_update_list", lambda p: True)
        import rag_preprocessor
        monkeypatch.setattr(rag_preprocessor, "index_file_list", _fake_index_file_list)

        result = mcp_mod.index_path(directory=str(target_file), ctx=_make_ctx(user))

        assert "⛔" not in result
        assert captured.get("kwargs", {}).get("collection_resolver") is None

    def test_personal_mode_unaffected(self, mcp_mod, monkeypatch, tmp_path):
        """No user at all (personal mode) -- always allowed, unchanged
        from before this cutover; confirms the None-user path still works
        with the gate removed."""
        target_file = tmp_path / "doc.txt"
        target_file.write_text("x")

        captured = {}

        def _fake_index_file_list(paths, **kwargs):
            captured["kwargs"] = kwargs
            return {"chunks": 1}

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        monkeypatch.setattr(mcp_mod, "load_config", lambda: None)
        monkeypatch.setattr(mcp_mod, "add_to_auto_update_list", lambda p: True)
        import rag_preprocessor
        monkeypatch.setattr(rag_preprocessor, "index_file_list", _fake_index_file_list)

        result = mcp_mod.index_path(directory=str(target_file), ctx=None)

        assert "⛔" not in result
