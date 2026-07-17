"""
tests/mcp/test_reindex_collection_aware.py
=============================================
Tests for reindex_file, reindex_directory, and reindex_all.

HISTORY: originally written for the server-mode collection-awareness fix —
these tools used to always purge/rebuild against the single default
"documents" collection regardless of caller, even though index_path()
routed server-mode content into scoped collections (user:<id>,
scope:<name>, shared) via _build_collection_resolver(). The fix made
reindex_file/reindex_directory sweep purge across every physical
collection and pass a resolver into index_file_list()/index_directory()
so fresh chunks landed back in the "correct" collection.

SUPERSEDED 2026-07-16/17 (SCOPE_SIMPLIFICATION_SPEC.md section 3.7, Phase
7 cutover): there is only one physical collection now, so both halves of
that fix are gone — no collection sweep (purge targets the single
COLLECTION_NAME collection directly), and no collection_resolver is ever
built or passed (scope comes from build_scope_resolver()'s chunk-metadata
tag instead, tested separately). The role-based manage_db gate
(_check_db_cap) is also removed from all three tools — direct product
decision: indexing isn't a data leak, and every directory that can be
reindexed was already admin/owner-created and tracked in the first
place, so any authenticated (or personal-mode) caller may trigger it.

Personal mode remains completely unaffected either way.
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


def _owner(uid="david-vavro"):
    return {"id": uid, "name": "David Vavro", "role": "owner", "status": "active"}


def _staff(uid="karen-s"):
    return {"id": uid, "name": "Karen S", "role": "staff", "status": "active"}


def _field_crew(uid="jake-r"):
    return {"id": uid, "name": "Jake R", "role": "field_crew", "status": "active"}


class TestReindexFileSingleCollection:

    def test_purges_only_the_single_collection(self, mcp_mod, monkeypatch, tmp_path):
        """reindex_file purges from the one physical collection directly --
        no sweep across client.list_collections()."""
        user = _owner()
        target = tmp_path / "notes.txt"
        target.write_text("hello")

        fake_coll = MagicMock()
        fake_client = MagicMock()
        fake_client.get_or_create_collection.return_value = fake_coll

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_resolve_allowlisted_path", lambda fp: (str(target), None))

        import rag_preprocessor
        monkeypatch.setattr(rag_preprocessor, "get_chroma_client", lambda: (fake_client, MagicMock()))
        monkeypatch.setattr(rag_preprocessor, "COLLECTION_NAME", "documents")
        monkeypatch.setattr(rag_preprocessor, "index_file_list",
                            lambda paths, **kw: {"chunks": 1})

        mcp_mod.reindex_file(filepath=str(target), ctx=_make_ctx(user))

        fake_client.get_or_create_collection.assert_called_once()
        fake_coll.delete.assert_called_once()
        # No collection-sweep API should ever be touched.
        fake_client.list_collections.assert_not_called()

    def test_no_collection_resolver_ever_passed(self, mcp_mod, monkeypatch, tmp_path):
        user = _owner()
        target = tmp_path / "notes.txt"
        target.write_text("hello")

        fake_client = MagicMock()
        fake_client.get_or_create_collection.return_value = MagicMock()

        captured = {}
        def _fake_index_file_list(paths, **kw):
            captured["kwargs"] = kw
            return {"chunks": 1}

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_resolve_allowlisted_path", lambda fp: (str(target), None))

        import rag_preprocessor
        monkeypatch.setattr(rag_preprocessor, "get_chroma_client", lambda: (fake_client, MagicMock()))
        monkeypatch.setattr(rag_preprocessor, "COLLECTION_NAME", "documents")
        monkeypatch.setattr(rag_preprocessor, "index_file_list", _fake_index_file_list)

        mcp_mod.reindex_file(filepath=str(target), ctx=_make_ctx(user))

        assert "collection_resolver" not in captured["kwargs"]
        assert captured["kwargs"].get("indexer_user") == user

    def test_personal_mode_unaffected(self, mcp_mod, monkeypatch, tmp_path):
        target = tmp_path / "notes.txt"
        target.write_text("hello")

        fake_client = MagicMock()
        fake_client.get_or_create_collection.return_value = MagicMock()

        captured = {}
        def _fake_index_file_list(paths, **kw):
            captured["kwargs"] = kw
            return {"chunks": 1}

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        monkeypatch.setattr(mcp_mod, "_resolve_allowlisted_path", lambda fp: (str(target), None))

        import rag_preprocessor
        monkeypatch.setattr(rag_preprocessor, "get_chroma_client", lambda: (fake_client, MagicMock()))
        monkeypatch.setattr(rag_preprocessor, "COLLECTION_NAME", "documents")
        monkeypatch.setattr(rag_preprocessor, "index_file_list", _fake_index_file_list)

        mcp_mod.reindex_file(filepath=str(target), ctx=None)

        assert "collection_resolver" not in captured["kwargs"]
        assert captured["kwargs"].get("indexer_user") is None

    def test_role_gate_removed_staff_can_reindex(self, mcp_mod, monkeypatch, tmp_path):
        """The old role gate (owner/manager only) is gone -- staff can now
        call reindex_file directly, same as any other authenticated user."""
        user = _staff()
        target = tmp_path / "notes.txt"
        target.write_text("hello")

        fake_client = MagicMock()
        fake_client.get_or_create_collection.return_value = MagicMock()

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_resolve_allowlisted_path", lambda fp: (str(target), None))

        import rag_preprocessor
        monkeypatch.setattr(rag_preprocessor, "get_chroma_client", lambda: (fake_client, MagicMock()))
        monkeypatch.setattr(rag_preprocessor, "COLLECTION_NAME", "documents")
        monkeypatch.setattr(rag_preprocessor, "index_file_list",
                            lambda paths, **kw: {"chunks": 1})

        result = mcp_mod.reindex_file(filepath=str(target), ctx=_make_ctx(user))
        assert "⛔" not in result

    def test_role_gate_removed_field_crew_can_reindex(self, mcp_mod, monkeypatch, tmp_path):
        user = _field_crew()
        target = tmp_path / "notes.txt"
        target.write_text("hello")

        fake_client = MagicMock()
        fake_client.get_or_create_collection.return_value = MagicMock()

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_resolve_allowlisted_path", lambda fp: (str(target), None))

        import rag_preprocessor
        monkeypatch.setattr(rag_preprocessor, "get_chroma_client", lambda: (fake_client, MagicMock()))
        monkeypatch.setattr(rag_preprocessor, "COLLECTION_NAME", "documents")
        monkeypatch.setattr(rag_preprocessor, "index_file_list",
                            lambda paths, **kw: {"chunks": 1})

        result = mcp_mod.reindex_file(filepath=str(target), ctx=_make_ctx(user))
        assert "⛔" not in result


class TestReindexDirectorySingleCollection:

    def test_purges_only_the_single_collection(self, mcp_mod, monkeypatch, tmp_path):
        user = _owner()
        target_dir = tmp_path / "companydocs"
        target_dir.mkdir()

        fake_coll = MagicMock()
        fake_coll.get.return_value = {"ids": [], "metadatas": []}
        fake_client = MagicMock()
        fake_client.get_or_create_collection.return_value = fake_coll

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_resolve_allowlisted_path", lambda d: (str(target_dir), None))
        monkeypatch.setattr(mcp_mod, "_prewarm_event", MagicMock(wait=lambda timeout: True))

        import ai_prowler_mcp as _mod
        monkeypatch.setattr(_mod, "_engine", MagicMock(
            get_chroma_client=lambda: (fake_client, MagicMock()),
            COLLECTION_NAME="documents"))
        monkeypatch.setattr(mcp_mod, "index_directory",
                            lambda d, **kw: {"files_indexed": 1, "chunks_added": 1})

        mcp_mod.reindex_directory(directory=str(target_dir), ctx=_make_ctx(user))

        fake_client.get_or_create_collection.assert_called_once()
        fake_client.list_collections.assert_not_called()

    def test_no_collection_resolver_ever_passed(self, mcp_mod, monkeypatch, tmp_path):
        user = _owner()
        target_dir = tmp_path / "companydocs"
        target_dir.mkdir()

        fake_coll = MagicMock()
        fake_coll.get.return_value = {"ids": [], "metadatas": []}
        fake_client = MagicMock()
        fake_client.get_or_create_collection.return_value = fake_coll

        captured = {}
        def _fake_index_directory(d, **kw):
            captured["kwargs"] = kw
            return {"files_indexed": 2, "chunks_added": 5}

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_resolve_allowlisted_path", lambda d: (str(target_dir), None))
        monkeypatch.setattr(mcp_mod, "_prewarm_event", MagicMock(wait=lambda timeout: True))

        import ai_prowler_mcp as _mod
        monkeypatch.setattr(_mod, "_engine", MagicMock(
            get_chroma_client=lambda: (fake_client, MagicMock()),
            COLLECTION_NAME="documents"))
        monkeypatch.setattr(mcp_mod, "index_directory", _fake_index_directory)

        mcp_mod.reindex_directory(directory=str(target_dir), ctx=_make_ctx(user))

        assert "collection_resolver" not in captured["kwargs"]
        assert captured["kwargs"].get("indexer_user") == user

    def test_personal_mode_unaffected(self, mcp_mod, monkeypatch, tmp_path):
        target_dir = tmp_path / "companydocs"
        target_dir.mkdir()

        fake_coll = MagicMock()
        fake_coll.get.return_value = {"ids": [], "metadatas": []}
        fake_client = MagicMock()
        fake_client.get_or_create_collection.return_value = fake_coll

        captured = {}
        def _fake_index_directory(d, **kw):
            captured["kwargs"] = kw
            return {"files_indexed": 1, "chunks_added": 1}

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        monkeypatch.setattr(mcp_mod, "_resolve_allowlisted_path", lambda d: (str(target_dir), None))
        monkeypatch.setattr(mcp_mod, "_prewarm_event", MagicMock(wait=lambda timeout: True))

        import ai_prowler_mcp as _mod
        monkeypatch.setattr(_mod, "_engine", MagicMock(
            get_chroma_client=lambda: (fake_client, MagicMock()),
            COLLECTION_NAME="documents"))
        monkeypatch.setattr(mcp_mod, "index_directory", _fake_index_directory)

        mcp_mod.reindex_directory(directory=str(target_dir), ctx=None)

        assert "collection_resolver" not in captured["kwargs"]
        assert captured["kwargs"].get("indexer_user") is None

    def test_role_gate_removed_field_crew_can_reindex_directory(self, mcp_mod, monkeypatch, tmp_path):
        user = _field_crew()
        target_dir = tmp_path / "companydocs"
        target_dir.mkdir()

        fake_coll = MagicMock()
        fake_coll.get.return_value = {"ids": [], "metadatas": []}
        fake_client = MagicMock()
        fake_client.get_or_create_collection.return_value = fake_coll

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_resolve_allowlisted_path", lambda d: (str(target_dir), None))
        monkeypatch.setattr(mcp_mod, "_prewarm_event", MagicMock(wait=lambda timeout: True))

        import ai_prowler_mcp as _mod
        monkeypatch.setattr(_mod, "_engine", MagicMock(
            get_chroma_client=lambda: (fake_client, MagicMock()),
            COLLECTION_NAME="documents"))
        monkeypatch.setattr(mcp_mod, "index_directory",
                            lambda d, **kw: {"files_indexed": 1, "chunks_added": 1})

        result = mcp_mod.reindex_directory(directory=str(target_dir), ctx=_make_ctx(user))
        assert "⛔" not in result


class TestReindexAllRoleGateRemoved:

    def test_reindex_all_delegates_ctx_to_reindex_directory(self, mcp_mod, monkeypatch):
        """reindex_all must still pass ctx through to reindex_directory for
        each tracked directory -- unaffected by the role-gate removal."""
        user = _owner()
        captured_ctxs = []

        def _fake_reindex_directory(d, purge_first=True, ctx=None):
            captured_ctxs.append(ctx)
            return "✅ Reindex complete for: fake\n   Files indexed : 1\n   Chunks created: 1\n"

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: ["C:/dir1", "C:/dir2"])
        monkeypatch.setattr(mcp_mod, "_prewarm_event", MagicMock(wait=lambda timeout: True))
        monkeypatch.setattr(mcp_mod, "reindex_directory", _fake_reindex_directory)

        result = mcp_mod.reindex_all(ctx=_make_ctx(user))

        assert len(captured_ctxs) == 2
        assert "⛔" not in result

    def test_role_gate_removed_staff_can_reindex_all(self, mcp_mod, monkeypatch):
        user = _staff()

        def _fake_reindex_directory(d, purge_first=True, ctx=None):
            return "✅ Reindex complete for: fake\n   Files indexed : 1\n   Chunks created: 1\n"

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: ["C:/dir1"])
        monkeypatch.setattr(mcp_mod, "_prewarm_event", MagicMock(wait=lambda timeout: True))
        monkeypatch.setattr(mcp_mod, "reindex_directory", _fake_reindex_directory)

        result = mcp_mod.reindex_all(ctx=_make_ctx(user))
        assert "⛔" not in result
