"""
tests/mcp/test_reindex_collection_aware.py
=============================================
Tests for the server-mode collection-awareness fix in reindex_file,
reindex_directory, and reindex_all.

Background
----------
All three previously always purged and rebuilt against the single default
"documents" collection, regardless of caller or mode — even though
index_path() correctly routes server-mode content into scoped collections
(user:<id>, scope:<name>, shared) via _build_collection_resolver().

If a file/directory's content actually lived in a scoped collection (e.g.
a field_crew member's private area), reindexing it would:
  1. Fail to purge the stale chunks from the REAL collection (only
     "documents" was ever checked).
  2. Write fresh chunks into "documents" — the shared, company-wide
     collection — instead of back into the original scoped collection.

Net effect: previously-private content would get duplicated into the
shared collection, visible to every role, while a stale copy lingered in
the original private collection.

Fixed by:
  - reindex_file / reindex_directory now purge stale chunks from EVERY
    collection (via client.list_collections()), not just "documents".
  - Both now pass collection_resolver=_build_collection_resolver(user)
    (server mode) into index_file_list()/index_directory(), so fresh
    chunks land back in the correct collection per current company rules.
  - reindex_all needs no separate fix — it delegates to reindex_directory
    for each tracked directory and inherits the fix automatically.

Personal mode (ctx has no user) is completely unchanged — resolver stays
None, exactly matching pre-fix behavior (single "documents" collection).

Role gating (owner/manager only, via _check_db_cap(user, "full")) is
unchanged and re-verified here for completeness.
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


def _fake_collection(name, chunks_with_this_filepath=0, source_path="C:/some/dir/file.txt"):
    col = MagicMock()
    col.name = name
    col.delete = MagicMock()
    col.get = MagicMock(return_value={
        "ids": [f"{name}-chunk-{i}" for i in range(chunks_with_this_filepath)],
        "metadatas": [{"source": source_path} for _ in range(chunks_with_this_filepath)],
    })
    return col


class TestReindexFileCollectionAware:

    def test_purges_across_all_collections_not_just_documents(self, mcp_mod, monkeypatch, tmp_path):
        """Core fix: reindex_file must check EVERY collection for stale
        chunks belonging to this file, not just 'documents'."""
        user = _owner()
        target = tmp_path / "notes.txt"
        target.write_text("hello")

        col_documents = _fake_collection("documents")
        col_private = _fake_collection("user:jake-r")
        col_scope = _fake_collection("scope:sales")
        fake_client = MagicMock()
        fake_client.list_collections.return_value = [col_documents, col_private, col_scope]
        fake_client.get_collection.side_effect = lambda name, embedding_function=None: {
            "documents": col_documents, "user:jake-r": col_private, "scope:sales": col_scope,
        }[name]

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_check_db_cap", lambda u, level: (True, "owner"))
        monkeypatch.setattr(mcp_mod, "_resolve_allowlisted_path", lambda fp: (str(target), None))
        monkeypatch.setattr(mcp_mod, "_build_collection_resolver", lambda u: (lambda fp: "user:jake-r"))

        import rag_preprocessor
        monkeypatch.setattr(rag_preprocessor, "get_chroma_client", lambda: (fake_client, MagicMock()))
        monkeypatch.setattr(rag_preprocessor, "index_file_list",
                            lambda paths, **kw: {"chunks": 1})

        mcp_mod.reindex_file(filepath=str(target), ctx=_make_ctx(user))

        # ALL THREE collections must have been checked/purged, not just "documents".
        col_documents.delete.assert_called_once()
        col_private.delete.assert_called_once()
        col_scope.delete.assert_called_once()

    def test_reindexes_into_resolver_collection_not_documents(self, mcp_mod, monkeypatch, tmp_path):
        """Fresh chunks must go into the collection the resolver says this
        file belongs to now — not blindly into 'documents'."""
        user = _owner()
        target = tmp_path / "notes.txt"
        target.write_text("hello")

        fake_client = MagicMock()
        fake_client.list_collections.return_value = []

        captured = {}
        def _fake_index_file_list(paths, **kw):
            captured["collection_resolver"] = kw.get("collection_resolver")
            captured["indexer_user"] = kw.get("indexer_user")
            return {"chunks": 1}

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_check_db_cap", lambda u, level: (True, "owner"))
        monkeypatch.setattr(mcp_mod, "_resolve_allowlisted_path", lambda fp: (str(target), None))
        monkeypatch.setattr(mcp_mod, "_build_collection_resolver",
                            lambda u: (lambda fp: "scope:sales"))

        import rag_preprocessor
        monkeypatch.setattr(rag_preprocessor, "get_chroma_client", lambda: (fake_client, MagicMock()))
        monkeypatch.setattr(rag_preprocessor, "index_file_list", _fake_index_file_list)

        mcp_mod.reindex_file(filepath=str(target), ctx=_make_ctx(user))

        assert captured["collection_resolver"] is not None
        assert captured["collection_resolver"]("anything") == "scope:sales"
        assert captured["indexer_user"] == user

    def test_personal_mode_resolver_is_none(self, mcp_mod, monkeypatch, tmp_path):
        """Personal mode: no resolver at all — unchanged, single default
        collection behavior."""
        target = tmp_path / "notes.txt"
        target.write_text("hello")

        fake_client = MagicMock()
        fake_client.list_collections.return_value = []

        captured = {}
        def _fake_index_file_list(paths, **kw):
            captured["collection_resolver"] = kw.get("collection_resolver")
            captured["indexer_user"] = kw.get("indexer_user")
            return {"chunks": 1}

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        monkeypatch.setattr(mcp_mod, "_check_db_cap", lambda u, level: (True, "personal mode"))
        monkeypatch.setattr(mcp_mod, "_resolve_allowlisted_path", lambda fp: (str(target), None))

        import rag_preprocessor
        monkeypatch.setattr(rag_preprocessor, "get_chroma_client", lambda: (fake_client, MagicMock()))
        monkeypatch.setattr(rag_preprocessor, "index_file_list", _fake_index_file_list)

        mcp_mod.reindex_file(filepath=str(target), ctx=None)

        assert captured["collection_resolver"] is None
        assert captured["indexer_user"] is None

    def test_role_gate_unaffected_staff_blocked(self, mcp_mod, monkeypatch, tmp_path):
        """Re-verify role gating still works: staff (manage_db != full)
        cannot call reindex_file at all."""
        user = {"id": "karen-s", "name": "Karen S", "role": "staff", "status": "active"}
        target = tmp_path / "notes.txt"
        target.write_text("hello")

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_check_db_cap",
                            lambda u, level: (False, "role 'staff' cannot reindex"))

        result = mcp_mod.reindex_file(filepath=str(target), ctx=_make_ctx(user))
        assert "⛔" in result


class TestReindexDirectoryCollectionAware:

    def test_purges_across_all_collections_not_just_documents(self, mcp_mod, monkeypatch, tmp_path):
        user = _owner()
        target_dir = tmp_path / "companydocs"
        target_dir.mkdir()

        col_documents = _fake_collection("documents", chunks_with_this_filepath=1,
                                         source_path=str(target_dir / "a.txt"))
        col_private = _fake_collection("user:jake-r", chunks_with_this_filepath=1,
                                       source_path=str(target_dir / "b.txt"))
        fake_client = MagicMock()
        fake_client.list_collections.return_value = [col_documents, col_private]
        fake_client.get_collection.side_effect = lambda name: {
            "documents": col_documents, "user:jake-r": col_private,
        }[name]

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_check_db_cap", lambda u, level: (True, "owner"))
        monkeypatch.setattr(mcp_mod, "_resolve_allowlisted_path", lambda d: (str(target_dir), None))
        monkeypatch.setattr(mcp_mod, "_build_collection_resolver", lambda u: (lambda fp: "documents"))
        monkeypatch.setattr(mcp_mod, "_prewarm_event", MagicMock(wait=lambda timeout: True))
        monkeypatch.setattr(mcp_mod, "_normalize_path_for_match",
                            lambda p: p.replace("\\", "/").rstrip("/").lower())

        import ai_prowler_mcp as _mod
        monkeypatch.setattr(_mod, "_engine", MagicMock(get_chroma_client=lambda: fake_client))
        monkeypatch.setattr(mcp_mod, "index_directory", lambda d, **kw: {"files_indexed": 1, "chunks_added": 1})

        mcp_mod.reindex_directory(directory=str(target_dir), ctx=_make_ctx(user))

        col_documents.delete.assert_called_once()
        col_private.delete.assert_called_once()

    def test_reindexes_via_resolver(self, mcp_mod, monkeypatch, tmp_path):
        user = _owner()
        target_dir = tmp_path / "companydocs"
        target_dir.mkdir()

        fake_client = MagicMock()
        fake_client.list_collections.return_value = []

        captured = {}
        def _fake_index_directory(d, **kw):
            captured["collection_resolver"] = kw.get("collection_resolver")
            captured["indexer_user"] = kw.get("indexer_user")
            return {"files_indexed": 2, "chunks_added": 5}

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_check_db_cap", lambda u, level: (True, "owner"))
        monkeypatch.setattr(mcp_mod, "_resolve_allowlisted_path", lambda d: (str(target_dir), None))
        monkeypatch.setattr(mcp_mod, "_build_collection_resolver", lambda u: (lambda fp: "scope:sales"))
        monkeypatch.setattr(mcp_mod, "_prewarm_event", MagicMock(wait=lambda timeout: True))

        import ai_prowler_mcp as _mod
        monkeypatch.setattr(_mod, "_engine", MagicMock(get_chroma_client=lambda: fake_client))
        monkeypatch.setattr(mcp_mod, "index_directory", _fake_index_directory)

        mcp_mod.reindex_directory(directory=str(target_dir), ctx=_make_ctx(user))

        assert captured["collection_resolver"]("anything") == "scope:sales"
        assert captured["indexer_user"] == user

    def test_personal_mode_resolver_is_none(self, mcp_mod, monkeypatch, tmp_path):
        target_dir = tmp_path / "companydocs"
        target_dir.mkdir()

        fake_client = MagicMock()
        fake_client.list_collections.return_value = []

        captured = {}
        def _fake_index_directory(d, **kw):
            captured["collection_resolver"] = kw.get("collection_resolver")
            captured["indexer_user"] = kw.get("indexer_user")
            return {"files_indexed": 1, "chunks_added": 1}

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        monkeypatch.setattr(mcp_mod, "_check_db_cap", lambda u, level: (True, "personal mode"))
        monkeypatch.setattr(mcp_mod, "_resolve_allowlisted_path", lambda d: (str(target_dir), None))
        monkeypatch.setattr(mcp_mod, "_prewarm_event", MagicMock(wait=lambda timeout: True))

        import ai_prowler_mcp as _mod
        monkeypatch.setattr(_mod, "_engine", MagicMock(get_chroma_client=lambda: fake_client))
        monkeypatch.setattr(mcp_mod, "index_directory", _fake_index_directory)

        mcp_mod.reindex_directory(directory=str(target_dir), ctx=None)

        assert captured["collection_resolver"] is None
        assert captured["indexer_user"] is None


class TestReindexAllInheritsFix:

    def test_reindex_all_delegates_ctx_to_reindex_directory(self, mcp_mod, monkeypatch):
        """reindex_all must pass ctx through to reindex_directory for each
        tracked directory — that's how it inherits the collection-aware fix
        without needing its own separate implementation."""
        user = _owner()
        captured_ctxs = []

        def _fake_reindex_directory(d, purge_first=True, ctx=None):
            captured_ctxs.append(ctx)
            return "✅ Reindex complete for: fake\n   Files indexed : 1\n   Chunks created: 1\n"

        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(mcp_mod, "_check_db_cap", lambda u, level: (True, "owner"))
        monkeypatch.setattr(mcp_mod, "load_auto_update_list", lambda: ["C:/dir1", "C:/dir2"])
        monkeypatch.setattr(mcp_mod, "_prewarm_event", MagicMock(wait=lambda timeout: True))
        monkeypatch.setattr(mcp_mod, "reindex_directory", _fake_reindex_directory)

        real_ctx = _make_ctx(user)
        mcp_mod.reindex_all(ctx=real_ctx)

        assert len(captured_ctxs) == 2
        assert all(c is real_ctx for c in captured_ctxs)
