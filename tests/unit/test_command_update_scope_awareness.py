"""
tests/unit/test_command_update_scope_awareness.py
====================================================
Tests for command_update()'s collection behavior.

HISTORY: originally written 2026-07-13 after the "Christina incident" --
under the old multi-collection architecture, the Scheduled Task's
standalone CLI invocation (rag_auto_update.bat, which has no acting
user/session) always silently indexed into the single default
"documents" collection regardless of server-mode collection_map rules,
orphaning an employee's file into the wrong collection. The original fix
added an internal auto-detection block to command_update() that consulted
collection_map (via _resolve_unattended_directory_scope) even with no
caller-supplied resolver, blocking unmatched paths rather than guessing.

SUPERSEDED 2026-07-16 (SCOPE_SIMPLIFICATION_SPEC.md section 3.7, Phase 7
cutover): that auto-detection block has been REMOVED from command_update.
This is not a regression of the original fix -- it's the fix becoming
unnecessary. The original bug was specifically "a file can land in the
WRONG collection, one it doesn't belong in." Under the new single-
collection design there is no wrong collection to land in -- every file,
matched or not, goes into the one physical collection, tagged with a
"scope" metadata field (via build_scope_resolver -> build_rich_metadata)
that query-time filtering enforces instead. An unmatched path defaults to
scope "shared" (direct product decision, section 3.4) rather than being
blocked -- see scope_lookup.resolve_scope_for_path's own docstring.

_resolve_unattended_directory_scope() itself is UNCHANGED and still
correct -- only command_update's internal call to it was removed. The
function's own tests (TestResolveUnattendedDirectoryScope below) are kept
as-is; it may still be relevant to other unattended-indexing paths
(file_watchdog.py) pending their own Phase 7 migration.

Run:
    pytest tests/unit/test_command_update_scope_awareness.py -v
    pytest tests/unit/test_command_update_scope_awareness.py -v -k slow
"""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture
def rag():
    import rag_preprocessor as _rp
    return _rp


# ─────────────────────────────────────────────────────────────────────────────
# command_update() no longer auto-builds a resolver, period -- confirms the
# old wiring (TestCommandUpdateWiring, pre-2026-07-16) is genuinely gone,
# not just coincidentally unused.
# ─────────────────────────────────────────────────────────────────────────────

class TestCommandUpdateNeverAutoResolvesCollection:

    def test_resolve_unattended_directory_scope_is_never_consulted(
            self, rag, monkeypatch, tmp_path):
        """Regardless of what _resolve_unattended_directory_scope would
        return -- blocked, scoped, or personal -- command_update must
        never call it at all anymore. If this starts failing, the old
        per-file collection-routing wiring has been reintroduced, which
        the single-collection redesign deliberately removed."""
        called = []
        monkeypatch.setattr(
            rag, "_resolve_unattended_directory_scope",
            lambda directory: called.append(True) or ("blocked", None))
        monkeypatch.setattr(
            rag, "scan_directory_for_changes", lambda *a, **k: None)

        rag.command_update(str(tmp_path), auto_confirm=True)

        assert called == []

    def test_directory_scan_is_always_reached_even_with_no_users_json(
            self, rag, monkeypatch, tmp_path):
        """The old 'blocked' skip-before-scan behavior is gone -- even a
        path that would have had no collection_map rule now proceeds
        straight to the normal scan/index flow."""
        reached = []
        monkeypatch.setattr(
            rag, "scan_directory_for_changes",
            lambda *a, **k: reached.append(True) or None)

        rag.command_update(str(tmp_path), auto_confirm=True)

        assert reached == [True]

    def test_caller_supplied_resolver_still_passes_through_unaffected(
            self, rag, monkeypatch, tmp_path):
        """A caller that explicitly supplies collection_resolver (e.g. a
        live MCP session) is unaffected by this change -- it was already
        never touched by the removed block, and still isn't."""
        received = {}

        def _fake_scan(directory, recursive=True):
            return None

        monkeypatch.setattr(rag, "scan_directory_for_changes", _fake_scan)
        my_resolver = lambda fp: "role:sales"
        # Must not raise, must not be overridden -- no direct way to
        # observe the resolver from outside once scan short-circuits, so
        # this is a smoke test that the call shape still works cleanly.
        rag.command_update(str(tmp_path), auto_confirm=True,
                           collection_resolver=my_resolver)


# ─────────────────────────────────────────────────────────────────────────────
# _resolve_unattended_directory_scope itself — the 3-state wrapper around
# scope_resolver, specific to command_update's calling convention. UNCHANGED
# by the Phase 7 cutover -- command_update just doesn't call it anymore.
# ─────────────────────────────────────────────────────────────────────────────

class TestResolveUnattendedDirectoryScope:

    def test_no_users_json_is_personal(self, rag, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        assert rag._resolve_unattended_directory_scope("C:/x") == ("personal", None)

    def test_matched_rule_is_scoped(self, rag, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        users_dir = tmp_path / ".ai-prowler"
        users_dir.mkdir(parents=True)
        data = {
            "collection_map": {"rules": [
                {"prefix": "C:/CompanyDocs/Sales", "collection": "role:sales"},
            ]},
            "users": {"tok-david": {"id": "david-owner", "role": "owner"}},
        }
        (users_dir / "users.json").write_text(json.dumps(data), encoding="utf-8")

        assert rag._resolve_unattended_directory_scope(
            "C:/CompanyDocs/Sales/q3.pdf") == ("scoped", "role:sales")

    def test_unmatched_path_is_blocked(self, rag, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        users_dir = tmp_path / ".ai-prowler"
        users_dir.mkdir(parents=True)
        data = {
            "collection_map": {"rules": [
                {"prefix": "C:/CompanyDocs/Sales", "collection": "role:sales"},
            ]},
            "users": {"tok-david": {"id": "david-owner", "role": "owner"}},
        }
        (users_dir / "users.json").write_text(json.dumps(data), encoding="utf-8")

        assert rag._resolve_unattended_directory_scope(
            "C:/SomewhereElse/x.pdf") == ("blocked", None)

    def test_deleted_user_rule_is_blocked(self, rag, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        users_dir = tmp_path / ".ai-prowler"
        users_dir.mkdir(parents=True)
        data = {
            "collection_map": {"rules": [
                {"prefix": "C:/Personal/Christina", "collection": "user:christina01"},
            ]},
            "users": {"tok-david": {"id": "david-owner", "role": "owner"}},
        }
        (users_dir / "users.json").write_text(json.dumps(data), encoding="utf-8")

        assert rag._resolve_unattended_directory_scope(
            "C:/Personal/Christina/notes.docx") == ("blocked", None)

    def test_corrupt_users_json_is_personal_not_a_crash(self, rag, monkeypatch, tmp_path):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        users_dir = tmp_path / ".ai-prowler"
        users_dir.mkdir(parents=True)
        (users_dir / "users.json").write_text("{not valid json", encoding="utf-8")

        assert rag._resolve_unattended_directory_scope("C:/x") == ("personal", None)


# ─────────────────────────────────────────────────────────────────────────────
# Real end-to-end integration — single-collection behavior, real ChromaDB
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.slow
def test_real_scheduled_task_indexes_into_the_single_collection_with_scope_tag(
        isolated_env, monkeypatch):
    """The real production scenario, end-to-end, under the new design: a
    file sits in a scope_map-matched directory. The Scheduled Task's exact
    call shape (no collection_resolver, no indexer_user -- precisely what
    rag_auto_update.bat does) indexes it. Must land in the SINGLE default
    collection (there is no other one), tagged with the matched scope in
    its chunk metadata -- this is the direct successor to the old "must
    land in Christina's own collection" assertion, updated for a world
    where there's only one collection and scope is metadata, not routing."""
    rag = isolated_env.rag
    monkeypatch.setattr(Path, "home", lambda: isolated_env.tmp_path)

    sales_dir = isolated_env.sample_root / "companydocs" / "sales"
    sales_dir.mkdir(parents=True)
    notes_file = sales_dir / "q3_notes.txt"
    notes_file.write_text("Client renewal discussion — follow up Friday", encoding="utf-8")

    users_dir = isolated_env.tmp_path / ".ai-prowler"
    users_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "scope_map": {
            str(sales_dir).replace("\\", "/"): "sales",
        },
        "users": {"tok-david": {"id": "david-owner", "role": "owner"}},
    }
    (users_dir / "users.json").write_text(json.dumps(data), encoding="utf-8")

    # This is the EXACT call shape rag_auto_update.bat uses — no
    # collection_resolver, no indexer_user, auto_confirm=True (the --yes flag).
    rag.command_update(str(sales_dir), recursive=True, auto_confirm=True)

    client, ef = rag.get_chroma_client()
    default_coll = client.get_or_create_collection(
        name=rag.COLLECTION_NAME, embedding_function=ef)
    results = default_coll.get(
        where={"filepath": rag.normalise_path(str(notes_file))},
        include=["documents", "metadatas"])
    assert len(results.get("documents") or []) >= 1, (
        "the file must be indexed into the single default collection")
    metas = results.get("metadatas") or []
    assert metas and metas[0].get("scope") == "sales", (
        "the chunk's scope metadata must reflect the matched scope_map entry"
    )


@pytest.mark.slow
def test_real_scheduled_task_unmatched_directory_still_indexes_with_shared_default(
        isolated_env, monkeypatch):
    """The other half of the real scenario, updated for the new design:
    server mode is active, but this directory has no matching scope_map
    entry. Direct product decision (SCOPE_SIMPLIFICATION_SPEC.md section
    3.4): this must NOT be blocked/skipped the way the old collection-
    routing design required -- it indexes normally, into the single
    collection, defaulting to scope "shared". This is the intentional
    opposite of the pre-2026-07-16 behavior tested here."""
    rag = isolated_env.rag
    monkeypatch.setattr(Path, "home", lambda: isolated_env.tmp_path)

    unmatched_dir = isolated_env.sample_root / "unmatched"
    unmatched_dir.mkdir(parents=True)
    stray_file = unmatched_dir / "random.txt"
    stray_file.write_text("some content", encoding="utf-8")

    users_dir = isolated_env.tmp_path / ".ai-prowler"
    users_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "scope_map": {
            "C:/CompanyDocs/Sales": "sales",
        },
        "users": {"tok-david": {"id": "david-owner", "role": "owner"}},
    }
    (users_dir / "users.json").write_text(json.dumps(data), encoding="utf-8")

    rag.command_update(str(unmatched_dir), recursive=True, auto_confirm=True)

    client, ef = rag.get_chroma_client()
    default_coll = client.get_or_create_collection(
        name=rag.COLLECTION_NAME, embedding_function=ef)
    results = default_coll.get(
        where={"filepath": rag.normalise_path(str(stray_file))},
        include=["documents", "metadatas"])
    assert len(results.get("documents") or []) >= 1, (
        "an unmatched directory must still be indexed -- never blocked, "
        "per the section 3.4 default-to-shared decision")
    metas = results.get("metadatas") or []
    assert metas and metas[0].get("scope") == "shared", (
        "an unmatched path's chunks must default to scope 'shared'"
    )
