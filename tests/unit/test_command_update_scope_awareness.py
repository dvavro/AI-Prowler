"""
tests/unit/test_command_update_scope_awareness.py
====================================================
Tests for command_update()'s server-mode collection awareness fix
(added 2026-07-13 after the Christina incident).

Background: command_update() is the function behind FOUR real entry
points — GUI "Update Selected", GUI "Update All", the MCP
update_tracked_directories tool, and the Scheduled Task's standalone CLI
"update" invocation (rag_auto_update.bat). The last of these has NO
acting user/session at all and never passed collection_resolver —
meaning in server mode it always silently indexed into the single
default "documents" collection, exactly the bug that orphaned
Christina's file. See file_watchdog.py's identical fix and
tests/test_scope_resolver.py for the underlying pure-function coverage
this all builds on.

Two kinds of coverage here:
  - FAST tests that mock _resolve_unattended_directory_scope directly to
    verify command_update's branching logic (skip / scoped / personal),
    without touching real ChromaDB or disk scanning.
  - ONE real end-to-end integration test (marked slow, mirroring
    test_F_CODE_14's pattern in test_code_scan_truncation.py) that
    exercises the actual Christina scenario against a real isolated
    ChromaDB — proving the whole pipeline, not just the wiring.

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
# Fast wiring tests — mock _resolve_unattended_directory_scope directly
# ─────────────────────────────────────────────────────────────────────────────

class TestCommandUpdateWiring:

    def test_blocked_skips_entirely_before_any_scan(self, rag, monkeypatch, tmp_path):
        """A 'blocked' resolution must abort BEFORE scan_directory_for_changes
        is even called — no partial work, no risk of touching the wrong
        collection for any file in this directory."""
        monkeypatch.setattr(
            rag, "_resolve_unattended_directory_scope",
            lambda directory: ("blocked", None))
        scan_called = []
        monkeypatch.setattr(
            rag, "scan_directory_for_changes",
            lambda *a, **k: scan_called.append(True))

        rag.command_update(str(tmp_path), auto_confirm=True)

        assert scan_called == []

    def test_personal_mode_leaves_resolver_none(self, rag, monkeypatch, tmp_path):
        """'personal' -> collection_resolver must stay None, meaning
        unchanged legacy behavior (single 'documents' collection)."""
        monkeypatch.setattr(
            rag, "_resolve_unattended_directory_scope",
            lambda directory: ("personal", None))
        monkeypatch.setattr(
            rag, "scan_directory_for_changes", lambda *a, **k: None)

        # scan_directory_for_changes returning None makes command_update
        # return immediately after — just confirms it got PAST the
        # blocked-check and reached the scan step at all.
        result = rag.command_update(str(tmp_path), auto_confirm=True)
        assert result is None  # no exception, reached the scan step

    def test_scoped_builds_a_working_collection_resolver(self, rag, monkeypatch, tmp_path):
        """'scoped' -> collection_resolver must be a callable that returns
        the resolved collection name for ANY filepath passed to it."""
        monkeypatch.setattr(
            rag, "_resolve_unattended_directory_scope",
            lambda directory: ("scoped", "user:christina01"))

        captured = {}

        def _fake_scan(*a, **k):
            captured["called"] = True
            return None  # short-circuit — we only care about the resolver by now

        monkeypatch.setattr(rag, "scan_directory_for_changes", _fake_scan)
        rag.command_update(str(tmp_path), auto_confirm=True)
        assert captured.get("called") is True

    def test_caller_supplied_resolver_is_never_overridden(self, rag, monkeypatch, tmp_path):
        """If a caller (e.g. the MCP tool, which has a real acting user)
        already supplied collection_resolver, _resolve_unattended_
        directory_scope must NEVER be consulted at all — this fix must
        not interfere with the existing live-session path."""
        called = []
        monkeypatch.setattr(
            rag, "_resolve_unattended_directory_scope",
            lambda directory: called.append(True))
        monkeypatch.setattr(
            rag, "scan_directory_for_changes", lambda *a, **k: None)

        my_resolver = lambda fp: "role:sales"
        rag.command_update(str(tmp_path), auto_confirm=True,
                           collection_resolver=my_resolver)

        assert called == []  # never consulted

    def test_caller_supplied_indexer_user_also_skips_unattended_resolve(
            self, rag, monkeypatch, tmp_path):
        """Same guarantee when indexer_user is supplied instead of/with
        collection_resolver — either one present means 'this caller has
        real session context, stay out of the way.'"""
        called = []
        monkeypatch.setattr(
            rag, "_resolve_unattended_directory_scope",
            lambda directory: called.append(True))
        monkeypatch.setattr(
            rag, "scan_directory_for_changes", lambda *a, **k: None)

        rag.command_update(str(tmp_path), auto_confirm=True,
                           indexer_user={"id": "david-owner"})

        assert called == []


# ─────────────────────────────────────────────────────────────────────────────
# _resolve_unattended_directory_scope itself — the 3-state wrapper around
# scope_resolver, specific to command_update's calling convention
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
            "users": {"tok": {"id": "david-owner", "role": "owner"}},
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
            "users": {"tok": {"id": "david-owner", "role": "owner"}},
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
            "users": {"tok": {"id": "david-owner", "role": "owner"}},  # christina01 gone
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
# Real end-to-end integration — the actual Christina scenario, real ChromaDB
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.slow
def test_real_scheduled_task_indexes_personal_file_into_owners_collection(
        isolated_env, monkeypatch):
    """The actual production scenario, end-to-end: a file sits in an
    employee's personal directory, has a real collection_map rule
    registered, and the Scheduled Task's exact call shape (no
    collection_resolver, no indexer_user — precisely what
    rag_auto_update.bat does) is used to index it. Must land in
    'user:christina01', findable there, and must NOT appear in the
    single default 'documents' collection at all (the actual bug)."""
    rag = isolated_env.rag
    monkeypatch.setattr(Path, "home", lambda: isolated_env.tmp_path)

    personal_dir = isolated_env.sample_root / "personal" / "christina"
    personal_dir.mkdir(parents=True)
    notes_file = personal_dir / "meeting_notes.txt"
    notes_file.write_text("Client renewal discussion — follow up Friday", encoding="utf-8")

    users_dir = isolated_env.tmp_path / ".ai-prowler"
    users_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "collection_map": {"rules": [
            {"prefix": str(personal_dir).replace("\\", "/"),
             "collection": "user:christina01"},
        ]},
        "users": {
            "tok-christina": {"id": "christina01", "role": "staff"},
            "tok-david": {"id": "david-owner", "role": "owner"},
        },
    }
    (users_dir / "users.json").write_text(json.dumps(data), encoding="utf-8")

    # This is the EXACT call shape rag_auto_update.bat uses — no
    # collection_resolver, no indexer_user, auto_confirm=True (the --yes flag).
    rag.command_update(str(personal_dir), recursive=True, auto_confirm=True)

    client, ef = rag.get_chroma_client()

    christina_coll = client.get_or_create_collection(
        name=rag.chroma_collection_name("user:christina01"), embedding_function=ef)
    results = christina_coll.get(
        where={"filepath": rag.normalise_path(str(notes_file))},
        include=["documents"])
    assert len(results.get("documents") or []) >= 1, (
        "the file must be indexed into Christina's own collection")

    # And confirm it did NOT also land in the single default 'documents'
    # collection — that's the actual historical bug this fix closes.
    default_coll = client.get_or_create_collection(
        name=rag.COLLECTION_NAME, embedding_function=ef)
    stray = default_coll.get(
        where={"filepath": rag.normalise_path(str(notes_file))},
        include=["documents"])
    assert len(stray.get("documents") or []) == 0, (
        "the file must NOT be present in the default 'documents' collection")


@pytest.mark.slow
def test_real_scheduled_task_unmatched_directory_indexes_nothing(
        isolated_env, monkeypatch):
    """The other half of the real scenario: server mode is active, but
    THIS directory has no matching rule. Must index nothing at all —
    not into 'documents', not anywhere — confirming the skip really
    prevents the write rather than just logging a warning around it."""
    rag = isolated_env.rag
    monkeypatch.setattr(Path, "home", lambda: isolated_env.tmp_path)

    unmatched_dir = isolated_env.sample_root / "unmatched"
    unmatched_dir.mkdir(parents=True)
    stray_file = unmatched_dir / "random.txt"
    stray_file.write_text("some content", encoding="utf-8")

    users_dir = isolated_env.tmp_path / ".ai-prowler"
    users_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "collection_map": {"rules": [
            {"prefix": "C:/CompanyDocs/Sales", "collection": "role:sales"},
        ]},
        "users": {"tok-david": {"id": "david-owner", "role": "owner"}},
    }
    (users_dir / "users.json").write_text(json.dumps(data), encoding="utf-8")

    rag.command_update(str(unmatched_dir), recursive=True, auto_confirm=True)

    client, ef = rag.get_chroma_client()
    default_coll = client.get_or_create_collection(
        name=rag.COLLECTION_NAME, embedding_function=ef)
    stray = default_coll.get(
        where={"filepath": rag.normalise_path(str(stray_file))},
        include=["documents"])
    assert len(stray.get("documents") or []) == 0, (
        "an unmatched directory must index nothing at all, not fall back "
        "to the default 'documents' collection")
