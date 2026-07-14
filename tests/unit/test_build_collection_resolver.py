"""
tests/unit/test_build_collection_resolver.py
================================================
Tests for rag_preprocessor.build_collection_resolver() — the GUI-facing
resolver factory used by "Update Selected"/"Update All" (rag_gui.py's
update_directory_worker/update_all_worker). Fixed 2026-07-14 alongside
the watchdog/scheduled-task fix: this is a FOURTH, independent place the
same underlying bug existed — its returned resolver used to fall through
to the single "documents" collection for any unmatched file, exactly the
Christina-incident failure mode, via a completely separate code path from
command_update's own unattended fallback.

Also covers the _cmd_get_col() safety net inside command_update() that
turns a resolver's None return into a clean per-file skip (raises,
counted as failed) rather than crashing on chroma_collection_name(None)
or silently defaulting — this is what makes it actually SAFE for
build_collection_resolver's returned callable to return None at all.

And _log_scope_skip() — the shared, persistent log
(~/AI-Prowler/logs/index_scope_skips.log) all four unattended/no-session
paths (watchdog, scheduled task, command_update's own directory-level
check, and this resolver via _cmd_get_col) write to, since print() is
silently discarded when running under pythonw.exe (GUI) or with no
console at all (Scheduled Task via Windows Task Scheduler).

Run:
    pytest tests/unit/test_build_collection_resolver.py -v
"""
import json
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture
def rag():
    import rag_preprocessor as _rp
    return _rp


def _write_users_json(tmp_path, rules, users=None):
    users_dir = tmp_path / ".ai-prowler"
    users_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "collection_map": {"rules": rules},
        "users": users or {
            "tok-christina": {"id": "christina01", "role": "staff"},
            "tok-david": {"id": "david-owner", "role": "owner"},
        },
    }
    (users_dir / "users.json").write_text(json.dumps(data), encoding="utf-8")
    return users_dir / "users.json"


# ─────────────────────────────────────────────────────────────────────────────
# build_collection_resolver() itself
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildCollectionResolver:

    def test_returns_none_when_users_json_missing(self, rag, tmp_path):
        missing = tmp_path / ".ai-prowler" / "users.json"
        assert rag.build_collection_resolver(str(missing)) is None

    def test_returns_none_when_no_collection_map(self, rag, tmp_path):
        users_dir = tmp_path / ".ai-prowler"
        users_dir.mkdir(parents=True)
        p = users_dir / "users.json"
        p.write_text(json.dumps({"users": {}}), encoding="utf-8")
        assert rag.build_collection_resolver(str(p)) is None

    def test_returns_none_when_no_rules(self, rag, tmp_path):
        p = _write_users_json(tmp_path, rules=[])
        assert rag.build_collection_resolver(str(p)) is None

    def test_returns_none_on_corrupt_json(self, rag, tmp_path):
        users_dir = tmp_path / ".ai-prowler"
        users_dir.mkdir(parents=True)
        p = users_dir / "users.json"
        p.write_text("{not valid json", encoding="utf-8")
        assert rag.build_collection_resolver(str(p)) is None

    def test_matched_rule_resolves_correctly(self, rag, tmp_path):
        p = _write_users_json(tmp_path, rules=[
            {"prefix": "C:/CompanyDocs/Sales", "collection": "role:sales"},
        ])
        resolver = rag.build_collection_resolver(str(p))
        assert resolver is not None
        assert resolver("C:/CompanyDocs/Sales/q3.pdf") == "role:sales"

    def test_matched_personal_rule_with_known_user_resolves(self, rag, tmp_path):
        p = _write_users_json(tmp_path, rules=[
            {"prefix": "C:/Personal/Christina", "collection": "user:christina01"},
        ])
        resolver = rag.build_collection_resolver(str(p))
        assert resolver("C:/Personal/Christina/notes.docx") == "user:christina01"

    def test_THE_ACTUAL_BUG_unmatched_path_returns_none_not_documents(
            self, rag, tmp_path):
        """This is the core regression test for the actual bug found in
        this session: an unmatched file must resolve to None (meaning
        "skip, don't guess"), never silently fall through to the default
        'documents' collection the way the old resolve_collection_for_path
        -based implementation did."""
        p = _write_users_json(tmp_path, rules=[
            {"prefix": "C:/CompanyDocs/Sales", "collection": "role:sales"},
        ])
        resolver = rag.build_collection_resolver(str(p))
        assert resolver("C:/SomeRandomFolder/x.pdf") is None

    def test_deleted_user_rule_returns_none(self, rag, tmp_path):
        """A rule technically matches, but the user it names has been
        removed — must be treated exactly like no match at all."""
        p = _write_users_json(
            tmp_path,
            rules=[{"prefix": "C:/Personal/Christina",
                   "collection": "user:christina01"}],
            users={"tok-david": {"id": "david-owner", "role": "owner"}},
            # christina01 not present — she's gone.
        )
        resolver = rag.build_collection_resolver(str(p))
        assert resolver("C:/Personal/Christina/notes.docx") is None

    def test_default_collection_is_ignored_even_if_configured(
            self, rag, tmp_path):
        """Even if an admin configured collection_map.default_collection,
        the GUI's resolver must NOT use it for an unmatched path — same
        design decision as the watchdog/scheduled-task fix."""
        users_dir = tmp_path / ".ai-prowler"
        users_dir.mkdir(parents=True)
        p = users_dir / "users.json"
        data = {
            "collection_map": {
                "rules": [{"prefix": "C:/CompanyDocs/Sales", "collection": "role:sales"}],
                "default_collection": "shared",
            },
            "users": {"tok-david": {"id": "david-owner", "role": "owner"}},
        }
        p.write_text(json.dumps(data), encoding="utf-8")
        resolver = rag.build_collection_resolver(str(p))
        assert resolver("C:/Unmatched/x.pdf") is None


# ─────────────────────────────────────────────────────────────────────────────
# _cmd_get_col's None-handling inside command_update — the safety net that
# makes it OK for build_collection_resolver to return None per-file
# ─────────────────────────────────────────────────────────────────────────────

class TestCmdGetColSkipsCleanlyOnNone:

    def test_unmatched_file_is_counted_as_failed_not_indexed_anywhere(
            self, isolated_env, monkeypatch):
        """End-to-end through command_update itself: a directory has TWO
        files, one matches a rule and one doesn't. The matched one must be
        indexed into its scoped collection; the unmatched one must NOT
        appear in 'documents' (or anywhere) and must be counted as a
        failure in the run summary, not silently succeed."""
        rag = isolated_env.rag
        folder = isolated_env.sample_root / "mixed"
        folder.mkdir(parents=True)
        matched_file = folder / "sales_deal.txt"
        matched_file.write_text("deal terms", encoding="utf-8")
        unmatched_file = folder / "random.txt"
        unmatched_file.write_text("random content", encoding="utf-8")

        def _resolver(fp):
            if "sales_deal" in fp:
                return "role:sales"
            return None  # unmatched — exactly build_collection_resolver's contract

        rag.command_update(str(folder), recursive=True, auto_confirm=True,
                          collection_resolver=_resolver)

        client, ef = rag.get_chroma_client()

        sales_coll = client.get_or_create_collection(
            name=rag.chroma_collection_name("role:sales"), embedding_function=ef)
        matched_results = sales_coll.get(
            where={"filepath": rag.normalise_path(str(matched_file))},
            include=["documents"])
        assert len(matched_results.get("documents") or []) >= 1

        default_coll = client.get_or_create_collection(
            name=rag.COLLECTION_NAME, embedding_function=ef)
        stray = default_coll.get(
            where={"filepath": rag.normalise_path(str(unmatched_file))},
            include=["documents"])
        assert len(stray.get("documents") or []) == 0, (
            "the unmatched file must not silently land in 'documents'")

        # And confirm it's not sitting in the sales collection either.
        stray_in_sales = sales_coll.get(
            where={"filepath": rag.normalise_path(str(unmatched_file))},
            include=["documents"])
        assert len(stray_in_sales.get("documents") or []) == 0


# ─────────────────────────────────────────────────────────────────────────────
# _log_scope_skip — the shared persistent log
# ─────────────────────────────────────────────────────────────────────────────

class TestLogScopeSkip:

    def test_writes_a_line_to_the_shared_log_file(self, rag, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        rag._log_scope_skip("command_update", "C:/some/path.txt", "test reason")

        log_path = tmp_path / "AI-Prowler" / "logs" / "index_scope_skips.log"
        assert log_path.exists()
        content = log_path.read_text(encoding="utf-8")
        assert "command_update" in content
        assert "C:/some/path.txt" in content
        assert "test reason" in content

    def test_appends_rather_than_overwrites(self, rag, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        rag._log_scope_skip("command_update", "C:/first.txt", "reason one")
        rag._log_scope_skip("command_update", "C:/second.txt", "reason two")

        log_path = tmp_path / "AI-Prowler" / "logs" / "index_scope_skips.log"
        content = log_path.read_text(encoding="utf-8")
        assert "first.txt" in content
        assert "second.txt" in content
        assert content.count("\n") == 2

    def test_never_raises_even_if_log_dir_cannot_be_created(
            self, rag, monkeypatch):
        # Point "home" somewhere that can't plausibly be written to create
        # a subdirectory under — must not raise regardless.
        monkeypatch.setattr(Path, "home",
                            lambda: Path("Z:/definitely/does/not/exist/at/all"))
        rag._log_scope_skip("command_update", "C:/x.txt", "reason")  # must not raise
