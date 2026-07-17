"""
tests/unit/test_build_scope_resolver.py
================================================
Tests for rag_preprocessor.build_scope_resolver() -- the write-side
counterpart to build_collection_resolver() (see that module's tests for
the read-side/routing sibling this deliberately does NOT mirror in one
key way -- see test_empty_scope_map_still_returns_a_working_resolver
below, the single most important behavioral difference between the two).

Also covers build_rich_metadata()'s new `scope` parameter/field, added
alongside this resolver so every indexed chunk can be tagged.

See SCOPE_SIMPLIFICATION_SPEC.md section 3.3b for the full design this
implements.

Run:
    pytest tests/unit/test_build_scope_resolver.py -v
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


def _write_users_json(tmp_path, scope_map=None):
    users_dir = tmp_path / ".ai-prowler"
    users_dir.mkdir(parents=True, exist_ok=True)
    data = {"scope_map": scope_map if scope_map is not None else {}}
    (users_dir / "users.json").write_text(json.dumps(data), encoding="utf-8")
    return users_dir / "users.json"


# ─────────────────────────────────────────────────────────────────────────────
# build_scope_resolver() -- personal-mode detection
# ─────────────────────────────────────────────────────────────────────────────

class TestPersonalModeDetection:

    def test_returns_none_when_users_json_missing(self, rag, tmp_path):
        missing = tmp_path / ".ai-prowler" / "users.json"
        assert rag.build_scope_resolver(str(missing)) is None

    def test_returns_none_on_corrupt_json(self, rag, tmp_path):
        users_dir = tmp_path / ".ai-prowler"
        users_dir.mkdir(parents=True)
        p = users_dir / "users.json"
        p.write_text("{not valid json", encoding="utf-8")
        assert rag.build_scope_resolver(str(p)) is None

    def test_returns_none_when_json_is_not_a_dict(self, rag, tmp_path):
        users_dir = tmp_path / ".ai-prowler"
        users_dir.mkdir(parents=True)
        p = users_dir / "users.json"
        p.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")
        assert rag.build_scope_resolver(str(p)) is None


# ─────────────────────────────────────────────────────────────────────────────
# The critical divergence from build_collection_resolver(): empty scope_map
# ─────────────────────────────────────────────────────────────────────────────

class TestEmptyScopeMapStillWorks:
    """build_collection_resolver() returns None for an empty rules list --
    treated as "not applicable". build_scope_resolver() must NOT do the
    same for an empty scope_map, because scope_lookup.resolve_scope_for_path
    has its own safe default ("shared") that a real server-mode install
    with no scopes assigned yet still needs -- see the function's own
    docstring for the full rationale. This is the single most important
    test in this file: getting it wrong silently disables ALL scope
    tagging (including private-folder-by-convention resolution) for
    every server-mode install until an admin manually assigns a scope."""

    def test_empty_scope_map_still_returns_a_working_resolver(self, rag, tmp_path):
        p = _write_users_json(tmp_path, scope_map={})
        resolver = rag.build_scope_resolver(str(p))
        assert resolver is not None, (
            "CRITICAL: an empty scope_map must still produce a working "
            "resolver -- it must NOT be treated as 'not server mode', "
            "unlike build_collection_resolver()'s empty-rules behavior."
        )

    def test_empty_scope_map_resolver_defaults_everything_to_shared(self, rag, tmp_path):
        p = _write_users_json(tmp_path, scope_map={})
        resolver = rag.build_scope_resolver(str(p))
        assert resolver("C:/CompanyDocs/Sales/q3.pdf") == "shared"
        assert resolver("C:/AnythingAtAll/x.txt") == "shared"

    def test_missing_scope_map_key_entirely_still_works(self, rag, tmp_path):
        """Not just an empty {} -- the key can be absent altogether (a
        users.json that predates this feature, or was never touched by
        the Admin tab's scope UI)."""
        users_dir = tmp_path / ".ai-prowler"
        users_dir.mkdir(parents=True)
        p = users_dir / "users.json"
        p.write_text(json.dumps({"users": {}}), encoding="utf-8")
        resolver = rag.build_scope_resolver(str(p))
        assert resolver is not None
        assert resolver("C:/anything.pdf") == "shared"


# ─────────────────────────────────────────────────────────────────────────────
# Matching behavior (delegates to scope_lookup -- these are integration-level
# checks that the delegation actually happened correctly, not a re-test of
# scope_lookup's own exhaustive matching logic, which lives in
# tests/test_scope_lookup.py)
# ─────────────────────────────────────────────────────────────────────────────

class TestMatching:

    def test_matched_rule_resolves_correctly(self, rag, tmp_path):
        p = _write_users_json(tmp_path, scope_map={
            "C:/CompanyDocs/Sales": "sales",
        })
        resolver = rag.build_scope_resolver(str(p))
        assert resolver("C:/CompanyDocs/Sales/q3.pdf") == "sales"

    def test_unmatched_path_defaults_to_shared_not_none(self, rag, tmp_path):
        p = _write_users_json(tmp_path, scope_map={
            "C:/CompanyDocs/Sales": "sales",
        })
        resolver = rag.build_scope_resolver(str(p))
        assert resolver("C:/SomeOtherFolder/x.pdf") == "shared"

    def test_private_folder_resolves_by_convention(self, rag, tmp_path, monkeypatch):
        """build_scope_resolver hardcodes privates_root as
        <home>/Documents/AI-Prowler-Server-privates -- patch Path.home()
        to make that deterministic for the test."""
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        p = _write_users_json(tmp_path, scope_map={})
        resolver = rag.build_scope_resolver(str(p))
        priv_path = str(tmp_path / "Documents" / "AI-Prowler-Server-privates"
                         / "david-vavro-private" / "notes.txt")
        assert resolver(priv_path) == "private:david-vavro"

    def test_longest_prefix_wins(self, rag, tmp_path):
        p = _write_users_json(tmp_path, scope_map={
            "C:/Co": "shared",
            "C:/Co/Sales": "sales",
        })
        resolver = rag.build_scope_resolver(str(p))
        assert resolver("C:/Co/Sales/deal.pdf") == "sales"


# ─────────────────────────────────────────────────────────────────────────────
# build_rich_metadata()'s new `scope` field
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildRichMetadataScopeField:

    def test_scope_field_present_and_set(self, rag):
        meta = rag.build_rich_metadata(
            filepath="C:/Docs/x.txt", filename="x.txt", chunk_idx=0,
            total_chunks=1, extension=".txt", scope="sales",
        )
        assert meta["scope"] == "sales"

    def test_scope_defaults_to_empty_string(self, rag):
        """Personal mode / no resolver -- callers pass nothing, and the
        field is still present (never missing entirely), just empty."""
        meta = rag.build_rich_metadata(
            filepath="C:/Docs/x.txt", filename="x.txt", chunk_idx=0,
            total_chunks=1, extension=".txt",
        )
        assert meta["scope"] == ""

    def test_scope_does_not_clobber_other_fields(self, rag):
        meta = rag.build_rich_metadata(
            filepath="C:/Docs/x.txt", filename="x.txt", chunk_idx=2,
            total_chunks=5, extension=".txt", scope="ops",
            document_id="abc123", doc_title="Report",
        )
        assert meta["scope"] == "ops"
        assert meta["document_id"] == "abc123"
        assert meta["doc_title"] == "Report"
        assert meta["chunk_index"] == 2
        assert meta["total_chunks"] == 5

    def test_scope_survives_extra_dict_merge(self, rag):
        """extra= is merged in AFTER the base dict is built -- confirms
        scope isn't accidentally positioned somewhere extra could
        clobber it for a normal (non-scope-colliding) extra dict."""
        meta = rag.build_rich_metadata(
            filepath="C:/Docs/x.txt", filename="x.txt", chunk_idx=0,
            total_chunks=1, extension=".txt", scope="field",
            extra={"email_uid": "uid-123"},
        )
        assert meta["scope"] == "field"
        assert meta["email_uid"] == "uid-123"
