"""
tests/mcp/test_kb_overview_tracked_dirs_scope.py
==================================================
Regression test for get_knowledge_base_overview()'s "Tracked source
directories" section.

Background
----------
The bulk of get_knowledge_base_overview() is correctly scoped via
_scoped_collections_for_ctx(ctx) — same function search_documents() uses —
so chunk counts, file-type breakdown, and the content-location directory
tree only ever reflect collections the caller can actually read.

The "Tracked source directories" footer previously called
load_auto_update_list() directly with no scoping at all: the raw,
install-wide list of every tracked path, shown identically to every role
regardless of what they could actually see. Fixed by filtering that list
down to only directories that contain at least one file the caller's
scoped collections actually surfaced.

Personal mode is untouched — the fix only applies when a user is present
on ctx (server mode).
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


def _patch_tracked_dirs(monkeypatch, dirs):
    """get_knowledge_base_overview() does a LOCAL
    'from rag_preprocessor import ... load_auto_update_list' inside the
    function body, which shadows any monkeypatch on ai_prowler_mcp itself —
    must patch the source module instead."""
    import rag_preprocessor
    monkeypatch.setattr(rag_preprocessor, "load_auto_update_list", lambda: dirs)


def _make_ctx(user):
    if user is None:
        return None
    ctx = MagicMock()
    ctx.request_context.request.state.user = user
    return ctx


def _fake_collection(metadatas):
    """A minimal stand-in for the single ChromaDB collection object
    (SCOPE_SIMPLIFICATION_SPEC.md section 3.7, Phase 7 cutover). Its
    .get() is called twice by get_knowledge_base_overview -- once for an
    id probe, once for the metadata sample -- and returns matching
    ids/metadatas regardless of which call site hits it, since each call
    site only reads the key it needs."""
    col = MagicMock()
    ids = [f"id-{i}" for i in range(len(metadatas))]
    col.get.return_value = {"ids": ids, "metadatas": metadatas}
    return col


def _meta(fp, ext="pdf"):
    return {
        "filepath": fp,
        "filename": fp.rsplit("/", 1)[-1],
        "extension": ext,
        "parent_directory": fp.rsplit("/", 1)[0],
        "total_chunks": 1,
    }


class TestTrackedDirsScoping:

    def test_personal_mode_shows_all_tracked_dirs(self, mcp_mod, monkeypatch):
        """Personal mode: unrestricted, exactly as before this fix."""
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: None)
        monkeypatch.setattr(
            mcp_mod, "_scoped_collections_for_ctx",
            lambda ctx: (_fake_collection([_meta("C:/docs/a.pdf")]), None)
        )
        _patch_tracked_dirs(monkeypatch, ["C:/docs", "C:/somewhere/else/entirely"])
        result = mcp_mod.get_knowledge_base_overview(ctx=None)
        assert "C:/docs" in result
        assert "C:/somewhere/else/entirely" in result

    def test_server_mode_filters_out_invisible_tracked_dirs(self, mcp_mod, monkeypatch):
        """Server mode: a tracked directory with no content in the caller's
        scoped collections must NOT appear in the report."""
        user = {"id": "jake-r", "name": "Jake R", "role": "field_crew"}
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        # Caller can only see one file, under C:/docs/customers/
        monkeypatch.setattr(
            mcp_mod, "_scoped_collections_for_ctx",
            lambda ctx: (_fake_collection([_meta("C:/docs/customers/quote.pdf")]),
                        {"scope": {"$in": ["shared"]}})
        )
        # But the GLOBAL tracked list includes an owner-private directory
        # this caller has no access to at all.
        _patch_tracked_dirs(monkeypatch,
            ["C:/docs/customers", "C:/Users/david/AI-Prowler-Private/david-vavro-private"])
        result = mcp_mod.get_knowledge_base_overview(ctx=_make_ctx(user))
        assert "C:/docs/customers" in result
        assert "david-vavro-private" not in result

    def test_server_mode_keeps_visible_tracked_dir(self, mcp_mod, monkeypatch):
        """Sanity check: a tracked dir that DOES have visible content is
        still shown — this isn't accidentally hiding everything."""
        user = {"id": "jake-r", "name": "Jake R", "role": "field_crew"}
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(
            mcp_mod, "_scoped_collections_for_ctx",
            lambda ctx: (_fake_collection([_meta("C:/shared/manual.pdf")]),
                        {"scope": {"$in": ["shared"]}})
        )
        _patch_tracked_dirs(monkeypatch, ["C:/shared"])
        result = mcp_mod.get_knowledge_base_overview(ctx=_make_ctx(user))
        assert "C:/shared" in result

    def test_server_mode_no_tracked_dirs_no_crash(self, mcp_mod, monkeypatch):
        """Empty tracked-dirs list must not raise."""
        user = {"id": "jake-r", "name": "Jake R", "role": "field_crew"}
        monkeypatch.setattr(mcp_mod, "_current_user", lambda ctx: user)
        monkeypatch.setattr(
            mcp_mod, "_scoped_collections_for_ctx",
            lambda ctx: (_fake_collection([_meta("C:/shared/manual.pdf")]),
                        {"scope": {"$in": ["shared"]}})
        )
        _patch_tracked_dirs(monkeypatch, [])
        result = mcp_mod.get_knowledge_base_overview(ctx=_make_ctx(user))
        assert "Tracked source directories" not in result
