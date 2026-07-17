"""
tests/gui/test_update_index_scope_column.py
================================================
Tests for the Update Index tab's editable scope column (SCOPE_SIMPLIFICATION_
SPEC.md section 3.3b): _get_pending_scope_changes, _tracked_row_scope_text,
_commit_pending_scope_changes. A scope change staged via the "Change Scope"
dialog does not write to scope_map immediately -- it's held in memory and
only committed (persisted, which lets the following reindex tag fresh
chunks with the new scope) when Update Selected/Update All actually runs.

Pure logic, never creates a Tk window -- mirrors the _FakeGui pattern in
tests/gui/test_admin_tab.py, WITHOUT the tkinter sys.modules mock (that mock
caused a reproducible full-suite-only collection crash when combined with
other test files -- see test_admin_scope_catalog.py's _attach_methods
docstring for the incident writeup; plain unmocked import works fine here).

Run:
    pytest tests/gui/test_update_index_scope_column.py -v
"""
from __future__ import annotations

import sys
import json
import pytest
from pathlib import Path

pytestmark = pytest.mark.usefixtures()  # no-op marker, clears inherited skip

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


class _FakeGui:
    """Minimal stand-in for self -- only data/Path operations needed."""

    def _admin_users_path(self):
        return Path(self._users_path)

    def _admin_load_users(self):
        p = self._admin_users_path()
        if p.exists():
            return json.loads(p.read_text(encoding='utf-8'))
        return {"users": {}}

    def _is_business_server_mode(self):
        return getattr(self, "_server_mode", True)


def _attach_methods(fake_cls):
    """Attach the real rag_gui methods needed by the scope-column staging
    logic to _FakeGui. Plain, unmocked import (see module docstring)."""
    try:
        import rag_gui as _rg
        for name in ('_admin_sync_collection_map', '_admin_save_users',
                     '_get_pending_scope_changes', '_tracked_row_scope_text',
                     '_commit_pending_scope_changes',
                     '_resolve_scope_for_path', '_display_scope'):
            if hasattr(_rg.RAGGui, name):
                setattr(fake_cls, name, getattr(_rg.RAGGui, name))
    except Exception as e:
        pytest.skip(f"Could not import rag_gui methods: {e}")


_attach_methods(_FakeGui)


@pytest.fixture
def fake_self(tmp_path):
    obj = _FakeGui()
    obj._users_path = str(tmp_path / "users.json")
    obj._server_mode = True
    return obj


def _write_users_json(tmp_path, scope_map=None, users=None):
    data = {"users": users or {}}
    if scope_map is not None:
        data["scope_map"] = scope_map
    (tmp_path / "users.json").write_text(json.dumps(data), encoding="utf-8")


# ── _get_pending_scope_changes ────────────────────────────────────────────

class TestGetPendingScopeChanges:

    def test_lazily_initializes_to_empty_dict(self, fake_self):
        assert fake_self._get_pending_scope_changes() == {}

    def test_returns_same_object_on_repeated_calls(self, fake_self):
        """Mutations must persist across calls -- this is the whole point
        of staging: the dialog mutates it, later code reads it back."""
        d1 = fake_self._get_pending_scope_changes()
        d1["c:/sales"] = "sales"
        d2 = fake_self._get_pending_scope_changes()
        assert d2 == {"c:/sales": "sales"}
        assert d1 is d2


# ── _tracked_row_scope_text ───────────────────────────────────────────────

class TestTrackedRowScopeText:

    def test_no_pending_shows_resolved_scope(self, fake_self):
        rules = [{"prefix": "C:/CompanyDocs/Sales", "collection": "role:sales"}]
        text = fake_self._tracked_row_scope_text(
            "C:/CompanyDocs/Sales", rules, "shared")
        assert text == "scope:sales"

    def test_pending_change_overrides_display(self, fake_self):
        rules = [{"prefix": "C:/CompanyDocs/Sales", "collection": "role:sales"}]
        pending = fake_self._get_pending_scope_changes()
        pending["c:/companydocs/sales"] = "ops"
        text = fake_self._tracked_row_scope_text(
            "C:/CompanyDocs/Sales", rules, "shared")
        assert text == "\u2192ops (pending)"

    def test_pending_lookup_is_path_normalized(self, fake_self):
        """Staged with backslashes, looked up with forward slashes (or vice
        versa) -- must still match, since the dialog and the tracked list
        may not always pass the path in identical raw form."""
        rules = []
        pending = fake_self._get_pending_scope_changes()
        pending["c:/companydocs/sales"] = "ops"
        text = fake_self._tracked_row_scope_text(
            r"C:\CompanyDocs\Sales", rules, "shared")
        assert text == "\u2192ops (pending)"

    def test_unrelated_pending_change_does_not_leak_to_other_rows(self, fake_self):
        rules = []
        pending = fake_self._get_pending_scope_changes()
        pending["c:/companydocs/office"] = "office"
        text = fake_self._tracked_row_scope_text(
            "C:/CompanyDocs/Sales", rules, "shared")
        assert "pending" not in text


# ── _commit_pending_scope_changes ─────────────────────────────────────────

class TestCommitPendingScopeChanges:

    def test_commits_matching_path_to_scope_map(self, fake_self, tmp_path):
        _write_users_json(tmp_path, scope_map={})
        pending = fake_self._get_pending_scope_changes()
        pending["c:/companydocs/sales"] = "sales"

        fake_self._commit_pending_scope_changes(["C:/CompanyDocs/Sales"])

        saved = json.loads((tmp_path / "users.json").read_text(encoding="utf-8"))
        assert saved["scope_map"] == {"c:/companydocs/sales": "sales"}

    def test_clears_committed_entry_from_pending(self, fake_self, tmp_path):
        _write_users_json(tmp_path, scope_map={})
        pending = fake_self._get_pending_scope_changes()
        pending["c:/companydocs/sales"] = "sales"

        fake_self._commit_pending_scope_changes(["C:/CompanyDocs/Sales"])

        assert fake_self._get_pending_scope_changes() == {}

    def test_leaves_unrelated_pending_changes_staged(self, fake_self, tmp_path):
        """Committing paths from an Update Selected run on ONE directory
        must not touch a DIFFERENT directory's still-staged change."""
        _write_users_json(tmp_path, scope_map={})
        pending = fake_self._get_pending_scope_changes()
        pending["c:/companydocs/sales"] = "sales"
        pending["c:/companydocs/office"] = "office"

        fake_self._commit_pending_scope_changes(["C:/CompanyDocs/Sales"])

        assert fake_self._get_pending_scope_changes() == {"c:/companydocs/office": "office"}
        saved = json.loads((tmp_path / "users.json").read_text(encoding="utf-8"))
        assert saved["scope_map"] == {"c:/companydocs/sales": "sales"}

    def test_noop_when_nothing_pending(self, fake_self, tmp_path):
        _write_users_json(tmp_path, scope_map={"c:/x": "shared"})
        before = (tmp_path / "users.json").read_text(encoding="utf-8")

        fake_self._commit_pending_scope_changes(["C:/CompanyDocs/Sales"])

        after = (tmp_path / "users.json").read_text(encoding="utf-8")
        assert before == after

    def test_noop_when_not_server_mode(self, fake_self, tmp_path):
        _write_users_json(tmp_path, scope_map={})
        fake_self._server_mode = False
        pending = fake_self._get_pending_scope_changes()
        pending["c:/companydocs/sales"] = "sales"

        fake_self._commit_pending_scope_changes(["C:/CompanyDocs/Sales"])

        assert not (tmp_path / "users.json").exists() or json.loads(
            (tmp_path / "users.json").read_text(encoding="utf-8")
        ).get("scope_map") != {"c:/companydocs/sales": "sales"}
        # Pending stays staged -- nothing was committed.
        assert fake_self._get_pending_scope_changes() == {"c:/companydocs/sales": "sales"}

    def test_preserves_existing_scope_map_entries_not_in_this_commit(self, fake_self, tmp_path):
        _write_users_json(tmp_path, scope_map={"c:/companydocs/ops": "ops"})
        pending = fake_self._get_pending_scope_changes()
        pending["c:/companydocs/sales"] = "sales"

        fake_self._commit_pending_scope_changes(["C:/CompanyDocs/Sales"])

        saved = json.loads((tmp_path / "users.json").read_text(encoding="utf-8"))
        assert saved["scope_map"] == {
            "c:/companydocs/ops": "ops",
            "c:/companydocs/sales": "sales",
        }

    def test_commit_all_pending_when_directories_list_covers_everything(self, fake_self, tmp_path):
        """Simulates update_all_worker's call: passing the FULL tracked-dirs
        list commits every staged change at once."""
        _write_users_json(tmp_path, scope_map={})
        pending = fake_self._get_pending_scope_changes()
        pending["c:/companydocs/sales"] = "sales"
        pending["c:/companydocs/office"] = "office"

        fake_self._commit_pending_scope_changes(
            ["C:/CompanyDocs/Sales", "C:/CompanyDocs/Office", "C:/CompanyDocs/Ops"])

        assert fake_self._get_pending_scope_changes() == {}
        saved = json.loads((tmp_path / "users.json").read_text(encoding="utf-8"))
        assert saved["scope_map"] == {
            "c:/companydocs/sales": "sales",
            "c:/companydocs/office": "office",
        }
