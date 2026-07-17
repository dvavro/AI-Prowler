"""
tests/gui/test_admin_scope_catalog.py
================================================
Tests for the Admin tab's scope-catalog data methods (SCOPE_SIMPLIFICATION_
SPEC.md section 3.3a): _admin_get_scope_catalog, _admin_add_scope_to_catalog,
_admin_remove_scope_from_catalog. These are thin wrappers around
scope_lookup.py's pure catalog functions (already exhaustively tested in
tests/test_scope_lookup.py) -- this file focuses on the GUI-layer wiring:
loading/saving users.json correctly, the optional `data` param for
in-session batching, and the save=False path.

Pure logic, never creates a Tk window -- mirrors the _FakeGui pattern in
tests/gui/test_admin_tab.py (mock out tkinter before import, attach the
real methods to a lightweight stand-in for self).

Run:
    pytest tests/gui/test_admin_scope_catalog.py -v
"""
from __future__ import annotations

import sys
import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

pytestmark = pytest.mark.usefixtures()  # no-op marker, clears inherited skip

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


class _FakeGui:
    """Minimal stand-in for self inside the admin scope-catalog methods --
    only data/Path operations are needed, no real widgets."""

    def _admin_users_path(self):
        return Path(self._users_path)

    def _admin_load_users(self):
        p = self._admin_users_path()
        if p.exists():
            return json.loads(p.read_text(encoding='utf-8'))
        return {"users": {}}

    def _admin_save_raw(self, data):
        p = self._admin_users_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2), encoding='utf-8')


def _attach_methods(fake_cls):
    """Attach the real rag_gui admin scope-catalog methods (plus their
    dependencies) to _FakeGui.

    Plain, unmocked import -- tkinter imports natively fine in this
    environment (confirmed independently), and mocking sys.modules for
    tkinter submodules here turned out to interact badly with OTHER test
    files' own top-level imports when collected in the same pytest
    process (a reproducible full-suite-only collection crash cascading
    into rag_preprocessor's chromadb/pdfplumber/docx import guard calling
    sys.exit(1), which isn't even catchable by `except Exception` since
    SystemExit is a BaseException). Isolated runs of this file were
    always clean either way; removing the mock here is the simpler, safer
    fix regardless of the exact mechanism."""
    try:
        import rag_gui as _rg
        for name in ('_admin_sync_collection_map', '_admin_save_users',
                     '_admin_get_scope_catalog', '_admin_add_scope_to_catalog',
                     '_admin_remove_scope_from_catalog'):
            if hasattr(_rg.RAGGui, name):
                setattr(fake_cls, name, getattr(_rg.RAGGui, name))
    except Exception as e:
        pytest.skip(f"Could not import rag_gui admin methods: {e}")


_attach_methods(_FakeGui)


@pytest.fixture
def fake_self(tmp_path):
    obj = _FakeGui()
    obj._users_path = str(tmp_path / "users.json")
    return obj


def _write_users_json(tmp_path, scope_catalog=None, users=None):
    data = {
        "users": users or {},
    }
    if scope_catalog is not None:
        data["scope_catalog"] = scope_catalog
    (tmp_path / "users.json").write_text(json.dumps(data), encoding="utf-8")


# ── _admin_get_scope_catalog ──────────────────────────────────────────────

class TestAdminGetScopeCatalog:

    def test_returns_catalog_from_file(self, fake_self, tmp_path):
        _write_users_json(tmp_path, scope_catalog=["office", "sales"])
        assert fake_self._admin_get_scope_catalog() == ["office", "sales"]

    def test_missing_users_json_returns_empty(self, fake_self):
        assert fake_self._admin_get_scope_catalog() == []

    def test_accepts_already_loaded_data_without_reading_disk(self, fake_self, tmp_path):
        """Passing data= should skip the disk read entirely -- confirmed
        by never writing users.json at all and still getting the right
        answer from the in-memory dict."""
        data = {"users": {}, "scope_catalog": ["ops"]}
        assert fake_self._admin_get_scope_catalog(data=data) == ["ops"]


# ── _admin_add_scope_to_catalog ───────────────────────────────────────────

class TestAdminAddScopeToCatalog:

    def test_add_to_empty_catalog_persists_to_disk(self, fake_self, tmp_path):
        ok, reason = fake_self._admin_add_scope_to_catalog("office")
        assert ok is True
        saved = json.loads((tmp_path / "users.json").read_text(encoding="utf-8"))
        assert saved["scope_catalog"] == ["office"]

    def test_add_second_scope_preserves_first(self, fake_self, tmp_path):
        fake_self._admin_add_scope_to_catalog("office")
        fake_self._admin_add_scope_to_catalog("sales")
        saved = json.loads((tmp_path / "users.json").read_text(encoding="utf-8"))
        assert saved["scope_catalog"] == ["office", "sales"]

    def test_rejects_duplicate_and_does_not_touch_disk(self, fake_self, tmp_path):
        fake_self._admin_add_scope_to_catalog("office")
        before = (tmp_path / "users.json").read_text(encoding="utf-8")
        ok, reason = fake_self._admin_add_scope_to_catalog("Office")
        assert ok is False
        after = (tmp_path / "users.json").read_text(encoding="utf-8")
        assert before == after

    def test_rejects_shared(self, fake_self):
        ok, reason = fake_self._admin_add_scope_to_catalog("shared")
        assert ok is False
        assert "shared" in reason.lower()

    def test_save_false_does_not_write_to_disk(self, fake_self, tmp_path):
        data = {"users": {}}
        ok, reason = fake_self._admin_add_scope_to_catalog(
            "office", data=data, save=False)
        assert ok is True
        assert data["scope_catalog"] == ["office"]
        assert not (tmp_path / "users.json").exists()

    def test_save_false_caller_can_batch_then_save_once(self, fake_self, tmp_path):
        data = {"users": {}}
        fake_self._admin_add_scope_to_catalog("office", data=data, save=False)
        fake_self._admin_add_scope_to_catalog("sales", data=data, save=False)
        assert not (tmp_path / "users.json").exists()
        fake_self._admin_save_users(data)
        saved = json.loads((tmp_path / "users.json").read_text(encoding="utf-8"))
        assert saved["scope_catalog"] == ["office", "sales"]


# ── _admin_remove_scope_from_catalog ──────────────────────────────────────

class TestAdminRemoveScopeFromCatalog:

    def test_remove_existing_scope_persists_to_disk(self, fake_self, tmp_path):
        _write_users_json(tmp_path, scope_catalog=["office", "sales"])
        changed = fake_self._admin_remove_scope_from_catalog("office")
        assert changed is True
        saved = json.loads((tmp_path / "users.json").read_text(encoding="utf-8"))
        assert saved["scope_catalog"] == ["sales"]

    def test_remove_missing_scope_is_noop_and_returns_false(self, fake_self, tmp_path):
        _write_users_json(tmp_path, scope_catalog=["office"])
        before = (tmp_path / "users.json").read_text(encoding="utf-8")
        changed = fake_self._admin_remove_scope_from_catalog("sales")
        assert changed is False
        after = (tmp_path / "users.json").read_text(encoding="utf-8")
        assert before == after

    def test_remove_does_not_touch_user_scope_assignments(self, fake_self, tmp_path):
        """Removing a scope from the catalog must not retroactively strip
        it from a user who already has it assigned -- catalog and
        per-user scopes are deliberately independent."""
        users = {"tok1": {"id": "vicki-vavro", "role": "manager",
                          "scopes": ["office", "sales"]}}
        _write_users_json(tmp_path, scope_catalog=["office", "sales"], users=users)
        fake_self._admin_remove_scope_from_catalog("office")
        saved = json.loads((tmp_path / "users.json").read_text(encoding="utf-8"))
        assert saved["users"]["tok1"]["scopes"] == ["office", "sales"]

    def test_save_false_does_not_write_to_disk(self, fake_self, tmp_path):
        data = {"users": {}, "scope_catalog": ["office"]}
        changed = fake_self._admin_remove_scope_from_catalog(
            "office", data=data, save=False)
        assert changed is True
        assert data["scope_catalog"] == []
        assert not (tmp_path / "users.json").exists()
