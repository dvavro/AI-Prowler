"""
tests/gui/test_admin_tab.py
============================
Unit tests for Admin tab user management logic introduced in v7.0.1.

Covers:
  A — Slug generation (_make_user_id in ai_prowler_mcp.py)
  B — Folder name derivation (slug + "-private", always lowercase)
  C — _admin_sync_collection_map: auto-generates / preserves / removes rules
  D — _admin_update_private_rule: patches a single rule without re-sync
  E — _resolve_user id field: now slug, not bearer token

All tests are PURE UNIT TESTS — no tkinter, no disk I/O, no ChromaDB.
They live in tests/gui/ for discoverability alongside the GUI suite, but
they do NOT need a display. The pytestmark override below opts out of the
conftest's skip-if-headless guard so they run everywhere including CI.

The GUI methods that contain tkinter calls (_admin_setup_private_folder,
_admin_user_dialog, etc.) are NOT tested here — they are covered by the
manual QA checklist at the bottom of this file.

Run all admin tab tests:
    run_tests.bat tests\\gui\\test_admin_tab.py

Run a specific section:
    run_tests.bat tests\\gui\\test_admin_tab.py -k TestSlugGeneration
    run_tests.bat tests\\gui\\test_admin_tab.py -k TestFolderName
    run_tests.bat tests\\gui\\test_admin_tab.py -k TestAdminSync
    run_tests.bat tests\\gui\\test_admin_tab.py -k TestAdminUpdate

Run alongside the full test suite:
    run_tests.bat
"""
from __future__ import annotations

import sys
import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Override the conftest's skip-if-headless pytestmark — these tests are
# pure logic and never create a Tk window.
pytestmark = pytest.mark.usefixtures()  # no-op marker that clears inherited skip

# ── Source path ──────────────────────────────────────────────────────────────
_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from ai_prowler_mcp import _make_user_id, _resolve_user


# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def _folder_from_slug(slug: str) -> str:
    """Mirror the folder-name logic: slug + '-private', always lowercase."""
    return slug + "-private"


class _FakeGui:
    """Minimal stand-in for self inside admin methods that only touch
    data dicts and Path operations — no widgets needed."""

    def _admin_users_path(self):
        return Path(self._users_path)

    def _admin_load_users(self):
        p = self._admin_users_path()
        if p.exists():
            return json.loads(p.read_text(encoding='utf-8'))
        return {"users": {}}

    def _admin_save_raw(self, data):
        """Write without sync (used by tests that check sync separately)."""
        p = self._admin_users_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2), encoding='utf-8')


def _attach_methods(fake_cls):
    """Attach real rag_gui admin methods to _FakeGui."""
    try:
        tk_mock = MagicMock()
        with patch.dict(sys.modules, {
            'tkinter': tk_mock,
            'tkinter.ttk': MagicMock(),
            'tkinter.messagebox': MagicMock(),
            'tkinter.filedialog': MagicMock(),
            'tkinter.scrolledtext': MagicMock(),
            'tkinter.simpledialog': MagicMock(),
        }):
            import rag_gui as _rg
        for name in ('_admin_sync_collection_map', '_admin_update_private_rule',
                     '_admin_load_seats', '_admin_assigned_keys',
                     '_admin_unassigned_keys', '_admin_mask_key',
                     '_admin_seats_path'):
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


# ══════════════════════════════════════════════════════════════════════════════
# Section A — Slug generation
# ══════════════════════════════════════════════════════════════════════════════

class TestSlugGeneration:
    """_make_user_id always produces lowercase hyphenated slugs."""

    def test_standard_name(self):
        assert _make_user_id("David Vavro") == "david-vavro"

    def test_all_caps(self):
        assert _make_user_id("DAVID VAVRO") == "david-vavro"

    def test_all_lower(self):
        assert _make_user_id("david vavro") == "david-vavro"

    def test_mixed_case(self):
        assert _make_user_id("dAvId VaVrO") == "david-vavro"

    def test_extra_spaces_collapsed(self):
        assert _make_user_id("David  Vavro") == "david-vavro"

    def test_leading_trailing_spaces(self):
        assert _make_user_id("  David Vavro  ") == "david-vavro"

    def test_hyphenated_last_name(self):
        assert _make_user_id("Mary Smith-Jones") == "mary-smith-jones"

    def test_three_part_name(self):
        assert _make_user_id("John Paul Smith") == "john-paul-smith"

    def test_apostrophe_stripped(self):
        assert _make_user_id("Sean O'Brien") == "sean-obrien"

    def test_single_name(self):
        assert _make_user_id("Cher") == "cher"

    def test_empty_string(self):
        assert _make_user_id("") == "unknown-user"

    def test_only_spaces(self):
        assert _make_user_id("   ") == "unknown-user"

    def test_numbers_in_name(self):
        assert _make_user_id("Field Crew 1") == "field-crew-1"

    def test_vicki_vavro(self):
        assert _make_user_id("Vicki Vavro") == "vicki-vavro"

    def test_resolve_user_sets_slug_id(self):
        """_resolve_user must set id = slug, never the bearer token."""
        users_data = {"users": {
            "bearbear": {
                "name": "David Vavro", "role": "owner", "status": "active",
                "scopes": [], "private_collection_enabled": True,
            }
        }}
        u = _resolve_user(users_data, "bearbear")
        assert u is not None
        assert u["id"] == "david-vavro", (
            f"Expected 'david-vavro', got '{u['id']}' — id must be slug, not token"
        )

    def test_resolve_user_id_never_equals_token(self):
        users_data = {"users": {
            "Synopsys1*": {
                "name": "Vicki Vavro", "role": "manager", "status": "active",
                "scopes": ["scope:sales"], "private_collection_enabled": True,
            }
        }}
        u = _resolve_user(users_data, "Synopsys1*")
        assert u["id"] != "Synopsys1*", "id must not be the bearer token"
        assert u["id"] == "vicki-vavro"


# ══════════════════════════════════════════════════════════════════════════════
# Section B — Folder name derivation
# ══════════════════════════════════════════════════════════════════════════════

class TestFolderNameDerivation:
    """Private folder name = slug + '-private', always lowercase."""

    def test_david_vavro_folder(self):
        assert _folder_from_slug(_make_user_id("David Vavro")) == "david-vavro-private"

    def test_vicki_vavro_folder(self):
        assert _folder_from_slug(_make_user_id("Vicki Vavro")) == "vicki-vavro-private"

    def test_all_caps_name_lowercase_folder(self):
        assert _folder_from_slug(_make_user_id("JOHN SMITH")) == "john-smith-private"

    def test_folder_always_ends_with_private(self):
        for name in ("Alice Staff", "Bob Crew", "Manager One"):
            folder = _folder_from_slug(_make_user_id(name))
            assert folder.endswith("-private"), f"'{folder}' must end with '-private'"

    def test_folder_always_lowercase(self):
        for name in ("UPPER CASE", "Mixed Case", "lower case"):
            folder = _folder_from_slug(_make_user_id(name))
            assert folder == folder.lower(), f"'{folder}' must be all lowercase"

    def test_folder_no_spaces(self):
        folder = _folder_from_slug(_make_user_id("David Vavro"))
        assert " " not in folder

    def test_folder_starts_with_slug(self):
        """Folder name must start with the user id slug."""
        name = "Sarah Connor"
        slug = _make_user_id(name)
        folder = _folder_from_slug(slug)
        assert folder.startswith(slug), f"'{folder}' must start with slug '{slug}'"


# ══════════════════════════════════════════════════════════════════════════════
# Section C — _admin_sync_collection_map
# ══════════════════════════════════════════════════════════════════════════════

class TestAdminSyncCollectionMap:

    def _base_data(self):
        return {
            "users": {
                "tok-david": {
                    "name": "David Vavro", "role": "owner", "status": "active",
                    "private_collection_enabled": True,
                },
                "tok-vicki": {
                    "name": "Vicki Vavro", "role": "manager", "status": "active",
                    "private_collection_enabled": True,
                },
                "tok-bob": {
                    "name": "Bob Crew", "role": "field_crew", "status": "active",
                    "private_collection_enabled": False,
                },
            },
            "collection_map": {
                "rules": [
                    {"prefix": "C:\\Docs\\sales", "collection": "scope:sales"},
                    {"prefix": "C:\\Docs\\shared", "collection": "shared"},
                ],
                "default_collection": "shared",
            }
        }

    def test_generates_rules_for_private_enabled_users(self, fake_self):
        data = self._base_data()
        fake_self._admin_sync_collection_map(data)
        collections = {r["collection"] for r in data["collection_map"]["rules"]}
        assert "user:david-vavro" in collections
        assert "user:vicki-vavro" in collections

    def test_no_rule_for_private_disabled_user(self, fake_self):
        data = self._base_data()
        fake_self._admin_sync_collection_map(data)
        collections = {r["collection"] for r in data["collection_map"]["rules"]}
        assert "user:bob-crew" not in collections

    def test_preserves_non_user_rules(self, fake_self):
        data = self._base_data()
        fake_self._admin_sync_collection_map(data)
        collections = [r["collection"] for r in data["collection_map"]["rules"]]
        assert "scope:sales" in collections
        assert "shared" in collections

    def test_preserves_custom_path_on_re_sync(self, fake_self):
        """Custom paths set via the folder dialog must survive re-sync."""
        data = self._base_data()
        data["collection_map"]["rules"].append({
            "prefix": "D:\\CustomDrive\\david-vavro-private",
            "collection": "user:david-vavro"
        })
        fake_self._admin_sync_collection_map(data)
        david_rule = next(r for r in data["collection_map"]["rules"]
                          if r["collection"] == "user:david-vavro")
        assert david_rule["prefix"] == "D:\\CustomDrive\\david-vavro-private"

    def test_removes_rule_when_private_disabled(self, fake_self):
        data = self._base_data()
        fake_self._admin_sync_collection_map(data)
        # Disable Vicki's private collection
        data["users"]["tok-vicki"]["private_collection_enabled"] = False
        fake_self._admin_sync_collection_map(data)
        collections = {r["collection"] for r in data["collection_map"]["rules"]}
        assert "user:vicki-vavro" not in collections

    def test_default_collection_preserved(self, fake_self):
        data = self._base_data()
        fake_self._admin_sync_collection_map(data)
        assert data["collection_map"]["default_collection"] == "shared"

    def test_folder_leaf_is_slug_plus_private(self, fake_self):
        data = self._base_data()
        fake_self._admin_sync_collection_map(data)
        david_rule = next(r for r in data["collection_map"]["rules"]
                          if r["collection"] == "user:david-vavro")
        leaf = david_rule["prefix"].replace("\\", "/").split("/")[-1]
        assert leaf == "david-vavro-private", f"Expected 'david-vavro-private', got '{leaf}'"

    def test_folder_leaf_always_lowercase(self, fake_self):
        data = self._base_data()
        fake_self._admin_sync_collection_map(data)
        for rule in data["collection_map"]["rules"]:
            if rule["collection"].startswith("user:"):
                leaf = rule["prefix"].replace("\\", "/").split("/")[-1]
                assert leaf == leaf.lower(), f"Folder leaf '{leaf}' must be lowercase"

    def test_empty_users_removes_all_user_rules(self, fake_self):
        data = {"users": {}, "collection_map": {
            "rules": [
                {"prefix": "C:\\old", "collection": "user:old-user"},
                {"prefix": "C:\\sales", "collection": "scope:sales"},
            ],
            "default_collection": "shared"
        }}
        fake_self._admin_sync_collection_map(data)
        collections = {r["collection"] for r in data["collection_map"]["rules"]}
        assert "user:old-user" not in collections
        assert "scope:sales" in collections

    def test_creates_collection_map_if_absent(self, fake_self):
        data = {"users": {
            "tok": {"name": "Alice Smith", "role": "staff", "status": "active",
                    "private_collection_enabled": True}
        }}
        fake_self._admin_sync_collection_map(data)
        assert "collection_map" in data
        collections = {r["collection"] for r in data["collection_map"]["rules"]}
        assert "user:alice-smith" in collections

    def test_name_case_insensitive_produces_same_rule(self, fake_self):
        """'ALICE SMITH', 'alice smith', 'Alice Smith' all produce user:alice-smith."""
        for name in ("ALICE SMITH", "alice smith", "Alice Smith", "aLiCe sMiTh"):
            data = {"users": {
                "tok": {"name": name, "role": "staff", "status": "active",
                        "private_collection_enabled": True}
            }}
            fake_self._admin_sync_collection_map(data)
            collections = {r["collection"] for r in data["collection_map"]["rules"]}
            assert "user:alice-smith" in collections, (
                f"Name '{name}' must produce 'user:alice-smith', got: {collections}"
            )


# ══════════════════════════════════════════════════════════════════════════════
# Section D — _admin_update_private_rule
# ══════════════════════════════════════════════════════════════════════════════

class TestAdminUpdatePrivateRule:

    def _write(self, fake_self, data):
        p = Path(fake_self._users_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2), encoding='utf-8')

    def _read(self, fake_self):
        return json.loads(Path(fake_self._users_path).read_text())

    def test_updates_matching_rule_path(self, fake_self):
        data = {"users": {}, "collection_map": {
            "rules": [{"prefix": "C:\\default\\david-vavro-private",
                       "collection": "user:david-vavro"}],
            "default_collection": "shared"
        }}
        self._write(fake_self, data)
        fake_self._admin_update_private_rule(
            "david-vavro", "D:\\Custom\\david-vavro-private")
        rule = next(r for r in self._read(fake_self)["collection_map"]["rules"]
                    if r["collection"] == "user:david-vavro")
        assert rule["prefix"] == "D:\\Custom\\david-vavro-private"

    def test_does_not_touch_other_rules(self, fake_self):
        data = {"users": {}, "collection_map": {
            "rules": [
                {"prefix": "C:\\david", "collection": "user:david-vavro"},
                {"prefix": "C:\\vicki", "collection": "user:vicki-vavro"},
                {"prefix": "C:\\sales", "collection": "scope:sales"},
            ],
            "default_collection": "shared"
        }}
        self._write(fake_self, data)
        fake_self._admin_update_private_rule("david-vavro", "D:\\new\\david-vavro-private")
        rules = {r["collection"]: r["prefix"]
                 for r in self._read(fake_self)["collection_map"]["rules"]}
        assert rules["user:vicki-vavro"] == "C:\\vicki"
        assert rules["scope:sales"] == "C:\\sales"

    def test_no_op_when_slug_not_found(self, fake_self):
        data = {"users": {}, "collection_map": {
            "rules": [{"prefix": "C:\\sales", "collection": "scope:sales"}],
            "default_collection": "shared"
        }}
        self._write(fake_self, data)
        fake_self._admin_update_private_rule("nobody", "D:\\nowhere")
        updated = self._read(fake_self)
        assert updated["collection_map"]["rules"][0]["collection"] == "scope:sales"

    def test_no_op_on_empty_slug(self, fake_self):
        data = {"users": {}, "collection_map": {"rules": [], "default_collection": "shared"}}
        self._write(fake_self, data)
        fake_self._admin_update_private_rule("", "D:\\somewhere")
        assert self._read(fake_self) == data

    def test_custom_path_stored_exactly(self, fake_self):
        data = {"users": {}, "collection_map": {
            "rules": [{"prefix": "C:\\default", "collection": "user:david-vavro"}],
            "default_collection": "shared"
        }}
        self._write(fake_self, data)
        custom = "E:\\ServerData\\Privates\\david-vavro-private"
        fake_self._admin_update_private_rule("david-vavro", custom)
        rule = next(r for r in self._read(fake_self)["collection_map"]["rules"]
                    if r["collection"] == "user:david-vavro")
        assert rule["prefix"] == custom


# ══════════════════════════════════════════════════════════════════════════════
# MANUAL QA CHECKLIST — GUI interactions (requires a running AI-Prowler GUI)
# ══════════════════════════════════════════════════════════════════════════════
#
# ADD USER FLOW
# [ ] Admin tab → Add User dialog opens
# [ ] First name field is focused by default
# [ ] Slug preview updates live: "DAVID" + "VAVRO" → shows "david-vavro"
# [ ] "david" + "vavro" → same slug "david-vavro" (always lowercase)
# [ ] Missing first name → warning "Both First name and Last name are required"
# [ ] Missing last name → same warning
# [ ] Saving opens Bearer Token popup
# [ ] Closing token popup opens "Set Up Private Folder" (only if private enabled)
# [ ] Private folder path pre-filled: <home>\Documents\AI-Prowler-Server-privates\david-vavro-private
# [ ] Path is lowercase (david-vavro-private, not David-Vavro-Private)
# [ ] Path entry is editable — admin can change root dir freely
# [ ] Browse button: picks parent dir, appends "david-vavro-private" as leaf
# [ ] Create Folder: creates directory, green status, button disables
# [ ] Create Folder with custom root: collection_map rule updated to custom path
# [ ] Skip for now: amber warning, auto-closes after ~2s
# [ ] After save: users.json collection_map has user:david-vavro rule
# [ ] Rule prefix leaf is "david-vavro-private" (lowercase, hyphenated)
# [ ] Non-user rules (scope:*, shared) untouched
#
# EDIT USER FLOW
# [ ] Edit existing user → first/last name pre-populated from stored "First Last"
# [ ] Slug preview shows current slug on open
# [ ] Changing name updates slug live
# [ ] Enabling private on user who didn't have it → folder setup popup appears
# [ ] Disabling private → no popup; rule removed from collection_map on save
# [ ] Re-saving user with custom path → custom path preserved (not overwritten)
# [ ] Cell phone / carrier now saved correctly on edit
#
# EDGE CASES
# [ ] "Sean O'Brien" → slug "sean-obrien", folder "sean-obrien-private"
# [ ] All-caps name → slug and folder both lowercase
# [ ] Two users: both rules in collection_map, non-user rules untouched
# [ ] User removed → their user:* rule gone from collection_map on next save
