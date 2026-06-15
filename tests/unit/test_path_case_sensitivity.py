"""
tests/unit/test_path_case_sensitivity.py
=========================================
Regression tests for Windows path case-insensitivity bugs in the tracking
and untracking system (found June 2026).

THE BUG
-------
normalise_path() only converts forward slashes to backslashes. It does NOT
normalise case. This causes silent mismatches on Windows because:

  1. The filesystem is case-insensitive: David-Vavro-Private and
     david-vavro-private refer to the same physical folder.

  2. Path.resolve() on Windows returns the ACTUAL case of the folder as it
     exists on disk. So if david-vavro-private is the real folder,
     Path("David-Vavro-Private").resolve() returns
     "...\\david-vavro-private" — the lowercase version.

  3. The tracking DB uses normalise_path() as its key. If the old entry was
     stored under "David-Vavro-Private" and Path.resolve() now returns
     "david-vavro-private", the remove lookup hits the wrong key.

REPRODUCTION STEPS (manual)
-----------------------------
1. Index C:\\...\\David-Vavro-Private   → stored in tracking DB under that key
2. Rename/recreate folder as david-vavro-private (lowercase)
3. Index david-vavro-private           → stored under new lowercase key
4. Try to remove "David-Vavro-Private" from Update Index tab
5. BUG: removes "david-vavro-private" instead (Path.resolve() returns
   the lowercase real name, matching the wrong tracking entry)

ROOT CAUSE
----------
normalise_path() at line 267-281 of rag_preprocessor.py:
    def normalise_path(filepath: str) -> str:
        return str(filepath).replace('/', '\\')

Only converts slashes — no case normalisation.

On Windows all path comparisons MUST be case-insensitive. The fix is to
lowercase the whole path on Windows before storage and lookup.

WHAT THESE TESTS CHECK
-----------------------
  A — normalise_path produces consistent output regardless of input case
  B — add_to_auto_update_list / remove_from_auto_update_list are case-safe
  C — remove_directory_from_index tracking DB lookup is case-safe
  D — ChromaDB filepath metadata matching is case-safe
  E — _normalize_path_for_match (used in collection resolver) is case-safe

Run:
    run_tests.bat tests\\unit\\test_path_case_sensitivity.py
    run_tests.bat tests\\unit\\test_path_case_sensitivity.py -v
"""
from __future__ import annotations

import json
import sys
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

# ── Source path ───────────────────────────────────────────────────────────────
_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import rag_preprocessor as rp


# ══════════════════════════════════════════════════════════════════════════════
# Section A — normalise_path case consistency
# ══════════════════════════════════════════════════════════════════════════════

class TestNormalisePath:
    """normalise_path preserves the user's original case but normalises
    separators to backslashes. Case-insensitive comparison is handled by
    path_equals() and path_startswith() — NOT by normalise_path itself."""

    def test_backslash_normalisation_forward_slash(self):
        """Forward slashes converted to backslashes, case preserved."""
        result = rp.normalise_path("C:/Users/david/Documents")
        assert result == r"C:\Users\david\Documents"

    def test_case_preserved_mixed(self):
        """Mixed case is stored as-entered — the user's folder name is kept."""
        result = rp.normalise_path(r"C:\Users\AI-Prowler-Server\David-Vavro-Private")
        assert result == r"C:\Users\AI-Prowler-Server\David-Vavro-Private"

    def test_case_preserved_upper(self):
        result = rp.normalise_path(r"C:\USERS\DAVID\DOCUMENTS")
        assert result == r"C:\USERS\DAVID\DOCUMENTS"

    def test_backslash_only_no_lowercase(self):
        """normalise_path must NOT lowercase — that would hide the stored name."""
        result = rp.normalise_path(r"C:\Users\David\Documents")
        assert "David" in result, "normalise_path must preserve case"

    def test_separator_normalised_not_case(self):
        """Only separator is normalised, not case."""
        a = rp.normalise_path("C:/Users/David/Documents")
        b = rp.normalise_path(r"C:\Users\David\Documents")
        assert a == b  # same because only separators differ


class TestPathEquals:
    """path_equals() is case-insensitive on Windows."""

    def test_same_path_equals(self):
        assert rp.path_equals(
            r"C:\privates\david-vavro-private",
            r"C:\privates\david-vavro-private")

    def test_mixed_case_same_as_lower(self):
        """'David-Vavro-Private' and 'david-vavro-private' must be equal."""
        assert rp.path_equals(
            r"C:\privates\David-Vavro-Private",
            r"C:\privates\david-vavro-private"), (
            "path_equals must treat case variants as equal on Windows"
        )

    def test_all_caps_equals_lower(self):
        assert rp.path_equals(r"C:\USERS\DAVID", r"C:\users\david")

    def test_drive_letter_case(self):
        assert rp.path_equals(r"C:\foo", r"c:\foo")

    def test_different_paths_not_equal(self):
        assert not rp.path_equals(
            r"C:\privates\david-vavro-private",
            r"C:\privates\vicki-vavro-private")

    def test_forward_slash_vs_backslash(self):
        assert rp.path_equals(
            "C:/privates/david-vavro-private",
            r"C:\privates\david-vavro-private")


class TestPathStartswith:
    """path_startswith() is case-insensitive on Windows and handles
    trailing separator edge cases."""

    def test_child_under_parent(self):
        assert rp.path_startswith(
            r"C:\privates\david-vavro-private\file.txt",
            r"C:\privates\david-vavro-private")

    def test_mixed_case_child_under_lower_parent(self):
        assert rp.path_startswith(
            r"C:\privates\David-Vavro-Private\file.txt",
            r"C:\privates\david-vavro-private"), (
            "path_startswith must match case variants"
        )

    def test_lower_child_under_mixed_case_parent(self):
        assert rp.path_startswith(
            r"C:\privates\david-vavro-private\file.txt",
            r"C:\privates\David-Vavro-Private")

    def test_exact_match_counts_as_startswith(self):
        assert rp.path_startswith(
            r"C:\privates\david-vavro-private",
            r"C:\privates\david-vavro-private")

    def test_no_spurious_prefix_match(self):
        """'C:\\Foo' must NOT match as parent of 'C:\\FooBar'."""
        assert not rp.path_startswith(
            r"C:\privates\david-vavro-private-extra",
            r"C:\privates\david-vavro-private")

    def test_sibling_not_matched(self):
        assert not rp.path_startswith(
            r"C:\privates\vicki-vavro-private\file.txt",
            r"C:\privates\david-vavro-private")


# ══════════════════════════════════════════════════════════════════════════════
# Section B — auto-update list add/remove case safety
# ══════════════════════════════════════════════════════════════════════════════

class TestAutoUpdateListCaseSafety:
    """add_to_auto_update_list and remove_from_auto_update_list must treat
    differently-cased paths to the same folder as identical."""

    def _make_list(self, tmp_path, paths):
        """Write a fake auto-update list JSON."""
        p = tmp_path / ".rag_auto_update_dirs.json"
        p.write_text(json.dumps({"directories": paths}), encoding="utf-8")
        return p

    def test_duplicate_add_different_case_rejected(self, tmp_path):
        """Adding 'David-Vavro-Private' when 'david-vavro-private' is already
        tracked must replace the old entry with the new name and return a
        warning string — not silently create a duplicate."""
        list_path = self._make_list(tmp_path, [
            r"C:\privates\david-vavro-private"
        ])
        with patch.object(rp, 'AUTO_UPDATE_LIST', list_path):
            result = rp.add_to_auto_update_list(
                r"C:\privates\David-Vavro-Private")
        # Must return a warning string (not True or False)
        assert isinstance(result, str), (
            f"Expected a warning string, got {result!r}. "
            "add_to_auto_update_list must warn when replacing a case variant."
        )
        assert "already tracked" in result.lower() or "replaced" in result.lower(), (
            f"Warning message doesn't mention replacement: {result}"
        )
        # List must still have exactly ONE entry
        dirs = json.loads(list_path.read_text())["directories"]
        assert len(dirs) == 1, f"Expected 1 entry after replacement, got {len(dirs)}: {dirs}"

    def test_remove_by_different_case_succeeds(self, tmp_path):
        """Removing 'David-Vavro-Private' when the list contains
        'david-vavro-private' must successfully remove the entry."""
        list_path = self._make_list(tmp_path, [
            r"C:\privates\david-vavro-private"
        ])
        with patch.object(rp, 'AUTO_UPDATE_LIST', list_path):
            rp.remove_from_auto_update_list(r"C:\privates\David-Vavro-Private")
        dirs = json.loads(list_path.read_text())["directories"]
        assert len(dirs) == 0, (
            f"remove_from_auto_update_list failed to remove case-variant entry. "
            f"Remaining: {dirs}"
        )

    def test_remove_lowercase_when_stored_as_upper(self, tmp_path):
        """Removing 'david-vavro-private' when stored as 'David-Vavro-Private'
        must also succeed (reverse of the above)."""
        list_path = self._make_list(tmp_path, [
            r"C:\privates\David-Vavro-Private"
        ])
        with patch.object(rp, 'AUTO_UPDATE_LIST', list_path):
            rp.remove_from_auto_update_list(r"C:\privates\david-vavro-private")
        dirs = json.loads(list_path.read_text())["directories"]
        assert len(dirs) == 0, (
            f"Should have removed the upper-case stored entry via lowercase key. "
            f"Remaining: {dirs}"
        )

    def test_two_case_variants_not_duplicated_after_add(self, tmp_path):
        """Adding both 'David-Vavro-Private' and 'david-vavro-private' must
        result in exactly ONE entry — the second replaces the first."""
        list_path = self._make_list(tmp_path, [])
        with patch.object(rp, 'AUTO_UPDATE_LIST', list_path):
            rp.add_to_auto_update_list(r"C:\privates\David-Vavro-Private")
            rp.add_to_auto_update_list(r"C:\privates\david-vavro-private")
        dirs = json.loads(list_path.read_text())["directories"]
        assert len(dirs) == 1, (
            f"Expected 1 entry after adding two case variants, got {len(dirs)}: {dirs}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section C — tracking DB lookup case safety
# ══════════════════════════════════════════════════════════════════════════════

class TestTrackingDBCaseSafety:
    """The tracking DB uses normalise_path as its key. Keys that differ only
    in case must resolve to the same entry."""

    def _make_tracking_db(self, tmp_path, entries: dict):
        """Write a fake tracking DB JSON."""
        p = tmp_path / ".rag_file_tracking.json"
        p.write_text(json.dumps(entries), encoding="utf-8")
        return p

    def test_tracking_db_key_case_collision(self, tmp_path):
        """If the tracking DB has 'david-vavro-private' as a key, looking up
        'David-Vavro-Private' should find the same entry — via path_equals,
        not raw string equality. normalise_path alone preserves case; the
        comparison must use path_equals."""
        lower_key   = rp.normalise_path(r"C:\privates\david-vavro-private")
        upper_input = r"C:\privates\David-Vavro-Private"

        # path_equals is the correct comparison tool — not == on normalised strings
        assert rp.path_equals(lower_key, upper_input), (
            f"path_equals must treat these as the same path on Windows:\n"
            f"  stored key : {lower_key}\n"
            f"  lookup key : {rp.normalise_path(upper_input)}\n"
        )

    def test_remove_directory_hits_correct_db_key(self, tmp_path):
        """remove_directory_from_index must remove the entry stored under
        the lowercase key when called with the uppercase path variant.

        This is the exact bug sequence:
          1. david-vavro-private indexed → stored in DB as lowercase key
          2. Admin tries to remove David-Vavro-Private (uppercase)
          3. BUG: removal fails or hits wrong key
          4. FIX: normalise_path lowercases both, they match
        """
        lower_key = rp.normalise_path(
            r"C:\privates\david-vavro-private")
        tracking_db = {
            lower_key: {
                "first_scan": "2026-06-13T00:00:00",
                "last_scan":  "2026-06-13T01:00:00",
                "files": {
                    lower_key + r"\test.txt": {
                        "modified": "2026-06-13T00:00:00",
                        "modified_human": "2026-06-13 00:00:00",
                        "size": 100
                    }
                }
            }
        }
        db_path = tmp_path / ".rag_file_tracking.json"
        db_path.write_text(json.dumps(tracking_db), encoding="utf-8")

        with (
            patch.object(rp, 'TRACKING_DB', db_path),
            patch.object(rp, 'AUTO_UPDATE_LIST', tmp_path / ".rag_auto_update_dirs.json"),
            patch('rag_preprocessor.get_chroma_client') as mock_chroma,
        ):
            mock_client = MagicMock()
            mock_collection = MagicMock()
            mock_collection.get.return_value = {'ids': [], 'metadatas': []}
            mock_client.get_or_create_collection.return_value = mock_collection
            mock_chroma.return_value = (mock_client, MagicMock())

            # Call remove with the UPPERCASE variant
            result = rp.remove_directory_from_index(
                r"C:\privates\David-Vavro-Private")

        # Load the tracking DB after removal
        remaining = json.loads(db_path.read_text())

        assert lower_key not in remaining, (
            f"REGRESSION: remove_directory_from_index called with uppercase path "
            f"'David-Vavro-Private' did NOT remove the lowercase-keyed entry "
            f"'david-vavro-private' from the tracking DB.\n"
            f"Remaining keys: {list(remaining.keys())}"
        )

    def test_remove_uppercase_stored_entry_via_lowercase_call(self, tmp_path):
        """Reverse test: entry stored under uppercase key, removed via lowercase."""
        upper_key = rp.normalise_path(
            r"C:\privates\David-Vavro-Private")
        tracking_db = {
            upper_key: {
                "first_scan": "2026-06-13T00:00:00",
                "last_scan": "2026-06-13T01:00:00",
                "files": {}
            }
        }
        db_path = tmp_path / ".rag_file_tracking.json"
        db_path.write_text(json.dumps(tracking_db), encoding="utf-8")

        with (
            patch.object(rp, 'TRACKING_DB', db_path),
            patch.object(rp, 'AUTO_UPDATE_LIST', tmp_path / ".rag_auto_update_dirs.json"),
            patch('rag_preprocessor.get_chroma_client') as mock_chroma,
        ):
            mock_client = MagicMock()
            mock_collection = MagicMock()
            mock_collection.get.return_value = {'ids': [], 'metadatas': []}
            mock_client.get_or_create_collection.return_value = mock_collection
            mock_chroma.return_value = (mock_client, MagicMock())

            rp.remove_directory_from_index(r"C:\privates\david-vavro-private")

        remaining = json.loads(db_path.read_text())
        # After fix, upper_key should equal lower_key, so nothing remains
        assert len(remaining) == 0, (
            f"Entry under uppercase key not removed via lowercase call. "
            f"Remaining: {remaining}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section D — ChromaDB filepath metadata matching
# ══════════════════════════════════════════════════════════════════════════════

class TestChromaDBFilepathCaseSafety:
    """ChromaDB chunks store the filepath in metadata. The untrack code
    uses path_startswith / path_equals to match which chunks to delete.
    A case mismatch must NOT prevent deletion — orphan chunks accumulate."""

    def test_filepath_comparison_case_insensitive(self):
        """path_startswith must match a chunk filepath stored in lowercase
        against a removal dir specified in Title Case."""
        stored_fp   = rp.normalise_path(r"C:\privates\david-vavro-private\test.txt")
        removal_dir = rp.normalise_path(r"C:\privates\David-Vavro-Private")

        assert rp.path_startswith(stored_fp, removal_dir), (
            f"ChromaDB chunk filepath:\n  {stored_fp}\n"
            f"does not match removal dir:\n  {removal_dir}\n"
            "path_startswith must be case-insensitive on Windows"
        )

    def test_filepath_exact_match_case_insensitive(self):
        """path_equals must treat Title-Case and lowercase variants as equal."""
        stored = rp.normalise_path(r"C:\privates\David-Vavro-Private\file.txt")
        lookup = rp.normalise_path(r"C:\privates\david-vavro-private\file.txt")
        assert rp.path_equals(stored, lookup), (
            f"path_equals must match:\n  {stored}\n  {lookup}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# Section E — _normalize_path_for_match (collection resolver)
# ══════════════════════════════════════════════════════════════════════════════

class TestNormalizePathForMatch:
    """_normalize_path_for_match is already lowercase+forward-slash. Verify
    it handles all the inputs the collection resolver will see."""

    def test_lowercases_path(self):
        result = rp._normalize_path_for_match(
            r"C:\Users\AI-Prowler-Server\Documents\David-Vavro-Private")
        assert result == result.lower()

    def test_converts_backslashes_to_forward(self):
        result = rp._normalize_path_for_match(
            r"C:\privates\david-vavro-private")
        assert "\\" not in result

    def test_strips_trailing_slash(self):
        a = rp._normalize_path_for_match(r"C:\privates\david-vavro-private\\")
        b = rp._normalize_path_for_match(r"C:\privates\david-vavro-private")
        assert a == b

    def test_david_vavro_variants_equal(self):
        a = rp._normalize_path_for_match(
            r"C:\privates\David-Vavro-Private")
        b = rp._normalize_path_for_match(
            r"C:\privates\david-vavro-private")
        assert a == b, (
            "_normalize_path_for_match must make case variants equal for "
            "collection_map prefix matching"
        )

    def test_collection_resolver_prefix_match_case_insensitive(self):
        """resolve_collection_for_path must match a prefix regardless of the
        case used in the collection_map rule vs the actual filepath."""
        mapping = {
            "rules": [
                {
                    "prefix": r"C:\privates\david-vavro-private",
                    "collection": "user:david-vavro"
                }
            ],
            "default_collection": "shared"
        }
        # File path uses Title-Case (as it may have been before rename)
        result = rp.resolve_collection_for_path(
            r"C:\privates\David-Vavro-Private\secret.txt",
            mapping
        )
        assert result == "user:david-vavro", (
            f"Collection resolver returned '{result}' instead of 'user:david-vavro'.\n"
            "Prefix matching must be case-insensitive."
        )
