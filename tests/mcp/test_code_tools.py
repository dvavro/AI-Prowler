"""
tests/mcp/test_code_tools.py — v6.0.2 code-aware retrieval

Validates the two new MCP tools introduced in AI-Prowler 6.0.2:

    grep_documents(...)     — literal/regex search across tracked files
    read_file_lines(...)    — direct line-range read, allowlist-gated

Plus the four shared helpers:

    _is_path_under_tracked_roots
    _resolve_allowlisted_path
    _iter_allowlisted_files
    _looks_binary

Test plan IDs in this file all begin with `C-MCP-*` (Code-aware MCP) following
the same convention used by the L-MCP-* learning tests. Mapping:

    Helpers              C-MCP-01 … C-MCP-15
    grep_documents       C-MCP-16 … C-MCP-35
    read_file_lines      C-MCP-36 … C-MCP-55
    Integration          C-MCP-56 … C-MCP-60

Isolation
---------
This file uses the existing `isolated_env` fixture from the top-level
`tests/conftest.py`, which gives every test a brand-new ChromaDB, tracking
JSON, and `auto_update.json`. We then call the real
`rag_preprocessor.add_to_auto_update_list()` to wire test files into the
allowlist — same code path the live indexer uses, so we exercise the actual
authorization surface rather than mocking around it.

These tests do NOT load the embedding model or index any files. They only
exercise the new tools against on-disk fixtures and the JSON allowlist.
Runtime budget: well under 1 second for the whole file.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# Module-level fixture: import ai_prowler_mcp once per session
#
# We can't put this in conftest.py because the MCP module imports the real
# `mcp` SDK at top level and we'd rather have any import failures show up
# as a per-test fixture error than a collection-time crash.
# ──────────────────────────────────────────────────────────────────────────────
@pytest.fixture(scope="session")
def mcp_mod():
    """Import ai_prowler_mcp exactly once per session."""
    import ai_prowler_mcp as ap
    # Ensure the prewarm gate is open — the stdio entry path clears it but
    # tests run before that path is ever taken.
    ap._prewarm_event.set()
    return ap


# ──────────────────────────────────────────────────────────────────────────────
# Workhorse fixture: a project tree wired into the per-test allowlist
#
# Builds the same canonical fixture every test in this file uses:
#
#   <tmp>/
#   ├── samples/
#   │   ├── tracked_dir/
#   │   │   └── project/
#   │   │       ├── main.py
#   │   │       ├── utils.py
#   │   │       ├── README.md
#   │   │       ├── subdir/helper.py
#   │   │       ├── __pycache__/main.cpython-311.pyc   (under SKIP_DIRECTORIES)
#   │   │       └── binary.bin                         (NUL-laced)
#   │   ├── tracked_file.md                            (single-file entry)
#   │   └── untracked/secret.py                        (must never be readable)
#
# The fixture calls the real `add_to_auto_update_list()` for both the
# directory and the single-file entry so the allowlist exercises both shapes.
# ──────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def code_tree(isolated_env):
    """Build the canonical code-tools test tree and track it. Returns an
    object exposing the relevant paths plus a handle to the rag module."""
    rag = isolated_env.rag
    root = isolated_env.sample_root

    tracked_dir = root / "tracked_dir"
    proj        = tracked_dir / "project"
    sub         = proj / "subdir"
    pyc         = proj / "__pycache__"
    untracked   = root / "untracked"
    for p in (proj, sub, pyc, untracked):
        p.mkdir(parents=True, exist_ok=True)

    (proj / "main.py").write_text(
        "def main():\n"
        "    print('hello world')\n"
        "\n"
        "def clear_database():\n"
        "    # TODO: drop all collections\n"
        "    return None\n"
        "\n"
        "class MyError(Exception):\n"
        "    pass\n",
        encoding="utf-8",
    )
    (proj / "utils.py").write_text(
        "import os\n"
        "API_KEY = 'sk-test'\n"
        "def helper():\n"
        "    return API_KEY\n",
        encoding="utf-8",
    )
    (proj / "README.md").write_text(
        "# Project\n\nThis project does TODO things.\n",
        encoding="utf-8",
    )
    (sub / "helper.py").write_text(
        "def deep():\n"
        "    return 42\n",
        encoding="utf-8",
    )
    (proj / "binary.bin").write_bytes(b"\x00\x01\x02\x03binary\x00garbage")
    (pyc / "main.cpython-311.pyc").write_bytes(b"\x00should\x00skip")
    tracked_file = root / "tracked_file.md"
    tracked_file.write_text(
        "# Tracked solo\nLine two TODO.\nLine three.\n",
        encoding="utf-8",
    )
    (untracked / "secret.py").write_text(
        "SECRET = 'must not leak'\n",
        encoding="utf-8",
    )

    # Wire into the per-test allowlist via the real preprocessor function —
    # this is the same call path add_and_index_directory uses, so we exercise
    # the production authorization surface.
    rag.add_to_auto_update_list(str(tracked_dir))
    rag.add_to_auto_update_list(str(tracked_file))

    class CodeTree:
        pass
    t = CodeTree()
    t.rag           = rag
    t.root          = root
    t.tracked_dir   = tracked_dir
    t.tracked_file  = tracked_file
    t.project       = proj
    t.subdir        = sub
    t.untracked     = untracked
    t.main_py       = proj / "main.py"
    t.utils_py      = proj / "utils.py"
    t.readme_md     = proj / "README.md"
    t.helper_py     = sub / "helper.py"
    t.binary_bin    = proj / "binary.bin"
    t.secret_py     = untracked / "secret.py"
    return t


@pytest.fixture
def empty_allowlist(isolated_env):
    """Yield an `isolated_env` whose allowlist has been cleared on disk."""
    isolated_env.auto_update.write_text(
        json.dumps({"directories": []}), encoding="utf-8"
    )
    return isolated_env


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  HELPERS: _is_path_under_tracked_roots  (C-MCP-01 … C-MCP-10)              ║
# ╚════════════════════════════════════════════════════════════════════════════╝

def test_C_MCP_01_empty_allowlist_denies(mcp_mod, empty_allowlist):
    """Empty allowlist denies all paths and explains why."""
    ok, info = mcp_mod._is_path_under_tracked_roots("/some/where/file.py")
    assert ok is False
    assert "empty" in info


def test_C_MCP_02_descendant_of_tracked_dir_allowed(mcp_mod, code_tree):
    """A file under a tracked directory is allowed."""
    ok, info = mcp_mod._is_path_under_tracked_roots(str(code_tree.main_py))
    assert ok is True, info


def test_C_MCP_03_exact_tracked_file_allowed(mcp_mod, code_tree):
    """A single-file allowlist entry is allowed via exact-match."""
    ok, _info = mcp_mod._is_path_under_tracked_roots(str(code_tree.tracked_file))
    assert ok is True


def test_C_MCP_04_untracked_sibling_denied(mcp_mod, code_tree):
    """A file outside any tracked entry is denied even when adjacent to one."""
    adjacent = code_tree.root / "tracked_file_sibling.md"
    adjacent.write_text("hi", encoding="utf-8")
    ok, info = mcp_mod._is_path_under_tracked_roots(str(adjacent))
    assert ok is False, info


def test_C_MCP_05_untracked_path_denied(mcp_mod, code_tree):
    """The untracked tree must never authorize."""
    ok, info = mcp_mod._is_path_under_tracked_roots(str(code_tree.secret_py))
    assert ok is False
    assert "not under any tracked root" in info


def test_C_MCP_06_prefix_collision_not_allowed(mcp_mod, code_tree):
    """`/foo` must NOT authorize `/foobar/leak.py` — classic prefix bug."""
    sneaky = code_tree.root / "tracked_dir_evil"
    sneaky.mkdir()
    target = sneaky / "leak.py"
    target.write_text("LEAK", encoding="utf-8")
    ok, info = mcp_mod._is_path_under_tracked_roots(str(target))
    assert ok is False, info


def test_C_MCP_07_nonexistent_descendant_still_evaluates(mcp_mod, code_tree):
    """Path-relationship check works even when the file doesn't exist yet."""
    phantom = code_tree.tracked_dir / "does_not_exist.py"
    ok, _info = mcp_mod._is_path_under_tracked_roots(str(phantom))
    assert ok is True


def test_C_MCP_08_returns_normalised_forward_slash_path(mcp_mod, code_tree):
    """Allowed path returns a forward-slash, resolved string."""
    messy = str(code_tree.tracked_dir / "." / "project" / "main.py")
    ok, info = mcp_mod._is_path_under_tracked_roots(messy)
    assert ok is True
    assert "\\" not in info
    assert "/./" not in info


def test_C_MCP_09_bogus_entry_does_not_break_check(mcp_mod, code_tree, isolated_env):
    """A bogus allowlist entry must not poison subsequent valid entries."""
    # Inject a malformed entry at the front of the auto-update list
    data = json.loads(isolated_env.auto_update.read_text(encoding="utf-8"))
    data["directories"].insert(0, "\x00garbage\x00")
    isolated_env.auto_update.write_text(json.dumps(data), encoding="utf-8")
    ok, info = mcp_mod._is_path_under_tracked_roots(str(code_tree.main_py))
    assert ok is True, info


def test_C_MCP_10_unicode_paths_allowed(mcp_mod, code_tree):
    """Non-ASCII path components are handled."""
    udir = code_tree.tracked_dir / "プロジェクト"
    udir.mkdir()
    ufile = udir / "ファイル.py"
    ufile.write_text("# unicode\n", encoding="utf-8")
    ok, _info = mcp_mod._is_path_under_tracked_roots(str(ufile))
    assert ok is True


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  HELPERS: _resolve_allowlisted_path  (C-MCP-11 … C-MCP-15)                 ║
# ╚════════════════════════════════════════════════════════════════════════════╝

def test_C_MCP_11_resolve_allow_returns_path_no_error(mcp_mod, code_tree):
    """Allowed path: returns (resolved, None)."""
    resolved, err = mcp_mod._resolve_allowlisted_path(str(code_tree.main_py))
    assert resolved is not None
    assert err is None


def test_C_MCP_12_resolve_deny_returns_friendly_message(mcp_mod, code_tree):
    """Denied path: returns (None, formatted error) and leaks no file content."""
    resolved, err = mcp_mod._resolve_allowlisted_path(str(code_tree.secret_py))
    assert resolved is None
    assert err is not None
    assert "🚫" in err and "Access denied" in err
    # Must NOT include file contents in the denial
    assert "must not leak" not in err


def test_C_MCP_13_denial_lists_currently_tracked(mcp_mod, code_tree):
    """Denial message shows the allowed entries so agent knows what to ask for."""
    _resolved, err = mcp_mod._resolve_allowlisted_path("/totally/outside.txt")
    assert "tracked_dir" in err


def test_C_MCP_14_empty_allowlist_explains_remediation(mcp_mod, empty_allowlist):
    """When nothing's tracked, the denial points to `add_and_index_directory`."""
    _resolved, err = mcp_mod._resolve_allowlisted_path("/some/file.txt")
    assert "No directories are tracked yet" in err
    assert "add_and_index_directory" in err


def test_C_MCP_15_long_allowlist_truncated_in_message(mcp_mod, isolated_env):
    """Denial only lists first 10 tracked entries plus an 'N more' line."""
    data = {"directories": [f"/x/dir{i}" for i in range(25)]}
    isolated_env.auto_update.write_text(json.dumps(data), encoding="utf-8")
    _resolved, err = mcp_mod._resolve_allowlisted_path("/y/outside.txt")
    assert "and 15 more" in err


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  HELPER: _iter_allowlisted_files  (C-MCP-16 … C-MCP-22)                    ║
# ╚════════════════════════════════════════════════════════════════════════════╝

def test_C_MCP_16_iter_walks_recursively(mcp_mod, code_tree):
    """Recursive walk reaches nested subdirectories."""
    files = [fp for fp, _ext in mcp_mod._iter_allowlisted_files()]
    assert any(f.endswith("subdir/helper.py") for f in files), files


def test_C_MCP_17_iter_includes_single_file_entries(mcp_mod, code_tree):
    """Single-file allowlist entries are yielded too."""
    files = [fp for fp, _ in mcp_mod._iter_allowlisted_files()]
    assert any(f.endswith("tracked_file.md") for f in files)


def test_C_MCP_18_iter_excludes_untracked(mcp_mod, code_tree):
    """Files outside the allowlist are never yielded."""
    files = [fp for fp, _ in mcp_mod._iter_allowlisted_files()]
    assert not any("untracked" in f for f in files)
    assert not any("secret.py" in f for f in files)


def test_C_MCP_19_iter_honors_skip_extensions(mcp_mod, code_tree):
    """SKIP_EXTENSIONS (.zip, .exe, etc.) filtered out even if inside a tracked tree."""
    (code_tree.tracked_dir / "junk.zip").write_bytes(b"PK\x03\x04")
    files = [fp for fp, _ in mcp_mod._iter_allowlisted_files()]
    assert not any(f.endswith("junk.zip") for f in files)


def test_C_MCP_20_iter_honors_skip_directories(mcp_mod, code_tree):
    """SKIP_DIRECTORIES (__pycache__, .git, etc.) pruned during walk."""
    files = [fp for fp, _ in mcp_mod._iter_allowlisted_files()]
    assert not any("__pycache__" in f for f in files)


def test_C_MCP_21_iter_filter_ext_normalises_dot(mcp_mod, code_tree):
    """filter_ext accepts both ".py" and "py" with identical results."""
    with_dot    = sorted(fp for fp, _ in mcp_mod._iter_allowlisted_files(filter_ext=".py"))
    without_dot = sorted(fp for fp, _ in mcp_mod._iter_allowlisted_files(filter_ext="py"))
    assert with_dot == without_dot
    assert all(f.endswith(".py") for f in with_dot)


def test_C_MCP_22_iter_filter_path_case_insensitive_substring(mcp_mod, code_tree):
    """filter_path matches as a case-insensitive substring."""
    files = [fp for fp, _ in mcp_mod._iter_allowlisted_files(filter_path="MAIN")]
    assert any(f.endswith("main.py") for f in files)
    assert not any(f.endswith("utils.py") for f in files)


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  HELPER: _looks_binary  (C-MCP-23 … C-MCP-26)                              ║
# ╚════════════════════════════════════════════════════════════════════════════╝

def test_C_MCP_23_looks_binary_text_negative(mcp_mod):
    assert mcp_mod._looks_binary(b"def foo():\n    return 1\n") is False


def test_C_MCP_24_looks_binary_nul_positive(mcp_mod):
    assert mcp_mod._looks_binary(b"\x00\x01\x02") is True


def test_C_MCP_25_looks_binary_empty_negative(mcp_mod):
    assert mcp_mod._looks_binary(b"") is False


def test_C_MCP_26_looks_binary_emoji_negative(mcp_mod):
    assert mcp_mod._looks_binary("hello 🚀 world".encode("utf-8")) is False


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  TOOL: grep_documents  (C-MCP-27 … C-MCP-44)                               ║
# ╚════════════════════════════════════════════════════════════════════════════╝

def test_C_MCP_27_grep_literal_match_returns_real_line_number(mcp_mod, code_tree):
    """Literal-match grep returns the file path and the actual line number."""
    out = mcp_mod.grep_documents("def clear_database")
    assert "def clear_database" in out
    assert "main.py" in out
    # Line 4 in our fixture is `def clear_database():`
    assert " 4 " in out or " 4  " in out


def test_C_MCP_28_grep_case_insensitive_by_default(mcp_mod, code_tree):
    out = mcp_mod.grep_documents("DEF CLEAR_DATABASE")
    assert "main.py" in out


def test_C_MCP_29_grep_case_sensitive_flag_respected(mcp_mod, code_tree):
    out = mcp_mod.grep_documents("DEF CLEAR_DATABASE", case_sensitive=True)
    assert "Matches      : 0" in out


def test_C_MCP_30_grep_regex_mode(mcp_mod, code_tree):
    out = mcp_mod.grep_documents(r"class \w+Error", regex=True)
    assert "MyError" in out


def test_C_MCP_31_grep_invalid_regex_friendly_error(mcp_mod, code_tree):
    out = mcp_mod.grep_documents("[unclosed", regex=True)
    assert "invalid regex" in out
    assert "regex=False" in out


def test_C_MCP_32_grep_filter_ext_restricts(mcp_mod, code_tree):
    """filter_ext='.py' must not surface matches in .md files."""
    out = mcp_mod.grep_documents("TODO", filter_ext=".py")
    assert "main.py" in out
    assert "README.md" not in out


def test_C_MCP_33_grep_filter_path_restricts(mcp_mod, code_tree):
    out = mcp_mod.grep_documents("def", filter_path="subdir")
    assert "helper.py" in out
    assert "utils.py" not in out


def test_C_MCP_34_grep_context_lines_shows_surrounding(mcp_mod, code_tree):
    """context_lines>=1 shows lines above and below the hit."""
    out = mcp_mod.grep_documents("clear_database", context_lines=1)
    assert "▶" in out
    # Line 5 (a TODO comment) follows the hit on line 4
    assert "TODO: drop" in out


def test_C_MCP_35_grep_context_zero_omits_surrounding(mcp_mod, code_tree):
    """context_lines=0 returns the hit line only, no surrounding."""
    out = mcp_mod.grep_documents("def clear_database", context_lines=0)
    assert "def clear_database" in out
    assert "TODO: drop" not in out


def test_C_MCP_36_grep_max_results_cap_honored(mcp_mod, code_tree):
    out = mcp_mod.grep_documents("def", max_results=1)
    assert "truncated" in out


def test_C_MCP_37_grep_no_matches_reports_clearly(mcp_mod, code_tree):
    out = mcp_mod.grep_documents("zzzzzz_nonexistent_zzzzzz")
    assert "No matches" in out


def test_C_MCP_38_grep_empty_pattern_rejected(mcp_mod, code_tree):
    assert "empty pattern" in mcp_mod.grep_documents("")
    assert "empty pattern" in mcp_mod.grep_documents("   ")


def test_C_MCP_39_grep_skips_binary_files(mcp_mod, code_tree):
    """Files with NUL bytes in the first 4KB must be skipped silently."""
    out = mcp_mod.grep_documents("binary")
    assert "binary.bin" not in out


def test_C_MCP_40_grep_never_searches_untracked(mcp_mod, code_tree):
    """Even a guaranteed-hit string must not surface from untracked files."""
    out = mcp_mod.grep_documents("SECRET")
    assert "secret.py" not in out
    assert "must not leak" not in out
    assert "No matches" in out


def test_C_MCP_41_grep_empty_allowlist_tips_user(mcp_mod, empty_allowlist):
    out = mcp_mod.grep_documents("anything")
    assert "list_tracked_directories" in out


def test_C_MCP_42_grep_suggests_followup_read_file_lines(mcp_mod, code_tree):
    """Each hit set ends with a suggested `read_file_lines(...)` call."""
    out = mcp_mod.grep_documents("def clear_database")
    assert "read_file_lines" in out


def test_C_MCP_43_grep_max_results_clamped_to_hard_cap(mcp_mod, code_tree):
    """Requesting absurd max_results doesn't crash — silently clamps."""
    out = mcp_mod.grep_documents("def", max_results=10_000)
    assert "Grep results" in out


def test_C_MCP_44_grep_context_lines_clamped_to_hard_cap(mcp_mod, code_tree):
    out = mcp_mod.grep_documents("def clear_database", context_lines=999)
    assert "Grep results" in out


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  TOOL: read_file_lines  (C-MCP-45 … C-MCP-62)                              ║
# ╚════════════════════════════════════════════════════════════════════════════╝

def test_C_MCP_45_read_allowed_returns_numbered_lines(mcp_mod, code_tree):
    out = mcp_mod.read_file_lines(str(code_tree.main_py), 1, 2)
    assert "1  def main():" in out
    assert "2      print('hello world')" in out


def test_C_MCP_46_read_untracked_denied_no_leak(mcp_mod, code_tree):
    """Untracked file: denied AND no content leakage."""
    out = mcp_mod.read_file_lines(str(code_tree.secret_py), 1)
    assert "🚫" in out
    assert "Access denied" in out
    assert "must not leak" not in out


def test_C_MCP_47_read_single_file_allowlist_works(mcp_mod, code_tree):
    out = mcp_mod.read_file_lines(str(code_tree.tracked_file), 1, 3)
    assert "Tracked solo" in out


def test_C_MCP_48_read_start_line_zero_corrected(mcp_mod, code_tree):
    """start_line < 1 is silently adjusted to 1, with a note in the header."""
    out = mcp_mod.read_file_lines(str(code_tree.main_py), 0, 2)
    assert "1  def main():" in out


def test_C_MCP_49_read_start_past_eof_explains(mcp_mod, code_tree):
    out = mcp_mod.read_file_lines(str(code_tree.main_py), 999_999, 1_000_000)
    assert "No content returned" in out


def test_C_MCP_50_read_end_before_start_rejected(mcp_mod, code_tree):
    out = mcp_mod.read_file_lines(str(code_tree.main_py), 5, end_line=2)
    assert "end_line" in out
    assert ">=" in out


def test_C_MCP_51_read_non_integer_start_rejected(mcp_mod, code_tree):
    out = mcp_mod.read_file_lines(str(code_tree.main_py), "abc")
    assert "must be an integer" in out


def test_C_MCP_52_read_non_integer_end_rejected(mcp_mod, code_tree):
    out = mcp_mod.read_file_lines(str(code_tree.main_py), 1, end_line="abc")
    assert "must be an integer" in out


def test_C_MCP_53_read_max_lines_cap_honored(mcp_mod, code_tree):
    """max_lines is a HARD cap, even when end_line asks for more."""
    big = code_tree.tracked_dir / "big.txt"
    big.write_text("\n".join(f"line {i}" for i in range(1, 51)), encoding="utf-8")
    out = mcp_mod.read_file_lines(str(big), 1, end_line=50, max_lines=5)
    assert "line 1" in out
    assert "line 5" in out
    assert "line 6" not in out


def test_C_MCP_54_read_continuation_hint_present_when_more(mcp_mod, code_tree):
    big = code_tree.tracked_dir / "big.txt"
    big.write_text("\n".join(f"line {i}" for i in range(1, 21)), encoding="utf-8")
    out = mcp_mod.read_file_lines(str(big), 1, end_line=5)
    assert "File continues" in out
    assert "start_line=6" in out


def test_C_MCP_55_read_no_continuation_hint_at_eof(mcp_mod, code_tree):
    small = code_tree.tracked_dir / "small.txt"
    small.write_text("only\ntwo lines\n", encoding="utf-8")
    out = mcp_mod.read_file_lines(str(small), 1, end_line=10)
    assert "File continues" not in out


def test_C_MCP_56_read_binary_file_rejected(mcp_mod, code_tree):
    """Binary file: rejected with explanation, no content leakage."""
    out = mcp_mod.read_file_lines(str(code_tree.binary_bin), 1)
    assert "binary" in out.lower()
    assert "garbage" not in out


def test_C_MCP_57_read_missing_file_explains(mcp_mod, code_tree):
    """Path under tracked tree but file no longer exists on disk."""
    phantom = code_tree.tracked_dir / "phantom.py"
    out = mcp_mod.read_file_lines(str(phantom), 1)
    assert "no longer exists" in out
    assert "update_tracked_directories" in out


def test_C_MCP_58_read_directory_not_a_file(mcp_mod, code_tree):
    out = mcp_mod.read_file_lines(str(code_tree.project), 1)
    assert "not a regular file" in out


def test_C_MCP_59_read_oversize_file_rejected(mcp_mod, code_tree, monkeypatch):
    """Files larger than the configured cap are rejected before any read."""
    big = code_tree.tracked_dir / "huge.txt"
    monkeypatch.setattr(mcp_mod, "_READ_FILE_MAX_BYTES", 1024)
    big.write_text("x" * 5000, encoding="utf-8")
    out = mcp_mod.read_file_lines(str(big), 1)
    assert "too large" in out


def test_C_MCP_60_read_lines_have_real_line_numbers(mcp_mod, code_tree):
    out = mcp_mod.read_file_lines(str(code_tree.main_py), 4, 5)
    assert "4  def clear_database():" in out
    assert "5      # TODO: drop all collections" in out


def test_C_MCP_61_read_unicode_content_preserved(mcp_mod, code_tree):
    uf = code_tree.tracked_dir / "uni.py"
    uf.write_text("# プロジェクト\nx = '🚀'\n", encoding="utf-8")
    out = mcp_mod.read_file_lines(str(uf), 1, 2)
    assert "プロジェクト" in out
    assert "🚀" in out


def test_C_MCP_62_read_default_max_lines_when_only_start(mcp_mod, code_tree):
    """Calling with start_line only caps at the default max_lines (200)."""
    big = code_tree.tracked_dir / "big.txt"
    big.write_text("\n".join(f"line {i}" for i in range(1, 1001)), encoding="utf-8")
    out = mcp_mod.read_file_lines(str(big), 1)
    assert "line 1" in out
    assert "line 200" in out
    assert "line 201" not in out


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  INTEGRATION  (C-MCP-63 … C-MCP-65)                                        ║
# ║  End-to-end "grep then read" workflow + cross-tool consistency             ║
# ╚════════════════════════════════════════════════════════════════════════════╝

def test_C_MCP_63_workflow_grep_then_read_extracts_full_function(mcp_mod, code_tree):
    """The canonical workflow: grep to locate, read_file_lines to extract."""
    grep_out = mcp_mod.grep_documents("def clear_database", filter_ext=".py")
    assert "main.py" in grep_out
    assert "read_file_lines" in grep_out

    read_out = mcp_mod.read_file_lines(str(code_tree.main_py), 4, end_line=6)
    assert "def clear_database" in read_out
    assert "TODO" in read_out
    assert "return None" in read_out


def test_C_MCP_64_workflow_resists_path_traversal(mcp_mod, code_tree):
    """An agent that constructs `../../untracked/secret.py` must be denied."""
    escape = (code_tree.project / ".." / ".." / "untracked" / "secret.py")
    out = mcp_mod.read_file_lines(str(escape), 1)
    assert "Access denied" in out
    assert "must not leak" not in out


def test_C_MCP_65_grep_finds_in_both_dir_and_single_file_entries(mcp_mod, code_tree):
    """A grep spanning both a directory entry AND a single-file entry returns
    hits from each — proves both allowlist shapes participate in the scan."""
    out = mcp_mod.grep_documents("TODO")
    assert "main.py" in out          # under tracked_dir
    assert "tracked_file.md" in out  # single-file entry
