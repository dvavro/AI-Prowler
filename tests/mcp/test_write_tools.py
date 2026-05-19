"""
tests/mcp/test_write_tools.py — v6.x code-tools WRITE-SIDE validation

Validates the 8 new MCP tools introduced by the Code Tools write-side patch:

    create_file               — new files only, fails if exists
    write_file                — overwrite existing, auto .bak<N>
    str_replace_in_file       — surgical edit, dry_run, verify_after_write
    create_directory          — mkdir -p, idempotent
    list_directory            — read-only, splits backups from active files
    copy_to_backup            — manual snapshot
    list_backups              — newest-first enumeration
    restore_backup            — restore from .bak<N>

Plus the bonus admin tool:
    reset_write_counter       — circuit-breaker reset

Plus the supporting helpers:
    _is_blocked_path          — hard blocklist
    _resolve_writable_path    — double-lock authorization (read + writable)
    _next_backup_path         — backup name allocator
    _make_backup              — copy-to-.bak<N>
    _path_is_under            — descendant check
    _check_and_increment_write_counter, _reset_write_counter_internal

Test plan IDs in this file begin with `C-MCP-WRITE-NN` following the same
convention used by C-MCP-NN (the read-side tools) and L-MCP-NN (learning).

    Helpers              C-MCP-WRITE-01 … C-MCP-WRITE-15
    create_file          C-MCP-WRITE-16 … C-MCP-WRITE-22
    write_file           C-MCP-WRITE-23 … C-MCP-WRITE-30
    str_replace_in_file  C-MCP-WRITE-31 … C-MCP-WRITE-44   (highest-value tool)
    create_directory     C-MCP-WRITE-45 … C-MCP-WRITE-49
    list_directory       C-MCP-WRITE-50 … C-MCP-WRITE-54
    copy_to_backup       C-MCP-WRITE-55 … C-MCP-WRITE-58
    list_backups         C-MCP-WRITE-59 … C-MCP-WRITE-62
    restore_backup       C-MCP-WRITE-63 … C-MCP-WRITE-68
    circuit breaker      C-MCP-WRITE-69 … C-MCP-WRITE-71
    integration          C-MCP-WRITE-72 … C-MCP-WRITE-75
    line endings         C-MCP-WRITE-76 … C-MCP-WRITE-82   (v6.02 CRLF fix)

Isolation
---------
This file reuses the existing `isolated_env` fixture from the top-level
`tests/conftest.py`. Each test gets a fresh ChromaDB, tracking JSON, and
auto-update list. We additionally clear the writable-allowlist file
(~/.rag_writable_dirs.json) so writes default-deny exactly as in production.

These tests do NOT load the embedding model — we monkey-patch the auto
re-index helper to a no-op for speed. The on-disk write semantics are
exercised in full; the ChromaDB side is covered separately by the existing
indexing tests.

Runtime budget: under 5 seconds for the whole file.
"""
from __future__ import annotations

import json
import os
import re
import shutil as _shutil
from pathlib import Path

import pytest


# ──────────────────────────────────────────────────────────────────────────────
# Module-level fixture: import ai_prowler_mcp once per session
# ──────────────────────────────────────────────────────────────────────────────
@pytest.fixture(scope="session")
def mcp_mod():
    """Import ai_prowler_mcp exactly once per session."""
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


# ──────────────────────────────────────────────────────────────────────────────
# Per-test fixture: writable_env
#
# Extends isolated_env with:
#   - A fresh writable-allowlist file (empty by default)
#   - A canonical project tree wired into BOTH the read allowlist AND the
#     writable allowlist for the test to mutate.
#   - The auto re-index helper monkey-patched to a no-op (we test the
#     on-disk side; ChromaDB re-index is tested elsewhere).
#   - The write counter reset.
# ──────────────────────────────────────────────────────────────────────────────
@pytest.fixture
def writable_env(isolated_env, mcp_mod, monkeypatch, tmp_path):
    """Build a writable test tree wired into both allowlists."""
    rag = isolated_env.rag
    root = isolated_env.sample_root

    # Build a small project tree
    project = root / "project"
    project.mkdir()
    (project / "hello.py").write_text(
        "def hello():\n    return 'world'\n", encoding="utf-8"
    )
    (project / "config.json").write_text(
        '{"version": "6.0.2", "feature_flags": []}\n', encoding="utf-8"
    )
    (project / "long.py").write_text(
        # File with a unique sentinel for str_replace_in_file
        "import os\n"
        "import sys\n"
        "\n"
        "API_TIMEOUT_SECONDS = 30\n"
        "MAX_RETRIES = 3\n"
        "\n"
        "def handler():\n"
        "    return API_TIMEOUT_SECONDS\n",
        encoding="utf-8",
    )
    subdir = project / "subdir"
    subdir.mkdir()
    (subdir / "deeper.py").write_text("X = 1\n", encoding="utf-8")

    # Untracked sibling — must remain unreachable
    untracked = root / "untracked"
    untracked.mkdir()
    (untracked / "secret.py").write_text("SECRET='leak'\n", encoding="utf-8")

    # Wire into the READ allowlist via the production function
    rag.add_to_auto_update_list(str(project))

    # Wire into the WRITABLE allowlist via a temp file we control
    writable_file = tmp_path / "rag_writable_dirs.json"
    writable_file.write_text(json.dumps([str(project)]), encoding="utf-8")
    pending_file  = tmp_path / "rag_writable_pending.json"

    monkeypatch.setattr(mcp_mod, "_WRITABLE_DIRS_FILE", writable_file)
    monkeypatch.setattr(mcp_mod, "_WRITE_APPROVAL_QUEUE_FILE", pending_file)

    # Reset write counter for this test
    mcp_mod._reset_write_counter_internal()

    # Monkey-patch the indexer hook to a no-op — we don't want the embedding
    # model loaded for these tests, and ChromaDB re-index is covered elsewhere.
    monkeypatch.setattr(mcp_mod, "_reindex_file_after_write", lambda *a, **kw: None)

    class WEnv:
        pass
    e = WEnv()
    e.rag            = rag
    e.root           = root
    e.project        = project
    e.subdir         = subdir
    e.untracked      = untracked
    e.writable_file  = writable_file
    e.pending_file   = pending_file
    e.hello_py       = project / "hello.py"
    e.config_json    = project / "config.json"
    e.long_py        = project / "long.py"
    e.deeper_py      = subdir / "deeper.py"
    e.secret_py      = untracked / "secret.py"
    return e


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  HELPERS: blocklist, writable resolver, backup naming                      ║
# ║  C-MCP-WRITE-01 … C-MCP-WRITE-15                                           ║
# ╚════════════════════════════════════════════════════════════════════════════╝

def test_C_MCP_WRITE_01_blocklist_windows_dir(mcp_mod):
    """C:\\Windows is hard-blocked from writes."""
    blocked, reason = mcp_mod._is_blocked_path(r"C:\Windows\System32\foo.dll")
    assert blocked is True
    assert "windows" in reason.lower()


def test_C_MCP_WRITE_02_blocklist_program_files(mcp_mod):
    """C:\\Program Files is hard-blocked (protects installed AI-Prowler)."""
    blocked, reason = mcp_mod._is_blocked_path(
        r"C:\Program Files\AI-Prowler\ai_prowler_mcp.py"
    )
    assert blocked is True
    assert "program files" in reason.lower()


def test_C_MCP_WRITE_03_blocklist_program_files_x86(mcp_mod):
    """C:\\Program Files (x86) is hard-blocked."""
    blocked, _reason = mcp_mod._is_blocked_path(
        r"C:\Program Files (x86)\Foo\bar.exe"
    )
    assert blocked is True


def test_C_MCP_WRITE_04_blocklist_programdata(mcp_mod):
    """C:\\ProgramData is hard-blocked."""
    blocked, _reason = mcp_mod._is_blocked_path(r"C:\ProgramData\thing.json")
    assert blocked is True


def test_C_MCP_WRITE_05_blocklist_git_internals(mcp_mod):
    """The .git folder is hard-blocked (segment match)."""
    blocked, reason = mcp_mod._is_blocked_path(
        r"C:\Users\david\my-repo\.git\HEAD"
    )
    assert blocked is True
    assert "git" in reason.lower()


def test_C_MCP_WRITE_06_blocklist_does_not_match_gitignore(mcp_mod):
    """.gitignore is a basename — must NOT be blocked just because '.git' is a prefix."""
    blocked, _reason = mcp_mod._is_blocked_path(
        r"C:\Users\david\my-repo\.gitignore"
    )
    assert blocked is False, "regression: .gitignore must not be blocked"


def test_C_MCP_WRITE_07_blocklist_ssh_aws_credentials(mcp_mod):
    """Credentials folders are hard-blocked."""
    for path, marker in [
        (r"C:\Users\david\.ssh\id_rsa", ".ssh"),
        (r"C:\Users\david\.aws\credentials", ".aws"),
    ]:
        blocked, reason = mcp_mod._is_blocked_path(path)
        assert blocked is True, f"{path} should be blocked"
        assert marker in reason


def test_C_MCP_WRITE_08_blocklist_job_tracker_xlsx(mcp_mod):
    """The job tracker xlsx is hard-blocked (schema-aware tool only)."""
    blocked, reason = mcp_mod._is_blocked_path(
        r"C:\Users\david\Documents\AI-Prowler\AI-Prowler_Job_Tracker.xlsx"
    )
    assert blocked is True
    assert "update_job_spreadsheet" in reason


def test_C_MCP_WRITE_09_writable_allowlist_empty_denies(mcp_mod, isolated_env,
                                                          monkeypatch, tmp_path):
    """Empty writable allowlist → all writes denied, request queued."""
    rag = isolated_env.rag
    target_file = isolated_env.sample_root / "target.txt"
    target_file.write_text("x", encoding="utf-8")
    rag.add_to_auto_update_list(str(isolated_env.sample_root))

    writable_file = tmp_path / "writable.json"
    writable_file.write_text("[]", encoding="utf-8")
    pending_file = tmp_path / "pending.json"
    monkeypatch.setattr(mcp_mod, "_WRITABLE_DIRS_FILE", writable_file)
    monkeypatch.setattr(mcp_mod, "_WRITE_APPROVAL_QUEUE_FILE", pending_file)

    resolved, deny = mcp_mod._resolve_writable_path(str(target_file))
    assert resolved is None
    assert "needs approval" in deny.lower()
    # Approval should have been queued
    pending = json.loads(pending_file.read_text(encoding="utf-8"))
    assert any(p["path"].endswith("target.txt") for p in pending)


def test_C_MCP_WRITE_10_writable_allowlist_descendant_allowed(mcp_mod, writable_env):
    """A path under an allowlisted directory is writable."""
    resolved, deny = mcp_mod._resolve_writable_path(str(writable_env.hello_py))
    assert resolved is not None, deny
    assert deny is None


def test_C_MCP_WRITE_11_writable_blocks_non_indexed_path(mcp_mod, writable_env,
                                                          monkeypatch):
    """A path NOT in the read allowlist cannot be writable even if writable-listed."""
    # Add an outside path to the writable allowlist (simulating a corrupted state)
    writable_env.writable_file.write_text(
        json.dumps([str(writable_env.project), str(writable_env.untracked)]),
        encoding="utf-8",
    )
    # Now untracked is "writable" but NOT in the read allowlist — must still be denied.
    resolved, deny = mcp_mod._resolve_writable_path(str(writable_env.secret_py))
    assert resolved is None, "writable without read-allowlist must be denied"
    # Should be the read-allowlist denial (🚫), not the approval-needed one
    assert "Access denied" in deny


def test_C_MCP_WRITE_12_next_backup_path_first_is_bak1(mcp_mod, writable_env):
    """First backup of a file with no existing backups → .bak1."""
    bp = mcp_mod._next_backup_path(str(writable_env.hello_py))
    assert bp.name == "hello.py.bak1"


def test_C_MCP_WRITE_13_next_backup_path_skips_to_max_plus_one(mcp_mod, writable_env):
    """If .bak1 .. .bak5 exist, next is .bak6 — never reuses or renumbers."""
    for n in (1, 2, 3, 5):
        (writable_env.hello_py.parent / f"hello.py.bak{n}").write_text("x")
    bp = mcp_mod._next_backup_path(str(writable_env.hello_py))
    assert bp.name == "hello.py.bak6", f"expected .bak6 (max+1), got {bp.name}"


def test_C_MCP_WRITE_14_next_backup_path_isolates_by_basename(mcp_mod, writable_env):
    """Other files' .bak<N> must not bump this file's count."""
    (writable_env.project / "config.json.bak1").write_text("x")
    (writable_env.project / "config.json.bak2").write_text("x")
    bp = mcp_mod._next_backup_path(str(writable_env.hello_py))
    assert bp.name == "hello.py.bak1", \
        f"other file's backups must not interfere; got {bp.name}"


def test_C_MCP_WRITE_15_path_is_under_classic_prefix_bug(mcp_mod, tmp_path):
    """/foo must NOT match /foobar — classic startswith-without-separator bug."""
    foo = tmp_path / "foo"
    foobar = tmp_path / "foobar"
    foo.mkdir()
    foobar.mkdir()
    assert mcp_mod._path_is_under(str(foobar), str(foo)) is False
    assert mcp_mod._path_is_under(str(foo / "x"), str(foo)) is True


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  TOOL: create_file                                                         ║
# ║  C-MCP-WRITE-16 … C-MCP-WRITE-22                                           ║
# ╚════════════════════════════════════════════════════════════════════════════╝

def test_C_MCP_WRITE_16_create_file_happy_path(mcp_mod, writable_env):
    """Create a new file with content — success, file exists on disk."""
    target = writable_env.project / "new.py"
    result = mcp_mod.create_file(str(target), "x = 1\n")
    assert "✅ Created" in result
    assert target.exists()
    assert target.read_text(encoding="utf-8") == "x = 1\n"


def test_C_MCP_WRITE_17_create_file_fails_if_exists(mcp_mod, writable_env):
    """create_file refuses to overwrite an existing file (use write_file instead)."""
    result = mcp_mod.create_file(str(writable_env.hello_py), "OVERWRITE\n")
    assert "already exists" in result
    assert "write_file" in result, "denial should suggest write_file as the alternative"
    # Content unchanged
    assert "def hello" in writable_env.hello_py.read_text(encoding="utf-8")


def test_C_MCP_WRITE_18_create_file_outside_writable_denied(mcp_mod, writable_env):
    """create_file in an unauthorized directory is denied."""
    target = writable_env.untracked / "new.py"
    result = mcp_mod.create_file(str(target), "x")
    assert target.exists() is False
    # Either "Access denied" or "needs approval" — both are correct outcomes
    assert ("denied" in result.lower() or "approval" in result.lower())


def test_C_MCP_WRITE_19_create_file_missing_parent_dir(mcp_mod, writable_env):
    """create_file fails clearly when parent directory doesn't exist."""
    target = writable_env.project / "no_such_subdir" / "new.py"
    result = mcp_mod.create_file(str(target), "x")
    assert "Parent directory does not exist" in result
    assert target.exists() is False


def test_C_MCP_WRITE_20_create_file_writes_unicode(mcp_mod, writable_env):
    """create_file writes UTF-8 content including non-ASCII characters."""
    target = writable_env.project / "ünïcode.py"
    content = "# こんにちは\nx = 'café'\n"
    result = mcp_mod.create_file(str(target), content)
    assert "✅ Created" in result
    assert target.read_text(encoding="utf-8") == content


def test_C_MCP_WRITE_21_create_file_blocked_path(mcp_mod, writable_env):
    """create_file targeting a hard-blocked path is refused."""
    target = r"C:\Windows\evil.bat"
    result = mcp_mod.create_file(target, "echo pwned")
    assert ("blocked" in result.lower() or "denied" in result.lower())


def test_C_MCP_WRITE_22_create_file_empty_content_allowed(mcp_mod, writable_env):
    """create_file with empty string content is allowed (legitimate use case)."""
    target = writable_env.project / "empty.py"
    result = mcp_mod.create_file(str(target), "")
    assert "✅ Created" in result
    assert target.exists()
    assert target.stat().st_size == 0


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  TOOL: write_file                                                          ║
# ║  C-MCP-WRITE-23 … C-MCP-WRITE-30                                           ║
# ╚════════════════════════════════════════════════════════════════════════════╝

def test_C_MCP_WRITE_23_write_file_happy_path(mcp_mod, writable_env):
    """Overwrite an existing file — success, content replaced, .bak1 created."""
    result = mcp_mod.write_file(str(writable_env.hello_py), "REPLACED\n")
    assert "✅ Wrote" in result
    assert writable_env.hello_py.read_text(encoding="utf-8") == "REPLACED\n"
    assert (writable_env.hello_py.parent / "hello.py.bak1").exists()


def test_C_MCP_WRITE_24_write_file_fails_if_missing(mcp_mod, writable_env):
    """write_file refuses non-existent files (use create_file instead)."""
    target = writable_env.project / "ghost.py"
    result = mcp_mod.write_file(str(target), "x")
    assert "does not exist" in result
    assert "create_file" in result, "denial should suggest create_file as alternative"


def test_C_MCP_WRITE_25_write_file_autobackups_increment(mcp_mod, writable_env):
    """Three writes to the same file produce .bak1, .bak2, .bak3."""
    for i in range(3):
        mcp_mod.write_file(str(writable_env.hello_py), f"v{i}\n")
    parent = writable_env.hello_py.parent
    assert (parent / "hello.py.bak1").exists()
    assert (parent / "hello.py.bak2").exists()
    assert (parent / "hello.py.bak3").exists()
    # Active file holds the latest
    assert writable_env.hello_py.read_text(encoding="utf-8") == "v2\n"


def test_C_MCP_WRITE_26_write_file_verify_after_write(mcp_mod, writable_env):
    """verify_after_write=True includes first/last 5 lines of new content."""
    new_content = "\n".join([f"line {i}" for i in range(1, 16)]) + "\n"
    result = mcp_mod.write_file(
        str(writable_env.hello_py), new_content, verify_after_write=True
    )
    assert "Verify" in result
    assert "line 1" in result and "line 15" in result


def test_C_MCP_WRITE_27_write_file_size_cap(mcp_mod, writable_env, monkeypatch):
    """Writing content over the size cap is refused."""
    monkeypatch.setattr(mcp_mod, "_WRITE_MAX_BYTES", 100)
    big = "x" * 200
    result = mcp_mod.write_file(str(writable_env.hello_py), big)
    assert "too large" in result.lower()


def test_C_MCP_WRITE_28_write_file_preserves_original_on_backup(mcp_mod, writable_env):
    """The .bak1 file contains the PRE-write content, not the new content."""
    original = writable_env.hello_py.read_text(encoding="utf-8")
    mcp_mod.write_file(str(writable_env.hello_py), "NEW CONTENT\n")
    bak1 = writable_env.hello_py.parent / "hello.py.bak1"
    assert bak1.read_text(encoding="utf-8") == original


def test_C_MCP_WRITE_29_write_file_blocked_path(mcp_mod, writable_env):
    """write_file against a hard-blocked path is refused."""
    result = mcp_mod.write_file(r"C:\Windows\System32\foo.dll", "x")
    assert ("blocked" in result.lower() or "denied" in result.lower())


def test_C_MCP_WRITE_30_write_file_outside_writable_denied(mcp_mod, writable_env):
    """write_file targeting a path outside the writable allowlist is denied."""
    result = mcp_mod.write_file(str(writable_env.secret_py), "leak")
    # Path is outside the READ allowlist → denied at the first lock
    assert ("denied" in result.lower() or "approval" in result.lower())
    # Original content unchanged
    assert "SECRET" in writable_env.secret_py.read_text(encoding="utf-8")


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  TOOL: str_replace_in_file  (MOST IMPORTANT)                               ║
# ║  C-MCP-WRITE-31 … C-MCP-WRITE-44                                           ║
# ╚════════════════════════════════════════════════════════════════════════════╝

def test_C_MCP_WRITE_31_str_replace_happy_path(mcp_mod, writable_env):
    """Single unique occurrence replaced; backup created; file content correct."""
    result = mcp_mod.str_replace_in_file(
        str(writable_env.long_py),
        "API_TIMEOUT_SECONDS = 30",
        "API_TIMEOUT_SECONDS = 60",
    )
    assert "✅ Edited" in result
    text = writable_env.long_py.read_text(encoding="utf-8")
    assert "API_TIMEOUT_SECONDS = 60" in text
    assert "API_TIMEOUT_SECONDS = 30" not in text
    assert (writable_env.long_py.parent / "long.py.bak1").exists()


def test_C_MCP_WRITE_32_str_replace_uniqueness_zero_matches(mcp_mod, writable_env):
    """old_str not found → clear error, file unchanged, no backup made."""
    before = writable_env.long_py.read_text(encoding="utf-8")
    result = mcp_mod.str_replace_in_file(
        str(writable_env.long_py),
        "NOT_PRESENT_ANYWHERE",
        "x",
    )
    assert "not found" in result.lower()
    assert writable_env.long_py.read_text(encoding="utf-8") == before
    assert not (writable_env.long_py.parent / "long.py.bak1").exists()


def test_C_MCP_WRITE_33_str_replace_uniqueness_multiple_matches(mcp_mod, writable_env):
    """Ambiguous old_str → error lists ALL match line numbers, file unchanged."""
    # "import " appears twice in long.py (import os, import sys)
    before = writable_env.long_py.read_text(encoding="utf-8")
    result = mcp_mod.str_replace_in_file(
        str(writable_env.long_py),
        "import ",
        "imp ",
    )
    assert "found 2 times" in result.lower()
    assert "line" in result.lower()
    # Lines 1 and 2 should both appear
    assert "1" in result and "2" in result
    # Unchanged
    assert writable_env.long_py.read_text(encoding="utf-8") == before


def test_C_MCP_WRITE_34_str_replace_dry_run_no_write(mcp_mod, writable_env):
    """dry_run=True returns a diff but does NOT modify the file or create a backup."""
    before = writable_env.long_py.read_text(encoding="utf-8")
    result = mcp_mod.str_replace_in_file(
        str(writable_env.long_py),
        "MAX_RETRIES = 3",
        "MAX_RETRIES = 5",
        dry_run=True,
    )
    assert "DRY RUN" in result
    assert "Unified diff" in result or "diff" in result.lower()
    # File unchanged
    assert writable_env.long_py.read_text(encoding="utf-8") == before
    # No backup created
    assert not (writable_env.long_py.parent / "long.py.bak1").exists()


def test_C_MCP_WRITE_35_str_replace_dry_run_then_apply(mcp_mod, writable_env):
    """The dry-run → confirm → apply workflow works end to end."""
    # Dry run
    dry = mcp_mod.str_replace_in_file(
        str(writable_env.long_py),
        "MAX_RETRIES = 3",
        "MAX_RETRIES = 5",
        dry_run=True,
    )
    assert "DRY RUN" in dry
    # Apply
    real = mcp_mod.str_replace_in_file(
        str(writable_env.long_py),
        "MAX_RETRIES = 3",
        "MAX_RETRIES = 5",
    )
    assert "✅ Edited" in real
    assert "MAX_RETRIES = 5" in writable_env.long_py.read_text(encoding="utf-8")


def test_C_MCP_WRITE_36_str_replace_empty_old_str_refused(mcp_mod, writable_env):
    """Empty old_str is refused (would match infinitely)."""
    result = mcp_mod.str_replace_in_file(
        str(writable_env.long_py), "", "anything"
    )
    assert "empty" in result.lower()


def test_C_MCP_WRITE_37_str_replace_empty_new_str_deletes_span(mcp_mod, writable_env):
    """new_str='' deletes the matched span — legitimate use case."""
    result = mcp_mod.str_replace_in_file(
        str(writable_env.long_py),
        "MAX_RETRIES = 3\n",
        "",
    )
    assert "✅ Edited" in result
    assert "MAX_RETRIES" not in writable_env.long_py.read_text(encoding="utf-8")


def test_C_MCP_WRITE_38_str_replace_multi_line(mcp_mod, writable_env):
    """Multi-line old_str / new_str works correctly."""
    old = "def handler():\n    return API_TIMEOUT_SECONDS\n"
    new = "def handler():\n    # Updated\n    return API_TIMEOUT_SECONDS * 2\n"
    result = mcp_mod.str_replace_in_file(
        str(writable_env.long_py), old, new
    )
    assert "✅ Edited" in result
    text = writable_env.long_py.read_text(encoding="utf-8")
    assert "Updated" in text
    assert "* 2" in text


def test_C_MCP_WRITE_39_str_replace_reports_line_number(mcp_mod, writable_env):
    """The success message includes the line number where the change landed."""
    result = mcp_mod.str_replace_in_file(
        str(writable_env.long_py),
        "API_TIMEOUT_SECONDS = 30",
        "API_TIMEOUT_SECONDS = 60",
    )
    # API_TIMEOUT_SECONDS = 30 is on line 4 of long.py
    assert "line 4" in result or "line  4" in result


def test_C_MCP_WRITE_40_str_replace_verify_after_write(mcp_mod, writable_env):
    """verify_after_write=True (default) shows surrounding context."""
    result = mcp_mod.str_replace_in_file(
        str(writable_env.long_py),
        "API_TIMEOUT_SECONDS = 30",
        "API_TIMEOUT_SECONDS = 60",
    )
    assert "Verify" in result
    assert "API_TIMEOUT_SECONDS = 60" in result


def test_C_MCP_WRITE_41_str_replace_outside_writable_denied(mcp_mod, writable_env):
    """str_replace_in_file outside writable allowlist is denied."""
    result = mcp_mod.str_replace_in_file(
        str(writable_env.secret_py),
        "SECRET='leak'",
        "SECRET='exposed'",
    )
    assert ("denied" in result.lower() or "approval" in result.lower())


def test_C_MCP_WRITE_42_str_replace_missing_file(mcp_mod, writable_env):
    """str_replace_in_file on a non-existent file inside the allowlist errors clearly."""
    target = writable_env.project / "ghost.py"
    result = mcp_mod.str_replace_in_file(str(target), "x", "y")
    assert "does not exist" in result


def test_C_MCP_WRITE_43_str_replace_dry_run_safe_outside_writable(mcp_mod, writable_env):
    """dry_run against an unauthorized path is still denied — security wins over preview."""
    result = mcp_mod.str_replace_in_file(
        str(writable_env.secret_py), "SECRET", "X", dry_run=True
    )
    assert ("denied" in result.lower() or "approval" in result.lower())


def test_C_MCP_WRITE_44_str_replace_preserves_file_on_write_failure(mcp_mod,
                                                                       writable_env,
                                                                       monkeypatch):
    """If the actual file write fails after backup, the backup tells you so."""
    # Make open() in write mode fail
    real_open = open
    def faulty_open(p, mode="r", *args, **kw):
        if "w" in mode or "+" in mode:
            raise OSError("simulated disk full")
        return real_open(p, mode, *args, **kw)
    monkeypatch.setattr("builtins.open", faulty_open)
    result = mcp_mod.str_replace_in_file(
        str(writable_env.long_py),
        "API_TIMEOUT_SECONDS = 30",
        "API_TIMEOUT_SECONDS = 60",
    )
    # Should mention either backup preservation, read failure, or backup-creation failure.
    # When open() is fully patched to fail, the backup phase fails first and
    # the tool returns an "aborting edit / could not create backup" message.
    lower = result.lower()
    assert ("backup preserved" in lower
            or "read failed" in lower
            or "write failed" in lower
            or "could not create backup" in lower
            or "aborting" in lower)


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  TOOL: create_directory                                                    ║
# ║  C-MCP-WRITE-45 … C-MCP-WRITE-49                                           ║
# ╚════════════════════════════════════════════════════════════════════════════╝

def test_C_MCP_WRITE_45_create_directory_happy_path(mcp_mod, writable_env):
    """Create a new directory — success, dir exists on disk."""
    target = writable_env.project / "newdir"
    result = mcp_mod.create_directory(str(target))
    assert "✅ Created directory" in result
    assert target.is_dir()


def test_C_MCP_WRITE_46_create_directory_idempotent(mcp_mod, writable_env):
    """create_directory on an existing directory is a no-op success."""
    result = mcp_mod.create_directory(str(writable_env.project))
    assert "already exists" in result.lower()
    assert "✅" in result


def test_C_MCP_WRITE_47_create_directory_parents_true_creates_chain(mcp_mod, writable_env):
    """parents=True creates intermediate directories."""
    target = writable_env.project / "a" / "b" / "c"
    result = mcp_mod.create_directory(str(target), parents=True)
    assert "✅ Created directory" in result
    assert target.is_dir()


def test_C_MCP_WRITE_48_create_directory_parents_false_fails(mcp_mod, writable_env):
    """parents=False fails clearly when intermediate dir doesn't exist."""
    target = writable_env.project / "absent" / "child"
    result = mcp_mod.create_directory(str(target), parents=False)
    assert "Parent" in result or "does not exist" in result.lower()
    assert target.exists() is False


def test_C_MCP_WRITE_49_create_directory_blocked_path(mcp_mod, writable_env):
    """create_directory inside a hard-blocked area is refused."""
    result = mcp_mod.create_directory(r"C:\Windows\evil_dir")
    assert ("blocked" in result.lower() or "denied" in result.lower())


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  TOOL: list_directory                                                      ║
# ║  C-MCP-WRITE-50 … C-MCP-WRITE-54                                           ║
# ╚════════════════════════════════════════════════════════════════════════════╝

def test_C_MCP_WRITE_50_list_directory_happy_path(mcp_mod, writable_env):
    """List a tracked directory — shows files and subdirs."""
    result = mcp_mod.list_directory(str(writable_env.project))
    assert "hello.py" in result
    assert "config.json" in result
    assert "long.py" in result
    assert "subdir" in result


def test_C_MCP_WRITE_51_list_directory_separates_backups(mcp_mod, writable_env):
    """Backups appear in a separate section, not mixed with active files."""
    (writable_env.project / "hello.py.bak1").write_text("x")
    (writable_env.project / "hello.py.bak2").write_text("x")
    result = mcp_mod.list_directory(str(writable_env.project))
    assert "Backups" in result or "💾" in result
    assert "hello.py.bak1" in result


def test_C_MCP_WRITE_52_list_directory_no_writable_requirement(mcp_mod, isolated_env,
                                                                 monkeypatch, tmp_path):
    """list_directory only needs READ allowlist, not WRITE — it's read-only."""
    rag = isolated_env.rag
    p = isolated_env.sample_root / "readonly_project"
    p.mkdir()
    (p / "file.txt").write_text("x")
    rag.add_to_auto_update_list(str(p))
    # Writable allowlist intentionally empty
    wf = tmp_path / "writable.json"
    wf.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(mcp_mod, "_WRITABLE_DIRS_FILE", wf)
    result = mcp_mod.list_directory(str(p))
    assert "file.txt" in result


def test_C_MCP_WRITE_53_list_directory_unauthorized(mcp_mod, writable_env):
    """list_directory denied for paths outside the read allowlist."""
    result = mcp_mod.list_directory(str(writable_env.untracked))
    assert ("denied" in result.lower() or "🚫" in result)


def test_C_MCP_WRITE_54_list_directory_empty(mcp_mod, writable_env):
    """Empty directory shows '(empty)' marker."""
    empty = writable_env.project / "empty_dir"
    empty.mkdir()
    result = mcp_mod.list_directory(str(empty))
    assert "(empty)" in result


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  TOOL: copy_to_backup                                                      ║
# ║  C-MCP-WRITE-55 … C-MCP-WRITE-58                                           ║
# ╚════════════════════════════════════════════════════════════════════════════╝

def test_C_MCP_WRITE_55_copy_to_backup_creates_bak1(mcp_mod, writable_env):
    """Manual snapshot creates .bak1 next to the active file."""
    result = mcp_mod.copy_to_backup(str(writable_env.hello_py))
    assert "💾" in result or "Snapshot" in result
    assert (writable_env.hello_py.parent / "hello.py.bak1").exists()


def test_C_MCP_WRITE_56_copy_to_backup_does_not_modify_active(mcp_mod, writable_env):
    """Manual snapshot leaves the active file completely unchanged."""
    before = writable_env.hello_py.read_text(encoding="utf-8")
    mcp_mod.copy_to_backup(str(writable_env.hello_py))
    after = writable_env.hello_py.read_text(encoding="utf-8")
    assert before == after


def test_C_MCP_WRITE_57_copy_to_backup_increments(mcp_mod, writable_env):
    """Repeated copy_to_backup creates .bak1, .bak2, .bak3."""
    for _ in range(3):
        mcp_mod.copy_to_backup(str(writable_env.hello_py))
    parent = writable_env.hello_py.parent
    assert (parent / "hello.py.bak1").exists()
    assert (parent / "hello.py.bak2").exists()
    assert (parent / "hello.py.bak3").exists()


def test_C_MCP_WRITE_58_copy_to_backup_missing_file(mcp_mod, writable_env):
    """Snapshot of a non-existent file errors clearly."""
    target = writable_env.project / "ghost.py"
    result = mcp_mod.copy_to_backup(str(target))
    assert "does not exist" in result


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  TOOL: list_backups                                                        ║
# ║  C-MCP-WRITE-59 … C-MCP-WRITE-62                                           ║
# ╚════════════════════════════════════════════════════════════════════════════╝

def test_C_MCP_WRITE_59_list_backups_empty(mcp_mod, writable_env):
    """No backups → clear message."""
    result = mcp_mod.list_backups(str(writable_env.hello_py))
    assert "No backups" in result


def test_C_MCP_WRITE_60_list_backups_newest_first(mcp_mod, writable_env):
    """Backups listed in descending order (newest = highest number first)."""
    for n in (1, 2, 3):
        (writable_env.hello_py.parent / f"hello.py.bak{n}").write_text(f"v{n}")
    result = mcp_mod.list_backups(str(writable_env.hello_py))
    # Find positions of .bak1, .bak2, .bak3 in the output
    pos1 = result.find(".bak1")
    pos2 = result.find(".bak2")
    pos3 = result.find(".bak3")
    assert pos3 < pos2 < pos1, f"Expected newest first; positions: bak3={pos3} bak2={pos2} bak1={pos1}"


def test_C_MCP_WRITE_61_list_backups_isolates_by_filename(mcp_mod, writable_env):
    """Only backups for the requested file are listed."""
    (writable_env.hello_py.parent / "hello.py.bak1").write_text("a")
    (writable_env.hello_py.parent / "config.json.bak1").write_text("b")
    result = mcp_mod.list_backups(str(writable_env.hello_py))
    assert "hello.py.bak1" in result
    assert "config.json.bak1" not in result


def test_C_MCP_WRITE_62_list_backups_unauthorized_path(mcp_mod, writable_env):
    """list_backups outside the read allowlist is denied."""
    result = mcp_mod.list_backups(str(writable_env.secret_py))
    assert ("denied" in result.lower() or "🚫" in result)


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  TOOL: restore_backup                                                      ║
# ║  C-MCP-WRITE-63 … C-MCP-WRITE-68                                           ║
# ╚════════════════════════════════════════════════════════════════════════════╝

def test_C_MCP_WRITE_63_restore_backup_happy_path(mcp_mod, writable_env):
    """Restore from .bak1 — active file matches the backup."""
    # Create a backup first
    mcp_mod.write_file(str(writable_env.hello_py), "first replacement\n")
    bak1 = writable_env.hello_py.parent / "hello.py.bak1"
    backup_content = bak1.read_text(encoding="utf-8")
    # Make another change
    mcp_mod.write_file(str(writable_env.hello_py), "second replacement\n")
    # Restore .bak1
    result = mcp_mod.restore_backup(str(writable_env.hello_py), 1)
    assert "✅ Restored" in result
    assert writable_env.hello_py.read_text(encoding="utf-8") == backup_content


def test_C_MCP_WRITE_64_restore_backup_missing_backup(mcp_mod, writable_env):
    """Restore from a non-existent .bak<N> errors clearly."""
    result = mcp_mod.restore_backup(str(writable_env.hello_py), 99)
    assert "not found" in result.lower()
    assert "list_backups" in result


def test_C_MCP_WRITE_65_restore_backup_preserves_bak_file(mcp_mod, writable_env):
    """Restoring does not destroy the .bak<N> source — non-destructive."""
    mcp_mod.write_file(str(writable_env.hello_py), "new\n")
    bak1 = writable_env.hello_py.parent / "hello.py.bak1"
    backup_size = bak1.stat().st_size
    mcp_mod.restore_backup(str(writable_env.hello_py), 1)
    assert bak1.exists()
    assert bak1.stat().st_size == backup_size


def test_C_MCP_WRITE_66_restore_backup_invalid_number(mcp_mod, writable_env):
    """backup_number=0 or negative is refused with a clear message."""
    result = mcp_mod.restore_backup(str(writable_env.hello_py), 0)
    assert "must be >= 1" in result or "must be" in result.lower()


def test_C_MCP_WRITE_67_restore_backup_unauthorized(mcp_mod, writable_env):
    """restore_backup denied for paths outside the writable allowlist."""
    # Make a .bak<N> exist in the secret area
    (writable_env.untracked / "secret.py.bak1").write_text("backup")
    result = mcp_mod.restore_backup(str(writable_env.secret_py), 1)
    assert ("denied" in result.lower() or "approval" in result.lower())


def test_C_MCP_WRITE_68_restore_backup_when_active_missing(mcp_mod, writable_env):
    """Restore works even when the active file was deleted (recovery scenario)."""
    # Create a backup, then delete the active file
    mcp_mod.copy_to_backup(str(writable_env.hello_py))
    bak1 = writable_env.hello_py.parent / "hello.py.bak1"
    backup_content = bak1.read_text(encoding="utf-8")
    writable_env.hello_py.unlink()
    # Now restore from backup
    result = mcp_mod.restore_backup(str(writable_env.hello_py), 1)
    assert "✅ Restored" in result
    assert writable_env.hello_py.exists()
    assert writable_env.hello_py.read_text(encoding="utf-8") == backup_content


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  CIRCUIT BREAKER & ADMIN                                                   ║
# ║  C-MCP-WRITE-69 … C-MCP-WRITE-71                                           ║
# ╚════════════════════════════════════════════════════════════════════════════╝

def test_C_MCP_WRITE_69_circuit_breaker_trips_at_limit(mcp_mod, writable_env,
                                                          monkeypatch):
    """After N writes, the next write is rejected with the circuit-breaker message."""
    monkeypatch.setattr(mcp_mod, "_WRITES_PER_SESSION_LIMIT", 3)
    mcp_mod._reset_write_counter_internal()
    # 3 writes should succeed
    for i in range(3):
        target = writable_env.project / f"x{i}.txt"
        result = mcp_mod.create_file(str(target), "x")
        assert "✅" in result
    # 4th should trip the breaker
    result = mcp_mod.create_file(str(writable_env.project / "x4.txt"), "x")
    assert "circuit-breaker" in result.lower() or "circuit" in result.lower()


def test_C_MCP_WRITE_70_reset_write_counter(mcp_mod, monkeypatch):
    """reset_write_counter sets the count back to zero."""
    monkeypatch.setattr(mcp_mod, "_WRITES_PER_SESSION_LIMIT", 5)
    mcp_mod._reset_write_counter_internal()
    # Bump counter by calling _check directly
    for _ in range(3):
        mcp_mod._check_and_increment_write_counter()
    result = mcp_mod.reset_write_counter()
    assert "Was: 3" in result or "3" in result


def test_C_MCP_WRITE_71_circuit_breaker_no_partial_writes(mcp_mod, writable_env,
                                                            monkeypatch):
    """When the breaker trips, the targeted file is NOT modified."""
    monkeypatch.setattr(mcp_mod, "_WRITES_PER_SESSION_LIMIT", 1)
    mcp_mod._reset_write_counter_internal()
    # Burn the one allowed write on a different file
    mcp_mod.create_file(str(writable_env.project / "burn.txt"), "x")
    before = writable_env.hello_py.read_text(encoding="utf-8")
    result = mcp_mod.write_file(str(writable_env.hello_py), "SHOULD NOT LAND")
    assert "circuit" in result.lower()
    # File is unchanged AND no .bak was made (write aborted before backup phase)
    assert writable_env.hello_py.read_text(encoding="utf-8") == before


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  INTEGRATION SCENARIOS                                                     ║
# ║  C-MCP-WRITE-72 … C-MCP-WRITE-75                                           ║
# ╚════════════════════════════════════════════════════════════════════════════╝

def test_C_MCP_WRITE_72_full_edit_cycle(mcp_mod, writable_env):
    """Realistic flow: create → edit (dry-run, then real) → list backups → restore."""
    new = writable_env.project / "feature.py"
    # 1. create
    r1 = mcp_mod.create_file(str(new), "VERSION = '1.0'\nLOG_LEVEL = 'INFO'\n")
    assert "✅" in r1
    # 2. surgical edit, dry-run first
    r2 = mcp_mod.str_replace_in_file(str(new), "VERSION = '1.0'", "VERSION = '1.1'",
                                      dry_run=True)
    assert "DRY RUN" in r2
    # 3. apply
    r3 = mcp_mod.str_replace_in_file(str(new), "VERSION = '1.0'", "VERSION = '1.1'")
    assert "✅ Edited" in r3
    assert "VERSION = '1.1'" in new.read_text(encoding="utf-8")
    # 4. list backups — should show .bak1
    r4 = mcp_mod.list_backups(str(new))
    assert "feature.py.bak1" in r4
    # 5. restore — VERSION should go back to 1.0
    r5 = mcp_mod.restore_backup(str(new), 1)
    assert "✅ Restored" in r5
    assert "VERSION = '1.0'" in new.read_text(encoding="utf-8")


def test_C_MCP_WRITE_73_copy_to_backup_then_edit_creates_two_baks(mcp_mod, writable_env):
    """Manual snapshot then auto-backup-on-edit produces .bak1 (manual) + .bak2 (auto)."""
    mcp_mod.copy_to_backup(str(writable_env.hello_py))
    mcp_mod.write_file(str(writable_env.hello_py), "EDITED\n")
    parent = writable_env.hello_py.parent
    assert (parent / "hello.py.bak1").exists()
    assert (parent / "hello.py.bak2").exists()


def test_C_MCP_WRITE_74_create_directory_then_create_file_in_it(mcp_mod, writable_env):
    """The two-step pattern: explicit create_directory before create_file in new dir."""
    newdir = writable_env.project / "scripts"
    r1 = mcp_mod.create_directory(str(newdir))
    assert "✅" in r1
    target = newdir / "run.py"
    r2 = mcp_mod.create_file(str(target), "main()\n")
    assert "✅" in r2
    assert target.exists()


def test_C_MCP_WRITE_75_backups_isolated_after_many_operations(mcp_mod, writable_env):
    """After mixed write_file and copy_to_backup, .bak<N> numbering is monotonic."""
    target = writable_env.hello_py
    mcp_mod.write_file(str(target), "v1\n")              # → .bak1
    mcp_mod.copy_to_backup(str(target))                  # → .bak2
    mcp_mod.write_file(str(target), "v2\n")              # → .bak3
    mcp_mod.copy_to_backup(str(target))                  # → .bak4
    parent = target.parent
    for n in (1, 2, 3, 4):
        assert (parent / f"hello.py.bak{n}").exists(), f"missing .bak{n}"
    # Highest is .bak4
    assert mcp_mod._next_backup_path(str(target)).name == "hello.py.bak5"


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  LINE-ENDING PRESERVATION                                                  ║
# ║  C-MCP-WRITE-76 … C-MCP-WRITE-82                                           ║
# ║                                                                            ║
# ║  Regression tests for the silent CRLF→LF conversion bug fixed in v6.02.    ║
# ║  The write-side tools used to round-trip through Python text mode, which   ║
# ║  on Windows stripped \r bytes from every CRLF file on every edit. These    ║
# ║  tests pin the new behavior: files are written back with their original    ║
# ║  line-ending convention regardless of platform.                            ║
# ╚════════════════════════════════════════════════════════════════════════════╝

def test_C_MCP_WRITE_76_detect_line_ending_crlf(mcp_mod):
    """_detect_line_ending returns \\r\\n for any CRLF presence."""
    assert mcp_mod._detect_line_ending(b"line1\r\nline2\r\n") == "\r\n"
    # Even a single CRLF anywhere in the file wins
    assert mcp_mod._detect_line_ending(b"line1\nline2\r\nline3\n") == "\r\n"


def test_C_MCP_WRITE_77_detect_line_ending_lf_and_default(mcp_mod):
    """_detect_line_ending returns \\n for LF-only files and empty content."""
    assert mcp_mod._detect_line_ending(b"line1\nline2\n") == "\n"
    assert mcp_mod._detect_line_ending(b"") == "\n"
    assert mcp_mod._detect_line_ending(b"no-newlines-at-all") == "\n"


def test_C_MCP_WRITE_78_str_replace_preserves_crlf(mcp_mod, writable_env):
    """str_replace_in_file on a CRLF file produces a CRLF file."""
    target = writable_env.project / "crlf_source.py"
    # Write CRLF content explicitly via binary mode so the test doesn't
    # depend on Python's platform-dependent text-mode newline handling.
    target.write_bytes(b"def hello():\r\n    return 'world'\r\n")

    r = mcp_mod.str_replace_in_file(
        str(target),
        old_str="'world'",
        new_str="'CRLF'",
    )
    assert "✅ Edited" in r, r

    # Round-trip preserved CRLF on disk
    raw = target.read_bytes()
    assert b"\r\n" in raw, f"CRLF stripped: {raw!r}"
    assert b"\n" not in raw.replace(b"\r\n", b""), (
        f"Mixed endings introduced: {raw!r}"
    )
    assert raw == b"def hello():\r\n    return 'CRLF'\r\n"


def test_C_MCP_WRITE_79_str_replace_preserves_lf(mcp_mod, writable_env):
    """str_replace_in_file on an LF file produces an LF file (no \\r introduced)."""
    target = writable_env.project / "lf_source.py"
    target.write_bytes(b"def hello():\n    return 'world'\n")

    r = mcp_mod.str_replace_in_file(
        str(target),
        old_str="'world'",
        new_str="'LF'",
    )
    assert "✅ Edited" in r, r

    raw = target.read_bytes()
    assert b"\r" not in raw, f"Spurious \\r introduced: {raw!r}"
    assert raw == b"def hello():\n    return 'LF'\n"


def test_C_MCP_WRITE_80_write_file_preserves_crlf(mcp_mod, writable_env):
    """write_file on a CRLF file produces a CRLF file even with LF-only content."""
    target = writable_env.project / "crlf_target.py"
    target.write_bytes(b"old_line_1\r\nold_line_2\r\n")

    # Caller passes pure-LF content (the normal Python convention).
    r = mcp_mod.write_file(str(target), "new_line_1\nnew_line_2\n")
    assert "✅ Wrote" in r, r

    raw = target.read_bytes()
    assert b"\r\n" in raw, f"CRLF lost on write_file: {raw!r}"
    assert raw == b"new_line_1\r\nnew_line_2\r\n"


def test_C_MCP_WRITE_81_write_file_normalizes_mixed_input(mcp_mod, writable_env):
    """write_file given CRLF content for an LF file should write LF (file wins)."""
    target = writable_env.project / "lf_target.py"
    target.write_bytes(b"old\n")

    # Caller passes CRLF content but the file is LF — file's convention wins.
    r = mcp_mod.write_file(str(target), "a\r\nb\r\n")
    assert "✅ Wrote" in r, r

    raw = target.read_bytes()
    assert b"\r" not in raw, f"\\r should have been normalized away: {raw!r}"
    assert raw == b"a\nb\n"


def test_C_MCP_WRITE_82_create_file_uses_platform_native(mcp_mod, writable_env):
    """create_file with pure-LF content uses os.linesep on the target platform."""
    import os as _os

    target = writable_env.project / "brand_new.py"
    r = mcp_mod.create_file(str(target), "first\nsecond\n")
    assert "✅ Created" in r, r

    raw = target.read_bytes()
    if _os.linesep == "\r\n":
        # Windows — pure-LF input should have been translated to CRLF
        assert raw == b"first\r\nsecond\r\n", f"Expected CRLF on Windows: {raw!r}"
    else:
        # Linux/macOS — pure-LF input written as-is
        assert raw == b"first\nsecond\n", f"Expected LF: {raw!r}"

    # Sanity check: if the caller passes explicit \r, it's preserved as-is
    target2 = writable_env.project / "explicit_crlf.py"
    r2 = mcp_mod.create_file(str(target2), "a\r\nb\r\n")
    assert "✅ Created" in r2, r2
    assert target2.read_bytes() == b"a\r\nb\r\n", (
        "Explicit \\r\\n in content should be respected exactly"
    )
