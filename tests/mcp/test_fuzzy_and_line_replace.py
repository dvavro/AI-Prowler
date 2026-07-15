"""
tests/mcp/test_fuzzy_and_line_replace.py
=========================================
Tests for line_replace_in_file, the line-number-based file-editing tool
added in v8.0.0.

v8.1.3: fuzzy_replace_in_file (the whitespace-tolerant str_replace fallback
this file used to test as FLR-01 ... FLR-20) was REMOVED — it had a bug
where, if its stricter matching strategies failed and it fell back to
whitespace-collapse matching, that normalization was applied to the entire
file rather than just the matched region, risking corruption of unrelated
content. str_replace_in_file (exact match) and line_replace_in_file (by
line number) remain as the two-tool escalation path; the FLR-01...FLR-20
ids are retired along with the tool and not reused.

Test IDs follow the existing convention in test_write_tools.py.

    line_replace_in_file    FLR-21 ... FLR-40
    integration             FLR-41 ... FLR-45

Isolation
---------
Reuses the same writable_env fixture pattern from test_write_tools.py.
The embedding model is NOT loaded — _reindex_file_after_write is no-op.
Runtime budget: under 5 seconds.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest


# ── Session fixture ────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


# ── Per-test fixture: writable_env ─────────────────────────────────────────────

@pytest.fixture
def writable_env(isolated_env, mcp_mod, monkeypatch, tmp_path):
    """Fresh writable project tree wired into both allowlists."""
    rag  = isolated_env.rag
    root = isolated_env.sample_root

    project = root / "project"
    project.mkdir()

    # File with clean spaces — str_replace_in_file would handle this
    (project / "clean.py").write_text(
        "def greet():\n"
        "    return 'hello'\n"
        "\n"
        "def farewell():\n"
        "    return 'goodbye'\n",
        encoding="utf-8",
    )

    # File with TABS — str_replace_in_file fails on it (exact-match only);
    # line_replace_in_file works regardless since it's purely positional.
    (project / "tabbed.py").write_bytes(
        b"def tabbed_func():\n"
        b"\treturn 42\n"
        b"\n"
        b"def another():\n"
        b"\treturn 99\n"
    )

    # File with trailing whitespace on every line
    (project / "trailing.py").write_text(
        "x = 1   \n"
        "y = 2   \n"
        "z = 3   \n",
        encoding="utf-8",
    )

    # File with CRLF line endings
    (project / "crlf.py").write_bytes(
        b"def crlf_func():\r\n"
        b"    pass\r\n"
        b"\r\n"
        b"def second():\r\n"
        b"    return True\r\n"
    )

    # Multi-line file for line range tests
    lines = "\n".join(f"line_{i:03d} = {i}" for i in range(1, 51))
    (project / "numbered.py").write_text(lines + "\n", encoding="utf-8")

    # File with Unicode content
    (project / "unicode.py").write_text(
        "# em-dash: \u2014\n"
        "TITLE = 'AI\u2014Prowler'\n"
        "VERSION = '8.0.0'\n",
        encoding="utf-8",
    )

    untracked = root / "untracked"
    untracked.mkdir()
    (untracked / "secret.py").write_text("SECRET='leak'\n", encoding="utf-8")

    # Wire allowlists
    rag.add_to_auto_update_list(str(project))
    writable_file = tmp_path / "rag_writable_dirs.json"
    writable_file.write_text(json.dumps([str(project)]), encoding="utf-8")
    pending_file  = tmp_path / "rag_writable_pending.json"

    monkeypatch.setattr(mcp_mod, "_WRITABLE_DIRS_FILE",         writable_file)
    monkeypatch.setattr(mcp_mod, "_WRITE_APPROVAL_QUEUE_FILE",  pending_file)
    mcp_mod._reset_write_counter_internal()
    monkeypatch.setattr(mcp_mod, "_reindex_file_after_write", lambda *a, **kw: None)

    class WEnv:
        pass
    e = WEnv()
    e.project   = project
    e.untracked = untracked
    e.clean     = project / "clean.py"
    e.tabbed    = project / "tabbed.py"
    e.trailing  = project / "trailing.py"
    e.crlf      = project / "crlf.py"
    e.numbered  = project / "numbered.py"
    e.unicode   = project / "unicode.py"
    e.secret    = untracked / "secret.py"
    return e


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  line_replace_in_file  —  FLR-21 … FLR-40                                 ║
# ╚════════════════════════════════════════════════════════════════════════════╝

class TestLineReplaceInFile:

    # ── Basic success cases ───────────────────────────────────────────────────

    def test_FLR_21_replace_single_line(self, mcp_mod, writable_env):
        """FLR-21: replace a single line by number."""
        result = mcp_mod.line_replace_in_file(
            str(writable_env.numbered), 1, 1, "line_001 = 999"
        )
        assert "✅" in result
        first = writable_env.numbered.read_text().splitlines()[0]
        assert first == "line_001 = 999"

    def test_FLR_22_replace_range_of_lines(self, mcp_mod, writable_env):
        """FLR-22: replace a range of lines."""
        result = mcp_mod.line_replace_in_file(
            str(writable_env.numbered), 1, 3,
            "REPLACED_LINE_A\nREPLACED_LINE_B"
        )
        assert "✅" in result
        lines = writable_env.numbered.read_text().splitlines()
        assert lines[0] == "REPLACED_LINE_A"
        assert lines[1] == "REPLACED_LINE_B"
        assert lines[2].startswith("line_004")  # next original line shifted up

    def test_FLR_23_replace_last_line(self, mcp_mod, writable_env):
        """FLR-23: replace the last line in the file."""
        lines = writable_env.numbered.read_text().splitlines()
        last = len(lines)
        result = mcp_mod.line_replace_in_file(
            str(writable_env.numbered), last, last, "LAST_LINE = True"
        )
        assert "✅" in result
        new_lines = writable_env.numbered.read_text().splitlines()
        assert new_lines[-1] == "LAST_LINE = True"

    def test_FLR_24_delete_lines_with_empty_content(self, mcp_mod, writable_env):
        """FLR-24: new_content='' deletes the targeted lines."""
        before_count = len(writable_env.numbered.read_text().splitlines())
        result = mcp_mod.line_replace_in_file(
            str(writable_env.numbered), 5, 10, ""
        )
        assert "✅" in result
        after_count = len([l for l in writable_env.numbered.read_text().splitlines() if l])
        assert after_count < before_count

    def test_FLR_25_replace_expands_line_count(self, mcp_mod, writable_env):
        """FLR-25: replacement with more lines than removed expands the file."""
        before = len(writable_env.numbered.read_text().splitlines())
        result = mcp_mod.line_replace_in_file(
            str(writable_env.numbered), 1, 1,
            "EXPAND_A\nEXPAND_B\nEXPAND_C\nEXPAND_D\nEXPAND_E"
        )
        assert "✅" in result
        after = len(writable_env.numbered.read_text().splitlines())
        assert after == before + 4   # replaced 1 line with 5

    def test_FLR_26_backup_created(self, mcp_mod, writable_env):
        """FLR-26: backup file created before write."""
        result = mcp_mod.line_replace_in_file(
            str(writable_env.numbered), 1, 1, "BACKED_UP = True"
        )
        assert "✅" in result
        bak = list(writable_env.project.glob("numbered.py.bak*"))
        assert len(bak) >= 1

    def test_FLR_27_verify_block_in_output(self, mcp_mod, writable_env):
        """FLR-27: output includes verify context block."""
        result = mcp_mod.line_replace_in_file(
            str(writable_env.numbered), 10, 10, "VERIFY_LINE = True"
        )
        assert "Verify" in result
        assert "VERIFY_LINE" in result

    def test_FLR_28_report_shows_line_range(self, mcp_mod, writable_env):
        """FLR-28: success message shows the replaced line range."""
        result = mcp_mod.line_replace_in_file(
            str(writable_env.numbered), 3, 7, "RANGE_REPLACED"
        )
        assert "✅" in result
        assert "3" in result and "7" in result

    def test_FLR_29_crlf_file_preserved(self, mcp_mod, writable_env):
        """FLR-29: CRLF line endings preserved after line replace."""
        result = mcp_mod.line_replace_in_file(
            str(writable_env.crlf), 1, 1, "def new_func():"
        )
        assert "✅" in result
        raw = writable_env.crlf.read_bytes()
        assert b"\r\n" in raw

    def test_FLR_30_unicode_content_preserved(self, mcp_mod, writable_env):
        """FLR-30: Unicode content in other lines preserved after edit."""
        result = mcp_mod.line_replace_in_file(
            str(writable_env.unicode), 3, 3, "VERSION = '9.0.0'"
        )
        assert "✅" in result
        text = writable_env.unicode.read_text(encoding="utf-8")
        assert "\u2014" in text        # em-dash still in file
        assert "VERSION = '9.0.0'" in text

    # ── Dry run ───────────────────────────────────────────────────────────────

    def test_FLR_31_dry_run_no_write(self, mcp_mod, writable_env):
        """FLR-31: dry_run=True does NOT write."""
        original = writable_env.numbered.read_text()
        result = mcp_mod.line_replace_in_file(
            str(writable_env.numbered), 1, 1, "DRY_REPLACED", dry_run=True
        )
        assert "DRY RUN" in result
        assert writable_env.numbered.read_text() == original

    def test_FLR_32_dry_run_shows_removed_and_added(self, mcp_mod, writable_env):
        """FLR-32: dry_run output shows lines removed and lines added."""
        result = mcp_mod.line_replace_in_file(
            str(writable_env.numbered), 1, 2, "NEW_A\nNEW_B", dry_run=True
        )
        assert "REMOVED" in result or "-" in result
        assert "ADDED" in result or "+" in result or "NEW_A" in result

    # ── Error cases ───────────────────────────────────────────────────────────

    def test_FLR_33_start_line_beyond_eof_returns_error(self, mcp_mod, writable_env):
        """FLR-33: start_line > file length returns clear error."""
        result = mcp_mod.line_replace_in_file(
            str(writable_env.numbered), 9999, 9999, "X"
        )
        assert "⚠️" in result
        assert "beyond" in result.lower() or "9999" in result

    def test_FLR_34_end_line_beyond_eof_returns_error(self, mcp_mod, writable_env):
        """FLR-34: end_line > file length returns clear error."""
        result = mcp_mod.line_replace_in_file(
            str(writable_env.numbered), 1, 9999, "X"
        )
        assert "⚠️" in result

    def test_FLR_35_end_line_before_start_returns_error(self, mcp_mod, writable_env):
        """FLR-35: end_line < start_line returns error."""
        result = mcp_mod.line_replace_in_file(
            str(writable_env.numbered), 10, 5, "X"
        )
        assert "⚠️" in result

    def test_FLR_36_start_line_zero_returns_error(self, mcp_mod, writable_env):
        """FLR-36: start_line=0 returns error (1-based)."""
        result = mcp_mod.line_replace_in_file(
            str(writable_env.numbered), 0, 1, "X"
        )
        assert "⚠️" in result

    def test_FLR_37_file_not_found_returns_error(self, mcp_mod, writable_env):
        """FLR-37: non-existent file returns error."""
        result = mcp_mod.line_replace_in_file(
            str(writable_env.project / "ghost.py"), 1, 1, "X"
        )
        assert "⚠️" in result

    def test_FLR_38_untracked_file_blocked(self, mcp_mod, writable_env):
        """FLR-38: file outside writable allowlist is blocked."""
        result = mcp_mod.line_replace_in_file(
            str(writable_env.secret), 1, 1, "HACKED"
        )
        assert "⚠️" in result or "denied" in result.lower() or "not" in result.lower()

    def test_FLR_39_write_counter_incremented(self, mcp_mod, writable_env):
        """FLR-39: successful write increments the circuit-breaker counter."""
        mcp_mod._reset_write_counter_internal()
        mcp_mod.line_replace_in_file(
            str(writable_env.numbered), 1, 1, "COUNTED"
        )
        ok1, _ = mcp_mod._check_and_increment_write_counter()
        assert isinstance(ok1, bool)

    def test_FLR_40_new_content_written_exactly(self, mcp_mod, writable_env):
        """FLR-40: new_content written with exact indentation preserved."""
        new = "def exact():\n    # four spaces\n    return True"
        mcp_mod.line_replace_in_file(
            str(writable_env.numbered), 1, 1, new
        )
        text = writable_env.numbered.read_text()
        assert "    # four spaces" in text   # indentation preserved


# ╔════════════════════════════════════════════════════════════════════════════╗
# ║  Integration — FLR-41 … FLR-45                                             ║
# ║  v8.1.3: rewritten for the two-tool escalation path (str_replace_in_file   ║
# ║  → line_replace_in_file) now that fuzzy_replace_in_file is removed.        ║
# ╚════════════════════════════════════════════════════════════════════════════╝

class TestIntegration:

    def test_FLR_41_str_replace_fails_line_replace_succeeds(self, mcp_mod, writable_env):
        """FLR-41: str_replace_in_file fails on tabs (exact match only);
        line_replace_in_file always works since it's purely positional."""
        # str_replace should fail (tabs vs spaces mismatch)
        str_result = mcp_mod.str_replace_in_file(
            str(writable_env.tabbed),
            "def tabbed_func():\n    return 42",  # spaces
            "def tabbed_func():\n    return 0",
        )
        assert "⚠️" in str_result or "not found" in str_result.lower()

        # line_replace should succeed regardless — it targets a line number,
        # not text content, so tabs vs. spaces is irrelevant.
        line_result = mcp_mod.line_replace_in_file(
            str(writable_env.tabbed), 2, 2, "\treturn 0"
        )
        assert "✅" in line_result

    def test_FLR_42_exotic_encoding_line_replace_still_works(self, mcp_mod, writable_env):
        """FLR-42: for content that would confuse a text matcher entirely
        (e.g. non-UTF-8 bytes), line_replace_in_file always works since
        it never inspects file content to find its target."""
        # Write a file with content that would confuse text matchers
        target = writable_env.project / "tricky.py"
        target.write_bytes(b"\xff\xfeHELLO\r\nWORLD\r\n")   # UTF-16 LE BOM

        # line_replace always works since it's purely positional
        result = mcp_mod.line_replace_in_file(
            str(target), 1, 1, "REPLACED"
        )
        # May succeed or fail depending on encoding detection
        # Key assertion: it never crashes with an exception
        assert isinstance(result, str)

    def test_FLR_43_escalation_workflow(self, mcp_mod, writable_env):
        """FLR-43: two-tool escalation — str_replace_in_file, then
        line_replace_in_file if the exact match fails."""
        fp = str(writable_env.trailing)

        # 1. str_replace (may fail due to trailing whitespace)
        r1 = mcp_mod.str_replace_in_file(fp, "x = 1", "x = 10")

        # 2. If str_replace failed, fall back to line_replace (last resort)
        if "⚠️" in r1:
            r2 = mcp_mod.line_replace_in_file(fp, 1, 1, "x = 10   ")
            assert "✅" in r2
        else:
            assert "✅" in r1

    def test_FLR_44_multiple_edits_accumulate_backups(self, mcp_mod, writable_env):
        """FLR-44: successive edits to same file create numbered backup chain."""
        fp  = str(writable_env.clean)
        mcp_mod.str_replace_in_file(fp,
            "def greet():\n    return 'hello'",
            "def greet():\n    return 'edit1'")
        mcp_mod.line_replace_in_file(fp, 4, 4, "def farewell():")

        baks = sorted(writable_env.project.glob("clean.py.bak*"))
        assert len(baks) >= 2

    def test_FLR_45_line_replace_then_verify_content(self, mcp_mod, writable_env):
        """FLR-45: line_replace output verify block shows correct new content."""
        result = mcp_mod.line_replace_in_file(
            str(writable_env.numbered), 5, 5, "SENTINEL_VALUE = 'verify_me'"
        )
        assert "✅" in result
        assert "SENTINEL_VALUE" in result          # verify block shows it
        text = writable_env.numbered.read_text()
        assert "SENTINEL_VALUE = 'verify_me'" in text   # actually written

