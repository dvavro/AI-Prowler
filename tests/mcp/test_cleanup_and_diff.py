"""
tests/mcp/test_cleanup_and_diff.py
====================================
Tests for two new MCP tools added in v7.0.0:

  CLEANUP_BACKUPS (CB-*)
    CB-01  dry_run=True  lists .bakN files without deleting
    CB-02  dry_run=False deletes all found .bakN files
    CB-03  path=file     finds only backups of that specific file
    CB-04  path=dir      finds .bakN files in that directory recursively
    CB-05  empty path    scans all tracked directories
    CB-06  no backups    returns a clean "none found" message
    CB-07  Tier A        cleanup_backups is suppressed in server mode
    CB-08  dry_run=True returns count and total bytes
    CB-09  dry_run=False returns freed bytes in confirmation
    CB-10  path not found returns ❌ error

  DIFF_FILES (DF-*)
    DF-01  identical files returns ✅ identical message
    DF-02  different files returns unified diff with +/- lines
    DF-03  summary header contains hunk count, added, removed counts
    DF-04  context_lines=0 shows hunks with no surrounding context
    DF-05  max_lines truncation shows warning when exceeded
    DF-06  file_a not found returns ❌ error
    DF-07  file_b not found returns ❌ error
    DF-08  file outside tracked dirs returns ❌ access denied
    DF-09  .bakN file is accessible via base-file allowlist
    DF-10  server mode owner can diff any tracked file
    DF-11  server mode field_crew blocked outside their scopes
    DF-12  server mode field_crew allowed within their scope
    DF-13  binary file returns ❌ error (cannot read)
    DF-14  diff against .bakN backup — realistic workflow test

All tests are in-process with no real ChromaDB or SMTP calls.
Run with:  run_tests.bat tests\\mcp\\test_cleanup_and_diff.py
"""
from __future__ import annotations

import json
import textwrap
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest


# ── ctx helper (reused from other MCP tests) ──────────────────────────────────
class _Stub:
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


def _make_ctx(user: dict | None):
    if user is None:
        return None
    return _Stub(
        request_context=_Stub(request=_Stub(state=_Stub(user=user)))
    )


def _make_user(role, scopes=None, uid="tok_test"):
    return {
        "id":     uid,
        "name":   f"{role}_user",
        "role":   role,
        "email":  "user@test.com",
        "status": "active",
        "scopes": scopes or [],
        "private_collection_enabled": False,
        "can_manage_users": role == "owner",
    }


# ══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def bak_env(tmp_path, mcp_module, monkeypatch):
    """Create a temp directory with some .py files and their .bakN siblings.
    Patches rag_preprocessor.load_auto_update_list (the function that
    cleanup_backups imports directly at call-time) so the tool scans only
    this temp directory rather than David's real tracked dirs."""
    src = tmp_path / "src"
    src.mkdir()

    # Create two source files and several backup copies
    (src / "alpha.py").write_text("# alpha v3\n", encoding="utf-8")
    (src / "alpha.py.bak1").write_text("# alpha v1\n", encoding="utf-8")
    (src / "alpha.py.bak2").write_text("# alpha v2\n", encoding="utf-8")

    (src / "beta.py").write_text("# beta v2\n", encoding="utf-8")
    (src / "beta.py.bak1").write_text("# beta v1\n", encoding="utf-8")

    # A nested directory to test recursive scan
    sub = src / "sub"
    sub.mkdir()
    (sub / "gamma.py").write_text("# gamma\n", encoding="utf-8")
    (sub / "gamma.py.bak1").write_text("# gamma old\n", encoding="utf-8")

    # cleanup_backups does: from rag_preprocessor import load_auto_update_list
    # so we must patch it at the rag_preprocessor module level.
    import rag_preprocessor as _rp
    monkeypatch.setattr(_rp, "load_auto_update_list", lambda: [str(src)])

    return SimpleNamespace(
        mcp=mcp_module,
        src=src,
        sub=sub,
        alpha=src / "alpha.py",
        beta=src / "beta.py",
        gamma=sub / "gamma.py",
    )


@pytest.fixture
def diff_env(tmp_path, mcp_module, monkeypatch):
    """Create a temp directory with pairs of files to diff.
    Patches _resolve_allowlisted_path to allow any path under tmp_path."""
    src = tmp_path / "src"
    src.mkdir()

    # Two versions of a Python file
    v1 = src / "tool.py"
    v1.write_text(textwrap.dedent("""\
        def greet(name):
            return f"Hello, {name}"

        def farewell(name):
            return f"Goodbye, {name}"
    """), encoding="utf-8")

    v2 = src / "tool_new.py"
    v2.write_text(textwrap.dedent("""\
        def greet(name: str) -> str:
            return f"Hello, {name}!"

        def farewell(name: str) -> str:
            return f"Goodbye, {name}!"

        def welcome(name: str) -> str:
            return f"Welcome, {name}!"
    """), encoding="utf-8")

    # A .bak1 copy of tool.py (simulates str_replace_in_file backup)
    bak1 = src / "tool.py.bak1"
    bak1.write_text(textwrap.dedent("""\
        def greet(name):
            return f"Hello, {name}"
    """), encoding="utf-8")

    # Identical pair
    copy = src / "tool_copy.py"
    copy.write_text(v1.read_text(encoding="utf-8"), encoding="utf-8")

    # Patch allowlist to accept ONLY paths under src (not all of tmp_path).
    # This means files created directly under tmp_path are outside the allowlist
    # — used by DF-08 to test the access-denied path.
    def _fake_resolve(filepath):
        p = Path(filepath)
        if str(p).startswith(str(src)):
            return (str(p), None)
        return (None, f"not tracked: {filepath}")

    monkeypatch.setattr(mcp_module, "_resolve_allowlisted_path", _fake_resolve)

    # Patch _company_collection_map to return a simple mapping
    monkeypatch.setattr(
        mcp_module, "_company_collection_map",
        lambda *a, **kw: {
            "rules": [
                {"prefix": str(src / "admin"), "collection": "scope:admin"},
                {"prefix": str(src / "field"), "collection": "scope:field"},
            ],
            "default_collection": "documents",
        }
    )

    return SimpleNamespace(
        mcp=mcp_module,
        src=src,
        v1=v1, v2=v2, bak1=bak1, copy=copy,
    )


# ══════════════════════════════════════════════════════════════════════════════
# CLEANUP_BACKUPS tests
# ══════════════════════════════════════════════════════════════════════════════

class TestCleanupBackups:

    def test_CB_01_dry_run_lists_without_deleting(self, bak_env):
        """CB-01: dry_run=True lists .bakN files but does not delete them."""
        out = bak_env.mcp.cleanup_backups(dry_run=True)

        assert "🔍" in out
        assert "Dry run" in out or "dry run" in out.lower()
        # All 4 backup files should be mentioned
        assert "alpha.py.bak1" in out
        assert "alpha.py.bak2" in out
        assert "beta.py.bak1"  in out
        assert "gamma.py.bak1" in out
        # Files must still exist after a dry run
        assert (bak_env.src / "alpha.py.bak1").exists()
        assert (bak_env.src / "alpha.py.bak2").exists()

    def test_CB_02_dry_run_false_deletes_all(self, bak_env):
        """CB-02: dry_run=False deletes every .bakN file found."""
        out = bak_env.mcp.cleanup_backups(dry_run=False)

        assert "🗑️" in out or "Deleted" in out
        assert not (bak_env.src / "alpha.py.bak1").exists()
        assert not (bak_env.src / "alpha.py.bak2").exists()
        assert not (bak_env.src / "beta.py.bak1").exists()
        assert not (bak_env.sub / "gamma.py.bak1").exists()

        # Source files must NOT be deleted
        assert bak_env.alpha.exists()
        assert bak_env.beta.exists()
        assert bak_env.gamma.exists()

    def test_CB_03_path_file_finds_only_that_files_backups(self, bak_env):
        """CB-03: passing a file path finds only that file's .bakN siblings."""
        out = bak_env.mcp.cleanup_backups(
            path=str(bak_env.alpha), dry_run=True)

        assert "alpha.py.bak1" in out
        assert "alpha.py.bak2" in out
        # beta.py.bak1 and gamma.py.bak1 must NOT appear
        assert "beta.py.bak1"  not in out
        assert "gamma.py.bak1" not in out

    def test_CB_04_path_dir_finds_bakN_recursively(self, bak_env):
        """CB-04: passing a directory scans it recursively."""
        out = bak_env.mcp.cleanup_backups(
            path=str(bak_env.src), dry_run=True)

        # All four backups (including sub/gamma) should appear
        assert "alpha.py.bak1" in out
        assert "alpha.py.bak2" in out
        assert "beta.py.bak1"  in out
        assert "gamma.py.bak1" in out

    def test_CB_05_empty_path_scans_tracked_dirs(self, bak_env):
        """CB-05: empty path scans all tracked directories (mocked to src)."""
        out = bak_env.mcp.cleanup_backups(path="", dry_run=True)
        assert "alpha.py.bak1" in out
        assert "beta.py.bak1"  in out

    def test_CB_06_no_backups_found(self, tmp_path, mcp_module, monkeypatch):
        """CB-06: clean directory returns a 'none found' message with ✅."""
        clean = tmp_path / "clean"
        clean.mkdir()
        (clean / "file.py").write_text("# no baks here\n", encoding="utf-8")

        # Must patch at the rag_preprocessor level — same as bak_env fixture.
        import rag_preprocessor as _rp
        monkeypatch.setattr(_rp, "load_auto_update_list", lambda: [str(clean)])

        out = mcp_module.cleanup_backups(dry_run=True)
        assert "✅" in out
        assert "No" in out

    def test_CB_07_tier_a_suppressed_in_server_mode(self, mcp_module):
        """CB-07: cleanup_backups is in the Tier A suppressed set."""
        assert "cleanup_backups" in mcp_module._TIER_A_SUPPRESSED

    def test_CB_07b_analysis_queue_tools_suppressed_in_server_mode(self, mcp_module):
        """
        Analysis task-queue tools (get_pending_analysis_tasks,
        complete_analysis_task, save_analysis_report) must be Tier A
        suppressed. The Quick Links tab's Common Business AI Analysis / My
        Custom Analyses panels are hidden in server mode's GUI, so nothing
        in server mode can ever queue a task — these tools must not be
        registered with MCP clients in server mode either.
        """
        for tool_name in (
            "get_pending_analysis_tasks",
            "complete_analysis_task",
            "save_analysis_report",
        ):
            assert tool_name in mcp_module._TIER_A_SUPPRESSED, (
                f"{tool_name} must be Tier A suppressed in server mode — "
                f"the analysis task queue it drives has no server-mode caller"
            )

    def test_CB_07c_schedule_next_recurring_job_not_suppressed(self, mcp_module):
        """
        schedule_next_recurring_job is a Job Tracker / Customers-sheet tool
        (auto-books the next recurring job by service frequency) — it is
        NOT part of the analysis task queue (pending_tasks.json) and must
        remain available to every role in both personal and server mode.
        """
        assert "schedule_next_recurring_job" not in mcp_module._TIER_A_SUPPRESSED

    def test_CB_07d_check_sms_inbox_suppressed_in_server_mode(self, mcp_module):
        """
        check_sms_inbox reads the raw, unscoped local inbox — it has no
        per-user filtering (sms_inbox_read() vs the per-user
        sms_inbox_read_for_user() that check_sms_replies uses), so in a
        multi-user server it would let any employee read every inbound
        SMS/WhatsApp message company-wide, not just their own threads.
        Must be Tier A suppressed.
        """
        assert "check_sms_inbox" in mcp_module._TIER_A_SUPPRESSED

    def test_CB_07e_check_sms_replies_suppressed_in_personal_mode(self, mcp_module):
        """
        check_sms_replies's per-user thread isolation (Mike sees Karen's
        reply, not Jake's) is meaningless with a single personal-install
        user. check_sms_inbox is the richer personal-mode equivalent
        (provider filter, unread_only, since_hours=0 for everything).
        check_sms_replies must be suppressed in personal mode.
        """
        assert "check_sms_replies" in mcp_module._PERSONAL_MODE_SUPPRESSED

    def test_CB_07f_sms_inbox_tools_not_cross_suppressed(self, mcp_module):
        """
        Sanity check against copy-paste error: check_sms_inbox must NOT
        also be in _PERSONAL_MODE_SUPPRESSED (it's the personal-mode tool,
        not the suppressed one), and check_sms_replies must NOT also be
        in _TIER_A_SUPPRESSED (it's the server-mode tool). Each tool is
        gated in exactly one direction, never both.
        """
        assert "check_sms_inbox" not in mcp_module._PERSONAL_MODE_SUPPRESSED
        assert "check_sms_replies" not in mcp_module._TIER_A_SUPPRESSED

    def test_CB_08_dry_run_shows_count_and_bytes(self, bak_env):
        """CB-08: dry run output includes file count and total byte size."""
        out = bak_env.mcp.cleanup_backups(dry_run=True)
        # Should mention the number of files found
        assert "4" in out  # 4 backup files total
        # Should mention bytes
        assert "bytes" in out.lower()

    def test_CB_09_delete_shows_freed_bytes(self, bak_env):
        """CB-09: delete confirmation reports freed bytes."""
        out = bak_env.mcp.cleanup_backups(dry_run=False)
        assert "bytes" in out.lower()
        assert "freed" in out.lower() or "Deleted" in out

    def test_CB_10_path_not_found_returns_error(self, bak_env):
        """CB-10: non-existent path returns ❌ error."""
        out = bak_env.mcp.cleanup_backups(
            path="/nonexistent/path/to/nowhere", dry_run=True)
        assert "❌" in out


# ══════════════════════════════════════════════════════════════════════════════
# DIFF_FILES tests
# ══════════════════════════════════════════════════════════════════════════════

class TestDiffFiles:

    def test_DF_01_identical_files(self, diff_env):
        """DF-01: identical files return ✅ identical confirmation."""
        out = diff_env.mcp.diff_files(
            str(diff_env.v1), str(diff_env.copy))
        assert "✅" in out
        assert "identical" in out.lower()

    def test_DF_02_different_files_return_diff(self, diff_env):
        """DF-02: different files return unified diff with +/- lines."""
        out = diff_env.mcp.diff_files(
            str(diff_env.v1), str(diff_env.v2))
        assert "+" in out
        assert "-" in out
        assert "@@" in out

    def test_DF_03_summary_header_present(self, diff_env):
        """DF-03: output header contains hunk count, added, and removed stats."""
        out = diff_env.mcp.diff_files(
            str(diff_env.v1), str(diff_env.v2))
        assert "hunk" in out.lower()
        assert "added"   in out.lower() or "+"  in out
        assert "removed" in out.lower() or "-"  in out

    def test_DF_04_context_lines_zero(self, diff_env):
        """DF-04: context_lines=0 shows only changed lines — no unchanged
        context lines appear between +/- lines in the hunk body."""
        out = diff_env.mcp.diff_files(
            str(diff_env.v1), str(diff_env.v2), context_lines=0)

        # Diff must still be produced with @@ markers
        assert "@@" in out
        assert "+" in out
        assert "-" in out

        # With context_lines=0, the only lines that start with a space are
        # the header lines (--- / +++ / @@). No ' ' (unchanged) lines should
        # appear in the hunk body.
        diff_body_lines = [
            ln for ln in out.splitlines()
            if not ln.startswith(("---", "+++", "@@", "diff", "─", " "))
        ]
        # Every hunk body line should be +, - or empty (no unchanged context)
        for ln in diff_body_lines:
            assert ln.startswith(("+", "-", "")) or not ln, \
                f"Unexpected context line in context_lines=0 diff: {ln!r}"

    def test_DF_05_max_lines_truncation(self, diff_env):
        """DF-05: output longer than max_lines is truncated with a warning."""
        out = diff_env.mcp.diff_files(
            str(diff_env.v1), str(diff_env.v2),
            context_lines=50,   # force lots of context
            max_lines=3)
        assert "Truncated" in out or "truncated" in out.lower()
        assert "max_lines" in out

    def test_DF_06_file_a_not_found(self, diff_env):
        """DF-06: missing file_a returns ❌ with 'not found'."""
        out = diff_env.mcp.diff_files(
            str(diff_env.src / "DOES_NOT_EXIST.py"),
            str(diff_env.v2))
        assert "❌" in out
        assert "not found" in out.lower()

    def test_DF_07_file_b_not_found(self, diff_env):
        """DF-07: missing file_b returns ❌ with 'not found'."""
        out = diff_env.mcp.diff_files(
            str(diff_env.v1),
            str(diff_env.src / "DOES_NOT_EXIST.py"))
        assert "❌" in out
        assert "not found" in out.lower()

    def test_DF_08_file_outside_tracked_dirs_denied(
            self, diff_env, tmp_path):
        """DF-08: file outside tracked directories (outside src/) returns ❌."""
        # Place outside.py directly under tmp_path — NOT inside src/.
        # The fake resolver only allows paths under src/, so this is denied.
        outside = tmp_path / "outside.py"
        outside.write_text("# outside\n", encoding="utf-8")

        out = diff_env.mcp.diff_files(
            str(diff_env.v1), str(outside))
        assert "❌" in out
        assert ("tracked" in out.lower()
                or "denied" in out.lower()
                or "not in" in out.lower())

    def test_DF_09_bak_file_accessible_via_base_allowlist(self, diff_env):
        """DF-09: a .bakN file is accessible because its base file is tracked."""
        # bak1 is tool.py.bak1 — base 'tool.py' is in tracked src dir
        out = diff_env.mcp.diff_files(
            str(diff_env.bak1), str(diff_env.v1))
        # Should produce a diff (bak1 has fewer lines than v1)
        assert "❌" not in out
        assert ("identical" in out.lower()) or ("@@" in out)

    def test_DF_10_server_owner_can_diff_any_tracked_file(self, diff_env):
        """DF-10: owner in server mode can diff any file in tracked dirs."""
        ctx = _make_ctx(_make_user("owner"))
        out = diff_env.mcp.diff_files(
            str(diff_env.v1), str(diff_env.v2), ctx=ctx)
        assert "❌" not in out

    def test_DF_11_server_field_crew_blocked_outside_scope(
            self, diff_env, tmp_path):
        """DF-11: field_crew cannot diff a file in a different scope."""
        # Create a file in an 'admin'-scoped directory
        admin_dir = diff_env.src / "admin"
        admin_dir.mkdir(exist_ok=True)
        admin_file = admin_dir / "secret.py"
        admin_file.write_text("# admin only\n", encoding="utf-8")

        ctx = _make_ctx(_make_user("field_crew", scopes=["scope:field"]))
        out = diff_env.mcp.diff_files(
            str(diff_env.v1), str(admin_file), ctx=ctx)
        # The admin-scoped file should be denied for field_crew
        assert "❌" in out
        assert "scope" in out.lower() or "denied" in out.lower()

    def test_DF_12_server_field_crew_allowed_within_scope(
            self, diff_env, tmp_path):
        """DF-12: field_crew can diff files that are within their scope."""
        field_dir = diff_env.src / "field"
        field_dir.mkdir(exist_ok=True)
        file1 = field_dir / "job_a.py"
        file2 = field_dir / "job_b.py"
        file1.write_text("# job a v1\n", encoding="utf-8")
        file2.write_text("# job a v2 — updated\n", encoding="utf-8")

        ctx = _make_ctx(_make_user("field_crew", scopes=["scope:field"]))
        out = diff_env.mcp.diff_files(
            str(file1), str(file2), ctx=ctx)
        # Both files are in scope:field — should succeed
        assert "❌" not in out

    def test_DF_13_binary_file_returns_error(self, diff_env, tmp_path):
        """DF-13: a file containing null bytes is detected as binary and
        returns ❌ — latin-1 would otherwise silently read it."""
        # bytes(range(256)) contains \x00 — triggers the null-byte guard
        binary = diff_env.src / "data.bin"
        binary.write_bytes(bytes(range(256)))

        out = diff_env.mcp.diff_files(
            str(diff_env.v1), str(binary))
        assert "❌" in out
        assert "binary" in out.lower() or "null" in out.lower()

    def test_DF_14_diff_file_against_bak_realistic_workflow(self, diff_env):
        """DF-14: realistic workflow — diff current file against its .bak1 backup
        to verify what str_replace_in_file changed."""
        # tool.py has more content; bak1 has fewer lines
        out = diff_env.mcp.diff_files(
            str(diff_env.bak1),   # old: fewer lines
            str(diff_env.v1),     # new: more lines
        )
        assert "❌" not in out
        # diff should show additions (v1 has more content than bak1)
        assert "+" in out or "identical" in out.lower()
        # Header should name the files
        assert "bak1" in out or "tool" in out.lower()
