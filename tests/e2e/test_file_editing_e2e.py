"""
tests/e2e/test_file_editing_e2e.py
=====================================
Phase 3b of the broader MCP tool E2E suite.

Covers the File editing family:
  create_file, write_file, str_replace_in_file, line_replace_in_file,
  create_directory, list_directory, copy_to_backup, list_backups,
  restore_backup, cleanup_backups, cleanup_job_logs (dry_run only),
  reset_write_counter, diff_files

SAFETY MODEL
------------
Creates one dedicated sandbox directory (_e2e_sandbox_file_editing) under
the already-writable/tracked work directory. Every file used by this
suite lives only inside that sandbox and the whole sandbox is deleted at
the end — nothing here ever touches real project files.

cleanup_job_logs is tested with dry_run=True ONLY — it operates on the
real ~/.ai-prowler/jobs/ directory (shared, not sandboxable, holds real
job logs from real usage including today's own test runs), so this suite
only verifies the tool runs and reports correctly, never actually deletes
anything there.

cleanup_backups is always called with an explicit sandbox path, never a
bare/empty path (which could otherwise sweep .bakN files across every
tracked directory).

REQUIREMENTS
------------
No ANTHROPIC_API_KEY needed.

RUN
---
  run_e2e_mcp_tool.bat -k file_editing
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

INSTALL_DIR = Path(os.environ.get("AI_PROWLER_SRC",
                                   r"C:\Program Files\AI-Prowler"))
WRITABLE_TEST_DIR = Path(os.environ.get(
    "AI_PROWLER_WRITABLE_TEST_DIR",
    r"C:\Users\david\AI-Prowler-V900_to_V910_work\AI-Prowler",
))
SANDBOX = WRITABLE_TEST_DIR / "_e2e_sandbox_file_editing"

if str(INSTALL_DIR) not in sys.path:
    sys.path.insert(0, str(INSTALL_DIR))


@pytest.fixture(scope="session")
def mcp_module():
    import ai_prowler_mcp as m
    return m


@pytest.fixture(scope="session", autouse=True)
def _sandbox_lifecycle():
    shutil.rmtree(SANDBOX, ignore_errors=True)  # clean slate if a prior
                                                  # failed run left it dirty
    yield
    shutil.rmtree(SANDBOX, ignore_errors=True)


@pytest.mark.mcp_tool_e2e
class TestFileEditingTools:

    backup_number: "int | None" = None

    def test_01_create_directory(self, mcp_module):
        result = mcp_module.create_directory(dirpath=str(SANDBOX))
        assert "❌" not in result, f"create_directory failed: {result}"
        assert SANDBOX.exists() and SANDBOX.is_dir()

    def test_02_create_file(self, mcp_module):
        target = SANDBOX / "created.txt"
        result = mcp_module.create_file(
            filepath=str(target), content="ZTEST line one\n")
        assert "✅" in result, f"create_file failed: {result}"
        assert target.read_text(encoding="utf-8") == "ZTEST line one\n"

    def test_02b_create_file_fails_if_exists(self, mcp_module):
        """create_file's own docstring: 'FAILS if the file already exists' —
        confirm that's actually enforced. The tool signals this with a
        ⚠️ warning marker, not ❌ — checking for "already exists" text
        directly is more robust than pinning to one specific emoji."""
        target = SANDBOX / "created.txt"
        result = mcp_module.create_file(
            filepath=str(target), content="should not overwrite\n")
        assert "already exists" in result.lower(), (
            f"create_file should refuse to overwrite an existing file: {result}"
        )
        assert target.read_text(encoding="utf-8") == "ZTEST line one\n", (
            "create_file overwrote an existing file despite reporting failure"
        )

    def test_03_write_file_overwrites(self, mcp_module):
        target = SANDBOX / "created.txt"
        result = mcp_module.write_file(
            filepath=str(target), content="ZTEST overwritten content\n")
        assert "✅" in result, f"write_file failed: {result}"
        assert target.read_text(encoding="utf-8") == "ZTEST overwritten content\n"

    def test_04_str_replace_in_file(self, mcp_module):
        target = SANDBOX / "created.txt"
        result = mcp_module.str_replace_in_file(
            filepath=str(target),
            old_str="overwritten",
            new_str="replaced",
        )
        assert "✅" in result, f"str_replace_in_file failed: {result}"
        assert "ZTEST replaced content" in target.read_text(encoding="utf-8")

    def test_05_line_replace_in_file(self, mcp_module):
        target = SANDBOX / "multiline.txt"
        target.write_text("line1\nline2\nline3\n", encoding="utf-8")
        result = mcp_module.line_replace_in_file(
            filepath=str(target), start_line=2, end_line=2,
            new_content="LINE2_REPLACED",
        )
        assert "✅" in result, f"line_replace_in_file failed: {result}"
        content = target.read_text(encoding="utf-8")
        assert "LINE2_REPLACED" in content
        assert "line1" in content and "line3" in content

    def test_06_list_directory(self, mcp_module):
        result = mcp_module.list_directory(dirpath=str(SANDBOX))
        assert "❌" not in result, f"list_directory failed: {result}"
        assert "created.txt" in result and "multiline.txt" in result

    def test_07_copy_to_backup(self, mcp_module):
        target = SANDBOX / "created.txt"
        result = mcp_module.copy_to_backup(filepath=str(target))
        assert "Snapshot created" in result or "💾" in result, (
            f"copy_to_backup failed: {result}"
        )
        import re
        m = re.search(r"\.bak(\d+)", result)
        assert m, (
            f"Could not parse the backup number from copy_to_backup's own "
            f"output — never assume .bak1, the numbering increments across "
            f"any prior backups of this file: {result}"
        )
        TestFileEditingTools.backup_number = int(m.group(1))
        assert (SANDBOX / f"created.txt.bak{self.backup_number}").exists(), (
            "copy_to_backup reported success but the .bakN file it named "
            "was not actually found on disk"
        )

    def test_08_list_backups(self, mcp_module):
        assert self.backup_number is not None, "test_07 must run first"
        target = SANDBOX / "created.txt"
        result = mcp_module.list_backups(filepath=str(target))
        assert "❌" not in result, f"list_backups failed: {result}"
        assert f"bak{self.backup_number}" in result, (
            f"Expected .bak{self.backup_number} to be listed: {result}"
        )

    def test_09_restore_backup(self, mcp_module):
        assert self.backup_number is not None, "test_07 must run first"
        target = SANDBOX / "created.txt"
        # target currently has "replaced" content (post test_04); the
        # backup taken in test_07 was of THAT same content, so restoring
        # is a no-op content-wise but exercises the tool's mechanics —
        # write something different first so restore has a visible effect.
        mcp_module.write_file(
            filepath=str(target), content="ZTEST content before restore\n")
        result = mcp_module.restore_backup(
            filepath=str(target), backup_number=self.backup_number)
        assert "✅" in result, f"restore_backup failed: {result}"
        restored_content = target.read_text(encoding="utf-8")
        assert "ZTEST replaced content" in restored_content, (
            f"restore_backup did not bring back the .bak{self.backup_number} "
            f"content: {restored_content!r}"
        )

    def test_10_diff_files(self, mcp_module):
        file_a = SANDBOX / "diff_a.txt"
        file_b = SANDBOX / "diff_b.txt"
        file_a.write_text("common line\nonly in A\n", encoding="utf-8")
        file_b.write_text("common line\nonly in B\n", encoding="utf-8")
        result = mcp_module.diff_files(file_a=str(file_a), file_b=str(file_b))
        assert "❌" not in result, f"diff_files failed: {result}"
        assert "only in A" in result and "only in B" in result, (
            f"diff_files did not surface the actual differences: {result}"
        )

    def test_11_cleanup_backups_dry_run_then_real(self, mcp_module):
        assert self.backup_number is not None, "test_07 must run first"
        backup_file = SANDBOX / f"created.txt.bak{self.backup_number}"
        dry_result = mcp_module.cleanup_backups(path=str(SANDBOX), dry_run=True)
        assert "❌" not in dry_result, f"cleanup_backups dry_run failed: {dry_result}"
        assert backup_file.exists(), (
            "dry_run cleanup_backups should not have deleted anything yet"
        )

        real_result = mcp_module.cleanup_backups(path=str(SANDBOX), dry_run=False)
        assert "❌" not in real_result, f"cleanup_backups real run failed: {real_result}"
        assert not backup_file.exists(), (
            f"cleanup_backups(dry_run=False) reported success but "
            f"{backup_file.name} still exists"
        )

    def test_12_cleanup_job_logs_dry_run_only(self, mcp_module):
        """dry_run=True only — this operates on the REAL, shared
        ~/.ai-prowler/jobs/ directory (not sandboxable), which holds real
        job logs including today's own test runs. Never call with
        dry_run=False in an automated test."""
        result = mcp_module.cleanup_job_logs(dry_run=True)
        assert "❌" not in result, f"cleanup_job_logs dry_run failed: {result}"

    def test_13_reset_write_counter(self, mcp_module):
        result = mcp_module.reset_write_counter()
        assert "❌" not in result, f"reset_write_counter failed: {result}"
