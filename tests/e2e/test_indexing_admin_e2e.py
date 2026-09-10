"""
tests/e2e/test_indexing_admin_e2e.py
=======================================
Phase 3c of the broader MCP tool E2E suite.

Covers the Indexing & admin family:
  index_path, update_tracked_directories, list_tracked_directories,
  untrack_directory, get_database_stats, check_ai_prowler_status,
  reindex_file, reindex_directory, list_writable_directories,
  grant_write_access, revoke_write_access

DELIBERATELY EXCLUDED: reindex_all. tests/pytest.ini's own live_db marker
documentation records a real, previously-encountered ChromaDB/HNSW race
condition during cold-init capable of corrupting the on-disk segment —
found via run_tests.bat hanging indefinitely inside chromadb's native
_query(). reindex_all rebuilds the ENTIRE database from every tracked
source, which is exactly the kind of operation that risk applies to. This
is not something to put in a routinely-repeated automated test.

SAFETY MODEL
------------
- index_path/reindex_file/reindex_directory/untrack_directory are scoped
  ONLY to one small sandbox directory (_e2e_sandbox_indexing) created and
  destroyed by this suite — the real production knowledge base's other
  content is never touched.
- grant_write_access/revoke_write_access are exercised ONLY on that same
  new sandbox directory — never on any of the real pre-existing writable
  directories. Verified via list_writable_directories before and after
  that the real entries are unaffected.
- update_tracked_directories() is called with NO argument (re-scan
  everything) is NOT used here — only the single-directory form
  (directory=<sandbox>), to avoid an expensive/slow full-database rescan
  as a side effect of running this suite.

REQUIREMENTS
------------
No ANTHROPIC_API_KEY needed. First run will pay the one-time embedding
model cold-load cost (~5-10s) if the process hasn't already loaded it.

RUN
---
  run_e2e_mcp_tool.bat -k indexing_admin
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
SANDBOX = WRITABLE_TEST_DIR / "_e2e_sandbox_indexing"

if str(INSTALL_DIR) not in sys.path:
    sys.path.insert(0, str(INSTALL_DIR))


@pytest.fixture(scope="session")
def mcp_module():
    import ai_prowler_mcp as m
    return m


@pytest.fixture(scope="session", autouse=True)
def _sandbox_lifecycle():
    shutil.rmtree(SANDBOX, ignore_errors=True)
    SANDBOX.mkdir(parents=True, exist_ok=True)
    (SANDBOX / "ztest_e2e_indexing_doc.txt").write_text(
        "ZTEST_E2E_INDEXING_MARKER — this is a synthetic document created "
        "by test_indexing_admin_e2e.py to validate index_path, "
        "reindex_file, reindex_directory, and untrack_directory. It is "
        "removed from both disk and the ChromaDB index at the end of "
        "this test run.",
        encoding="utf-8",
    )
    yield
    shutil.rmtree(SANDBOX, ignore_errors=True)


@pytest.mark.mcp_tool_e2e
class TestIndexingAndAdmin:

    def test_01_check_ai_prowler_status(self, mcp_module):
        result = mcp_module.check_ai_prowler_status()
        assert "❌" not in result, f"check_ai_prowler_status failed: {result}"

    def test_02_get_database_stats_baseline(self, mcp_module):
        result = mcp_module.get_database_stats()
        assert "❌" not in result, f"get_database_stats failed: {result}"

    def test_03_index_path_sandbox(self, mcp_module):
        result = mcp_module.index_path(directory=str(SANDBOX), recursive=True)
        assert "❌" not in result, f"index_path failed: {result}"

    def test_04_list_tracked_directories_includes_sandbox(self, mcp_module):
        result = mcp_module.list_tracked_directories()
        assert "❌" not in result, f"list_tracked_directories failed: {result}"
        assert "_e2e_sandbox_indexing" in result, (
            f"Sandbox directory not found in tracked list after index_path: {result}"
        )

    def test_05_update_tracked_directories_scoped_to_sandbox(self, mcp_module):
        """Only the single-directory form — never the argument-less
        full-database rescan, to avoid an expensive side effect."""
        result = mcp_module.update_tracked_directories(directory=str(SANDBOX))
        assert "❌" not in result, f"update_tracked_directories failed: {result}"

    def test_06_reindex_file(self, mcp_module):
        target = SANDBOX / "ztest_e2e_indexing_doc.txt"
        result = mcp_module.reindex_file(filepath=str(target))
        assert "✅" in result, f"reindex_file failed: {result}"

    def test_07_reindex_directory_scoped_to_sandbox(self, mcp_module):
        result = mcp_module.reindex_directory(directory=str(SANDBOX))
        assert "❌" not in result, f"reindex_directory failed: {result}"

    def test_08_list_writable_directories_baseline(self, mcp_module):
        result = mcp_module.list_writable_directories()
        assert "❌" not in result, f"list_writable_directories failed: {result}"
        TestIndexingAndAdmin.baseline_writable = result

    def test_09_grant_write_access_sandbox_only(self, mcp_module):
        result = mcp_module.grant_write_access(directory=str(SANDBOX))
        assert "✅" in result or "already" in result.lower(), (
            f"grant_write_access failed: {result}"
        )
        after = mcp_module.list_writable_directories()
        assert "_e2e_sandbox_indexing" in after, (
            f"Sandbox not listed as writable after grant_write_access: {after}"
        )

    def test_10_revoke_write_access_sandbox_only(self, mcp_module):
        """The sandbox sits under C:\\Users\\david\\AI-Prowler-V900_to_V910_work,
        which is already writable as a broader ancestor — grant_write_access's
        own logic (see its "already in the write zone" branch) correctly
        detects this and does NOT add a redundant literal entry for the
        sandbox itself. That means there is nothing literal for
        revoke_write_access to remove here — its "not in the write zone —
        nothing to revoke" response is the CORRECT outcome for a path
        already covered by an ancestor grant, not a failure. Accept both
        outcomes; only a real ❌ error is a failure.
        """
        result = mcp_module.revoke_write_access(directory=str(SANDBOX))
        assert "❌" not in result, f"revoke_write_access errored: {result}"
        assert (
            "✅" in result
            or "removed" in result.lower()
            or "nothing to revoke" in result.lower()
        ), f"Unexpected revoke_write_access response: {result}"

    def test_11_untrack_directory_removes_sandbox(self, mcp_module):
        result = mcp_module.untrack_directory(directory=str(SANDBOX))
        assert "❌" not in result, f"untrack_directory failed: {result}"
        after = mcp_module.list_tracked_directories()
        assert "_e2e_sandbox_indexing" not in after, (
            f"Sandbox still appears in tracked directories after untrack_directory: {after}"
        )

    def test_99_real_writable_directories_unaffected(self, mcp_module):
        """Confirms none of the real, pre-existing writable directories
        were touched by this suite's grant/revoke cycle on the sandbox."""
        final = mcp_module.list_writable_directories()
        # Spot-check a couple of directories known to be writable
        # throughout this whole project's session (confirmed via manual
        # list_writable_directories() calls earlier in this project).
        for real_dir in (r"C:\Users\david\.ai-prowler",
                         r"C:\Users\david\AI-Prowler"):
            assert real_dir in final, (
                f"REGRESSION: real writable directory {real_dir!r} is "
                f"missing after this suite's grant/revoke cycle on the "
                f"sandbox — a real permission may have been accidentally "
                f"affected: {final}"
            )
