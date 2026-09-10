"""
tests/e2e/test_learnings_and_retrieval_e2e.py
================================================
Phase 1 of the broader MCP tool E2E suite (see run_e2e_mcp_tool.bat header
comments for the full category breakdown and risk assessment behind this
phased rollout).

Covers three of AI-Prowler's ten tool families, chosen first because they
are the lowest-risk: either fully read-only against the real production
knowledge base, or writing to one isolated file with a proper dedicated
delete tool for cleanup (unlike categories such as File editing / Dev
tools / Indexing & admin, which touch real files or the real ChromaDB and
need a separate, more careful design before any test is written for them).

  1. Self-learning memory (record_learning, search_learnings,
     list_learnings, update_learning, delete_learning, get_learning_stats,
     get_learnings_report, export_learnings_file, send_learnings_report,
     rebuild_learnings_index)
  2. Knowledge retrieval / RAG (get_knowledge_base_overview,
     list_indexed_documents, list_indexed_directories, search_documents,
     search_within_directory, multi_query_search, expand_search_result,
     read_document)
  3. Code-aware retrieval (grep_documents, read_file_lines)

SAFETY MODEL
------------
Self-learning memory tests write ONE real learning entry, tagged
"ztest_e2e" and titled with a "ZTEST:" prefix so it is unambiguously
identifiable and never collides with real learnings. Cleanup uses the
tool's own dedicated delete_learning() — the correct, designed-for-this
mechanism in this domain, unlike the spreadsheet suites which restore a
whole-file backup because no per-row delete tool exists there.
get_learning_stats() is snapshotted before and after to confirm the count
returns to baseline.

Knowledge retrieval and code-aware retrieval tests are 100% read-only
against the real, already-indexed production knowledge base — no backup
or cleanup needed, since nothing is ever written.

send_learnings_report() sends ONE real email, scoped tightly to
tag="ztest_e2e" so it contains only the single test learning, not real
production learnings data.

REQUIREMENTS
------------
No ANTHROPIC_API_KEY needed — this suite calls tools directly, it does
not exercise Claude's tool-selection (matching
test_route_scheduling_e2e.py and test_job_tracker_remaining_tools_e2e.py's
approach). Needs AI-Prowler's real knowledge base to already have at
least one indexed document (true for any real install) and email
configured for the send_learnings_report test.

RUN
---
  Via the consolidated runner (recommended):
    run_e2e_mcp_tool.bat -k learnings_and_retrieval
  Directly:
    pytest tests/e2e/test_learnings_and_retrieval_e2e.py -v -s -m mcp_tool_e2e
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

INSTALL_DIR = Path(os.environ.get("AI_PROWLER_SRC",
                                   r"C:\Program Files\AI-Prowler"))
TEST_EMAIL_TO = "david.vavro1@gmail.com"
ZTEST_TAG = "ztest_e2e"

if str(INSTALL_DIR) not in sys.path:
    sys.path.insert(0, str(INSTALL_DIR))


@pytest.fixture(scope="session")
def mcp_module():
    import ai_prowler_mcp as m
    return m


def _parse_stat_total(stats_text: str) -> int:
    m = re.search(r"Total learnings\s*:\s*(\d+)", stats_text)
    assert m, f"Could not parse total learnings count from: {stats_text!r}"
    return int(m.group(1))


def _parse_search_hit(search_text: str) -> "tuple[str, int] | None":
    """Extract (filename, chunk_index) from the first hit in
    search_documents()-style output: '[1] index.html  chunk 1/1  ...'"""
    m = re.search(r"^\[\d+\]\s+(\S+)\s+chunk\s+(\d+)/\d+", search_text,
                  re.MULTILINE)
    if not m:
        return None
    return (m.group(1), int(m.group(2)))


# ═══════════════════════════════════════════════════════════════════════
# Category 1 — Self-learning memory
# ═══════════════════════════════════════════════════════════════════════
@pytest.mark.mcp_tool_e2e
class TestSelfLearningMemory:

    learning_id: "str | None" = None
    baseline_total: "int | None" = None

    def test_00_snapshot_baseline_stats(self, mcp_module):
        stats = mcp_module.get_learning_stats()
        TestSelfLearningMemory.baseline_total = _parse_stat_total(stats)

    def test_01_record_learning(self, mcp_module):
        result = mcp_module.record_learning(
            title="ZTEST: E2E suite test learning — safe to ignore",
            content="This is a synthetic learning created by "
                    "test_learnings_and_retrieval_e2e.py to validate the "
                    "record_learning/search_learnings/update_learning/"
                    "delete_learning tool chain. It is deleted "
                    "automatically at the end of the test run.",
            category="general",
            source="E2E test suite",
            confidence=0.5,
            tags=ZTEST_TAG,
        )
        assert "✅" in result or "recorded" in result.lower(), (
            f"record_learning did not report success: {result}"
        )
        m = re.search(r"\b([A-Za-z0-9_-]{6,})\b", result)
        # Most AI-Prowler tools echo the created ID somewhere in the
        # confirmation text — try to capture it, but fall back to
        # searching by title if the ID format isn't found this way.
        id_match = re.search(r"ID:\s*(\S+)", result) or re.search(
            r"\b(learn[_-][A-Za-z0-9]+)\b", result, re.IGNORECASE)
        if id_match:
            TestSelfLearningMemory.learning_id = id_match.group(1)

    def test_02_search_learnings_finds_it(self, mcp_module):
        result = mcp_module.search_learnings(
            query="E2E suite test learning synthetic", n_results=5)
        assert "ZTEST" in result, (
            f"Newly recorded test learning not found via search_learnings: {result}"
        )

    def test_03_list_learnings_with_tag_filter(self, mcp_module):
        result = mcp_module.list_learnings(tag=ZTEST_TAG, limit=25)
        assert "ZTEST" in result, (
            f"Test learning not found via list_learnings(tag={ZTEST_TAG!r}): {result}"
        )
        # If we didn't capture an ID from record_learning's own output,
        # try to recover it from the list output instead.
        if not TestSelfLearningMemory.learning_id:
            id_match = re.search(r"ID:\s*(\S+)", result)
            if id_match:
                TestSelfLearningMemory.learning_id = id_match.group(1)

    def test_04_update_learning(self, mcp_module):
        assert self.learning_id, (
            "Could not determine the created learning's ID from either "
            "record_learning's or list_learnings' output — check whether "
            "the ID format in the tool's confirmation text changed."
        )
        result = mcp_module.update_learning(
            learning_id=self.learning_id,
            updates={"confidence": 0.9,
                     "content": "Updated by test_04 — confirms "
                                 "update_learning() works."},
        )
        assert "✅" in result or "updated" in result.lower(), (
            f"update_learning failed: {result}"
        )

    def test_05_get_learning_stats_reflects_new_entry(self, mcp_module):
        stats = mcp_module.get_learning_stats()
        current_total = _parse_stat_total(stats)
        assert current_total == self.baseline_total + 1, (
            f"Expected total learnings to increase by 1 "
            f"({self.baseline_total} -> {self.baseline_total + 1}), "
            f"got {current_total}"
        )

    def test_06_get_learnings_report_includes_entry(self, mcp_module):
        result = mcp_module.get_learnings_report(format="summary")
        assert "❌" not in result, f"get_learnings_report failed: {result}"
        # Not asserting ZTEST appears here specifically — get_learnings_report
        # may summarize/truncate; the point of this test is that the tool
        # itself runs cleanly, not a duplicate content check already done
        # by test_03.

    def test_07_export_learnings_file(self, mcp_module):
        # Must use a directory already in AI-Prowler's tracked+writable
        # allowlist — export_learnings_file() correctly refuses paths
        # outside it (confirmed: %TEMP% is rejected with "not under any
        # tracked root", which is the tool's security model working
        # correctly, not a bug). The work directory this suite itself
        # lives under is already writable.
        out_dir = Path(os.environ.get(
            "AI_PROWLER_WRITABLE_TEST_DIR",
            r"C:\Users\david\AI-Prowler-V900_to_V910_work\AI-Prowler",
        ))
        out_path = out_dir / "ztest_e2e_learnings_export.csv"
        result = mcp_module.export_learnings_file(
            filepath=str(out_path), format="csv")
        assert "✅" in result or "Exported" in result, (
            f"export_learnings_file failed: {result}"
        )
        assert out_path.exists(), (
            f"export_learnings_file reported success but no file at {out_path}"
        )
        out_path.unlink(missing_ok=True)  # clean up the export itself

    def test_08_send_learnings_report(self, mcp_module):
        """Sends ONE real email, scoped to tag=ztest_e2e so it contains
        only the single synthetic test learning, not real production data."""
        result = mcp_module.send_learnings_report(
            to=TEST_EMAIL_TO,
            tags=ZTEST_TAG,
            subject="[E2E TEST] AI-Prowler Learnings Report — safe to ignore",
        )
        assert result.startswith("✅"), f"send_learnings_report failed: {result}"

    def test_09_delete_learning_cleans_up(self, mcp_module):
        assert self.learning_id, "No learning_id captured — cannot clean up"
        result = mcp_module.delete_learning(learning_id=self.learning_id)
        assert "✅" in result or "deleted" in result.lower(), (
            f"delete_learning failed — TEST DATA MAY STILL BE PRESENT, "
            f"manual cleanup needed for learning_id={self.learning_id}: {result}"
        )

    def test_10_rebuild_learnings_index_after_cleanup(self, mcp_module):
        result = mcp_module.rebuild_learnings_index()
        assert "❌" not in result, f"rebuild_learnings_index failed: {result}"

    def test_99_verify_stats_restored(self, mcp_module):
        stats = mcp_module.get_learning_stats()
        final_total = _parse_stat_total(stats)
        assert final_total == self.baseline_total, (
            f"REGRESSION / CLEANUP FAILURE: expected total learnings to "
            f"return to baseline ({self.baseline_total}), got {final_total} "
            f"— the ZTEST learning from this suite may still be present."
        )
        result = mcp_module.search_learnings(
            query="E2E suite test learning synthetic", n_results=5)
        assert "ZTEST" not in result, (
            f"Deleted test learning still appears in search results: {result}"
        )


# ═══════════════════════════════════════════════════════════════════════
# Category 2 — Knowledge retrieval (100% read-only)
# ═══════════════════════════════════════════════════════════════════════
@pytest.mark.mcp_tool_e2e
class TestKnowledgeRetrieval:

    a_real_directory: "str | None" = None
    a_real_filename: "str | None" = None
    a_real_chunk_index: "int | None" = None

    def test_01_get_knowledge_base_overview(self, mcp_module):
        result = mcp_module.get_knowledge_base_overview()
        assert "❌" not in result, f"get_knowledge_base_overview failed: {result}"
        assert re.search(r"\d+", result), (
            f"Expected at least one number (doc/chunk count) in overview: {result}"
        )

    def test_02_list_indexed_directories(self, mcp_module):
        result = mcp_module.list_indexed_directories()
        assert "❌" not in result, f"list_indexed_directories failed: {result}"
        # Grab a plausible directory name to scope test_05's search with —
        # best-effort parse, not required for this test's own pass/fail.
        m = re.search(r"([A-Za-z0-9_\-\\/. ]{3,60})", result)
        if m:
            TestKnowledgeRetrieval.a_real_directory = m.group(1).strip()

    def test_03_list_indexed_documents(self, mcp_module):
        result = mcp_module.list_indexed_documents(limit=10)
        assert "❌" not in result, f"list_indexed_documents failed: {result}"

    def test_04_search_documents(self, mcp_module):
        result = mcp_module.search_documents(
            query="AI-Prowler job tracker", n_results=3)
        assert "❌" not in result, f"search_documents failed: {result}"
        hit = _parse_search_hit(result)
        assert hit is not None, (
            f"Could not parse a [N] filename chunk C/T hit from search "
            f"results — format may have changed: {result[:300]}"
        )
        TestKnowledgeRetrieval.a_real_filename = hit[0]
        TestKnowledgeRetrieval.a_real_chunk_index = hit[1]

    def test_05_search_within_directory(self, mcp_module):
        if not self.a_real_directory:
            pytest.skip("No directory parsed from list_indexed_directories")
        result = mcp_module.search_within_directory(
            query="AI-Prowler", directory=self.a_real_directory, n_results=3)
        assert "❌" not in result, f"search_within_directory failed: {result}"

    def test_06_multi_query_search(self, mcp_module):
        result = mcp_module.multi_query_search(
            queries=["AI-Prowler job tracker", "email invoice"],
            n_results_each=2,
        )
        assert "❌" not in result, f"multi_query_search failed: {result}"

    def test_07_expand_search_result(self, mcp_module):
        assert self.a_real_filename, "test_04 must run first and find a real filename"
        result = mcp_module.expand_search_result(
            filename=self.a_real_filename,
            chunk_index=self.a_real_chunk_index,
            window=1,
        )
        assert "❌" not in result, f"expand_search_result failed: {result}"

    def test_08_read_document(self, mcp_module):
        assert self.a_real_filename, "test_04 must run first and find a real filename"
        result = mcp_module.read_document(
            filename=self.a_real_filename, max_chunks=2)
        assert "❌" not in result, f"read_document failed: {result}"


# ═══════════════════════════════════════════════════════════════════════
# Category 3 — Code-aware retrieval (100% read-only)
# ═══════════════════════════════════════════════════════════════════════
@pytest.mark.mcp_tool_e2e
class TestCodeAwareRetrieval:

    def test_01_grep_documents(self, mcp_module):
        result = mcp_module.grep_documents(
            pattern="def create_job",
            filter_path="ai_prowler_mcp.py",
            max_results=5,
        )
        assert "❌" not in result, f"grep_documents failed: {result}"
        assert "create_job" in result, (
            f"Expected to find 'def create_job' via grep_documents: {result[:300]}"
        )

    def test_02_read_file_lines(self, mcp_module):
        target = INSTALL_DIR / "ai_prowler_mcp.py"
        result = mcp_module.read_file_lines(
            filepath=str(target), start_line=1, end_line=5)
        assert "❌" not in result, f"read_file_lines failed: {result}"
