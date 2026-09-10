"""
tests/e2e/test_agentic_tasks_e2e.py
======================================
Phase 5 of the broader MCP tool E2E suite — the final category.

Covers the Agentic Analysis Tasks family:
  create_analysis_task, list_analysis_tasks, queue_single_task,
  get_pending_analysis_tasks, get_all_queued_tasks, complete_analysis_task,
  update_analysis_task, delete_analysis_task

WHY THIS ORDER OF TESTING (manual walkthrough before writing this file)
--------------------------------------------------------------------------
Before writing any test code, the full create -> queue -> complete ->
delete lifecycle was walked through manually against the real
custom_analysis_tasks.json / pending_tasks.json on this install, to learn
the tools' actual real-world behavior first-hand rather than guess from
docstrings alone:
  - queue_single_task() generates a NEW queue-entry task_id distinct from
    the definition's task_id, formatted as "<definition_id>_<timestamp>"
    — get_pending_analysis_tasks()'s "task_id" field is this queue-entry
    ID, linked back to the definition via its own "source_id" field.
    complete_analysis_task() and the queue-entry variant of
    delete_analysis_task() take the QUEUE-ENTRY id, not the definition id.
  - complete_analysis_task() on a one-shot (schedule="none") task
    correctly and permanently removes it from get_pending_analysis_tasks()
    — confirmed live, matches the docstring's documented "unified re-arm"
    behavior.
  - delete_analysis_task() on a DEFINITION id correctly removes both the
    definition itself AND any of its queue entries, confirmed by watching
    list_analysis_tasks()'s total_count return to the exact pre-test
    baseline (6) after cleanup.

SAFETY MODEL
------------
- Creates exactly ONE real task definition, clearly labeled "ZTEST E2E
  task — safe to ignore", schedule="none" (one-shot — no recurring
  next_due math to reason about, and it self-cleans from the pending
  queue once completed).
- Baseline task count (real, pre-existing tasks — 6 on this install) is
  snapshotted via list_analysis_tasks() before any write, and the test
  asserts the count returns to that exact baseline after
  delete_analysis_task() cleanup — proving no real task was ever
  disturbed.
- Uses the tool's own dedicated delete_analysis_task() for cleanup — the
  correct, purpose-built mechanism for this domain (same pattern as
  delete_learning() in test_learnings_and_retrieval_e2e.py), not a raw
  file restore, since custom_analysis_tasks.json has no simple
  whole-file backup/restore primitive of its own.
- 25-task cap is respected implicitly: this suite only ever adds 1 task
  at a time and deletes it before the next test class would run, so it
  never meaningfully contributes toward the cap even on a repeated run.

REQUIREMENTS
------------
No ANTHROPIC_API_KEY needed.

RUN
---
  run_e2e_mcp_tool.bat -k agentic_tasks
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest

INSTALL_DIR = Path(os.environ.get("AI_PROWLER_SRC",
                                   r"C:\Program Files\AI-Prowler"))

if str(INSTALL_DIR) not in sys.path:
    sys.path.insert(0, str(INSTALL_DIR))


@pytest.fixture(scope="session")
def mcp_module():
    import ai_prowler_mcp as m
    return m


def _current_task_count(mcp_module) -> int:
    data = json.loads(mcp_module.list_analysis_tasks())
    return data["total_count"]


@pytest.mark.mcp_tool_e2e
class TestAgenticAnalysisTasks:

    baseline_count: "int | None" = None
    definition_task_id: "str | None" = None
    queue_entry_task_id: "str | None" = None

    def test_00_snapshot_baseline_count(self, mcp_module):
        TestAgenticAnalysisTasks.baseline_count = _current_task_count(mcp_module)

    def test_01_create_analysis_task(self, mcp_module):
        result = mcp_module.create_analysis_task(
            label="ZTEST E2E task — safe to ignore",
            prompt="This is a synthetic test task created by "
                   "test_agentic_tasks_e2e.py to validate the "
                   "create/queue/complete/delete lifecycle. No real "
                   "analysis needed.",
            schedule="none",
            output_learnings=True,
        )
        assert result.startswith("✅"), f"create_analysis_task failed: {result}"
        m = re.search(r"task_id\s*:\s*(\S+)", result)
        assert m, f"Could not parse task_id from: {result}"
        TestAgenticAnalysisTasks.definition_task_id = m.group(1)

    def test_02_list_analysis_tasks_includes_new_task(self, mcp_module):
        data = json.loads(mcp_module.list_analysis_tasks())
        assert data["total_count"] == self.baseline_count + 1, (
            f"Expected task count to increase by 1 "
            f"({self.baseline_count} -> {self.baseline_count + 1}), "
            f"got {data['total_count']}"
        )
        ids = [t["task_id"] for t in data["tasks"]]
        assert self.definition_task_id in ids, (
            f"New task_id {self.definition_task_id!r} not found in "
            f"list_analysis_tasks() output"
        )

    def test_03_update_analysis_task(self, mcp_module):
        result = mcp_module.update_analysis_task(
            task_id=self.definition_task_id,
            label="ZTEST E2E task — UPDATED — safe to ignore",
        )
        assert result.startswith("✅"), f"update_analysis_task failed: {result}"

        data = json.loads(mcp_module.list_analysis_tasks())
        updated = next(t for t in data["tasks"]
                       if t["task_id"] == self.definition_task_id)
        assert updated["label"] == "ZTEST E2E task — UPDATED — safe to ignore"

    def test_04_queue_single_task(self, mcp_module):
        result = mcp_module.queue_single_task(task_id=self.definition_task_id)
        assert result.startswith("✅"), f"queue_single_task failed: {result}"
        # The queue entry ID is DIFFERENT from the definition ID — it's
        # "<definition_id>_<timestamp>" (confirmed via live manual test).
        m = re.search(r"entry ID:\s*(\S+)\)", result)
        assert m, f"Could not parse queue entry ID from: {result}"
        TestAgenticAnalysisTasks.queue_entry_task_id = m.group(1)
        assert self.queue_entry_task_id.startswith(self.definition_task_id), (
            f"Expected queue entry ID to start with the definition ID: "
            f"{self.queue_entry_task_id!r} vs {self.definition_task_id!r}"
        )

    def test_05_get_all_queued_tasks_includes_entry(self, mcp_module):
        queued = json.loads(mcp_module.get_all_queued_tasks())
        ids = [t["task_id"] for t in queued]
        assert self.queue_entry_task_id in ids, (
            f"Queue entry {self.queue_entry_task_id!r} not found in "
            f"get_all_queued_tasks() output"
        )

    def test_06_get_pending_analysis_tasks_includes_entry(self, mcp_module):
        result = mcp_module.get_pending_analysis_tasks()
        data = json.loads(result)
        ids = [t["task_id"] for t in data["tasks"]]
        assert self.queue_entry_task_id in ids, (
            f"Queue entry {self.queue_entry_task_id!r} not found in "
            f"get_pending_analysis_tasks() output: {result}"
        )
        matched = next(t for t in data["tasks"]
                       if t["task_id"] == self.queue_entry_task_id)
        assert matched["source_id"] == self.definition_task_id, (
            "Queue entry's source_id must link back to the definition"
        )

    def test_07_complete_analysis_task(self, mcp_module):
        result = mcp_module.complete_analysis_task(
            task_id=self.queue_entry_task_id,
            summary="E2E test completed successfully — safe to ignore",
        )
        assert result.startswith("✅"), f"complete_analysis_task failed: {result}"

    def test_08_one_shot_task_no_longer_pending_after_completion(self, mcp_module):
        """schedule='none' tasks complete PERMANENTLY (the 'unified re-arm'
        behavior) — must not reappear in get_pending_analysis_tasks()."""
        result = mcp_module.get_pending_analysis_tasks()
        assert self.queue_entry_task_id not in result, (
            f"REGRESSION: completed one-shot task still appears pending: {result}"
        )

    def test_09_delete_analysis_task_removes_definition(self, mcp_module):
        result = mcp_module.delete_analysis_task(task_id=self.definition_task_id)
        assert result.startswith("✅"), f"delete_analysis_task failed: {result}"

    def test_99_task_count_restored_to_baseline(self, mcp_module):
        final_count = _current_task_count(mcp_module)
        assert final_count == self.baseline_count, (
            f"REGRESSION / CLEANUP FAILURE: expected task count to return "
            f"to baseline ({self.baseline_count}), got {final_count} — "
            f"the ZTEST task may still be present."
        )
        data = json.loads(mcp_module.list_analysis_tasks())
        ids = [t["task_id"] for t in data["tasks"]]
        assert self.definition_task_id not in ids, (
            "Deleted task definition still appears in list_analysis_tasks()"
        )
