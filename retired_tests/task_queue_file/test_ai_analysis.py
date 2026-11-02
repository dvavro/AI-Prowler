"""
tests/subscription/test_ai_analysis.py
=======================================
Phase 8 test suite — AI Analysis Queue feature (v8.0.0).

Tests the get_pending_analysis_tasks and complete_analysis_task MCP tools,
and the pending_tasks.json queue mechanism used by the Quick Links buttons.

All tests are fully mocked — no live Claude or MCP server needed.

Run:
    run_tests.bat tests\subscription\test_ai_analysis.py -v
"""

import json
import pytest
from unittest.mock import patch
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_task(task_type="analyze_business", status="pending", ts="20260623_143022"):
    return {
        "task_id":    f"{task_type}_{ts}",
        "type":       task_type,
        "label":      f"Test {task_type.replace('_', ' ').title()}",
        "prompt":     f"Analyze {task_type} data and record findings as learnings.",
        "created_at": "2026-06-23T14:30:22Z",
        "status":     status,
    }


def _write_tasks(tasks_path, tasks):
    tasks_path.parent.mkdir(parents=True, exist_ok=True)
    tasks_path.write_text(
        json.dumps(tasks, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# TC-ANALYSIS-001  get_pending_analysis_tasks
# ---------------------------------------------------------------------------

class TestGetPendingAnalysisTasks:

    def test_TC_ANALYSIS_001_returns_pending_tasks(self, tmp_path):
        """get_pending_analysis_tasks returns pending tasks from the queue file."""
        tasks_path = tmp_path / ".ai-prowler" / "pending_tasks.json"
        _write_tasks(tasks_path, [
            _make_task("analyze_business", "pending"),
            _make_task("find_problems", "pending", "20260623_150000"),
        ])
        import ai_prowler_mcp as mcp
        with patch("ai_prowler_mcp._PENDING_TASKS_FILE", tasks_path):
            result = mcp.get_pending_analysis_tasks()
        data = json.loads(result)
        assert data["pending_count"] == 2
        assert len(data["tasks"]) == 2
        assert "instruction" in data

    def test_TC_ANALYSIS_001_filters_out_completed(self, tmp_path):
        """get_pending_analysis_tasks filters out completed tasks."""
        tasks_path = tmp_path / ".ai-prowler" / "pending_tasks.json"
        _write_tasks(tasks_path, [
            _make_task("analyze_business", "pending"),
            _make_task("weekly_advisor", "completed", "20260623_120000"),
        ])
        import ai_prowler_mcp as mcp
        with patch("ai_prowler_mcp._PENDING_TASKS_FILE", tasks_path):
            result = mcp.get_pending_analysis_tasks()
        data = json.loads(result)
        assert data["pending_count"] == 1
        assert data["tasks"][0]["type"] == "analyze_business"

    def test_TC_ANALYSIS_001_empty_queue_returns_message(self, tmp_path):
        """get_pending_analysis_tasks returns plain message when queue is empty."""
        tasks_path = tmp_path / ".ai-prowler" / "pending_tasks.json"
        _write_tasks(tasks_path, [])
        import ai_prowler_mcp as mcp
        with patch("ai_prowler_mcp._PENDING_TASKS_FILE", tasks_path):
            result = mcp.get_pending_analysis_tasks()
        assert "no pending" in result.lower()

    def test_TC_ANALYSIS_001_missing_file_returns_message(self, tmp_path):
        """get_pending_analysis_tasks handles missing file gracefully."""
        tasks_path = tmp_path / ".ai-prowler" / "pending_tasks.json"
        import ai_prowler_mcp as mcp
        with patch("ai_prowler_mcp._PENDING_TASKS_FILE", tasks_path):
            result = mcp.get_pending_analysis_tasks()
        assert "no pending" in result.lower()

    def test_TC_ANALYSIS_001_task_has_required_fields(self, tmp_path):
        """Each pending task has all required fields."""
        tasks_path = tmp_path / ".ai-prowler" / "pending_tasks.json"
        _write_tasks(tasks_path, [_make_task("analyze_business", "pending")])
        import ai_prowler_mcp as mcp
        with patch("ai_prowler_mcp._PENDING_TASKS_FILE", tasks_path):
            result = mcp.get_pending_analysis_tasks()
        task = json.loads(result)["tasks"][0]
        for field in ["task_id", "type", "label", "prompt", "created_at"]:
            assert field in task, f"Missing: {field}"

    def test_TC_ANALYSIS_001_prompt_is_non_empty(self, tmp_path):
        """Each pending task has a non-empty prompt field."""
        tasks_path = tmp_path / ".ai-prowler" / "pending_tasks.json"
        tasks = [_make_task(t, "pending", f"2026062{i}_143022")
                 for i, t in enumerate([
                     "run_pending", "analyze_business", "weekly_advisor",
                     "find_problems", "growth_opportunities"
                 ])]
        _write_tasks(tasks_path, tasks)
        import ai_prowler_mcp as mcp
        with patch("ai_prowler_mcp._PENDING_TASKS_FILE", tasks_path):
            result = mcp.get_pending_analysis_tasks()
        for task in json.loads(result)["tasks"]:
            assert len(task["prompt"].strip()) > 20, \
                f"Prompt too short for {task['type']}"


# ---------------------------------------------------------------------------
# TC-ANALYSIS-002  complete_analysis_task
# ---------------------------------------------------------------------------

class TestCompleteAnalysisTask:

    def test_TC_ANALYSIS_002_marks_task_completed(self, tmp_path):
        """complete_analysis_task sets status=completed on the matching task."""
        tasks_path = tmp_path / ".ai-prowler" / "pending_tasks.json"
        task = _make_task("analyze_business", "pending")
        _write_tasks(tasks_path, [task])
        import ai_prowler_mcp as mcp
        with patch("ai_prowler_mcp._PENDING_TASKS_FILE", tasks_path):
            result = mcp.complete_analysis_task(
                task_id=task["task_id"],
                summary="Found 3 overdue invoices.")
        assert "✅" in result
        saved = json.loads(tasks_path.read_text())
        assert saved[0]["status"] == "completed"
        assert "completed_at" in saved[0]
        assert saved[0]["completion_summary"] == "Found 3 overdue invoices."

    def test_TC_ANALYSIS_002_summary_optional(self, tmp_path):
        """complete_analysis_task works without a summary."""
        tasks_path = tmp_path / ".ai-prowler" / "pending_tasks.json"
        task = _make_task("weekly_advisor", "pending")
        _write_tasks(tasks_path, [task])
        import ai_prowler_mcp as mcp
        with patch("ai_prowler_mcp._PENDING_TASKS_FILE", tasks_path):
            result = mcp.complete_analysis_task(task_id=task["task_id"])
        assert "✅" in result
        saved = json.loads(tasks_path.read_text())
        assert saved[0]["status"] == "completed"
        assert "completion_summary" not in saved[0]

    def test_TC_ANALYSIS_002_only_matching_task_updated(self, tmp_path):
        """complete_analysis_task only updates the matching task."""
        tasks_path = tmp_path / ".ai-prowler" / "pending_tasks.json"
        tasks = [
            _make_task("analyze_business", "pending", "20260623_100000"),
            _make_task("find_problems",    "pending", "20260623_110000"),
            _make_task("weekly_advisor",   "pending", "20260623_120000"),
        ]
        _write_tasks(tasks_path, tasks)
        import ai_prowler_mcp as mcp
        with patch("ai_prowler_mcp._PENDING_TASKS_FILE", tasks_path):
            mcp.complete_analysis_task(task_id=tasks[1]["task_id"],
                                       summary="Done.")
        saved = json.loads(tasks_path.read_text())
        assert saved[0]["status"] == "pending"
        assert saved[1]["status"] == "completed"
        assert saved[2]["status"] == "pending"

    def test_TC_ANALYSIS_002_unknown_id_returns_warning(self, tmp_path):
        """complete_analysis_task returns warning for unknown task_id."""
        tasks_path = tmp_path / ".ai-prowler" / "pending_tasks.json"
        _write_tasks(tasks_path, [_make_task("analyze_business", "pending")])
        import ai_prowler_mcp as mcp
        with patch("ai_prowler_mcp._PENDING_TASKS_FILE", tasks_path):
            result = mcp.complete_analysis_task(task_id="nonexistent_id")
        assert "⚠" in result or "not found" in result.lower()

    def test_TC_ANALYSIS_002_empty_task_id_returns_error(self):
        """complete_analysis_task rejects empty task_id."""
        import ai_prowler_mcp as mcp
        result = mcp.complete_analysis_task(task_id="")
        assert "❌" in result
        assert "required" in result.lower()

    def test_TC_ANALYSIS_002_whitespace_task_id_returns_error(self):
        """complete_analysis_task rejects whitespace-only task_id."""
        import ai_prowler_mcp as mcp
        result = mcp.complete_analysis_task(task_id="   ")
        assert "❌" in result


# ---------------------------------------------------------------------------
# TC-ANALYSIS-003  Queue persistence
# ---------------------------------------------------------------------------

class TestQueuePersistence:

    def test_TC_ANALYSIS_003_completed_tasks_remain_in_file(self, tmp_path):
        """Completed tasks remain in the file for audit purposes."""
        tasks_path = tmp_path / ".ai-prowler" / "pending_tasks.json"
        task = _make_task("analyze_business", "pending")
        _write_tasks(tasks_path, [task])
        import ai_prowler_mcp as mcp
        with patch("ai_prowler_mcp._PENDING_TASKS_FILE", tasks_path):
            mcp.complete_analysis_task(task_id=task["task_id"],
                                       summary="Done.")
        saved = json.loads(tasks_path.read_text())
        assert len(saved) == 1, "Completed task should stay in file"
        assert saved[0]["status"] == "completed"

    def test_TC_ANALYSIS_003_get_after_complete_shows_remaining(self, tmp_path):
        """After completing one task, get_pending shows only remaining pending."""
        tasks_path = tmp_path / ".ai-prowler" / "pending_tasks.json"
        tasks = [
            _make_task("analyze_business", "pending", "20260623_100000"),
            _make_task("find_problems",    "pending", "20260623_110000"),
        ]
        _write_tasks(tasks_path, tasks)
        import ai_prowler_mcp as mcp
        with patch("ai_prowler_mcp._PENDING_TASKS_FILE", tasks_path):
            mcp.complete_analysis_task(task_id=tasks[0]["task_id"],
                                       summary="Done.")
            result = mcp.get_pending_analysis_tasks()
        data = json.loads(result)
        assert data["pending_count"] == 1
        assert data["tasks"][0]["type"] == "find_problems"


# ---------------------------------------------------------------------------
# TC-ANALYSIS-004  Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:

    def test_TC_ANALYSIS_004_corrupt_json_handled(self, tmp_path):
        """get_pending_analysis_tasks handles corrupt JSON without crashing."""
        tasks_path = tmp_path / ".ai-prowler" / "pending_tasks.json"
        tasks_path.parent.mkdir(parents=True, exist_ok=True)
        tasks_path.write_text("{ not valid json }", encoding="utf-8")
        import ai_prowler_mcp as mcp
        with patch("ai_prowler_mcp._PENDING_TASKS_FILE", tasks_path):
            result = mcp.get_pending_analysis_tasks()
        assert isinstance(result, str)

    def test_TC_ANALYSIS_004_non_list_json_handled(self, tmp_path):
        """get_pending_analysis_tasks handles non-list JSON without crashing."""
        tasks_path = tmp_path / ".ai-prowler" / "pending_tasks.json"
        tasks_path.parent.mkdir(parents=True, exist_ok=True)
        tasks_path.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
        import ai_prowler_mcp as mcp
        with patch("ai_prowler_mcp._PENDING_TASKS_FILE", tasks_path):
            result = mcp.get_pending_analysis_tasks()
        assert isinstance(result, str)

    def test_TC_ANALYSIS_004_complete_with_missing_file_returns_warning(self, tmp_path):
        """complete_analysis_task returns warning when file doesn't exist."""
        tasks_path = tmp_path / ".ai-prowler" / "pending_tasks.json"
        import ai_prowler_mcp as mcp
        with patch("ai_prowler_mcp._PENDING_TASKS_FILE", tasks_path):
            result = mcp.complete_analysis_task(task_id="any_id")
        assert isinstance(result, str)
        assert "⚠" in result or "not found" in result.lower()


# ---------------------------------------------------------------------------
# TC-ANALYSIS-005  All 5 task types round-trip
# ---------------------------------------------------------------------------

class TestTaskTypes:

    @pytest.mark.parametrize("task_type", [
        "run_pending",
        "analyze_business",
        "weekly_advisor",
        "find_problems",
        "growth_opportunities",
    ])
    def test_TC_ANALYSIS_005_all_types_round_trip(self, task_type, tmp_path):
        """Each of the 5 task types can be queued and completed successfully."""
        tasks_path = tmp_path / ".ai-prowler" / "pending_tasks.json"
        task = _make_task(task_type, "pending")
        _write_tasks(tasks_path, [task])
        import ai_prowler_mcp as mcp
        with patch("ai_prowler_mcp._PENDING_TASKS_FILE", tasks_path):
            get_result = mcp.get_pending_analysis_tasks()
            data = json.loads(get_result)
            assert data["pending_count"] == 1
            assert data["tasks"][0]["type"] == task_type

            complete_result = mcp.complete_analysis_task(
                task_id=task["task_id"],
                summary=f"Completed {task_type}.")
            assert "✅" in complete_result

            final = mcp.get_pending_analysis_tasks()
            assert "no pending" in final.lower()

    def test_TC_ANALYSIS_005_task_id_format(self):
        """Task IDs follow {type}_{YYYYMMDD_HHMMSS} format."""
        task = _make_task("analyze_business", "pending", "20260623_143022")
        assert task["task_id"] == "analyze_business_20260623_143022"

    def test_TC_ANALYSIS_005_unique_ids_same_type(self):
        """Two tasks of the same type at different times have unique IDs."""
        task1 = _make_task("analyze_business", "pending", "20260623_143022")
        task2 = _make_task("analyze_business", "pending", "20260623_143023")
        assert task1["task_id"] != task2["task_id"]
