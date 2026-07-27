"""
tests/analysis/test_unified_queue_v817.py
============================================
Tests for the v8.1.9 queue-unification work:
  - custom_tasks_manager.is_queue_entry_ready()
  - get_pending_analysis_tasks() due-filtering
  - complete_analysis_task() unified re-arm (built-in == custom)
  - sync_due_tasks_to_queue() (new MCP tool)
  - delete_analysis_task() (new MCP tool)
  - update_analysis_task() (new MCP tool)

Design decision under test (David, 2026-07-24): Common Business Analysis
(built-in) and My Custom AI Analyses (custom) tasks must behave IDENTICALLY
once they're in the run queue — same due-filtering, same re-arm-on-complete
behavior. The only difference is where their definition lives (custom tasks
have a standalone definition in custom_analysis_tasks.json; built-in tasks
carry schedule/next_due directly on their queue entry).
"""

import sys
import datetime
from pathlib import Path
from unittest.mock import patch

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


def _today():
    return datetime.date.today().isoformat()


def _yesterday():
    return (datetime.date.today() - datetime.timedelta(days=1)).isoformat()


def _tomorrow():
    return (datetime.date.today() + datetime.timedelta(days=1)).isoformat()


@pytest.fixture(scope="module")
def ctm():
    import custom_tasks_manager as _ctm
    return _ctm


@pytest.fixture(scope="module")
def mcp():
    import ai_prowler_mcp as _mcp
    return _mcp


# ---------------------------------------------------------------------------
# is_queue_entry_ready()
# ---------------------------------------------------------------------------

class TestIsQueueEntryReady:

    def test_one_shot_entry_always_ready(self, ctm):
        assert ctm.is_queue_entry_ready({"schedule": "none"}) is True

    def test_missing_schedule_field_treated_as_one_shot(self, ctm):
        assert ctm.is_queue_entry_ready({}) is True

    def test_recurring_entry_due_today_is_ready(self, ctm):
        entry = {"schedule": "weekly", "next_due": _today()}
        assert ctm.is_queue_entry_ready(entry) is True

    def test_recurring_entry_overdue_is_ready(self, ctm):
        entry = {"schedule": "weekly", "next_due": _yesterday()}
        assert ctm.is_queue_entry_ready(entry) is True

    def test_recurring_entry_future_is_not_ready(self, ctm):
        entry = {"schedule": "weekly", "next_due": _tomorrow()}
        assert ctm.is_queue_entry_ready(entry) is False

    def test_recurring_entry_missing_next_due_defaults_ready(self, ctm):
        # Defensive: shouldn't get stuck in limbo
        entry = {"schedule": "weekly", "next_due": None}
        assert ctm.is_queue_entry_ready(entry) is True


# ---------------------------------------------------------------------------
# get_pending_analysis_tasks() — due filtering
# ---------------------------------------------------------------------------

class TestGetPendingDueFiltering:

    def _patch_load(self, entries):
        return patch("ai_prowler_mcp._load_pending_tasks",
                     side_effect=lambda: [e.copy() for e in entries])

    def test_future_recurring_entry_excluded(self, mcp):
        entries = [{
            "task_id": "t1", "status": "pending", "label": "Future",
            "schedule": "weekly", "next_due": _tomorrow(),
            "created_at": "2026-07-24T00:00:00Z",
        }]
        with self._patch_load(entries):
            result = mcp.get_pending_analysis_tasks()
        assert "No tasks are due" in result
        assert "1 task(s) are queued but not yet due" in result

    def test_due_recurring_entry_included(self, mcp):
        entries = [{
            "task_id": "t1", "status": "pending", "label": "Due Now",
            "schedule": "weekly", "next_due": _today(),
            "created_at": "2026-07-24T00:00:00Z",
        }]
        with self._patch_load(entries):
            result = mcp.get_pending_analysis_tasks()
        assert "Due Now" in result
        assert '"pending_count": 1' in result

    def test_one_shot_entry_always_included(self, mcp):
        entries = [{
            "task_id": "t1", "status": "pending", "label": "One Shot",
            "schedule": "none",
            "created_at": "2026-07-24T00:00:00Z",
        }]
        with self._patch_load(entries):
            result = mcp.get_pending_analysis_tasks()
        assert "One Shot" in result

    def test_completed_entry_excluded_regardless_of_due(self, mcp):
        entries = [{
            "task_id": "t1", "status": "completed", "label": "Done",
            "schedule": "none",
            "created_at": "2026-07-24T00:00:00Z",
        }]
        with self._patch_load(entries):
            result = mcp.get_pending_analysis_tasks()
        assert "Done" not in result

    def test_truly_empty_queue_gives_original_message(self, mcp):
        with self._patch_load([]):
            result = mcp.get_pending_analysis_tasks()
        assert "AI Analysis buttons" in result
        assert "not yet due" not in result


# ---------------------------------------------------------------------------
# complete_analysis_task() — unified re-arm behavior
# ---------------------------------------------------------------------------

class TestUnifiedReArmBehavior:
    """Built-in and custom recurring entries must behave identically."""

    def _run_complete(self, mcp, entries, task_id, custom_tasks=None):
        saved = {"pending": list(entries), "custom": list(custom_tasks or [])}

        def _load_pending():
            return [e.copy() for e in saved["pending"]]

        def _save_pending(tasks):
            saved["pending"] = tasks

        def _load_custom():
            return [e.copy() for e in saved["custom"]]

        def _save_custom(tasks):
            saved["custom"] = tasks

        with patch("ai_prowler_mcp._load_pending_tasks", side_effect=_load_pending), \
             patch("ai_prowler_mcp._save_pending_tasks", side_effect=_save_pending), \
             patch("custom_tasks_manager.load_custom_tasks", side_effect=_load_custom), \
             patch("custom_tasks_manager.save_custom_tasks", side_effect=_save_custom):
            result = mcp.complete_analysis_task(task_id=task_id, summary="done")
        return result, saved

    def test_builtin_recurring_rearms_to_pending(self, mcp):
        entry = {
            "task_id": "builtin1", "status": "pending", "label": "Weekly Biz",
            "schedule": "weekly", "next_due": _yesterday(),
            "source_id": None,
        }
        _, saved = self._run_complete(mcp, [entry], "builtin1")
        done = saved["pending"][0]
        assert done["status"] == "pending"
        assert done["next_due"] > _today()

    def test_custom_recurring_rearms_to_pending(self, mcp):
        custom_def = {
            "task_id": "custom1", "schedule": "weekly",
            "next_due": _yesterday(), "label": "Weekly Custom",
        }
        entry = {
            "task_id": "entry1", "status": "pending", "label": "Weekly Custom",
            "source_id": "custom1",
        }
        _, saved = self._run_complete(mcp, [entry], "entry1", [custom_def])
        done = saved["pending"][0]
        assert done["status"] == "pending"
        assert done["next_due"] > _today()
        # Source definition also advanced, staying in sync
        assert saved["custom"][0]["next_due"] == done["next_due"]

    def test_builtin_one_shot_completes_permanently(self, mcp):
        entry = {
            "task_id": "b2", "status": "pending", "label": "One-off",
            "schedule": "none", "source_id": None,
        }
        _, saved = self._run_complete(mcp, [entry], "b2")
        assert saved["pending"][0]["status"] == "completed"

    def test_custom_one_shot_completes_permanently(self, mcp):
        custom_def = {"task_id": "c2", "schedule": "none", "label": "Manual"}
        entry = {
            "task_id": "e2", "status": "pending", "label": "Manual",
            "source_id": "c2",
        }
        _, saved = self._run_complete(mcp, [entry], "e2", [custom_def])
        assert saved["pending"][0]["status"] == "completed"

    def test_rearmed_entry_carries_schedule_for_future_self_description(self, mcp):
        # Legacy-style entry with no "schedule" field on the entry itself
        # (pre-v8.1.9 custom-derived entries didn't carry it) — after
        # completion it should be stamped for future self-sufficiency.
        custom_def = {"task_id": "c3", "schedule": "daily", "next_due": _yesterday()}
        entry = {"task_id": "e3", "status": "pending", "source_id": "c3"}
        _, saved = self._run_complete(mcp, [entry], "e3", [custom_def])
        assert saved["pending"][0]["schedule"] == "daily"


# ---------------------------------------------------------------------------
# sync_due_tasks_to_queue()
# ---------------------------------------------------------------------------

class TestSyncDueTasksToQueue:

    def _patch(self, custom_tasks, pending):
        saved = {"custom": list(custom_tasks), "pending": list(pending)}

        def _load_custom():
            return [e.copy() for e in saved["custom"]]

        def _load_pending():
            return [e.copy() for e in saved["pending"]]

        def _save_pending(tasks):
            saved["pending"] = tasks

        ctx = (
            patch("custom_tasks_manager.load_custom_tasks", side_effect=_load_custom),
            patch("ai_prowler_mcp._load_pending_tasks", side_effect=_load_pending),
            patch("ai_prowler_mcp._save_pending_tasks", side_effect=_save_pending),
        )
        return ctx, saved

    def test_due_task_gets_queued(self, mcp):
        custom_tasks = [{
            "task_id": "c1", "label": "Due Task", "prompt": "Analyze.",
            "schedule": "weekly", "next_due": _today(),
            "output_learnings": True, "output_report": False,
            "scope_dirs": [], "report_folder": "C:\\reports",
        }]
        ctx, saved = self._patch(custom_tasks, [])
        with ctx[0], ctx[1], ctx[2]:
            result = mcp.sync_due_tasks_to_queue()
        assert "Queued 1 due task" in result
        assert len(saved["pending"]) == 1
        assert saved["pending"][0]["source_id"] == "c1"

    def test_not_due_task_skipped(self, mcp):
        custom_tasks = [{
            "task_id": "c1", "label": "Future", "prompt": "x",
            "schedule": "weekly", "next_due": _tomorrow(),
        }]
        ctx, saved = self._patch(custom_tasks, [])
        with ctx[0], ctx[1], ctx[2]:
            result = mcp.sync_due_tasks_to_queue()
        assert "No custom task definitions are due" in result
        assert len(saved["pending"]) == 0

    def test_already_queued_due_task_not_duplicated(self, mcp):
        custom_tasks = [{
            "task_id": "c1", "label": "Due Task", "prompt": "x",
            "schedule": "weekly", "next_due": _today(),
        }]
        existing_entry = {
            "task_id": "c1_20260701_000000_000000_0",
            "source_id": "c1", "status": "pending", "label": "Due Task",
        }
        ctx, saved = self._patch(custom_tasks, [existing_entry])
        with ctx[0], ctx[1], ctx[2]:
            result = mcp.sync_due_tasks_to_queue()
        assert "already have a live queue entry" in result
        assert len(saved["pending"]) == 1  # unchanged, not duplicated


# ---------------------------------------------------------------------------
# delete_analysis_task()
# ---------------------------------------------------------------------------

class TestDeleteAnalysisTask:

    def _patch(self, custom_tasks, pending):
        saved = {"custom": list(custom_tasks), "pending": list(pending)}

        def _load_custom():
            return [e.copy() for e in saved["custom"]]

        def _save_custom(tasks):
            saved["custom"] = tasks

        def _load_pending():
            return [e.copy() for e in saved["pending"]]

        def _save_pending(tasks):
            saved["pending"] = tasks

        ctx = (
            patch("custom_tasks_manager.load_custom_tasks", side_effect=_load_custom),
            patch("custom_tasks_manager.save_custom_tasks", side_effect=_save_custom),
            patch("ai_prowler_mcp._load_pending_tasks", side_effect=_load_pending),
            patch("ai_prowler_mcp._save_pending_tasks", side_effect=_save_pending),
        )
        return ctx, saved

    def test_deletes_definition_and_linked_queue_entries(self, mcp):
        custom_tasks = [{"task_id": "c1", "label": "ToDelete"}]
        pending = [
            {"task_id": "e1", "source_id": "c1", "status": "pending"},
            {"task_id": "e2", "source_id": "other", "status": "pending"},
        ]
        ctx, saved = self._patch(custom_tasks, pending)
        with ctx[0], ctx[1], ctx[2], ctx[3]:
            result = mcp.delete_analysis_task("c1")
        assert "Deleted custom task 'ToDelete'" in result
        assert "removed 1 queued instance" in result
        assert saved["custom"] == []
        assert len(saved["pending"]) == 1
        assert saved["pending"][0]["task_id"] == "e2"

    def test_deletes_single_queue_entry_for_builtin(self, mcp):
        pending = [{"task_id": "b1", "label": "Builtin Entry", "status": "pending"}]
        ctx, saved = self._patch([], pending)
        with ctx[0], ctx[1], ctx[2], ctx[3]:
            result = mcp.delete_analysis_task("b1")
        assert "Removed queued task 'Builtin Entry'" in result
        assert saved["pending"] == []

    def test_unknown_id_returns_warning(self, mcp):
        ctx, saved = self._patch([], [])
        with ctx[0], ctx[1], ctx[2], ctx[3]:
            result = mcp.delete_analysis_task("nonexistent")
        assert "didn't match" in result

    def test_empty_task_id_returns_error(self, mcp):
        result = mcp.delete_analysis_task("")
        assert "task_id is required" in result


# ---------------------------------------------------------------------------
# update_analysis_task()
# ---------------------------------------------------------------------------

class TestUpdateAnalysisTask:

    def _patch(self, custom_tasks):
        saved = {"custom": list(custom_tasks)}

        def _load():
            return [e.copy() for e in saved["custom"]]

        def _save(tasks):
            saved["custom"] = tasks

        ctx = (
            patch("custom_tasks_manager.load_custom_tasks", side_effect=_load),
            patch("custom_tasks_manager.save_custom_tasks", side_effect=_save),
        )
        return ctx, saved

    def test_updates_schedule_and_recomputes_next_due(self, mcp):
        custom_tasks = [{
            "task_id": "c1", "label": "T", "schedule": "weekly",
            "first_due": "2026-06-23", "next_due": "2026-08-04",
            "output_learnings": True,
        }]
        ctx, saved = self._patch(custom_tasks)
        with ctx[0], ctx[1]:
            result = mcp.update_analysis_task(
                "c1", schedule="daily", first_due="2026-06-23")
        assert "Updated task" in result
        assert saved["custom"][0]["schedule"] == "daily"
        # v8.1.13: "daily" now produces a datetime next_due (date + the
        # default daily_start_time of "09:00", since none was passed here).
        assert saved["custom"][0]["next_due"] == "2026-06-23T09:00:00"

    def test_updates_daily_time_of_day_params(self, mcp):
        custom_tasks = [{
            "task_id": "c1", "label": "T", "schedule": "daily",
            "first_due": "2026-07-26", "next_due": "2026-07-26T09:00:00",
            "daily_start_time": "09:00", "daily_end_time": "17:00",
            "daily_times_per_day": 1, "output_learnings": True,
        }]
        ctx, saved = self._patch(custom_tasks)
        with ctx[0], ctx[1]:
            result = mcp.update_analysis_task(
                "c1", daily_start_time="08:00", daily_end_time="20:00",
                daily_times_per_day=3)
        assert "Updated task" in result
        assert saved["custom"][0]["daily_start_time"] == "08:00"
        assert saved["custom"][0]["daily_end_time"] == "20:00"
        assert saved["custom"][0]["daily_times_per_day"] == 3
        # Changing daily_* fields resets next_due, same as schedule/first_due.
        assert saved["custom"][0]["next_due"] == "2026-07-26T08:00:00"

    def test_invalid_schedule_rejected(self, mcp):
        ctx, saved = self._patch([{"task_id": "c1", "schedule": "none"}])
        with ctx[0], ctx[1]:
            result = mcp.update_analysis_task("c1", schedule="fortnightly")
        assert "Invalid schedule" in result

    def test_unknown_task_id_returns_warning(self, mcp):
        ctx, saved = self._patch([])
        with ctx[0], ctx[1]:
            result = mcp.update_analysis_task("nope", label="x")
        assert "not found" in result

    def test_no_fields_provided_returns_error(self, mcp):
        result = mcp.update_analysis_task("c1")
        assert "No fields provided" in result

    def test_unrelated_field_edit_does_not_touch_next_due(self, mcp):
        custom_tasks = [{
            "task_id": "c1", "label": "T", "schedule": "weekly",
            "first_due": "2026-06-23", "next_due": "2026-08-04",
        }]
        ctx, saved = self._patch(custom_tasks)
        with ctx[0], ctx[1]:
            mcp.update_analysis_task("c1", output_report=True)
        assert saved["custom"][0]["next_due"] == "2026-08-04"
        assert saved["custom"][0]["output_report"] is True


# ---------------------------------------------------------------------------
# Tier A suppression — the 3 new tools must be personal-install-only,
# matching every other analysis-queue tool (get_pending_analysis_tasks,
# complete_analysis_task, save_analysis_report, create_analysis_task,
# list_analysis_tasks). There is no server-mode caller for any of them.
# ---------------------------------------------------------------------------

class TestTierASuppression:

    def test_sync_due_tasks_to_queue_is_tier_a_suppressed(self, mcp):
        assert "sync_due_tasks_to_queue" in mcp._TIER_A_SUPPRESSED

    def test_delete_analysis_task_is_tier_a_suppressed(self, mcp):
        assert "delete_analysis_task" in mcp._TIER_A_SUPPRESSED

    def test_update_analysis_task_is_tier_a_suppressed(self, mcp):
        assert "update_analysis_task" in mcp._TIER_A_SUPPRESSED

    def test_grouped_with_all_analysis_queue_siblings(self, mcp):
        family = {
            "get_pending_analysis_tasks", "complete_analysis_task",
            "save_analysis_report", "create_analysis_task",
            "list_analysis_tasks", "sync_due_tasks_to_queue",
            "delete_analysis_task", "update_analysis_task",
        }
        assert family.issubset(mcp._TIER_A_SUPPRESSED)
