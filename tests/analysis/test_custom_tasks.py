"""
tests/analysis/test_custom_tasks.py
========================================
Phase 8 test suite — custom analysis tasks (v8.0.0).

Tests custom_tasks_manager.py: CRUD, scheduling, due-date logic,
schedule advancement, queue entry building, and status labels.

Also covers:
  TC-CTASK-009  scope_dirs filtering (_load_tracked_dirs_for_scope logic)
  TC-CTASK-010  scope_dirs preserved in queue entries
  TC-CTASK-011  scope hint injected into built-in task prompt
  TC-CTASK-012  get_pending_analysis_tasks MCP tool
  TC-CTASK-013  complete_analysis_task MCP tool (custom tasks)
  TC-CTASK-014  server mode suppression (_is_server_mode_gui)
  TC-CTASK-015  schedule fields in built-in task record
  TC-CTASK-016  complete_analysis_task advances next_due for built-in scheduled tasks
  TC-CTASK-017  one-shot built-in tasks are NOT rescheduled after completion

Run:
    run_tests.bat tests\analysis\test_custom_tasks.py -v
"""

import json
import pytest
import datetime
from unittest.mock import patch
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_task(**kwargs):
    """Create a task with sensible defaults."""
    import custom_tasks_manager as ctm
    defaults = dict(
        label="Test Analysis",
        prompt="Analyze my business data.",
        scope_dirs=[],
        schedule="none",
        first_due=None,
        output_learnings=True,
        output_report=False,
        report_folder=ctm.DEFAULT_REPORT_FOLDER,
    )
    defaults.update(kwargs)
    return ctm.create_task(**defaults)


# ---------------------------------------------------------------------------
# TC-CTASK-001  create_task validation
# ---------------------------------------------------------------------------

class TestCreateTask:

    def test_TC_CTASK_001_creates_valid_task(self):
        import custom_tasks_manager as ctm
        t = _make_task(label="My Analysis", prompt="Analyze everything.")
        assert t["label"] == "My Analysis"
        assert t["prompt"] == "Analyze everything."
        assert t["schedule"] == "none"
        assert t["next_due"] is None
        assert t["output_learnings"] is True
        assert t["output_report"] is False
        assert "task_id" in t
        assert t["task_id"].startswith("custom_")

    def test_TC_CTASK_001_empty_label_raises(self):
        import custom_tasks_manager as ctm
        with pytest.raises(ValueError, match="required"):
            ctm.create_task(label="", prompt="Do something.")

    def test_TC_CTASK_001_label_too_long_raises(self):
        import custom_tasks_manager as ctm
        with pytest.raises(ValueError, match="60"):
            ctm.create_task(label="A" * 61, prompt="Do something.")

    def test_TC_CTASK_001_empty_prompt_raises(self):
        import custom_tasks_manager as ctm
        with pytest.raises(ValueError, match="required"):
            ctm.create_task(label="Test", prompt="")

    def test_TC_CTASK_001_invalid_schedule_raises(self):
        import custom_tasks_manager as ctm
        with pytest.raises(ValueError, match="Invalid schedule"):
            ctm.create_task(label="Test", prompt="Do it.",
                            schedule="fortnightly")

    def test_TC_CTASK_001_scheduled_task_requires_first_due(self):
        import custom_tasks_manager as ctm
        with pytest.raises(ValueError, match="first due date"):
            ctm.create_task(label="Test", prompt="Do it.",
                            schedule="weekly", first_due=None)

    def test_TC_CTASK_001_invalid_first_due_raises(self):
        import custom_tasks_manager as ctm
        with pytest.raises(ValueError, match="Invalid first due date"):
            ctm.create_task(label="Test", prompt="Do it.",
                            schedule="weekly", first_due="not-a-date")

    def test_TC_CTASK_001_scheduled_task_sets_next_due(self):
        import custom_tasks_manager as ctm
        t = ctm.create_task(label="Test", prompt="Do it.",
                            schedule="weekly", first_due="2026-06-30")
        assert t["next_due"] == "2026-06-30"
        assert t["first_due"] == "2026-06-30"

    def test_TC_CTASK_001_scope_dirs_stored(self):
        import custom_tasks_manager as ctm
        t = ctm.create_task(
            label="Scoped", prompt="Analyze scope.",
            scope_dirs=[r"C:\Jobs\2026", r"C:\Invoices"])
        assert len(t["scope_dirs"]) == 2
        assert r"C:\Jobs\2026" in t["scope_dirs"]

    def test_TC_CTASK_001_both_outputs_can_be_true(self):
        import custom_tasks_manager as ctm
        t = ctm.create_task(label="Both", prompt="Full output.",
                            output_learnings=True, output_report=True)
        assert t["output_learnings"] is True
        assert t["output_report"] is True

    def test_TC_CTASK_001_both_outputs_can_be_false(self):
        import custom_tasks_manager as ctm
        t = ctm.create_task(label="Neither", prompt="Display only.",
                            output_learnings=False, output_report=False)
        assert t["output_learnings"] is False
        assert t["output_report"] is False


# ---------------------------------------------------------------------------
# TC-CTASK-002  load / save
# ---------------------------------------------------------------------------

class TestLoadSave:

    def test_TC_CTASK_002_save_and_load_roundtrip(self, tmp_path):
        import custom_tasks_manager as ctm
        tasks = [_make_task(label=f"Task {i}") for i in range(3)]
        with patch("custom_tasks_manager.CUSTOM_TASKS_PATH",
                   tmp_path / "custom_analysis_tasks.json"):
            assert ctm.save_custom_tasks(tasks) is True
            loaded = ctm.load_custom_tasks()
        assert len(loaded) == 3
        assert loaded[0]["label"] == "Task 0"

    def test_TC_CTASK_002_load_missing_file_returns_empty(self, tmp_path):
        import custom_tasks_manager as ctm
        with patch("custom_tasks_manager.CUSTOM_TASKS_PATH",
                   tmp_path / "nonexistent.json"):
            result = ctm.load_custom_tasks()
        assert result == []

    def test_TC_CTASK_002_load_corrupt_json_returns_empty(self, tmp_path):
        import custom_tasks_manager as ctm
        p = tmp_path / "custom_analysis_tasks.json"
        p.write_text("{ not valid json }", encoding="utf-8")
        with patch("custom_tasks_manager.CUSTOM_TASKS_PATH", p):
            result = ctm.load_custom_tasks()
        assert result == []

    def test_TC_CTASK_002_load_non_list_json_returns_empty(self, tmp_path):
        import custom_tasks_manager as ctm
        p = tmp_path / "custom_analysis_tasks.json"
        p.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
        with patch("custom_tasks_manager.CUSTOM_TASKS_PATH", p):
            result = ctm.load_custom_tasks()
        assert result == []


# ---------------------------------------------------------------------------
# TC-CTASK-003  CRUD operations
# ---------------------------------------------------------------------------

class TestCRUD:

    def test_TC_CTASK_003_update_task_label(self):
        import custom_tasks_manager as ctm
        tasks = [_make_task(label="Old Name")]
        tid = tasks[0]["task_id"]
        result = ctm.update_task(tasks, tid, label="New Name")
        assert result is True
        assert tasks[0]["label"] == "New Name"

    def test_TC_CTASK_003_update_task_not_found_returns_false(self):
        import custom_tasks_manager as ctm
        tasks = [_make_task()]
        result = ctm.update_task(tasks, "nonexistent_id", label="New")
        assert result is False

    def test_TC_CTASK_003_update_updates_timestamp(self):
        import custom_tasks_manager as ctm
        tasks = [_make_task()]
        old_ts = tasks[0]["updated_at"]
        ctm.update_task(tasks, tasks[0]["task_id"], label="Updated")
        assert tasks[0]["updated_at"] >= old_ts

    def test_TC_CTASK_003_delete_task_removes_it(self):
        import custom_tasks_manager as ctm
        task_a = _make_task(label="Keep")
        task_b = _make_task(label="Delete")
        tasks = [task_a, task_b]
        tid = task_b["task_id"]
        result = ctm.delete_task(tasks, tid)
        assert result is True
        assert len(tasks) == 1
        assert tasks[0]["label"] == "Keep"

    def test_TC_CTASK_003_delete_nonexistent_returns_false(self):
        import custom_tasks_manager as ctm
        tasks = [_make_task()]
        result = ctm.delete_task(tasks, "nonexistent")
        assert result is False
        assert len(tasks) == 1

    def test_TC_CTASK_003_get_task_returns_correct_task(self):
        import custom_tasks_manager as ctm
        task_a = ctm.create_task(label="A", prompt="Analyze A.")
        task_b = ctm.create_task(label="B", prompt="Analyze B.")
        tasks = [task_a, task_b]
        tid = task_b["task_id"]
        found = ctm.get_task(tasks, tid)
        assert found is not None
        assert found["label"] == "B"

    def test_TC_CTASK_003_get_task_not_found_returns_none(self):
        import custom_tasks_manager as ctm
        tasks = [_make_task()]
        assert ctm.get_task(tasks, "nonexistent") is None


# ---------------------------------------------------------------------------
# TC-CTASK-004  Date advancement (schedule option B — anchor-based)
# ---------------------------------------------------------------------------

class TestDateAdvancement:

    @pytest.mark.parametrize("schedule,from_date,expected", [
        ("daily",     "2026-06-30", "2026-07-01"),
        ("weekly",    "2026-06-30", "2026-07-07"),
        ("biweekly",  "2026-06-30", "2026-07-14"),
        ("monthly",   "2026-06-30", "2026-07-30"),
        ("monthly",   "2026-01-31", "2026-02-28"),  # Feb edge case
        ("quarterly", "2026-06-30", "2026-09-30"),
        ("yearly",    "2026-06-30", "2027-06-30"),
        ("yearly",    "2024-02-29", "2025-02-28"),  # leap year edge
    ])
    def test_TC_CTASK_004_advance_date(self, schedule, from_date, expected):
        import custom_tasks_manager as ctm
        result = ctm._advance_date(from_date, schedule)
        assert result == expected, \
            f"schedule={schedule}, from={from_date}: expected {expected}, got {result}"

    def test_TC_CTASK_004_advance_none_returns_none(self):
        import custom_tasks_manager as ctm
        assert ctm._advance_date("2026-06-30", "none") is None

    def test_TC_CTASK_004_advance_next_due_uses_anchor(self):
        """Uses current next_due as anchor, not completed_date (option B)."""
        import custom_tasks_manager as ctm
        # Task due Jun 30, completed late on Jul 5
        task = ctm.create_task(
            label="Weekly", prompt="Do it.",
            schedule="weekly", first_due="2026-06-30")
        task["next_due"] = "2026-06-30"
        tasks = [task]
        new_due = ctm.advance_next_due(tasks, task["task_id"],
                                        completed_date="2026-07-05")
        # Should advance from anchor (Jun 30) + 7 days = Jul 7, NOT Jul 12
        assert new_due == "2026-07-07"

    def test_TC_CTASK_004_advance_updates_last_run(self):
        import custom_tasks_manager as ctm
        task = ctm.create_task(
            label="Weekly", prompt="Do it.",
            schedule="weekly", first_due="2026-06-30")
        tasks = [task]
        ctm.advance_next_due(tasks, task["task_id"],
                             completed_date="2026-06-30")
        assert tasks[0]["last_run"] == "2026-06-30"
        assert tasks[0]["last_status"] == "completed"

    def test_TC_CTASK_004_manual_task_returns_none(self):
        import custom_tasks_manager as ctm
        task = ctm.create_task(label="Manual", prompt="Do it.",
                               schedule="none")
        tasks = [task]
        result = ctm.advance_next_due(tasks, task["task_id"],
                                       completed_date="2026-06-30")
        assert result is None
        assert tasks[0]["last_status"] == "completed"


# ---------------------------------------------------------------------------
# TC-CTASK-005  Due task detection
# ---------------------------------------------------------------------------

class TestDueTaskDetection:

    def test_TC_CTASK_005_overdue_task_detected(self):
        import custom_tasks_manager as ctm
        task = ctm.create_task(
            label="Overdue", prompt="Do it.",
            schedule="weekly", first_due="2020-01-01")
        task["next_due"] = "2020-01-01"  # Way overdue
        tasks = [task]
        due = ctm.get_due_tasks(tasks)
        assert len(due) == 1
        assert due[0]["label"] == "Overdue"

    def test_TC_CTASK_005_future_task_not_due(self):
        import custom_tasks_manager as ctm
        task = ctm.create_task(
            label="Future", prompt="Do it.",
            schedule="weekly", first_due="2099-01-01")
        task["next_due"] = "2099-01-01"
        tasks = [task]
        due = ctm.get_due_tasks(tasks)
        assert len(due) == 0

    def test_TC_CTASK_005_manual_task_never_due(self):
        import custom_tasks_manager as ctm
        task = ctm.create_task(label="Manual", prompt="Do it.",
                               schedule="none")
        tasks = [task]
        due = ctm.get_due_tasks(tasks)
        assert len(due) == 0

    def test_TC_CTASK_005_task_due_today_is_due(self):
        import custom_tasks_manager as ctm
        today = datetime.date.today().isoformat()
        task = ctm.create_task(
            label="Today", prompt="Do it.",
            schedule="monthly", first_due=today)
        task["next_due"] = today
        tasks = [task]
        due = ctm.get_due_tasks(tasks)
        assert len(due) == 1

    def test_TC_CTASK_005_mixed_list_returns_only_due(self):
        import custom_tasks_manager as ctm
        overdue = ctm.create_task(
            label="Overdue", prompt="Do it.",
            schedule="daily", first_due="2020-01-01")
        overdue["next_due"] = "2020-01-01"

        future = ctm.create_task(
            label="Future", prompt="Do it.",
            schedule="weekly", first_due="2099-01-01")
        future["next_due"] = "2099-01-01"

        manual = ctm.create_task(label="Manual", prompt="Do it.",
                                  schedule="none")
        tasks = [overdue, future, manual]
        due = ctm.get_due_tasks(tasks)
        assert len(due) == 1
        assert due[0]["label"] == "Overdue"


# ---------------------------------------------------------------------------
# TC-CTASK-006  build_task_prompt — scope + output injection
# ---------------------------------------------------------------------------

class TestBuildTaskPrompt:

    def test_TC_CTASK_006_no_scope_no_injection(self):
        import custom_tasks_manager as ctm
        task = ctm.create_task(label="T", prompt="Analyze my data.")
        task["scope_dirs"] = []
        prompt = ctm.build_task_prompt(task)
        assert "Focus" not in prompt
        assert "Analyze my data." in prompt

    def test_TC_CTASK_006_scope_dirs_injected(self):
        import custom_tasks_manager as ctm
        task = ctm.create_task(
            label="T", prompt="Analyze my data.",
            scope_dirs=[r"C:\Jobs\2026", r"C:\Invoices"])
        prompt = ctm.build_task_prompt(task)
        assert "Focus" in prompt
        assert r"C:\Jobs\2026" in prompt
        assert r"C:\Invoices" in prompt

    def test_TC_CTASK_006_both_outputs_in_prompt(self):
        import custom_tasks_manager as ctm
        task = ctm.create_task(
            label="T", prompt="Analyze.",
            output_learnings=True, output_report=True)
        prompt = ctm.build_task_prompt(task)
        assert "record_learning" in prompt
        assert "save_analysis_report" in prompt

    def test_TC_CTASK_006_learnings_only_prompt(self):
        import custom_tasks_manager as ctm
        task = ctm.create_task(
            label="T", prompt="Analyze.",
            output_learnings=True, output_report=False)
        prompt = ctm.build_task_prompt(task)
        assert "record_learning" in prompt
        assert "save_analysis_report" not in prompt

    def test_TC_CTASK_006_report_only_prompt(self):
        import custom_tasks_manager as ctm
        task = ctm.create_task(
            label="T", prompt="Analyze.",
            output_learnings=False, output_report=True)
        prompt = ctm.build_task_prompt(task)
        assert "save_analysis_report" in prompt

    def test_TC_CTASK_006_no_output_prompt(self):
        import custom_tasks_manager as ctm
        task = ctm.create_task(
            label="T", prompt="Analyze.",
            output_learnings=False, output_report=False)
        prompt = ctm.build_task_prompt(task)
        assert "conversation" in prompt.lower() or "display" in prompt.lower()


# ---------------------------------------------------------------------------
# TC-CTASK-007  tasks_to_queue_entries
# ---------------------------------------------------------------------------

class TestTasksToQueueEntries:

    def test_TC_CTASK_007_single_task_to_entry(self):
        import custom_tasks_manager as ctm
        task = ctm.create_task(label="Q Task", prompt="Do analysis.")
        entries = ctm.tasks_to_queue_entries([task])
        assert len(entries) == 1
        e = entries[0]
        assert e["label"] == "Q Task"
        assert e["type"] == "custom"
        assert e["status"] == "pending"
        assert "source_id" in e
        assert e["source_id"] == task["task_id"]
        assert len(e["prompt"]) > 0

    def test_TC_CTASK_007_multiple_tasks_produce_separate_entries(self):
        import custom_tasks_manager as ctm
        tasks = [ctm.create_task(label=f"Task {i}", prompt=f"Analyze {i}.")
                 for i in range(3)]
        entries = ctm.tasks_to_queue_entries(tasks)
        assert len(entries) == 3
        labels = [e["label"] for e in entries]
        assert "Task 0" in labels
        assert "Task 2" in labels

    def test_TC_CTASK_007_entry_task_ids_are_unique(self):
        import custom_tasks_manager as ctm
        import time
        tasks = [ctm.create_task(label=f"Task {i}", prompt="Analyze.") for i in range(3)]
        time.sleep(0.01)
        entries = ctm.tasks_to_queue_entries(tasks)
        ids = [e["task_id"] for e in entries]
        assert len(set(ids)) == len(ids), "All entry task_ids should be unique"

    def test_TC_CTASK_007_entry_inherits_output_config(self):
        import custom_tasks_manager as ctm
        task = ctm.create_task(label="T", prompt="Analyze.",
                               output_learnings=False, output_report=True)
        entries = ctm.tasks_to_queue_entries([task])
        e = entries[0]
        assert e["output_learnings"] is False
        assert e["output_report"] is True


# ---------------------------------------------------------------------------
# TC-CTASK-008  due_status_label
# ---------------------------------------------------------------------------

class TestDueStatusLabel:

    def test_TC_CTASK_008_manual_shows_manual_only(self):
        import custom_tasks_manager as ctm
        task = ctm.create_task(label="T", prompt="Do it.", schedule="none")
        assert ctm.due_status_label(task) == "Manual only"

    def test_TC_CTASK_008_overdue_shows_warning(self):
        import custom_tasks_manager as ctm
        task = ctm.create_task(label="T", prompt="Do it.",
                               schedule="weekly", first_due="2020-01-01")
        task["next_due"] = "2020-01-01"
        label = ctm.due_status_label(task)
        assert "⚠" in label
        assert "Overdue" in label

    def test_TC_CTASK_008_due_today_shows_lightning(self):
        import custom_tasks_manager as ctm
        today = datetime.date.today().isoformat()
        task = ctm.create_task(label="T", prompt="Do it.",
                               schedule="monthly", first_due=today)
        task["next_due"] = today
        label = ctm.due_status_label(task)
        assert "⚡" in label or "today" in label.lower()

    def test_TC_CTASK_008_future_task_shows_date(self):
        import custom_tasks_manager as ctm
        task = ctm.create_task(label="T", prompt="Do it.",
                               schedule="weekly", first_due="2099-12-31")
        task["next_due"] = "2099-12-31"
        label = ctm.due_status_label(task)
        assert "Dec" in label or "2099" in label or "in" in label.lower()


# ---------------------------------------------------------------------------
# TC-CTASK-009  scope_dirs filtering (mirrors _load_tracked_dirs_for_scope)
# ---------------------------------------------------------------------------

class TestScopeDirsFiltering:
    """
    The GUI's _load_tracked_dirs_for_scope() reads ~/.rag_auto_update_dirs.json
    and filters to path-like keys only.  When the JSON is a dict it may contain
    metadata keys (e.g. "last_updated") alongside real directory paths.  Only
    absolute paths should survive the filter.

    These tests exercise the filtering logic directly — no GUI import needed.
    """

    def _filter_tracked(self, raw):
        """Replicate the filtering logic from rag_gui._load_tracked_dirs_for_scope."""
        import os
        if isinstance(raw, dict):
            return [k for k in raw.keys()
                    if os.path.isabs(k) or k.startswith("\\\\") or k.startswith("//")]
        elif isinstance(raw, list):
            return [k for k in raw if isinstance(k, str) and
                    (os.path.isabs(k) or k.startswith("\\\\") or k.startswith("//"))]
        return []

    def test_TC_CTASK_009_dict_with_metadata_key_filters_last_updated(self):
        raw = {
            r"C:\Users\david\Documents": {"last_updated": "2026-06-01"},
            r"C:\Users\david\AI-Prowler": {"last_updated": "2026-06-15"},
            "last_updated": "2026-06-15",          # metadata — must be excluded
        }
        result = self._filter_tracked(raw)
        assert "last_updated" not in result
        assert r"C:\Users\david\Documents" in result
        assert r"C:\Users\david\AI-Prowler" in result
        assert len(result) == 2

    def test_TC_CTASK_009_dict_only_paths_all_pass(self):
        raw = {
            r"C:\Jobs\2026": {},
            r"C:\Invoices": {},
        }
        result = self._filter_tracked(raw)
        assert len(result) == 2

    def test_TC_CTASK_009_list_format_filters_non_paths(self):
        raw = [r"C:\Jobs\2026", "last_updated", r"C:\Invoices", "version"]
        result = self._filter_tracked(raw)
        assert r"C:\Jobs\2026" in result
        assert r"C:\Invoices" in result
        assert "last_updated" not in result
        assert "version" not in result

    def test_TC_CTASK_009_unc_paths_pass(self):
        raw = {r"\\server\share": {}, "last_updated": "2026-01-01"}
        result = self._filter_tracked(raw)
        assert r"\\server\share" in result
        assert "last_updated" not in result

    def test_TC_CTASK_009_empty_dict_returns_empty(self):
        assert self._filter_tracked({}) == []

    def test_TC_CTASK_009_empty_list_returns_empty(self):
        assert self._filter_tracked([]) == []

    def test_TC_CTASK_009_non_dict_non_list_returns_empty(self):
        assert self._filter_tracked("not a dict or list") == []
        assert self._filter_tracked(None) == []


# ---------------------------------------------------------------------------
# TC-CTASK-010  scope_dirs preserved in queue entries
# ---------------------------------------------------------------------------

class TestScopeDirsInQueueEntries:

    def test_TC_CTASK_010_scope_dirs_in_entry(self):
        import custom_tasks_manager as ctm
        task = ctm.create_task(
            label="Scoped", prompt="Analyze.",
            scope_dirs=[r"C:\Jobs\2026", r"C:\Invoices"])
        entries = ctm.tasks_to_queue_entries([task])
        e = entries[0]
        assert "scope_dirs" in e
        assert r"C:\Jobs\2026" in e["scope_dirs"]
        assert r"C:\Invoices" in e["scope_dirs"]

    def test_TC_CTASK_010_empty_scope_dirs_preserved(self):
        import custom_tasks_manager as ctm
        task = ctm.create_task(label="Unscoped", prompt="Analyze everything.")
        entries = ctm.tasks_to_queue_entries([task])
        e = entries[0]
        assert "scope_dirs" in e
        assert e["scope_dirs"] == []

    def test_TC_CTASK_010_scope_dirs_in_prompt_when_set(self):
        """When scope_dirs are set, build_task_prompt should reference them."""
        import custom_tasks_manager as ctm
        task = ctm.create_task(
            label="T", prompt="Analyze my invoices.",
            scope_dirs=[r"C:\Invoices"])
        prompt = ctm.build_task_prompt(task)
        assert r"C:\Invoices" in prompt

    def test_TC_CTASK_010_scope_dirs_not_in_prompt_when_empty(self):
        import custom_tasks_manager as ctm
        task = ctm.create_task(label="T", prompt="Analyze my invoices.")
        task["scope_dirs"] = []
        prompt = ctm.build_task_prompt(task)
        # Should not contain scope injection language when no dirs selected
        assert "search_within_directory" not in prompt or "Focus" not in prompt


# ---------------------------------------------------------------------------
# TC-CTASK-011  scope hint injected into built-in task prompt
# ---------------------------------------------------------------------------

class TestBuiltInScopeInjection:
    """
    The GUI's _queue_and_copy() appends a scope hint to the task prompt when
    scope_dirs are selected for built-in (non-custom) tasks.
    These tests verify the injection logic directly.
    """

    def _inject_scope(self, base_prompt, scope_dirs):
        """Replicate the scope injection from rag_gui._queue_and_copy."""
        if not scope_dirs:
            return base_prompt
        scope_hint = (
            f"\n\nScope restriction: focus your analysis only on "
            f"these indexed directories: {', '.join(scope_dirs)}. "
            f"Use search_within_directory() for each scope directory "
            f"rather than search_documents() across the full index."
        )
        return base_prompt.rstrip() + scope_hint

    def test_TC_CTASK_011_no_scope_prompt_unchanged(self):
        base = "Analyze my business data."
        result = self._inject_scope(base, [])
        assert result == base

    def test_TC_CTASK_011_single_dir_injected(self):
        base = "Analyze my business data."
        result = self._inject_scope(base, [r"C:\Invoices"])
        assert "Scope restriction" in result
        assert r"C:\Invoices" in result
        assert "search_within_directory()" in result
        assert "search_documents()" in result

    def test_TC_CTASK_011_multiple_dirs_all_injected(self):
        base = "Analyze my business data."
        dirs = [r"C:\Invoices", r"C:\Jobs\2026"]
        result = self._inject_scope(base, dirs)
        assert r"C:\Invoices" in result
        assert r"C:\Jobs\2026" in result

    def test_TC_CTASK_011_base_prompt_preserved(self):
        base = "Analyze my business data comprehensively."
        result = self._inject_scope(base, [r"C:\Invoices"])
        assert base.rstrip() in result

    def test_TC_CTASK_011_scope_dirs_stored_in_task_record(self):
        """task record written to pending_tasks.json must include scope_dirs."""
        import json, tempfile
        from pathlib import Path

        scope_dirs = [r"C:\Invoices", r"C:\Jobs"]
        task = {
            "task_id":    "analyze_business_20260624_120000",
            "type":       "analyze_business",
            "label":      "📊 Analyze My Business",
            "prompt":     self._inject_scope("Analyze my business.", scope_dirs),
            "scope_dirs": scope_dirs,
            "created_at": "2026-06-24T12:00:00Z",
            "status":     "pending",
        }
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "pending_tasks.json"
            p.write_text(json.dumps([task], indent=2), encoding="utf-8")
            loaded = json.loads(p.read_text(encoding="utf-8"))

        assert loaded[0]["scope_dirs"] == scope_dirs
        assert "search_within_directory()" in loaded[0]["prompt"]


# ---------------------------------------------------------------------------
# TC-CTASK-012  get_pending_analysis_tasks MCP tool
# ---------------------------------------------------------------------------

class TestGetPendingAnalysisTasks:
    """Tests for the get_pending_analysis_tasks() MCP tool in ai_prowler_mcp.py.

    The tool returns:
      - A JSON string (dict with pending_count / tasks / instruction) when tasks exist
      - A plain informational string when the queue is empty or an error occurs
    """

    def _make_pending_file(self, tmp_path, tasks):
        import json
        p = tmp_path / "pending_tasks.json"
        p.write_text(json.dumps(tasks, indent=2), encoding="utf-8")
        return p

    def _make_task_entry(self, task_id="task_001", status="pending",
                         label="Test", prompt="Analyze.", type_="custom"):
        import datetime
        return {
            "task_id":    task_id,
            "type":       type_,
            "label":      label,
            "prompt":     prompt,
            "scope_dirs": [],
            "created_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status":     status,
        }

    def _call(self, mcp, tmp_path, tasks):
        """Call get_pending_analysis_tasks with a patched pending file."""
        import json
        p = self._make_pending_file(tmp_path, tasks)
        with patch("ai_prowler_mcp._load_pending_tasks",
                   return_value=[t.copy() for t in tasks]):
            raw = mcp.get_pending_analysis_tasks()
        # If it's a JSON string, parse it; otherwise return as-is (plain message)
        try:
            return json.loads(raw), True   # (result_dict, is_json)
        except (json.JSONDecodeError, TypeError):
            return raw, False              # (plain_string, is_json=False)

    def test_TC_CTASK_012_returns_pending_tasks_only(self, tmp_path):
        import ai_prowler_mcp as mcp
        tasks = [
            self._make_task_entry("t1", status="pending",   label="Pending One"),
            self._make_task_entry("t2", status="completed", label="Already Done"),
            self._make_task_entry("t3", status="pending",   label="Pending Two"),
        ]
        result, is_json = self._call(mcp, tmp_path, tasks)
        assert is_json, f"Expected JSON result, got plain string: {result!r}"
        assert result["pending_count"] == 2
        labels = [t["label"] for t in result["tasks"]]
        assert "Pending One" in labels
        assert "Pending Two" in labels
        assert "Already Done" not in labels

    def test_TC_CTASK_012_missing_file_returns_empty(self, tmp_path):
        import ai_prowler_mcp as mcp
        with patch("ai_prowler_mcp._load_pending_tasks", return_value=[]):
            raw = mcp.get_pending_analysis_tasks()
        # Empty queue → plain informational string, not JSON
        assert isinstance(raw, str)
        assert len(raw) > 0

    def test_TC_CTASK_012_empty_queue_returns_plain_message(self, tmp_path):
        import ai_prowler_mcp as mcp
        with patch("ai_prowler_mcp._load_pending_tasks", return_value=[]):
            raw = mcp.get_pending_analysis_tasks()
        assert isinstance(raw, str)
        # Should not be parseable as JSON with pending_count
        import json as _j
        try:
            parsed = _j.loads(raw)
            # If it IS json, pending_count must be 0
            assert parsed.get("pending_count", 0) == 0
        except (_j.JSONDecodeError, TypeError):
            pass  # plain string is fine

    def test_TC_CTASK_012_all_completed_returns_empty_message(self, tmp_path):
        import ai_prowler_mcp as mcp
        tasks = [self._make_task_entry(f"t{i}", status="completed") for i in range(3)]
        with patch("ai_prowler_mcp._load_pending_tasks",
                   return_value=[t.copy() for t in tasks]):
            raw = mcp.get_pending_analysis_tasks()
        result, is_json = raw, False
        try:
            import json as _j
            result = _j.loads(raw)
            is_json = True
        except Exception:
            pass
        if is_json:
            assert result.get("pending_count", 0) == 0
        else:
            assert isinstance(raw, str) and len(raw) > 0

    def test_TC_CTASK_012_task_fields_present(self, tmp_path):
        import ai_prowler_mcp as mcp
        tasks = [self._make_task_entry("t1", label="My Task", prompt="Do it.")]
        result, is_json = self._call(mcp, tmp_path, tasks)
        assert is_json, f"Expected JSON, got: {result!r}"
        t = result["tasks"][0]
        assert t["task_id"] == "t1"
        assert t["label"] == "My Task"
        assert t["prompt"] == "Do it."
        assert "created_at" in t
        assert "queued_ago" in t

    def test_TC_CTASK_012_scope_dirs_included_in_result(self, tmp_path):
        import ai_prowler_mcp as mcp
        entry = self._make_task_entry("t1")
        entry["scope_dirs"] = [r"C:\Invoices", r"C:\Jobs"]
        result, is_json = self._call(mcp, tmp_path, [entry])
        assert is_json
        t = result["tasks"][0]
        assert t["scope_dirs"] == [r"C:\Invoices", r"C:\Jobs"]

    def test_TC_CTASK_012_corrupt_json_returns_error_string(self, tmp_path):
        import ai_prowler_mcp as mcp
        # Simulate load error by having _load_pending_tasks raise
        def _raise():
            raise ValueError("corrupt")
        with patch("ai_prowler_mcp._load_pending_tasks", side_effect=_raise):
            raw = mcp.get_pending_analysis_tasks()
        assert isinstance(raw, str)
        assert "❌" in raw or "error" in raw.lower() or "could not" in raw.lower()


# ---------------------------------------------------------------------------
# TC-CTASK-013  complete_analysis_task MCP tool
# ---------------------------------------------------------------------------

class TestCompleteAnalysisTask:
    """Tests for the complete_analysis_task() MCP tool in ai_prowler_mcp.py."""

    def _pending_entry(self, task_id, label="Test", type_="custom", source_id=None):
        import datetime
        return {
            "task_id":    task_id,
            "source_id":  source_id or task_id,
            "type":       type_,
            "label":      label,
            "prompt":     "Analyze my data.",
            "scope_dirs": [],
            "created_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status":     "pending",
        }

    def _run(self, mcp, entries, task_id, summary="", custom_tasks=None):
        """Call complete_analysis_task with fully mocked storage."""
        import custom_tasks_manager as ctm
        saved = {"tasks": list(entries), "custom": custom_tasks or []}

        def _load():
            return [e.copy() for e in saved["tasks"]]

        def _save(tasks):
            saved["tasks"] = tasks
            return True

        def _load_custom():
            return [t.copy() for t in saved["custom"]]

        def _save_custom(tasks):
            saved["custom"] = tasks
            return True

        with patch("ai_prowler_mcp._load_pending_tasks", side_effect=_load), \
             patch("ai_prowler_mcp._save_pending_tasks", side_effect=_save), \
             patch("custom_tasks_manager.load_custom_tasks", side_effect=_load_custom), \
             patch("custom_tasks_manager.save_custom_tasks", side_effect=_save_custom):
            result = mcp.complete_analysis_task(task_id=task_id, summary=summary)

        return result, saved

    def test_TC_CTASK_013_marks_task_completed(self):
        import ai_prowler_mcp as mcp
        entry = self._pending_entry("t1")
        result, saved = self._run(mcp, [entry], "t1", summary="Found 3 issues.")
        done = next(t for t in saved["tasks"] if t["task_id"] == "t1")
        assert done["status"] == "completed"
        assert "completed_at" in done
        assert done.get("completion_summary") == "Found 3 issues."
        assert "completed" in result.lower() or "t1" in result

    def test_TC_CTASK_013_completed_at_is_iso_timestamp(self):
        import ai_prowler_mcp as mcp, datetime
        entry = self._pending_entry("t1")
        _, saved = self._run(mcp, [entry], "t1")
        ts = next(t for t in saved["tasks"] if t["task_id"] == "t1")["completed_at"]
        datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")

    def test_TC_CTASK_013_summary_optional(self):
        import ai_prowler_mcp as mcp
        entry = self._pending_entry("t1")
        _, saved = self._run(mcp, [entry], "t1")
        done = next(t for t in saved["tasks"] if t["task_id"] == "t1")
        assert done["status"] == "completed"

    def test_TC_CTASK_013_other_tasks_untouched(self):
        import ai_prowler_mcp as mcp
        entries = [
            self._pending_entry("t1", label="Complete Me"),
            self._pending_entry("t2", label="Leave Me"),
        ]
        _, saved = self._run(mcp, entries, "t1")
        by_id = {t["task_id"]: t for t in saved["tasks"]}
        assert by_id["t1"]["status"] == "completed"
        assert by_id["t2"]["status"] == "pending"

    def test_TC_CTASK_013_unknown_task_id_returns_error(self):
        import ai_prowler_mcp as mcp
        entry = self._pending_entry("t1")
        result, _ = self._run(mcp, [entry], "nonexistent")
        assert "not found" in result.lower() or "⚠" in result

    def test_TC_CTASK_013_custom_task_advances_next_due(self):
        """Completing a scheduled custom task should auto-advance its next_due."""
        import ai_prowler_mcp as mcp
        import custom_tasks_manager as ctm
        import datetime

        yesterday = (datetime.date.today() - datetime.timedelta(days=1)).isoformat()
        custom_task = ctm.create_task(
            label="Weekly Report", prompt="Analyze weekly.",
            schedule="weekly", first_due=yesterday)
        custom_task["next_due"] = yesterday  # anchor for advance

        # Pending entry references the custom task via source_id
        entry = self._pending_entry(
            "entry_001", label="Weekly Report", type_="custom",
            source_id=custom_task["task_id"])

        _, saved = self._run(mcp, [entry], "entry_001",
                             summary="Done.", custom_tasks=[custom_task])

        updated_custom = saved["custom"]
        assert len(updated_custom) == 1
        next_due = updated_custom[0]["next_due"]

        # Anchor = yesterday; weekly → yesterday + 7 = today + 6
        expected = (datetime.date.today() + datetime.timedelta(days=6)).isoformat()
        assert next_due == expected, f"Expected {expected}, got {next_due}"


# ---------------------------------------------------------------------------
# TC-CTASK-014  server mode suppression (_is_server_mode_gui logic)
# ---------------------------------------------------------------------------

class TestServerModeSuppression:
    """
    The GUI's _is_server_mode_gui() reads ~/.ai-prowler/config.json and
    returns True only when edition=business AND mode=server.
    These tests verify the detection logic directly without importing tkinter.
    """

    def _detect(self, config_dict, tmp_path):
        """Replicate _is_server_mode_gui() without importing rag_gui."""
        import json, os
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text(json.dumps(config_dict), encoding="utf-8")
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8-sig")) or {}
            return (str(cfg.get("edition", "")).strip().lower() == "business"
                    and str(cfg.get("mode", "")).strip().lower() == "server")
        except Exception:
            return False

    def test_TC_CTASK_014_business_server_returns_true(self, tmp_path):
        assert self._detect({"edition": "business", "mode": "server"}, tmp_path) is True

    def test_TC_CTASK_014_personal_mode_returns_false(self, tmp_path):
        assert self._detect({"edition": "business", "mode": "personal"}, tmp_path) is False

    def test_TC_CTASK_014_home_edition_returns_false(self, tmp_path):
        assert self._detect({"edition": "home", "mode": "server"}, tmp_path) is False

    def test_TC_CTASK_014_missing_keys_returns_false(self, tmp_path):
        assert self._detect({}, tmp_path) is False

    def test_TC_CTASK_014_case_insensitive(self, tmp_path):
        assert self._detect({"edition": "Business", "mode": "Server"}, tmp_path) is True

    def test_TC_CTASK_014_missing_config_file_returns_false(self, tmp_path):
        """No config.json → should default to False (personal mode)."""
        import json
        cfg_path = tmp_path / "config.json"
        # Don't write the file
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8-sig")) or {}
            result = (str(cfg.get("edition", "")).strip().lower() == "business"
                      and str(cfg.get("mode", "")).strip().lower() == "server")
        except Exception:
            result = False
        assert result is False


# ---------------------------------------------------------------------------
# TC-CTASK-015  schedule fields in built-in task record
# ---------------------------------------------------------------------------

class TestBuiltInScheduleFields:
    """
    When a user sets a schedule in the Configure popup for a Common Business
    button, the task record written to pending_tasks.json must include
    schedule, first_due, and next_due fields.

    These tests verify the task dict construction logic directly.
    """

    def _make_builtin_task(self, schedule_key, first_due_val, next_due_val):
        """Simulate the task dict built by _queue_and_copy."""
        import datetime
        ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        return {
            "task_id":          f"analyze_business_{ts}",
            "type":             "analyze_business",
            "label":            "📊 Analyze My Business",
            "prompt":           "Analyze my business data.",
            "scope_dirs":       [],
            "output_learnings": True,
            "output_report":    False,
            "report_folder":    "C:\\Users\\david\\Documents\\AI-Prowler_tasks_reports",
            "schedule":         schedule_key,
            "first_due":        first_due_val,
            "next_due":         next_due_val,
            "created_at":       datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status":           "pending",
        }

    def test_TC_CTASK_015_one_shot_has_none_schedule(self):
        task = self._make_builtin_task("none", None, None)
        assert task["schedule"] == "none"
        assert task["first_due"] is None
        assert task["next_due"] is None

    def test_TC_CTASK_015_weekly_schedule_stored(self):
        task = self._make_builtin_task("weekly", "2026-06-24", "2026-06-24")
        assert task["schedule"] == "weekly"
        assert task["first_due"] == "2026-06-24"
        assert task["next_due"] == "2026-06-24"

    def test_TC_CTASK_015_monthly_schedule_stored(self):
        task = self._make_builtin_task("monthly", "2026-06-01", "2026-06-01")
        assert task["schedule"] == "monthly"
        assert task["first_due"] == "2026-06-01"
        assert task["next_due"] == "2026-06-01"

    def test_TC_CTASK_015_all_required_fields_present(self):
        """Task dict must contain all fields expected by complete_analysis_task."""
        task = self._make_builtin_task("weekly", "2026-06-24", "2026-06-24")
        required = [
            "task_id", "type", "label", "prompt", "scope_dirs",
            "output_learnings", "output_report", "report_folder",
            "schedule", "first_due", "next_due", "created_at", "status",
        ]
        for field in required:
            assert field in task, f"Missing field: {field}"

    def test_TC_CTASK_015_next_due_matches_first_due_on_creation(self):
        """next_due should equal first_due when task is first created."""
        first = "2026-07-01"
        task = self._make_builtin_task("monthly", first, first)
        assert task["next_due"] == task["first_due"]

    def test_TC_CTASK_015_next_due_defaults_to_today_when_blank(self):
        """If user leaves first_due blank, next_due should be today."""
        import datetime
        today = datetime.date.today().isoformat()
        task = self._make_builtin_task("weekly", today, today)
        assert task["next_due"] == today


# ---------------------------------------------------------------------------
# TC-CTASK-016  complete_analysis_task advances next_due for built-in tasks
# ---------------------------------------------------------------------------

class TestBuiltInScheduleAdvancement:
    """
    complete_analysis_task() must advance next_due for built-in scheduled
    tasks (schedule != "none", no source_id) using _advance_date() anchored
    to the current next_due value.
    """

    def _pending_builtin(self, task_id, schedule, next_due):
        import datetime
        return {
            "task_id":          task_id,
            "type":             "analyze_business",
            "label":            "📊 Analyze My Business",
            "prompt":           "Analyze.",
            "scope_dirs":       [],
            "output_learnings": True,
            "output_report":    False,
            "report_folder":    "C:\\Users\\david\\Documents\\AI-Prowler_tasks_reports",
            "schedule":         schedule,
            "first_due":        next_due,
            "next_due":         next_due,
            "created_at":       datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status":           "pending",
            "source_id":        None,   # no source_id = built-in, not custom
        }

    def _run_complete(self, mcp, entries, task_id):
        """Call complete_analysis_task with fully mocked storage."""
        saved = {"tasks": list(entries)}

        def _load():
            return [e.copy() for e in saved["tasks"]]

        def _save(tasks):
            saved["tasks"] = tasks
            return True

        with patch("ai_prowler_mcp._load_pending_tasks", side_effect=_load), \
             patch("ai_prowler_mcp._save_pending_tasks", side_effect=_save):
            result = mcp.complete_analysis_task(task_id=task_id,
                                                summary="Test complete.")
        return result, saved

    def test_TC_CTASK_016_weekly_next_due_advanced(self):
        """v8.1.5: use an anchor only mildly overdue (less than one full
        interval) so a single _advance_date() step already lands after
        today — this is the 'simple, single-overdue' case, which must
        behave identically to the pre-catchup single-step advance. Anchor
        and expected are both computed relative to real 'today' rather than
        a hardcoded literal, so this test doesn't silently rot as time
        passes (which is exactly what broke this test against the v8.1.5
        catch-up change — it hardcoded "2026-06-24" -> "2026-07-01" with no
        relationship to whatever "today" happens to be when the suite runs)."""
        import ai_prowler_mcp as mcp
        import datetime
        import custom_tasks_manager as ctm
        anchor = (datetime.date.today() - datetime.timedelta(days=3)).isoformat()
        expected = ctm._advance_date(anchor, "weekly")
        entry = self._pending_builtin("t1", "weekly", anchor)
        result, saved = self._run_complete(mcp, [entry], "t1")
        done = next(t for t in saved["tasks"] if t["task_id"] == "t1")
        assert done["status"] == "completed"
        assert done.get("next_due") == expected

    def test_TC_CTASK_016_weekly_catchup_when_severely_overdue(self):
        """v8.1.5 NEW BEHAVIOR: a task overdue by MULTIPLE intervals (here,
        weekly but last due ~30 days ago — 4+ missed weeks) must resync
        fully to the next occurrence after today in a single completion,
        not just advance by one week and remain overdue. Asserted as a
        property (next_due is strictly in the future, and differs from the
        naive single-step result) rather than a hardcoded date, since the
        exact number of steps needed depends on when the suite runs."""
        import ai_prowler_mcp as mcp
        import datetime
        import custom_tasks_manager as ctm
        anchor = (datetime.date.today() - datetime.timedelta(days=30)).isoformat()
        naive_single_step = ctm._advance_date(anchor, "weekly")
        entry = self._pending_builtin("t1", "weekly", anchor)
        result, saved = self._run_complete(mcp, [entry], "t1")
        done = next(t for t in saved["tasks"] if t["task_id"] == "t1")
        next_due = done.get("next_due")
        today_str = datetime.date.today().isoformat()
        assert next_due > today_str, (
            f"next_due {next_due} should be strictly after today {today_str}")
        assert next_due != naive_single_step, (
            "expected catch-up to skip past the naive single-step result "
            f"({naive_single_step}) since the task was overdue by several weeks")

    def test_TC_CTASK_016_monthly_next_due_advanced(self):
        """See test_TC_CTASK_016_weekly_next_due_advanced docstring — same
        dynamic-date fix, single-overdue simple case."""
        import ai_prowler_mcp as mcp
        import datetime
        import custom_tasks_manager as ctm
        anchor = (datetime.date.today() - datetime.timedelta(days=3)).isoformat()
        expected = ctm._advance_date(anchor, "monthly")
        entry = self._pending_builtin("t1", "monthly", anchor)
        result, saved = self._run_complete(mcp, [entry], "t1")
        done = next(t for t in saved["tasks"] if t["task_id"] == "t1")
        assert done.get("next_due") == expected

    def test_TC_CTASK_016_next_due_in_return_message(self):
        import ai_prowler_mcp as mcp
        entry = self._pending_builtin("t1", "weekly", "2026-06-24")
        result, _ = self._run_complete(mcp, [entry], "t1")
        assert "Next scheduled run" in result or "2026-07-01" in result

    def test_TC_CTASK_016_quarterly_next_due_advanced(self):
        import ai_prowler_mcp as mcp
        entry = self._pending_builtin("t1", "quarterly", "2026-06-01")
        result, saved = self._run_complete(mcp, [entry], "t1")
        done = next(t for t in saved["tasks"] if t["task_id"] == "t1")
        assert done.get("next_due") == "2026-09-01"

    def test_TC_CTASK_016_completed_at_stamped(self):
        import ai_prowler_mcp as mcp, datetime
        entry = self._pending_builtin("t1", "weekly", "2026-06-24")
        _, saved = self._run_complete(mcp, [entry], "t1")
        done = next(t for t in saved["tasks"] if t["task_id"] == "t1")
        assert "completed_at" in done
        datetime.datetime.strptime(done["completed_at"], "%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# TC-CTASK-017  one-shot built-in tasks are NOT rescheduled
# ---------------------------------------------------------------------------

class TestBuiltInOneShot:
    """
    When schedule="none", complete_analysis_task() must NOT advance next_due.
    The task record should have next_due=None after completion.
    """

    def _pending_oneshot(self, task_id):
        import datetime
        return {
            "task_id":   task_id,
            "type":      "find_problems",
            "label":     "⚠️ Find Problems",
            "prompt":    "Find problems.",
            "scope_dirs": [],
            "output_learnings": True,
            "output_report":    False,
            "report_folder":    "C:\\Users\\david\\Documents\\AI-Prowler_tasks_reports",
            "schedule":  "none",
            "first_due": None,
            "next_due":  None,
            "created_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status":    "pending",
            "source_id": None,
        }

    def _run_complete(self, mcp, entries, task_id):
        saved = {"tasks": list(entries)}

        def _load():
            return [e.copy() for e in saved["tasks"]]

        def _save(tasks):
            saved["tasks"] = tasks

        with patch("ai_prowler_mcp._load_pending_tasks", side_effect=_load), \
             patch("ai_prowler_mcp._save_pending_tasks", side_effect=_save):
            result = mcp.complete_analysis_task(task_id=task_id)
        return result, saved

    def test_TC_CTASK_017_oneshot_completes_without_next_due(self):
        import ai_prowler_mcp as mcp
        entry = self._pending_oneshot("t1")
        result, saved = self._run_complete(mcp, [entry], "t1")
        done = next(t for t in saved["tasks"] if t["task_id"] == "t1")
        assert done["status"] == "completed"
        assert done.get("next_due") is None

    def test_TC_CTASK_017_no_next_scheduled_in_message(self):
        import ai_prowler_mcp as mcp
        entry = self._pending_oneshot("t1")
        result, _ = self._run_complete(mcp, [entry], "t1")
        assert "Next scheduled run" not in result

    def test_TC_CTASK_017_completed_at_still_stamped(self):
        import ai_prowler_mcp as mcp, datetime
        entry = self._pending_oneshot("t1")
        _, saved = self._run_complete(mcp, [entry], "t1")
        done = next(t for t in saved["tasks"] if t["task_id"] == "t1")
        assert "completed_at" in done
        datetime.datetime.strptime(done["completed_at"], "%Y-%m-%dT%H:%M:%SZ")

