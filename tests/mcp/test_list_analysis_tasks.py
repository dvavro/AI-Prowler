"""
tests/mcp/test_list_analysis_tasks.py
=======================================
Tests for the list_analysis_tasks() MCP tool — lets Claude read the FULL
custom-analysis task definition list (custom_analysis_tasks.json), not just
whatever is currently queued in pending_tasks.json.

Built in response to a real gap: get_pending_analysis_tasks() only ever
returns tasks that have been explicitly queued (due-and-pulled by "Run Due
Tasks" in the GUI, or manually queued). A task can be fully defined and
scheduled and simply never show up there until both its due date arrives
AND someone queues it. This tool answers "what's in my task queue / what
have I set up" without either of those preconditions.

Covers:
  - Tier A suppression (personal-install-only, grouped with its 4 siblings:
    get_pending_analysis_tasks, complete_analysis_task, save_analysis_report,
    create_analysis_task)
  - Empty list → plain message, not an error or empty JSON blob
  - Non-empty list → JSON with total_count, max_tasks, full task objects
  - is_due is computed correctly per task (via custom_tasks_manager's
    get_due_tasks(), not reimplemented ad hoc in the tool)
  - custom_tasks_manager import failure is surfaced cleanly, not a crash
  - Read-only: never calls save_custom_tasks or otherwise mutates state
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="module")
def mcp_mod():
    import ai_prowler_mcp as ap
    ap._prewarm_event.set()
    return ap


class TestTierASuppression:

    def test_list_analysis_tasks_is_tier_a_suppressed(self, mcp_mod):
        assert "list_analysis_tasks" in mcp_mod._TIER_A_SUPPRESSED

    def test_grouped_with_its_siblings(self, mcp_mod):
        family = {"get_pending_analysis_tasks", "complete_analysis_task",
                 "save_analysis_report", "create_analysis_task",
                 "list_analysis_tasks"}
        assert family.issubset(mcp_mod._TIER_A_SUPPRESSED)


class TestEmptyQueue:

    def test_no_tasks_returns_plain_message_not_json(self, mcp_mod, monkeypatch):
        class _FakeCTM:
            @staticmethod
            def load_custom_tasks():
                return []
            @staticmethod
            def get_due_tasks(tasks):
                return []
            MAX_CUSTOM_TASKS = 25

        import sys as _sys
        monkeypatch.setitem(_sys.modules, "custom_tasks_manager", _FakeCTM)

        result = mcp_mod.list_analysis_tasks()
        assert "✅" in result
        assert "no custom analysis tasks" in result.lower()
        # Must NOT look like JSON — this is the plain-message branch.
        assert not result.strip().startswith("{")


class TestNonEmptyQueue:

    def _fake_ctm(self, tasks, due_task_ids):
        class _FakeCTM:
            @staticmethod
            def load_custom_tasks():
                return list(tasks)
            @staticmethod
            def get_due_tasks(all_tasks):
                return [t for t in all_tasks if t["task_id"] in due_task_ids]
            MAX_CUSTOM_TASKS = 25
        return _FakeCTM

    def test_returns_json_with_total_count_and_max_tasks(self, mcp_mod, monkeypatch):
        tasks = [
            {"task_id": "custom_0001", "label": "Daily Stock Check",
             "prompt": "Check the market.", "schedule": "daily",
             "first_due": "2026-07-13", "next_due": "2026-07-13",
             "last_run": None, "last_status": None,
             "output_learnings": True, "output_report": False,
             "report_folder": None, "scope_dirs": []},
        ]
        import sys as _sys
        monkeypatch.setitem(_sys.modules, "custom_tasks_manager",
                            self._fake_ctm(tasks, due_task_ids=set()))

        result = mcp_mod.list_analysis_tasks()
        assert result.strip().startswith("{")

        import json as _json
        parsed = _json.loads(result)
        assert parsed["total_count"] == 1
        assert parsed["max_tasks"] == 25
        assert len(parsed["tasks"]) == 1
        assert parsed["tasks"][0]["task_id"] == "custom_0001"

    def test_future_dated_task_shows_is_due_false(self, mcp_mod, monkeypatch):
        """The core bug this tool fixes: a task that exists but isn't due
        yet must still appear in the list — just flagged is_due=False,
        not omitted the way get_pending_analysis_tasks() would omit it."""
        tasks = [
            {"task_id": "custom_0001", "label": "Not due yet",
             "schedule": "daily", "next_due": "2099-01-01"},
        ]
        import sys as _sys
        monkeypatch.setitem(_sys.modules, "custom_tasks_manager",
                            self._fake_ctm(tasks, due_task_ids=set()))

        result = mcp_mod.list_analysis_tasks()
        import json as _json
        parsed = _json.loads(result)
        assert parsed["total_count"] == 1
        assert parsed["tasks"][0]["is_due"] is False

    def test_overdue_task_shows_is_due_true(self, mcp_mod, monkeypatch):
        tasks = [
            {"task_id": "custom_0002", "label": "Overdue task",
             "schedule": "weekly", "next_due": "2020-01-01"},
        ]
        import sys as _sys
        monkeypatch.setitem(_sys.modules, "custom_tasks_manager",
                            self._fake_ctm(tasks, due_task_ids={"custom_0002"}))

        result = mcp_mod.list_analysis_tasks()
        import json as _json
        parsed = _json.loads(result)
        assert parsed["tasks"][0]["is_due"] is True

    def test_mixed_due_and_not_due_both_present(self, mcp_mod, monkeypatch):
        """The whole point: both due AND not-due tasks show up together —
        this is a full listing, not a filtered one."""
        tasks = [
            {"task_id": "custom_A", "label": "Due now", "next_due": "2020-01-01"},
            {"task_id": "custom_B", "label": "Not due", "next_due": "2099-01-01"},
        ]
        import sys as _sys
        monkeypatch.setitem(_sys.modules, "custom_tasks_manager",
                            self._fake_ctm(tasks, due_task_ids={"custom_A"}))

        result = mcp_mod.list_analysis_tasks()
        import json as _json
        parsed = _json.loads(result)
        assert parsed["total_count"] == 2
        by_id = {t["task_id"]: t for t in parsed["tasks"]}
        assert by_id["custom_A"]["is_due"] is True
        assert by_id["custom_B"]["is_due"] is False

    def test_result_includes_explanatory_note_field(self, mcp_mod, monkeypatch):
        """The note distinguishing this from the run-queue must be present —
        otherwise Claude (or a future maintainer) could misread is_due=true
        as meaning the task already ran or is about to run automatically."""
        tasks = [{"task_id": "custom_X", "label": "X", "next_due": None}]
        import sys as _sys
        monkeypatch.setitem(_sys.modules, "custom_tasks_manager",
                            self._fake_ctm(tasks, due_task_ids=set()))

        result = mcp_mod.list_analysis_tasks()
        import json as _json
        parsed = _json.loads(result)
        assert "note" in parsed
        assert "queue" in parsed["note"].lower()


class TestImportFailureHandledCleanly:

    def test_missing_custom_tasks_manager_module_returns_error_not_crash(
            self, mcp_mod, monkeypatch):
        import sys as _sys
        import builtins as _builtins

        real_import = _builtins.__import__

        def _blocking_import(name, *args, **kwargs):
            if name == "custom_tasks_manager":
                raise ImportError("No module named 'custom_tasks_manager'")
            return real_import(name, *args, **kwargs)

        monkeypatch.delitem(_sys.modules, "custom_tasks_manager", raising=False)
        monkeypatch.setattr(_builtins, "__import__", _blocking_import)

        result = mcp_mod.list_analysis_tasks()
        assert "❌" in result
        assert "custom_tasks_manager" in result


class TestReadOnly:

    def test_never_calls_save_custom_tasks(self, mcp_mod, monkeypatch):
        """This tool must be strictly read-only — no mutation path exists,
        so save_custom_tasks should never even be looked up, let alone
        called. Fail loudly if that ever changes."""
        save_calls = []

        class _FakeCTM:
            @staticmethod
            def load_custom_tasks():
                return [{"task_id": "custom_0001", "label": "X", "next_due": None}]
            @staticmethod
            def get_due_tasks(tasks):
                return []
            @staticmethod
            def save_custom_tasks(tasks):
                save_calls.append(tasks)
                return True
            MAX_CUSTOM_TASKS = 25

        import sys as _sys
        monkeypatch.setitem(_sys.modules, "custom_tasks_manager", _FakeCTM)

        mcp_mod.list_analysis_tasks()
        assert save_calls == []
