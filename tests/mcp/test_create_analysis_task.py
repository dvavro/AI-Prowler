"""
tests/mcp/test_create_analysis_task.py
=========================================
Tests for the new create_analysis_task() MCP tool — lets Claude define a
new recurring/one-off custom analysis task from a plain-language request,
wrapping custom_tasks_manager.create_task().

Covers:
  - Tier A suppression (personal-install-only, matching its 3 siblings:
    get_pending_analysis_tasks, complete_analysis_task, save_analysis_report)
  - Successful creation, both scheduled and one-off
  - Validation errors propagate cleanly (empty label, invalid schedule,
    missing first_due for a scheduled task)
  - The MAX_CUSTOM_TASKS cap (now centralized in create_task() itself)
    is respected here too — this tool cannot bypass it
  - Persistence: the new task actually gets appended and saved, not just
    validated and discarded
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

    def test_create_analysis_task_is_tier_a_suppressed(self, mcp_mod):
        """Must be blocked in server mode, matching its 3 siblings — this
        whole feature is a personal-install-only GUI-backed capability."""
        assert "create_analysis_task" in mcp_mod._TIER_A_SUPPRESSED

    def test_grouped_with_its_siblings(self, mcp_mod):
        family = {"get_pending_analysis_tasks", "complete_analysis_task",
                 "save_analysis_report", "create_analysis_task"}
        assert family.issubset(mcp_mod._TIER_A_SUPPRESSED)


class TestSuccessfulCreation:

    def test_one_off_task_creation(self, mcp_mod, monkeypatch):
        saved = {}

        class _FakeCTM:
            @staticmethod
            def load_custom_tasks():
                return []
            @staticmethod
            def create_task(**kwargs):
                return {
                    "task_id": "custom_20260709_0001",
                    "label": kwargs["label"],
                    "next_due": None,
                }
            @staticmethod
            def save_custom_tasks(tasks):
                saved["tasks"] = tasks
                return True

        import sys as _sys
        monkeypatch.setitem(_sys.modules, "custom_tasks_manager", _FakeCTM)

        result = mcp_mod.create_analysis_task(
            label="Summarize Q3 contracts",
            prompt="Summarize the key risks in Q3 contracts.",
        )
        assert "✅" in result
        assert "custom_20260709_0001" in result
        assert "one-off" in result.lower()
        assert len(saved["tasks"]) == 1

    def test_scheduled_task_creation(self, mcp_mod, monkeypatch):
        class _FakeCTM:
            @staticmethod
            def load_custom_tasks():
                return []
            @staticmethod
            def create_task(**kwargs):
                assert kwargs["schedule"] == "weekly"
                assert kwargs["first_due"] == "2026-07-13"
                return {
                    "task_id": "custom_20260709_0002",
                    "label": kwargs["label"],
                    "next_due": "2026-07-13",
                }
            @staticmethod
            def save_custom_tasks(tasks):
                return True

        import sys as _sys
        monkeypatch.setitem(_sys.modules, "custom_tasks_manager", _FakeCTM)

        result = mcp_mod.create_analysis_task(
            label="Check invoice replies",
            prompt="Check for unread invoice-related emails and summarize.",
            schedule="weekly",
            first_due="2026-07-13",
        )
        assert "✅" in result
        assert "2026-07-13" in result
        assert "weekly" in result


class TestValidationErrorsPropagate:

    def test_empty_label_returns_error(self, mcp_mod, monkeypatch):
        class _FakeCTM:
            @staticmethod
            def load_custom_tasks():
                return []
            @staticmethod
            def create_task(**kwargs):
                raise ValueError("Task name is required.")
            @staticmethod
            def save_custom_tasks(tasks):
                return True

        import sys as _sys
        monkeypatch.setitem(_sys.modules, "custom_tasks_manager", _FakeCTM)

        result = mcp_mod.create_analysis_task(label="", prompt="Do something.")
        assert "❌" in result
        assert "required" in result.lower()

    def test_missing_first_due_for_scheduled_task_returns_error(self, mcp_mod, monkeypatch):
        class _FakeCTM:
            @staticmethod
            def load_custom_tasks():
                return []
            @staticmethod
            def create_task(**kwargs):
                raise ValueError("A first due date is required for scheduled tasks.")
            @staticmethod
            def save_custom_tasks(tasks):
                return True

        import sys as _sys
        monkeypatch.setitem(_sys.modules, "custom_tasks_manager", _FakeCTM)

        result = mcp_mod.create_analysis_task(
            label="Weekly check", prompt="Check things.", schedule="weekly"
        )
        assert "❌" in result
        assert "first due date" in result.lower()


class TestCapRespected:

    def test_cap_hit_returns_clear_error_not_a_crash(self, mcp_mod, monkeypatch):
        """The tool must surface create_task()'s cap ValueError cleanly —
        proves this tool cannot bypass the centralized 25-task limit."""
        class _FakeCTM:
            @staticmethod
            def load_custom_tasks():
                return [{"task_id": f"t{i}"} for i in range(25)]
            @staticmethod
            def create_task(**kwargs):
                raise ValueError("Maximum 25 custom tasks allowed. "
                                "Delete an existing task before adding a new one.")
            @staticmethod
            def save_custom_tasks(tasks):
                return True

        import sys as _sys
        monkeypatch.setitem(_sys.modules, "custom_tasks_manager", _FakeCTM)

        result = mcp_mod.create_analysis_task(label="One too many", prompt="x")
        assert "❌" in result
        assert "Maximum 25" in result


class TestPersistence:

    def test_new_task_actually_appended_and_saved(self, mcp_mod, monkeypatch):
        existing = [{"task_id": "custom_old_0001", "label": "Existing task"}]
        saved = {}

        class _FakeCTM:
            @staticmethod
            def load_custom_tasks():
                return list(existing)
            @staticmethod
            def create_task(**kwargs):
                return {"task_id": "custom_new_0002", "label": kwargs["label"], "next_due": None}
            @staticmethod
            def save_custom_tasks(tasks):
                saved["tasks"] = tasks
                return True

        import sys as _sys
        monkeypatch.setitem(_sys.modules, "custom_tasks_manager", _FakeCTM)

        mcp_mod.create_analysis_task(label="Brand new task", prompt="x")

        assert len(saved["tasks"]) == 2
        ids = {t["task_id"] for t in saved["tasks"]}
        assert ids == {"custom_old_0001", "custom_new_0002"}
