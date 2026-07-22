"""
tests/unit/test_catch_up_all_due_tasks.py
==============================================
Tests for custom_tasks_manager.catch_up_all_due_tasks() — v8.1.6, called
when the Autonomous Task Queue is enabled (OFF -> ON transition) so that
overdue custom-task backlog doesn't all fire on day one just because it
accumulated while automation was off.

Distinguished from advance_next_due(): that function is for an ACTUAL
completion Claude reports (marks last_run + last_status="completed").
catch_up_all_due_tasks() never claims anything was run — it only resyncs
next_due to the schedule's normal cadence, tagging last_status as
"skipped_on_enable" so the history stays honest.
"""

import sys
import datetime
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(scope="module")
def ctm():
    import custom_tasks_manager as _ctm
    return _ctm


def _today(ctm):
    return datetime.date.today().isoformat()


def _yesterday():
    return (datetime.date.today() - datetime.timedelta(days=1)).isoformat()


def _next_week():
    return (datetime.date.today() + datetime.timedelta(days=7)).isoformat()


class TestCatchUpAdvancesOverdueTasks:

    def test_overdue_daily_task_gets_advanced_past_today(self, ctm):
        tasks = [{"task_id": "t1", "schedule": "daily", "next_due": _yesterday()}]
        n = ctm.catch_up_all_due_tasks(tasks)
        assert n == 1
        assert tasks[0]["next_due"] > _today(ctm)

    def test_multiple_overdue_tasks_all_advanced(self, ctm):
        tasks = [
            {"task_id": "t1", "schedule": "daily", "next_due": _yesterday()},
            {"task_id": "t2", "schedule": "weekly", "next_due": _yesterday()},
        ]
        n = ctm.catch_up_all_due_tasks(tasks)
        assert n == 2
        for t in tasks:
            assert t["next_due"] > _today(ctm)

    def test_far_overdue_task_catches_up_in_one_call(self, ctm):
        """Same catch-up guarantee advance_next_due() already provides —
        a daily task overdue by 10 days should land strictly after today
        in a single call, not require 10 separate catch-up passes."""
        ten_days_ago = (datetime.date.today() - datetime.timedelta(days=10)).isoformat()
        tasks = [{"task_id": "t1", "schedule": "daily", "next_due": ten_days_ago}]
        ctm.catch_up_all_due_tasks(tasks)
        assert tasks[0]["next_due"] > _today(ctm)


class TestCatchUpDoesNotClaimCompletion:

    def test_marks_skipped_not_completed(self, ctm):
        tasks = [{"task_id": "t1", "schedule": "daily", "next_due": _yesterday()}]
        ctm.catch_up_all_due_tasks(tasks)
        assert tasks[0]["last_status"] == "skipped_on_enable"

    def test_does_not_set_last_run(self, ctm):
        """Unlike advance_next_due(), this never claims the task actually
        ran — last_run should be untouched (still absent/None)."""
        tasks = [{"task_id": "t1", "schedule": "daily", "next_due": _yesterday()}]
        ctm.catch_up_all_due_tasks(tasks)
        assert "last_run" not in tasks[0] or tasks[0]["last_run"] is None


class TestCatchUpIgnoresNonDueTasks:

    def test_not_yet_due_task_untouched(self, ctm):
        tasks = [{"task_id": "t1", "schedule": "weekly", "next_due": _next_week()}]
        n = ctm.catch_up_all_due_tasks(tasks)
        assert n == 0
        assert tasks[0]["next_due"] == _next_week()
        assert "last_status" not in tasks[0]

    def test_one_off_task_with_no_schedule_untouched(self, ctm):
        """schedule='none' tasks aren't recurring at all — nothing to
        catch up, regardless of next_due."""
        tasks = [{"task_id": "t1", "schedule": "none", "next_due": _yesterday()}]
        n = ctm.catch_up_all_due_tasks(tasks)
        assert n == 0
        assert "last_status" not in tasks[0]

    def test_task_with_no_next_due_untouched(self, ctm):
        tasks = [{"task_id": "t1", "schedule": "daily"}]
        n = ctm.catch_up_all_due_tasks(tasks)
        assert n == 0

    def test_empty_task_list_returns_zero(self, ctm):
        assert ctm.catch_up_all_due_tasks([]) == 0

    def test_mixed_list_only_advances_the_due_ones(self, ctm):
        tasks = [
            {"task_id": "due1",     "schedule": "daily",  "next_due": _yesterday()},
            {"task_id": "not_due1", "schedule": "weekly", "next_due": _next_week()},
            {"task_id": "manual1",  "schedule": "none",   "next_due": _yesterday()},
        ]
        n = ctm.catch_up_all_due_tasks(tasks)
        assert n == 1
        assert tasks[0]["last_status"] == "skipped_on_enable"
        assert "last_status" not in tasks[1]
        assert "last_status" not in tasks[2]


class TestCatchUpModifiesInPlace:

    def test_returns_int_count_not_the_list(self, ctm):
        tasks = [{"task_id": "t1", "schedule": "daily", "next_due": _yesterday()}]
        result = ctm.catch_up_all_due_tasks(tasks)
        assert isinstance(result, int)

    def test_does_not_call_save_itself(self, ctm, monkeypatch):
        """Caller is responsible for save_custom_tasks() — this function
        must not have its own save side effect, per its docstring."""
        save_calls = []
        monkeypatch.setattr(ctm, "save_custom_tasks", lambda tasks: save_calls.append(tasks))
        tasks = [{"task_id": "t1", "schedule": "daily", "next_due": _yesterday()}]
        ctm.catch_up_all_due_tasks(tasks)
        assert len(save_calls) == 0
