"""
tests/unit/test_update_task_schedule_retention.py
====================================================
Tests for custom_tasks_manager.update_task()'s next_due recompute logic —
v8.1.9 fix. Regression coverage for the bug where editing a task's
schedule or first_due date had no visible effect, because the old code
only ever moved next_due FORWARD (comparing the incoming first_due,
usually unchanged since the dialog pre-fills it, against the already-
advanced next_due).
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


def _today():
    return datetime.date.today().isoformat()


def _in_days(n):
    return (datetime.date.today() + datetime.timedelta(days=n)).isoformat()


class TestScheduleChangeRecomputesNextDue:

    def test_changing_schedule_key_resets_next_due_to_first_due(self, ctm):
        # A weekly task that has already advanced several cycles ahead —
        # edited to Daily, with first_due left at its original value (as
        # the GUI pre-fills it). next_due must reset to first_due, not
        # stay frozen at the old weekly-advanced date.
        tasks = [{
            "task_id": "t1", "schedule": "weekly",
            "first_due": "2026-06-23", "next_due": "2026-08-04",
            "output_learnings": True,
        }]
        ok = ctm.update_task(tasks, "t1", schedule="daily",
                              first_due="2026-06-23")
        assert ok is True
        assert tasks[0]["schedule"] == "daily"
        # v8.1.11: "daily" now produces a datetime next_due (date + the
        # default daily_start_time, since none was passed here) rather
        # than a bare date — this fixture has no daily_start_time key, so
        # it falls back to the documented default of "09:00".
        assert tasks[0]["next_due"] == "2026-06-23T09:00:00"

    def test_changing_first_due_to_earlier_date_takes_effect(self, ctm):
        # Old bug: a first_due EARLIER than the stored next_due was
        # ignored entirely (comparison only fired when later).
        tasks = [{
            "task_id": "t2", "schedule": "monthly",
            "first_due": "2026-07-01", "next_due": "2026-08-01",
            "output_learnings": True,
        }]
        ok = ctm.update_task(tasks, "t2", schedule="monthly",
                              first_due="2026-07-15")
        assert ok is True
        assert tasks[0]["next_due"] == "2026-07-15"

    def test_switching_from_none_to_scheduled_sets_next_due(self, ctm):
        tasks = [{
            "task_id": "t3", "schedule": "none",
            "first_due": None, "next_due": None,
            "output_learnings": True,
        }]
        ok = ctm.update_task(tasks, "t3", schedule="weekly",
                              first_due="2026-08-01")
        assert ok is True
        assert tasks[0]["next_due"] == "2026-08-01"

    def test_switching_to_none_clears_next_due(self, ctm):
        tasks = [{
            "task_id": "t4", "schedule": "weekly",
            "first_due": "2026-06-23", "next_due": "2026-08-04",
            "output_learnings": True,
        }]
        ok = ctm.update_task(tasks, "t4", schedule="none")
        assert ok is True
        assert tasks[0]["next_due"] is None


class TestUnrelatedEditsDoNotResetNextDue:

    def test_editing_only_prompt_leaves_next_due_untouched(self, ctm):
        tasks = [{
            "task_id": "t5", "schedule": "weekly",
            "first_due": "2026-06-23", "next_due": "2026-08-04",
            "prompt": "old prompt", "output_learnings": True,
        }]
        ok = ctm.update_task(tasks, "t5", prompt="new prompt")
        assert ok is True
        assert tasks[0]["prompt"] == "new prompt"
        # next_due must NOT regress to first_due just because an
        # unrelated field changed.
        assert tasks[0]["next_due"] == "2026-08-04"

    def test_editing_output_options_leaves_next_due_untouched(self, ctm):
        tasks = [{
            "task_id": "t6", "schedule": "daily",
            "first_due": "2026-07-01", "next_due": "2026-07-20",
        }]
        ok = ctm.update_task(tasks, "t6", output_report=True)
        assert ok is True
        assert tasks[0]["next_due"] == "2026-07-20"

    def test_resaving_same_schedule_and_first_due_leaves_next_due_untouched(self, ctm):
        # The common real-world case: editor dialog resubmits the SAME
        # schedule + first_due the task already had (nothing actually
        # changed in those two fields) — next_due must stay put.
        tasks = [{
            "task_id": "t7", "schedule": "weekly",
            "first_due": "2026-06-23", "next_due": "2026-08-04",
            "output_learnings": True,
        }]
        ok = ctm.update_task(tasks, "t7", schedule="weekly",
                              first_due="2026-06-23", label="renamed")
        assert ok is True
        assert tasks[0]["next_due"] == "2026-08-04"


class TestEdgeCases:

    def test_task_with_no_prior_next_due_gets_seeded(self, ctm):
        # Defensive case: schedule/first_due unchanged in kwargs, but
        # next_due was somehow missing/null — should still get seeded
        # rather than staying null forever.
        tasks = [{
            "task_id": "t8", "schedule": "weekly",
            "first_due": "2026-06-23", "next_due": None,
            "output_learnings": True,
        }]
        ok = ctm.update_task(tasks, "t8", label="renamed only")
        assert ok is True
        assert tasks[0]["next_due"] == "2026-06-23"

    def test_unknown_task_id_returns_false(self, ctm):
        tasks = [{"task_id": "real", "schedule": "none"}]
        ok = ctm.update_task(tasks, "does-not-exist", label="x")
        assert ok is False
