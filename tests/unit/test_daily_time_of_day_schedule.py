"""
tests/unit/test_daily_time_of_day_schedule.py
================================================
Tests for the v8.1.11 "Daily with start/end time-of-day and N times per
day" feature — the core date/time engine in custom_tasks_manager.py.

Design: Daily gains an optional start time, end time, and times-per-day
count. 1 = classic once-daily at start time. N > 1 spreads N runs evenly
across [start, end] INCLUSIVE of both endpoints (first run exactly at
start, last run exactly at end) -- confirmed with David: "24 times/day
between 00:00-23:00" is how "hourly" ends up expressed; there's no
separate Hourly schedule key. Capped at MAX_DAILY_TIMES_PER_DAY (24).

Weekly/biweekly/monthly/quarterly/yearly remain date-only, unaffected --
covered here just enough to confirm the shared functions
(is_queue_entry_ready, _is_due, advance_next_due_for_task) still handle
them correctly alongside the new daily datetime logic.
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


# ---------------------------------------------------------------------------
# compute_daily_run_times()
# ---------------------------------------------------------------------------

class TestComputeDailyRunTimes:

    def test_times_per_day_one_returns_just_start(self, ctm):
        assert ctm.compute_daily_run_times("08:00", "20:00", 1) == ["08:00"]

    def test_times_per_day_one_ignores_end_time_entirely(self, ctm):
        # end_time is irrelevant when times_per_day == 1 -- confirm it
        # doesn't leak into the result even if nonsensical (end < start).
        assert ctm.compute_daily_run_times("08:00", "01:00", 1) == ["08:00"]

    def test_three_times_per_day_hits_both_endpoints_exactly(self, ctm):
        assert ctm.compute_daily_run_times("08:00", "20:00", 3) == \
            ["08:00", "14:00", "20:00"]

    def test_two_times_per_day_is_start_and_end_only(self, ctm):
        assert ctm.compute_daily_run_times("09:00", "17:00", 2) == \
            ["09:00", "17:00"]

    def test_five_times_per_day_even_spacing(self, ctm):
        # 08:00-20:00 = 720 min span, /4 = 180 min (3h) steps
        assert ctm.compute_daily_run_times("08:00", "20:00", 5) == \
            ["08:00", "11:00", "14:00", "17:00", "20:00"]

    def test_24_times_per_day_00_to_23_is_exactly_hourly(self, ctm):
        # The documented convention for "hourly, all day" -- no separate
        # Hourly schedule key, Daily generalizes to cover it exactly.
        result = ctm.compute_daily_run_times("00:00", "23:00", 24)
        assert len(result) == 24
        assert result[0] == "00:00"
        assert result[-1] == "23:00"
        assert result[1] == "01:00"
        assert result[12] == "12:00"

    def test_same_start_and_end_with_multiple_times_collapses_to_one_point(self, ctm):
        # Degenerate but shouldn't crash -- all N "slots" land on the same
        # minute since span is 0.
        result = ctm.compute_daily_run_times("12:00", "12:00", 4)
        assert all(t == "12:00" for t in result)

    def test_zero_or_negative_times_per_day_clamped_to_one(self, ctm):
        assert ctm.compute_daily_run_times("08:00", "20:00", 0) == ["08:00"]
        assert ctm.compute_daily_run_times("08:00", "20:00", -5) == ["08:00"]


class TestFormatDailyRunTimesPreview:
    """v8.1.11: shared by both the Custom and Common Business dialogs, so
    they can never drift out of sync with each other on what a given
    Start/End/Times-per-day combination actually produces."""

    def test_single_run_preview(self, ctm):
        assert ctm.format_daily_run_times_preview("09:00", "17:00", 1) == "Runs at: 09:00"

    def test_multiple_runs_preview(self, ctm):
        assert ctm.format_daily_run_times_preview("08:00", "20:00", 3) == \
            "Runs at: 08:00, 14:00, 20:00"

    def test_invalid_input_returns_empty_string_not_crash(self, ctm):
        # times_per_day > 1 is required to actually exercise the time
        # parsing path -- with times_per_day == 1, compute_daily_run_times
        # returns [start_time] verbatim without ever parsing it.
        assert ctm.format_daily_run_times_preview("not-a-time", "17:00", 3) == ""
        assert ctm.format_daily_run_times_preview("09:00", "17:00", "abc") == ""

    def test_string_times_per_day_coerced_to_int(self, ctm):
        # GUI text fields hand this in as a raw string -- must work the
        # same as a real int.
        assert ctm.format_daily_run_times_preview("08:00", "20:00", "3") == \
            "Runs at: 08:00, 14:00, 20:00"


# ---------------------------------------------------------------------------
# _parse_due_datetime()
# ---------------------------------------------------------------------------

class TestParseDueDatetime:

    def test_bare_date_treated_as_midnight(self, ctm):
        result = ctm._parse_due_datetime("2026-07-26")
        assert result == datetime.datetime(2026, 7, 26, 0, 0, 0)

    def test_full_datetime_parses_exactly(self, ctm):
        result = ctm._parse_due_datetime("2026-07-26T14:30:00")
        assert result == datetime.datetime(2026, 7, 26, 14, 30, 0)


# ---------------------------------------------------------------------------
# _first_daily_datetime()
# ---------------------------------------------------------------------------

class TestFirstDailyDatetime:

    def test_combines_first_due_with_start_time(self, ctm):
        result = ctm._first_daily_datetime("2026-07-26", "08:00", "20:00", 3)
        assert result == "2026-07-26T08:00:00"

    def test_once_daily_uses_start_time_regardless_of_end(self, ctm):
        result = ctm._first_daily_datetime("2026-07-26", "09:00", "17:00", 1)
        assert result == "2026-07-26T09:00:00"


# ---------------------------------------------------------------------------
# _advance_daily_datetime_catchup()
# ---------------------------------------------------------------------------

class TestAdvanceDailyDatetimeCatchup:

    def test_advances_to_next_slot_same_day(self, ctm):
        anchor = "2026-07-26T08:00:00"
        now = datetime.datetime(2026, 7, 26, 9, 0, 0)  # between 08:00 and 14:00
        result = ctm._advance_daily_datetime_catchup(
            anchor, "08:00", "20:00", 3, now=now)
        assert result == "2026-07-26T14:00:00"

    def test_rolls_to_next_day_when_past_last_slot(self, ctm):
        anchor = "2026-07-26T08:00:00"
        now = datetime.datetime(2026, 7, 26, 21, 0, 0)  # after 20:00, last slot
        result = ctm._advance_daily_datetime_catchup(
            anchor, "08:00", "20:00", 3, now=now)
        assert result == "2026-07-27T08:00:00"

    def test_catchup_across_multiple_missed_days(self, ctm):
        # Anchor is 3 days stale -- should resync directly to the next
        # slot after "now", not require one completion per missed day.
        anchor = "2026-07-20T08:00:00"
        now = datetime.datetime(2026, 7, 26, 10, 0, 0)
        result = ctm._advance_daily_datetime_catchup(
            anchor, "08:00", "20:00", 3, now=now)
        assert result == "2026-07-26T14:00:00"

    def test_once_daily_advances_to_tomorrow_when_run_today(self, ctm):
        anchor = "2026-07-26T09:00:00"
        now = datetime.datetime(2026, 7, 26, 9, 30, 0)  # just completed
        result = ctm._advance_daily_datetime_catchup(
            anchor, "09:00", "17:00", 1, now=now)
        assert result == "2026-07-27T09:00:00"

    def test_defaults_now_to_real_current_time_when_omitted(self, ctm):
        # Just confirm it doesn't crash and returns something in the future
        # relative to a very old anchor, without needing to mock "now".
        anchor = "2020-01-01T08:00:00"
        result = ctm._advance_daily_datetime_catchup(anchor, "08:00", "20:00", 1)
        assert ctm._parse_due_datetime(result) > datetime.datetime.now()


# ---------------------------------------------------------------------------
# advance_next_due_for_task() -- unified dispatch
# ---------------------------------------------------------------------------

class TestAdvanceNextDueForTaskDispatch:

    def test_daily_schedule_uses_datetime_aware_advancement(self, ctm):
        task = {
            "schedule": "daily", "next_due": "2026-07-26T08:00:00",
            "daily_start_time": "08:00", "daily_end_time": "20:00",
            "daily_times_per_day": 3,
        }
        result = ctm.advance_next_due_for_task(task, today_str="2026-07-26")
        assert "T" in result  # datetime, not bare date

    def test_weekly_schedule_still_uses_classic_date_only_advancement(self, ctm):
        task = {"schedule": "weekly", "next_due": "2026-07-26"}
        result = ctm.advance_next_due_for_task(task, today_str="2026-07-26")
        assert result == "2026-08-02"
        assert "T" not in result

    def test_none_schedule_returns_none(self, ctm):
        task = {"schedule": "none", "next_due": "2026-07-26"}
        assert ctm.advance_next_due_for_task(task) is None

    def test_missing_next_due_returns_none(self, ctm):
        task = {"schedule": "daily", "next_due": None}
        assert ctm.advance_next_due_for_task(task) is None

    def test_daily_missing_daily_fields_falls_back_to_documented_defaults(self, ctm):
        # A legacy daily task with no daily_* keys at all shouldn't crash --
        # falls back to the documented defaults (09:00-17:00, once/day).
        # Anchored relative to the real current moment (not a hardcoded
        # date) so this doesn't silently go stale as real wall-clock time
        # passes across a long session or between test runs.
        anchor = (datetime.datetime.now() - datetime.timedelta(days=5)).strftime("%Y-%m-%dT09:00:00")
        task = {"schedule": "daily", "next_due": anchor}
        result = ctm.advance_next_due_for_task(task)
        result_dt = ctm._parse_due_datetime(result)
        assert result_dt > datetime.datetime.now()
        assert result_dt.strftime("%H:%M:%S") == "09:00:00"


# ---------------------------------------------------------------------------
# is_queue_entry_ready() / _is_due() -- daily time-of-day awareness
# ---------------------------------------------------------------------------

class TestDueCheckingWithDailyTimeOfDay:

    def test_entry_not_ready_before_its_time_today(self, ctm, monkeypatch):
        # next_due is later today -- must NOT be ready yet.
        future = (datetime.datetime.now() + datetime.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
        entry = {"schedule": "daily", "next_due": future}
        assert ctm.is_queue_entry_ready(entry) is False

    def test_entry_ready_once_its_time_has_passed(self, ctm):
        past = (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S")
        entry = {"schedule": "daily", "next_due": past}
        assert ctm.is_queue_entry_ready(entry) is True

    def test_bare_date_schedules_still_work_as_before(self, ctm):
        # weekly/monthly/etc with a bare YYYY-MM-DD next_due -- confirms
        # the switch to datetime.now() comparison didn't break date-only
        # schedules (today's bare date == midnight, always <= now).
        today = datetime.date.today().isoformat()
        entry = {"schedule": "weekly", "next_due": today}
        assert ctm.is_queue_entry_ready(entry) is True

    def test_future_bare_date_not_ready(self, ctm):
        tomorrow = (datetime.date.today() + datetime.timedelta(days=1)).isoformat()
        entry = {"schedule": "monthly", "next_due": tomorrow}
        assert ctm.is_queue_entry_ready(entry) is False


# ---------------------------------------------------------------------------
# create_task() -- daily_* validation and next_due seeding
# ---------------------------------------------------------------------------

class TestCreateTaskDailyValidation:

    def test_daily_default_once_per_day_at_9am(self, ctm, monkeypatch):
        monkeypatch.setattr(ctm, "load_custom_tasks", lambda: [])
        t = ctm.create_task(label="T", prompt="x", schedule="daily",
                             first_due="2026-07-26")
        assert t["next_due"] == "2026-07-26T09:00:00"
        assert t["daily_times_per_day"] == 1

    def test_daily_with_times_per_day_seeds_first_slot(self, ctm, monkeypatch):
        monkeypatch.setattr(ctm, "load_custom_tasks", lambda: [])
        t = ctm.create_task(label="T", prompt="x", schedule="daily",
                             first_due="2026-07-26",
                             daily_start_time="08:00", daily_end_time="20:00",
                             daily_times_per_day=3)
        assert t["next_due"] == "2026-07-26T08:00:00"

    def test_times_per_day_over_max_rejected(self, ctm, monkeypatch):
        monkeypatch.setattr(ctm, "load_custom_tasks", lambda: [])
        with pytest.raises(ValueError, match="between 1 and"):
            ctm.create_task(label="T", prompt="x", schedule="daily",
                             first_due="2026-07-26",
                             daily_times_per_day=ctm.MAX_DAILY_TIMES_PER_DAY + 1)

    def test_times_per_day_25_specifically_rejected(self, ctm, monkeypatch):
        # The exact practical limit requested: no more than 24/day.
        monkeypatch.setattr(ctm, "load_custom_tasks", lambda: [])
        with pytest.raises(ValueError):
            ctm.create_task(label="T", prompt="x", schedule="daily",
                             first_due="2026-07-26", daily_times_per_day=25)

    def test_times_per_day_24_is_allowed(self, ctm, monkeypatch):
        monkeypatch.setattr(ctm, "load_custom_tasks", lambda: [])
        t = ctm.create_task(label="T", prompt="x", schedule="daily",
                             first_due="2026-07-26",
                             daily_start_time="00:00", daily_end_time="23:00",
                             daily_times_per_day=24)
        assert t["daily_times_per_day"] == 24

    def test_end_time_before_start_time_rejected_when_multiple_per_day(self, ctm, monkeypatch):
        monkeypatch.setattr(ctm, "load_custom_tasks", lambda: [])
        with pytest.raises(ValueError, match="End time must be after start time"):
            ctm.create_task(label="T", prompt="x", schedule="daily",
                             first_due="2026-07-26",
                             daily_start_time="20:00", daily_end_time="08:00",
                             daily_times_per_day=3)

    def test_end_time_before_start_time_allowed_when_once_per_day(self, ctm, monkeypatch):
        # end_time is irrelevant when times_per_day == 1, so a "backwards"
        # end time shouldn't block creation.
        monkeypatch.setattr(ctm, "load_custom_tasks", lambda: [])
        t = ctm.create_task(label="T", prompt="x", schedule="daily",
                             first_due="2026-07-26",
                             daily_start_time="20:00", daily_end_time="08:00",
                             daily_times_per_day=1)
        assert t["next_due"] == "2026-07-26T20:00:00"

    def test_invalid_start_time_format_rejected(self, ctm, monkeypatch):
        monkeypatch.setattr(ctm, "load_custom_tasks", lambda: [])
        with pytest.raises(ValueError, match="Invalid start time"):
            ctm.create_task(label="T", prompt="x", schedule="daily",
                             first_due="2026-07-26", daily_start_time="9am")

    def test_non_daily_schedule_ignores_daily_fields_entirely(self, ctm, monkeypatch):
        # Weekly task with nonsensical daily_* values shouldn't be
        # validated at all -- those fields are simply irrelevant.
        monkeypatch.setattr(ctm, "load_custom_tasks", lambda: [])
        t = ctm.create_task(label="T", prompt="x", schedule="weekly",
                             first_due="2026-07-26",
                             daily_times_per_day=999)
        assert t["next_due"] == "2026-07-26"


# ---------------------------------------------------------------------------
# update_task() -- daily_* change detection and next_due recompute
# ---------------------------------------------------------------------------

class TestUpdateTaskDailyFieldChanges:

    def test_changing_times_per_day_resets_next_due(self, ctm):
        tasks = [{
            "task_id": "t1", "schedule": "daily",
            "first_due": "2026-07-26", "next_due": "2026-07-30T09:00:00",
            "daily_start_time": "09:00", "daily_end_time": "17:00",
            "daily_times_per_day": 1, "output_learnings": True,
        }]
        ok = ctm.update_task(tasks, "t1", daily_times_per_day=3,
                              daily_end_time="20:00")
        assert ok is True
        # Resets to first_due's date at the NEW first slot (start_time
        # unchanged at 09:00, since only times_per_day/end_time changed).
        assert tasks[0]["next_due"] == "2026-07-26T09:00:00"

    def test_changing_only_start_time_resets_next_due(self, ctm):
        tasks = [{
            "task_id": "t1", "schedule": "daily",
            "first_due": "2026-07-26", "next_due": "2026-07-30T09:00:00",
            "daily_start_time": "09:00", "daily_end_time": "17:00",
            "daily_times_per_day": 1, "output_learnings": True,
        }]
        ok = ctm.update_task(tasks, "t1", daily_start_time="06:00")
        assert ok is True
        assert tasks[0]["next_due"] == "2026-07-26T06:00:00"

    def test_unrelated_edit_leaves_daily_next_due_untouched(self, ctm):
        tasks = [{
            "task_id": "t1", "schedule": "daily",
            "first_due": "2026-07-26", "next_due": "2026-07-30T09:00:00",
            "daily_start_time": "09:00", "daily_end_time": "17:00",
            "daily_times_per_day": 1, "output_learnings": True,
        }]
        ok = ctm.update_task(tasks, "t1", label="renamed")
        assert ok is True
        assert tasks[0]["next_due"] == "2026-07-30T09:00:00"

    def test_resulting_times_per_day_over_max_rejected(self, ctm):
        tasks = [{
            "task_id": "t1", "schedule": "daily",
            "first_due": "2026-07-26", "next_due": "2026-07-26T09:00:00",
            "daily_start_time": "09:00", "daily_end_time": "17:00",
            "daily_times_per_day": 1, "output_learnings": True,
        }]
        with pytest.raises(ValueError, match="between 1 and"):
            ctm.update_task(tasks, "t1", daily_times_per_day=30)


# ---------------------------------------------------------------------------
# due_status_label() -- real-world bug: this returned "Unknown" for every
# daily task, because it used _parse_date() (bare YYYY-MM-DD only), which
# raises on the full datetime next_due values the daily-time-of-day
# feature actually produces (e.g. "2026-07-26T14:00:00"). Reported live:
# "Check NSB" (daily, 2x/day) showed "Unknown" in the My Custom AI
# Analyses list instead of a real due status.
# ---------------------------------------------------------------------------

class TestDueStatusLabelDailyTimeAware:

    def test_daily_due_now_shows_due_now_not_unknown(self, ctm):
        past = (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S")
        task = {"schedule": "daily", "next_due": past}
        assert ctm.due_status_label(task) == "⚡ Due now"

    def test_daily_due_later_today_shows_time(self, ctm):
        future = (datetime.datetime.now() + datetime.timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S")
        task = {"schedule": "daily", "next_due": future}
        result = ctm.due_status_label(task)
        assert result != "Unknown"
        assert "today at" in result

    def test_daily_due_tomorrow_shows_tomorrow_and_time(self, ctm):
        tomorrow = (datetime.datetime.now() + datetime.timedelta(days=1)).strftime("%Y-%m-%dT09:00:00")
        task = {"schedule": "daily", "next_due": tomorrow}
        result = ctm.due_status_label(task)
        assert result != "Unknown"
        assert "tomorrow at" in result

    def test_daily_due_further_out_shows_date_and_time(self, ctm):
        future = (datetime.datetime.now() + datetime.timedelta(days=5)).strftime("%Y-%m-%dT08:00:00")
        task = {"schedule": "daily", "next_due": future}
        result = ctm.due_status_label(task)
        assert result != "Unknown"
        assert " at " in result

    def test_weekly_bare_date_behavior_unchanged(self, ctm):
        # Confirms the fix didn't disturb existing date-only schedules --
        # same exact output format as before.
        tomorrow = (datetime.date.today() + datetime.timedelta(days=1)).isoformat()
        task = {"schedule": "weekly", "next_due": tomorrow}
        assert ctm.due_status_label(task) == "Due tomorrow"

    def test_weekly_overdue_bare_date_unchanged(self, ctm):
        past = (datetime.date.today() - datetime.timedelta(days=3)).isoformat()
        task = {"schedule": "monthly", "next_due": past}
        assert ctm.due_status_label(task) == "⚠ Overdue 3 days"

    def test_manual_only_unaffected(self, ctm):
        assert ctm.due_status_label({"schedule": "none"}) == "Manual only"

    def test_not_scheduled_unaffected(self, ctm):
        assert ctm.due_status_label({"schedule": "weekly", "next_due": None}) == "Not scheduled"
