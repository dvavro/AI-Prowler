"""
tests/gui/test_scheduled_backup_date_logic.py
=================================================
Scheduled backup cadence control (Small Business tab, requested after
Job Board Architecture Spec Phase 8/8a). Tests the pure date-due logic
in most_recent_scheduled_backup_date() — the GUI wiring itself (Tkinter
widgets, config.json read/write) isn't unit-testable the same way, but
this is the actual decision logic that determines whether a backup is
due, so it's the part that most needs real coverage.

Run with:
    run_tests.bat tests\\gui\\test_scheduled_backup_date_logic.py -v
"""
from __future__ import annotations

import datetime
import sys
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parent.parent.parent
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from rag_gui import most_recent_scheduled_backup_date


# ══════════════════════════════════════════════════════════════════════════
# Weekly
# ══════════════════════════════════════════════════════════════════════════

def test_weekly_today_is_the_scheduled_day():
    # 2026-09-14 is a Monday (weekday 0).
    today = datetime.date(2026, 9, 14)
    result = most_recent_scheduled_backup_date('weekly', 0, 'end', today)
    assert result == today


def test_weekly_scheduled_day_already_passed_this_week():
    # Today is Thursday (weekday 3); scheduled day is Monday (0) —
    # most recent occurrence is 3 days ago.
    today = datetime.date(2026, 9, 17)  # Thursday
    result = most_recent_scheduled_backup_date('weekly', 0, 'end', today)
    assert result == datetime.date(2026, 9, 14)  # the Monday of that week


def test_weekly_scheduled_day_upcoming_uses_last_weeks_occurrence():
    # Today is Monday (0); scheduled day is Friday (4) — most recent
    # occurrence is LAST Friday, not this upcoming one.
    today = datetime.date(2026, 9, 14)  # Monday
    result = most_recent_scheduled_backup_date('weekly', 4, 'end', today)
    assert result == datetime.date(2026, 9, 11)  # the preceding Friday


def test_weekly_sunday_scheduled():
    # Sunday = weekday 6. Today is Sunday itself.
    today = datetime.date(2026, 9, 13)  # a Sunday
    result = most_recent_scheduled_backup_date('weekly', 6, 'end', today)
    assert result == today


# ══════════════════════════════════════════════════════════════════════════
# Monthly — start of month
# ══════════════════════════════════════════════════════════════════════════

def test_monthly_start_mid_month_uses_first_of_this_month():
    today = datetime.date(2026, 9, 14)
    result = most_recent_scheduled_backup_date('monthly', 0, 'start', today)
    assert result == datetime.date(2026, 9, 1)


def test_monthly_start_on_the_first_itself():
    today = datetime.date(2026, 9, 1)
    result = most_recent_scheduled_backup_date('monthly', 0, 'start', today)
    assert result == datetime.date(2026, 9, 1)


# ══════════════════════════════════════════════════════════════════════════
# Monthly — end of month
# ══════════════════════════════════════════════════════════════════════════

def test_monthly_end_mid_month_uses_last_months_end():
    # September 14 — the end of September hasn't happened yet, so the
    # most recent scheduled occurrence is August 31.
    today = datetime.date(2026, 9, 14)
    result = most_recent_scheduled_backup_date('monthly', 0, 'end', today)
    assert result == datetime.date(2026, 8, 31)


def test_monthly_end_on_the_last_day_itself():
    today = datetime.date(2026, 9, 30)
    result = most_recent_scheduled_backup_date('monthly', 0, 'end', today)
    assert result == datetime.date(2026, 9, 30)


def test_monthly_end_day_after_month_end_uses_this_months_end():
    # October 1 — September's end (Sept 30) just passed and is the most
    # recent occurrence.
    today = datetime.date(2026, 10, 1)
    result = most_recent_scheduled_backup_date('monthly', 0, 'end', today)
    assert result == datetime.date(2026, 9, 30)


def test_monthly_end_handles_february_leap_year():
    # 2028 is a leap year — Feb has 29 days.
    today = datetime.date(2028, 3, 5)
    result = most_recent_scheduled_backup_date('monthly', 0, 'end', today)
    assert result == datetime.date(2028, 2, 29)


def test_monthly_end_handles_february_non_leap_year():
    today = datetime.date(2026, 3, 5)
    result = most_recent_scheduled_backup_date('monthly', 0, 'end', today)
    assert result == datetime.date(2026, 2, 28)


# ══════════════════════════════════════════════════════════════════════════
# "Is it due" comparison logic (mirrors what _check_scheduled_backup does)
# ══════════════════════════════════════════════════════════════════════════

def test_due_when_last_run_before_scheduled_date():
    today = datetime.date(2026, 9, 14)  # Monday, scheduled weekly on Monday
    due_date = most_recent_scheduled_backup_date('weekly', 0, 'end', today)
    last_run = datetime.date(2026, 9, 7)  # last Monday
    assert due_date > last_run  # due


def test_not_due_when_already_run_for_this_occurrence():
    today = datetime.date(2026, 9, 14)
    due_date = most_recent_scheduled_backup_date('weekly', 0, 'end', today)
    last_run = today  # already ran today
    assert not (due_date > last_run)  # not due


def test_catch_up_after_being_closed_for_a_week():
    """The core 'catches up' promise made in the GUI's own help text —
    if the app was closed on the scheduled day and only opens days
    later, it must still recognize the backup is overdue."""
    scheduled_monday = datetime.date(2026, 9, 7)
    today = datetime.date(2026, 9, 14)  # a week later, also a Monday
    due_date = most_recent_scheduled_backup_date('weekly', 0, 'end', today)
    last_run = datetime.date(2026, 8, 31)  # from well before the missed occurrence
    assert due_date == today
    assert due_date > last_run  # still due — catches up
