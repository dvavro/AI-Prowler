"""2026-10-22 — found by the time-machine task-queue story (test_tm_task_queue.py
TQ-11): a custom analysis pinned to a weekday (e.g. "monthly, Tuesday") ran on
its first Tuesday, but completing it from the queue (complete_analysis_task ->
advance_next_due_for_task) dropped the pin, so the next run moved to the same
date next month — Tue 2027-03-02 -> Fri 2027-04-02. The pin must be kept.
"""
import datetime as dt
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import custom_tasks_manager as ctm  # noqa: E402


@pytest.mark.parametrize("schedule,anchor,dow,expected", [
    ("monthly", "2027-03-02", 1, "2027-04-06"),    # Tue -> first Tue on/after Apr 2
    ("monthly", "2026-11-03", 1, "2026-12-08"),    # Tue -> Dec 3 is Thu -> Tue Dec 8
    ("weekly", "2027-01-06", 2, "2027-01-13"),     # Wed stays Wed
    ("biweekly", "2027-01-06", 2, "2027-01-20"),
])
def test_completion_keeps_the_weekday_pin(schedule, anchor, dow, expected):
    nxt = ctm.advance_next_due_for_task(
        {"schedule": schedule, "next_due": anchor, "schedule_day_of_week": dow}, anchor)
    assert nxt == expected
    assert dt.date.fromisoformat(nxt).weekday() == dow


def test_unpinned_monthly_is_unchanged():
    assert ctm.advance_next_due_for_task(
        {"schedule": "monthly", "next_due": "2027-03-02", "schedule_day_of_week": None},
        "2027-03-02") == "2027-04-02"
    assert ctm.advance_next_due_for_task(
        {"schedule": "monthly", "next_due": "2027-03-02"}, "2027-03-02") == "2027-04-02"


def test_complete_analysis_task_passes_the_pin():
    src = (Path(__file__).resolve().parents[2] / "ai_prowler_mcp.py").read_text(encoding="utf-8")
    i = src.index("def complete_analysis_task(")
    body = src[i:src.index("\n@mcp.tool()", i)]
    assert '"schedule_day_of_week": _daily_source.get("schedule_day_of_week")' in body
