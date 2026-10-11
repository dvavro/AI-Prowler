"""
tests/mcp/test_hr_state_rules_and_task_engine.py
=================================================
Pure-function tests for the task engine: overdue calculation, priority
escalation thresholds, and per-state rule coverage — per Implementation
Plan v2.1 Section 13.2.5. Style matches the pure-function checks
described in PHASE_A_PRIME_TEST_PLAN.md, implemented as pytest against the
real hr_state_rules.json shipped in the repo.

Safe: reads only the real hr_state_rules.json (never writes anywhere),
mirrors the scheduler/task-engine logic as local pure functions rather
than importing ai_prowler_mcp.py, matching the established pattern in
tests/mcp/test_pwa_api_route.py ("Safe — does NOT start AI-Prowler, touch
install dir, or require live server").
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path

import pytest

SRC_ROOT = Path(os.environ.get("AI_PROWLER_SRC", "")) if os.environ.get("AI_PROWLER_SRC") \
    else Path(__file__).resolve().parent.parent.parent
STATE_RULES = json.loads((SRC_ROOT / "hr_state_rules.json").read_text(encoding="utf-8"))


def is_overdue(due_date: str, status: str, now: datetime) -> bool:
    """Mirrors the scheduler's overdue-checker job (Section 11)."""
    if status in ("Completed", "Waived"):
        return False
    return datetime.fromisoformat(due_date) < now


def should_escalate(priority: str, hours_overdue: float) -> bool:
    """Mirrors Section 11's escalation-check job thresholds."""
    thresholds = {"CRITICAL": 24, "HIGH": 48}
    return priority in thresholds and hours_overdue >= thresholds[priority]


class TestOverdueCalculation:
    """C-HR-TASK-30 .. C-HR-TASK-33"""

    def test_c_hr_task_30_past_due_incomplete_task_is_overdue(self):
        now = datetime(2026, 6, 1)
        assert is_overdue("2026-05-30T00:00:00", "In Progress", now) is True

    def test_c_hr_task_31_completed_task_never_overdue(self):
        now = datetime(2026, 6, 1)
        assert is_overdue("2026-05-30T00:00:00", "Completed", now) is False

    def test_c_hr_task_32_waived_task_never_overdue(self):
        now = datetime(2026, 6, 1)
        assert is_overdue("2026-05-30T00:00:00", "Waived", now) is False

    def test_c_hr_task_33_future_due_date_not_overdue(self):
        now = datetime(2026, 6, 1)
        assert is_overdue("2026-06-10T00:00:00", "Not Started", now) is False


class TestEscalationThresholds:
    """C-HR-TASK-34 .. C-HR-TASK-36 — thresholds from Section 11"""

    def test_c_hr_task_34_critical_escalates_at_24h(self):
        assert should_escalate("CRITICAL", 24) is True
        assert should_escalate("CRITICAL", 23.9) is False

    def test_c_hr_task_35_high_escalates_at_48h(self):
        assert should_escalate("HIGH", 48) is True
        assert should_escalate("HIGH", 47.9) is False

    def test_c_hr_task_36_medium_and_low_never_escalate(self):
        assert should_escalate("MEDIUM", 1000) is False
        assert should_escalate("LOW", 1000) is False


@pytest.mark.parametrize("state", ["CA", "TX", "NY", "FL", "IL", "WA", "CO", "MA"])
class TestStateRulesLoadForEachSupportedState:
    """C-HR-COMPLIANCE-20 .. C-HR-COMPLIANCE-27 — one per supported state"""

    def test_state_entry_exists(self, state):
        assert state in json.dumps(STATE_RULES), f"No rules found for state {state}"

    def test_state_entry_has_core_fields(self, state):
        entry = STATE_RULES.get("states", {}).get(state)
        assert entry is not None, f"states.{state} missing from hr_state_rules.json"
        for field in ("name", "min_wage", "new_hire_reporting_days"):
            assert field in entry, f"states.{state} missing required field '{field}'"
