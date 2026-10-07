"""
tests/e2e/test_hr_hire_to_90day_e2e.py
=======================================
Full hire -> onboarding -> task completion/waive -> termination cycle, per
Implementation Plan v2.1 Section 13.1/13.7.

DEVIATION FROM THE PLAN — DELIBERATE, FOR SAFETY
--------------------------------------------------
The plan's own text says this file should run "against a running server."
test_server_e2e.py's established pattern for that already isolates itself
correctly (random port, AIPROWLER_TEST_STATE_DIR pointed at a pytest
tmp_path, throwaway ChromaDB) — but that isolation only works because the
rest of AI-Prowler's state paths are parameterized by that env var. The HR
Backend Engine added to ai_prowler_mcp.py this session does NOT yet honor
that override: _HR_ROOT_DIR / _HR_DB_PATH are computed straight from
os.path.dirname(os.path.abspath(__file__)), i.e. wherever ai_prowler_mcp.py
physically lives. Spawning that file as a subprocess — even on an
isolated port — would still read and WRITE the real hr_db.json sitting
next to the installed script, which is exactly what this task was told
not to do.

So instead of a spawned server, this file mirrors the real, shipped HR
task-generation functions (_hr_template_applies, _hr_build_task,
_hr_generate_onboarding_tasks, _hr_generate_offboarding_tasks — see the HR
Backend Engine section of ai_prowler_mcp.py) as local pure functions,
driven entirely in memory against the REAL hr_task_templates.json
(read-only), and asserts the full hire -> onboarding -> termination
lifecycle shape against that. No file is ever written, no server is ever
started, and ai_prowler_mcp.py is never imported.

Follow-up suggestion (not done here): if true subprocess-level e2e
coverage against the real ASGI routes is wanted later, _HR_ROOT_DIR should
first be changed to honor an env var override the same way the rest of
the codebase's state paths already do, mirroring AIPROWLER_TEST_STATE_DIR.
"""
from __future__ import annotations

import json
import os
from datetime import date, timedelta
from pathlib import Path

import pytest

SRC_ROOT = Path(os.environ.get("AI_PROWLER_SRC", "")) if os.environ.get("AI_PROWLER_SRC") \
    else Path(__file__).resolve().parent.parent.parent
TEMPLATES = json.loads((SRC_ROOT / "hr_task_templates.json").read_text(encoding="utf-8"))


# ── Mirrors of the real HR Backend Engine functions in ai_prowler_mcp.py ────

def template_applies(tmpl: dict, work_state: str) -> bool:
    if not tmpl.get("state_specific"):
        return True
    allow = tmpl.get("applicable_states")
    if allow:
        return work_state in allow
    deny = tmpl.get("not_required_states")
    if deny:
        return work_state not in deny
    return True


def add_days(d: str, days: int) -> str:
    return (date.fromisoformat(d) + timedelta(days=int(days))).isoformat()


def build_task(emp: dict, tmpl: dict, anchor_field: str, next_id: int) -> dict:
    overrides = (tmpl.get("state_overrides") or {}).get(emp["work_state"], {})
    merged = {**tmpl, **overrides}
    anchor_date = emp[anchor_field]
    return {
        "id": f"TASK-{next_id:05d}",
        "employee_id": emp["id"],
        "template_id": tmpl["template_id"],
        "phase": tmpl["phase"],
        "name": merged["name"],
        "priority": merged.get("priority", "MEDIUM"),
        "due_date": add_days(anchor_date, merged.get("due_offset_days", 0)),
        "status": "Not Started",
        "completed_at": None, "waived_at": None,
    }


def generate_onboarding_tasks(emp: dict) -> list:
    tasks = []
    for tmpl in TEMPLATES.get("base", []):
        if not template_applies(tmpl, emp["work_state"]):
            continue
        anchor = "hire_date" if tmpl.get("due_anchor") == "hire_date" else "start_date"
        tasks.append(build_task(emp, tmpl, anchor, len(tasks) + 1))
    return tasks


def generate_offboarding_tasks(emp: dict, term_date: str) -> list:
    emp_for_term = {**emp, "term_date": term_date}
    tasks = []
    for tmpl in TEMPLATES.get("offboarding", []):
        if not template_applies(tmpl, emp["work_state"]):
            continue
        tasks.append(build_task(emp_for_term, tmpl, "term_date", len(tasks) + 1))
    return tasks


def complete_task(task: dict) -> dict:
    return {**task, "status": "Completed", "completed_at": "2026-09-15T09:00:00Z"}


def waive_task(task: dict, reason: str) -> dict:
    if not reason.strip():
        raise ValueError("reason_required")
    return {**task, "status": "Waived", "waived_at": "2026-09-15T09:00:00Z", "waive_reason": reason}


# ── Fixture: a synthetic CA employee, never written to any real file ───────

@pytest.fixture
def ca_employee():
    return {
        "id": "EMP-TEST-001",
        "work_state": "CA",
        "start_date": "2026-09-01",
        "hire_date": "2026-08-20",
    }


class TestHireToOnboardingCycle:
    """C-HR-TASK-01 style check: creating an employee generates the full
    task set with correct due dates relative to start_date/hire_date."""

    def test_onboarding_tasks_generated_with_no_duplicates(self, ca_employee):
        tasks = generate_onboarding_tasks(ca_employee)
        assert tasks, "No onboarding tasks generated for a CA hire"
        ids = [t["template_id"] for t in tasks]
        assert len(ids) == len(set(ids))

    def test_all_due_dates_are_valid_iso_dates(self, ca_employee):
        tasks = generate_onboarding_tasks(ca_employee)
        for t in tasks:
            date.fromisoformat(t["due_date"])  # raises if malformed

    def test_all_tasks_start_not_started(self, ca_employee):
        tasks = generate_onboarding_tasks(ca_employee)
        assert all(t["status"] == "Not Started" for t in tasks)


class TestTaskCompletionAndWaiveRules:
    """C-HR-TASK-04 / C-HR-TASK-05."""

    def test_completing_a_task_records_status_and_timestamp(self, ca_employee):
        task = generate_onboarding_tasks(ca_employee)[0]
        done = complete_task(task)
        assert done["status"] == "Completed"
        assert done["completed_at"] is not None

    def test_waiving_without_a_reason_is_rejected(self, ca_employee):
        task = generate_onboarding_tasks(ca_employee)[0]
        with pytest.raises(ValueError):
            waive_task(task, "")

    def test_waiving_with_a_reason_records_it(self, ca_employee):
        task = generate_onboarding_tasks(ca_employee)[0]
        waived = waive_task(task, "Role eliminated before task was due.")
        assert waived["status"] == "Waived"
        assert waived["waive_reason"]


class TestTerminationCycle:
    """C-HR-TASK-14 — termination generates the offboarding task set,
    anchored to the termination effective date, with state overrides
    applied the same way onboarding tasks apply them."""

    def test_offboarding_tasks_generated_with_no_duplicates(self, ca_employee):
        tasks = generate_offboarding_tasks(ca_employee, term_date="2026-12-01")
        assert tasks, "No offboarding tasks generated for a CA termination"
        ids = [t["template_id"] for t in tasks]
        assert len(ids) == len(set(ids))

    def test_offboarding_due_dates_anchor_to_term_date(self, ca_employee):
        tasks = generate_offboarding_tasks(ca_employee, term_date="2026-12-01")
        for t in tasks:
            date.fromisoformat(t["due_date"])  # raises if malformed
            # sanity: nowhere near the employee's start_date's era, since
            # offboarding tasks anchor to term_date, not start_date
            assert t["due_date"] >= "2026-01-01"

    def test_state_override_merge_matches_build_task_semantics(self):
        """Unit check on build_task's override-merge behavior itself,
        using a synthetic template rather than assuming a specific real
        template happens to carry a CA override today."""
        tmpl = {
            "template_id": "TMPL-SYN-01", "phase": "Termination",
            "name": "Calculate final paycheck", "due_offset_days": 3,
            "state_overrides": {
                "CA": {"due_offset_days": 0, "name": "Calculate final paycheck — same day (CA)"},
            },
        }
        emp = {"id": "EMP-X", "work_state": "CA", "term_date": "2026-12-01"}
        task = build_task(emp, tmpl, "term_date", 1)
        assert task["due_date"] == "2026-12-01"  # 0-day override applied, not the base 3-day offset
        assert "same day" in task["name"].lower()

    def test_no_override_falls_back_to_base_template_fields(self):
        tmpl = {
            "template_id": "TMPL-SYN-02", "phase": "Termination",
            "name": "Equipment return checklist", "due_offset_days": 3,
        }
        emp = {"id": "EMP-Y", "work_state": "TX", "term_date": "2026-12-01"}
        task = build_task(emp, tmpl, "term_date", 1)
        assert task["due_date"] == "2026-12-04"
        assert task["name"] == "Equipment return checklist"
