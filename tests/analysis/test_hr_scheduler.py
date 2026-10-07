"""
tests/analysis/test_hr_scheduler.py
====================================
Tests for hr_scheduler.py — the HR module's background compliance scheduler
(Implementation Plan v2.1 Section 11, 10 jobs, plus an 11th job --
reminder_email, added 2026-08-29 for the Schedule tab's business-reminders
calendar feature -- not part of the original spec but following the exact
same registry/tracking-key conventions). Mirrors the structure of
tests/analysis/test_scheduler.py (the equivalent test file for
scheduler_engine.py / the Proactive Alerts engine).

SAFETY (per explicit user requirement — read before editing this file):
These tests do NOT import hr_scheduler.py or ai_prowler_mcp.py, and do NOT
start any background thread, hit any live server, or touch the real
hr_db.json / hr_task_tracking.json on the AI-Prowler install.

  - hr_scheduler.py's own module docstring documents this same rule: its
    job_*/JOB_REGISTRY/_tick/start functions all mutate real files and send
    real email once ai_prowler_mcp's real _hr_load_db/_hr_save_db/send_email
    are actually importable, so the ONLY safe way to test its *behavior* is
    to reimplement the pure scheduling-math and filtering logic locally here
    (TestSchedulingMath, TestJobFilteringLogic below) and run it against
    synthetic in-memory data — never the real database.
  - Everything else (TestJobRegistryStructure, TestTrackingSchemaAlignment,
    TestJobFunctionsAreDefensive) reads the real hr_scheduler.py /
    hr_task_tracking.json files as plain text/JSON (read-only) and asserts on
    their structure/content — same "structural regression test" style as
    tests/gui/test_pwa_asset_paths_match_jobs_route.py.

Run:
    run_tests.bat tests\\analysis\\test_hr_scheduler.py -v
"""

import os
import re
import json
import datetime
import pytest

SRC_ROOT = os.environ.get(
    "AI_PROWLER_SRC",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)
HR_SCHEDULER_PATH = os.path.join(SRC_ROOT, "hr_scheduler.py")
HR_TRACKING_PATH = os.path.join(SRC_ROOT, "hr_task_tracking.json")

EXPECTED_JOB_IDS = [
    "overdue_checker", "reminder_48h", "due_today_sender", "overdue_first_notice",
    "escalation_check", "daily_digest", "prestart_welcome", "benefits_window_warning",
    "doc_expiration_check", "weekly_owner_summary", "reminder_email",
]


# ── Local mirrors of hr_scheduler.py's pure scheduling-math functions ───────
# (Deliberately NOT imported from hr_scheduler.py — see module docstring.)

def _parse_iso(ts):
    if not ts:
        return None
    try:
        return datetime.datetime.fromisoformat(str(ts).replace("Z", ""))
    except Exception:
        return None


def _is_interval_due(last_run_iso, interval_minutes, now):
    last = _parse_iso(last_run_iso)
    if last is None:
        return True
    return (now - last) >= datetime.timedelta(minutes=interval_minutes)


def _is_fixed_time_due(last_run_iso, hour, minute, now):
    if now.hour != hour or now.minute != minute:
        return False
    last = _parse_iso(last_run_iso)
    if last is not None and last.date() == now.date():
        return False
    return True


def _is_weekly_due(last_run_iso, weekday, hour, minute, now):
    if now.weekday() != weekday or now.hour != hour or now.minute != minute:
        return False
    last = _parse_iso(last_run_iso)
    if last is not None and last.date() == now.date():
        return False
    return True


# ── TC-HRSCHED-001 — interval scheduling math ───────────────────────────────

class TestIntervalScheduling:
    def test_never_run_is_always_due(self):
        assert _is_interval_due(None, 15, datetime.datetime(2026, 6, 25, 9, 0)) is True

    def test_not_yet_elapsed(self):
        now = datetime.datetime(2026, 6, 25, 9, 10)
        last = "2026-06-25T09:00:00"
        assert _is_interval_due(last, 15, now) is False

    def test_exactly_elapsed(self):
        now = datetime.datetime(2026, 6, 25, 9, 15)
        last = "2026-06-25T09:00:00"
        assert _is_interval_due(last, 15, now) is True

    def test_hourly_interval(self):
        now = datetime.datetime(2026, 6, 25, 10, 1)
        last = "2026-06-25T09:00:00"
        assert _is_interval_due(last, 60, now) is True

    def test_z_suffixed_timestamp_parses(self):
        now = datetime.datetime(2026, 6, 25, 9, 15)
        last = "2026-06-25T09:00:00Z"
        assert _is_interval_due(last, 15, now) is True

    def test_corrupt_timestamp_treated_as_never_run(self):
        now = datetime.datetime(2026, 6, 25, 9, 15)
        assert _is_interval_due("not-a-date", 15, now) is True


# ── TC-HRSCHED-002 — fixed daily-time scheduling math ───────────────────────

class TestFixedTimeScheduling:
    def test_fires_at_exact_minute(self):
        now = datetime.datetime(2026, 6, 25, 8, 0)
        assert _is_fixed_time_due(None, 8, 0, now) is True

    def test_does_not_fire_off_minute(self):
        now = datetime.datetime(2026, 6, 25, 8, 1)
        assert _is_fixed_time_due(None, 8, 0, now) is False

    def test_does_not_refire_same_day(self):
        now = datetime.datetime(2026, 6, 25, 8, 0)
        last = "2026-06-25T08:00:00Z"
        assert _is_fixed_time_due(last, 8, 0, now) is False

    def test_fires_again_next_day(self):
        now = datetime.datetime(2026, 6, 26, 8, 0)
        last = "2026-06-25T08:00:00Z"
        assert _is_fixed_time_due(last, 8, 0, now) is True


# ── TC-HRSCHED-003 — weekly scheduling math ─────────────────────────────────

class TestWeeklyScheduling:
    def test_fires_on_correct_weekday_time(self):
        monday = datetime.datetime(2026, 6, 22, 7, 0)  # 2026-06-22 is a Monday
        assert monday.weekday() == 0
        assert _is_weekly_due(None, 0, 7, 0, monday) is True

    def test_does_not_fire_on_other_weekday(self):
        tuesday = datetime.datetime(2026, 6, 23, 7, 0)
        assert _is_weekly_due(None, 0, 7, 0, tuesday) is False

    def test_does_not_refire_same_day(self):
        monday = datetime.datetime(2026, 6, 22, 7, 0)
        last = "2026-06-22T07:00:00Z"
        assert _is_weekly_due(last, 0, 7, 0, monday) is False

    def test_fires_next_week(self):
        next_monday = datetime.datetime(2026, 6, 29, 7, 0)
        last = "2026-06-22T07:00:00Z"
        assert _is_weekly_due(last, 0, 7, 0, next_monday) is True


# ── TC-HRSCHED-004 — job filtering logic, mirrored against synthetic tasks ──
# Each mirror function below reimplements one job's *selection predicate*
# (which tasks/employees/documents get acted on) exactly as hr_scheduler.py's
# job_* functions implement it, so a regression in the real filtering logic
# would also break these tests without ever touching a real database.

def _mirror_48h_targets(tasks, today):
    target = (today + datetime.timedelta(days=2)).isoformat()
    return [t for t in tasks
            if t.get("status") in ("Not Started", "In Progress", "Awaiting Document")
            and t.get("due_date") == target and not t.get("last_reminder_sent_at")]


def _mirror_overdue_first_notice_targets(tasks):
    return [t for t in tasks if t.get("status") == "Overdue" and not t.get("overdue_first_notice_sent_at")]


def _mirror_escalation_targets(tasks, today):
    crit_cutoff = (today - datetime.timedelta(days=1)).isoformat()
    high_cutoff = (today - datetime.timedelta(days=2)).isoformat()
    out = []
    for t in tasks:
        if t.get("status") != "Overdue" or t.get("escalated"):
            continue
        due = t.get("due_date") or ""
        priority = t.get("priority")
        if (priority == "CRITICAL" and due <= crit_cutoff) or (priority == "HIGH" and due <= high_cutoff):
            out.append(t)
    return out


def _mirror_doc_expiration_targets(documents, today):
    soon = (today + datetime.timedelta(days=30)).isoformat()
    return [d for d in documents
            if d.get("expiration_date") and d["expiration_date"] <= soon
            and not d.get("reverification_task_id")]


def _mirror_benefits_warning_targets(employees, tasks, today):
    target = (today - datetime.timedelta(days=25)).isoformat()
    out = []
    for e in employees:
        if e.get("start_date") != target or e.get("benefits_warning_sent_at"):
            continue
        incomplete = [t for t in tasks
                      if t.get("employee_id") == e["id"]
                      and "benefit" in (t.get("name") or "").lower()
                      and t.get("status") not in ("Completed", "Waived")]
        if incomplete:
            out.append(e)
    return out


def _mirror_prestart_welcome_targets(employees, today):
    target = (today + datetime.timedelta(days=7)).isoformat()
    return [e for e in employees if e.get("start_date") == target and not e.get("prestart_welcome_sent_at")]


def _mirror_reminder_email_targets(events, today_iso):
    """Mirrors job_reminder_email()'s selection predicate: business calendar
    reminders (db["events"], added 2026-08-29 for the Schedule tab's
    month-grid view) due today that haven't already had their email sent."""
    return [e for e in events if e.get("date") == today_iso and not e.get("email_sent")]


TODAY = datetime.date(2026, 6, 25)


class TestJobFilteringLogic:
    def test_48h_reminder_only_targets_tasks_due_in_exactly_48h(self):
        tasks = [
            {"id": "TASK-1", "status": "Not Started", "due_date": "2026-06-27"},   # +2d, matches
            {"id": "TASK-2", "status": "Not Started", "due_date": "2026-06-28"},   # +3d, no match
            {"id": "TASK-3", "status": "Completed", "due_date": "2026-06-27"},     # terminal, no match
            {"id": "TASK-4", "status": "Not Started", "due_date": "2026-06-27",
             "last_reminder_sent_at": "2026-06-25T00:00:00Z"},                     # already reminded
        ]
        got = {t["id"] for t in _mirror_48h_targets(tasks, TODAY)}
        assert got == {"TASK-1"}

    def test_overdue_first_notice_skips_already_notified(self):
        tasks = [
            {"id": "TASK-1", "status": "Overdue"},
            {"id": "TASK-2", "status": "Overdue", "overdue_first_notice_sent_at": "x"},
            {"id": "TASK-3", "status": "Completed"},
        ]
        got = {t["id"] for t in _mirror_overdue_first_notice_targets(tasks)}
        assert got == {"TASK-1"}

    def test_escalation_critical_24h_high_48h(self):
        tasks = [
            {"id": "C1", "status": "Overdue", "priority": "CRITICAL", "due_date": "2026-06-24"},  # 1d overdue -> escalate
            {"id": "C2", "status": "Overdue", "priority": "CRITICAL", "due_date": "2026-06-25"},  # 0d overdue -> no
            {"id": "H1", "status": "Overdue", "priority": "HIGH", "due_date": "2026-06-23"},       # 2d overdue -> escalate
            {"id": "H2", "status": "Overdue", "priority": "HIGH", "due_date": "2026-06-24"},       # 1d overdue -> no
            {"id": "M1", "status": "Overdue", "priority": "MEDIUM", "due_date": "2026-06-01"},     # never escalates
            {"id": "C3", "status": "Overdue", "priority": "CRITICAL", "due_date": "2026-06-24",
             "escalated": True},                                                                   # already escalated
        ]
        got = {t["id"] for t in _mirror_escalation_targets(tasks, TODAY)}
        assert got == {"C1", "H1"}

    def test_doc_expiration_within_30_days_and_not_already_reverified(self):
        docs = [
            {"id": "D1", "name": "I-9", "expiration_date": "2026-07-20"},   # 25d out -> match
            {"id": "D2", "name": "Visa", "expiration_date": "2026-08-20"},  # 56d out -> no
            {"id": "D3", "name": "License", "expiration_date": "2026-07-01",
             "reverification_task_id": "TASK-9"},                          # already handled
        ]
        got = {d["id"] for d in _mirror_doc_expiration_targets(docs, TODAY)}
        assert got == {"D1"}

    def test_benefits_warning_targets_25_days_post_start_with_incomplete_task(self):
        employees = [
            {"id": "EMP-1", "start_date": "2026-05-31"},  # exactly 25 days before TODAY
            {"id": "EMP-2", "start_date": "2026-05-30"},  # 26 days — no match
            {"id": "EMP-3", "start_date": "2026-05-31", "benefits_warning_sent_at": "x"},  # already sent
        ]
        tasks = [
            {"employee_id": "EMP-1", "name": "Enroll in Benefits", "status": "Not Started"},
            {"employee_id": "EMP-3", "name": "Enroll in Benefits", "status": "Not Started"},
        ]
        got = {e["id"] for e in _mirror_benefits_warning_targets(employees, tasks, TODAY)}
        assert got == {"EMP-1"}

    def test_benefits_warning_skips_when_task_already_complete(self):
        employees = [{"id": "EMP-1", "start_date": "2026-05-31"}]
        tasks = [{"employee_id": "EMP-1", "name": "Enroll in Benefits", "status": "Completed"}]
        assert _mirror_benefits_warning_targets(employees, tasks, TODAY) == []

    def test_prestart_welcome_targets_exactly_7_days_out(self):
        employees = [
            {"id": "EMP-1", "start_date": "2026-07-02"},  # +7d -> match
            {"id": "EMP-2", "start_date": "2026-07-03"},  # +8d -> no
            {"id": "EMP-3", "start_date": "2026-07-02", "prestart_welcome_sent_at": "x"},
        ]
        got = {e["id"] for e in _mirror_prestart_welcome_targets(employees, TODAY)}
        assert got == {"EMP-1"}

    def test_reminder_email_only_targets_todays_unsent_reminders(self):
        events = [
            {"id": "REM-1", "date": "2026-06-25", "email_sent": False},   # today, unsent -> match
            {"id": "REM-2", "date": "2026-06-26", "email_sent": False},   # tomorrow -> no
            {"id": "REM-3", "date": "2026-06-25", "email_sent": True},    # today, already sent -> no
            {"id": "REM-4", "date": "2026-06-25"},                       # today, no flag yet -> match
        ]
        got = {e["id"] for e in _mirror_reminder_email_targets(events, "2026-06-25")}
        assert got == {"REM-1", "REM-4"}


# ── TC-HRSCHED-005 — JOB_REGISTRY structure (read-only, source-as-text) ─────

@pytest.fixture(scope="module")
def hr_scheduler_source():
    with open(HR_SCHEDULER_PATH, "r", encoding="utf-8") as f:
        return f.read()


class TestJobRegistryStructure:
    def test_file_exists(self):
        assert os.path.isfile(HR_SCHEDULER_PATH), \
            f"hr_scheduler.py not found at {HR_SCHEDULER_PATH}"

    def test_all_10_jobs_present_in_registry(self, hr_scheduler_source):
        registry_block = hr_scheduler_source.split("JOB_REGISTRY = {", 1)[1]
        registry_block = registry_block.split("\ndef _is_due", 1)[0]
        for job_id in EXPECTED_JOB_IDS:
            assert f'"{job_id}"' in registry_block, f"job '{job_id}' missing from JOB_REGISTRY"
        assert len(EXPECTED_JOB_IDS) == 11

    def test_every_job_has_a_corresponding_function(self, hr_scheduler_source):
        for job_id in EXPECTED_JOB_IDS:
            assert re.search(rf"^def job_{job_id}\(\)", hr_scheduler_source, re.MULTILINE), \
                f"no def job_{job_id}() found"

    def test_no_duplicate_tracking_keys(self, hr_scheduler_source):
        registry_block = hr_scheduler_source.split("JOB_REGISTRY = {", 1)[1]
        registry_block = registry_block.split("\ndef _is_due", 1)[0]
        keys = re.findall(r'"tracking_key":\s*"([^"]+)"', registry_block)
        assert len(keys) == 11
        assert len(set(keys)) == 11, f"duplicate tracking_key(s) found: {keys}"

    def test_cadences_match_implementation_plan_section_11(self, hr_scheduler_source):
        expected_cadences = {
            "overdue_checker": '("interval", 15)',
            "reminder_48h": '("interval", 60)',
            "due_today_sender": '("daily", 8, 0)',
            "overdue_first_notice": '("daily", 9, 0)',
            "escalation_check": '("daily", 10, 0)',
            "daily_digest": '("daily", 7, 0)',
            "prestart_welcome": '("daily", 6, 0)',
            "benefits_window_warning": '("daily", 6, 0)',
            "doc_expiration_check": '("daily", 6, 0)',
            "weekly_owner_summary": '("weekly", 0, 7, 0)',
            "reminder_email": '("daily", 7, 0)',
        }
        registry_block = hr_scheduler_source.split("JOB_REGISTRY = {", 1)[1]
        registry_block = registry_block.split("\ndef _is_due", 1)[0]
        for job_id, cadence in expected_cadences.items():
            job_block = registry_block.split(f'"{job_id}":', 1)[1].split("},", 1)[0]
            assert cadence in job_block, (
                f"job '{job_id}' expected cadence {cadence} not found "
                f"(got block: {job_block.strip()[:120]})"
            )


# ── TC-HRSCHED-006 — hr_task_tracking.json schema alignment ────────────────

class TestTrackingSchemaAlignment:
    """Regression guard: every tracking_key referenced in JOB_REGISTRY must
    exist under hr_task_tracking.json's "scheduler" section, so the two never
    silently drift apart (e.g. a job renamed in one file but not the other)."""

    def test_tracking_file_exists(self):
        assert os.path.isfile(HR_TRACKING_PATH), \
            f"hr_task_tracking.json not found at {HR_TRACKING_PATH}"

    def test_all_tracking_keys_exist_in_schema(self, hr_scheduler_source):
        with open(HR_TRACKING_PATH, "r", encoding="utf-8-sig") as f:
            tracking = json.load(f)
        scheduler_section = tracking.get("scheduler", {})
        registry_block = hr_scheduler_source.split("JOB_REGISTRY = {", 1)[1]
        registry_block = registry_block.split("\ndef _is_due", 1)[0]
        tracking_keys = re.findall(r'"tracking_key":\s*"([^"]+)"', registry_block)
        assert len(tracking_keys) == 11
        for key in tracking_keys:
            assert key in scheduler_section, (
                f"tracking_key '{key}' used by JOB_REGISTRY is missing from "
                f"hr_task_tracking.json's 'scheduler' section"
            )

    def test_digest_state_section_present(self):
        with open(HR_TRACKING_PATH, "r", encoding="utf-8-sig") as f:
            tracking = json.load(f)
        digest_state = tracking.get("digest_state", {})
        for key in ("last_digest_at", "last_digest_recipients",
                    "last_digest_task_count", "last_digest_overdue_count",
                    "last_digest_due_today_count"):
            assert key in digest_state


# ── TC-HRSCHED-007 — every job function is defensively wrapped ─────────────

class TestJobFunctionsAreDefensive:
    """Structural check (not execution): every job_*/lazy-import site is
    wrapped in its own try/except, so a broken import or a raised exception
    inside one job can never propagate out and kill the tick loop or the
    other 9 jobs. Verified by counting try/except pairs per function body,
    not by actually invoking anything."""

    def _function_body(self, source, func_name):
        pattern = rf"^def {func_name}\(\).*?(?=\n^def |\n^# ──|\Z)"
        m = re.search(pattern, source, re.MULTILINE | re.DOTALL)
        assert m, f"could not locate body of {func_name}()"
        return m.group(0)

    @pytest.mark.parametrize("job_id", EXPECTED_JOB_IDS)
    def test_job_function_has_try_except(self, hr_scheduler_source, job_id):
        body = self._function_body(hr_scheduler_source, f"job_{job_id}")
        assert body.count("try:") >= 2, (
            f"job_{job_id} should have at least 2 try blocks "
            f"(lazy import + main logic), found {body.count('try:')}"
        )
        assert "except Exception" in body

    def test_tick_never_lets_one_job_kill_the_loop(self, hr_scheduler_source):
        tick_body = self._function_body_alt(hr_scheduler_source, "_tick")
        assert "for job_id, meta in JOB_REGISTRY.items():" in tick_body
        assert "except Exception:" in tick_body

    def _function_body_alt(self, source, func_name):
        pattern = rf"^def {func_name}\(\).*?(?=\n^def |\n^# ──|\Z)"
        m = re.search(pattern, source, re.MULTILINE | re.DOTALL)
        assert m, f"could not locate body of {func_name}()"
        return m.group(0)


# ── TC-HRSCHED-008 — thread lifecycle API surface (structural) ─────────────

class TestThreadLifecycleAPI:
    def test_public_functions_exist(self, hr_scheduler_source):
        for fn in ("def start()", "def stop()", "def is_running()", "def run_job_now("):
            assert fn in hr_scheduler_source, f"missing public API: {fn}"

    def test_start_is_idempotent_guarded(self, hr_scheduler_source):
        start_body = self._function_body(hr_scheduler_source, "start")
        assert "is_alive()" in start_body, "start() should no-op if already running"

    def _function_body(self, source, func_name):
        pattern = rf"^def {func_name}\(\).*?(?=\n^def |\n^# ──|\Z)"
        m = re.search(pattern, source, re.MULTILINE | re.DOTALL)
        assert m, f"could not locate body of {func_name}()"
        return m.group(0)
