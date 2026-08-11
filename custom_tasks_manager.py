"""
custom_tasks_manager.py
=======================
Manages custom analysis task definitions for the AI-Prowler
Links & Analysis tab (v8.0.0).

Responsibilities:
  - Load / save custom tasks to ~/.ai-prowler/custom_analysis_tasks.json
  - Validate task definitions
  - Compute next_due dates when tasks are created or edited (AI-Prowler side)
  - Advance next_due after completion (called by complete_analysis_task MCP tool)
  - Return tasks that are due today or overdue
  - Merge built-in and custom tasks into a unified queue view

Schedule intervals supported:
  none, daily, weekly, biweekly, monthly
  (quarterly and yearly removed — use monthly for longer cadences)

Day-of-week pinning (v9.0.2):
  weekly, biweekly, and monthly tasks optionally carry a
  schedule_day_of_week field (0=Mon … 6=Sun, None = unpinned /
  current behaviour). When set, next_due is snapped to that weekday
  instead of advancing by a raw +7/+14/+30 interval, letting you
  stagger tasks across the week to spread credit consumption.
  Monthly tasks snap to the FIRST occurrence of that weekday on or
  after the otherwise-computed monthly date.

File schema (list of task objects):
  {
    "task_id":               str   — unique, e.g. "custom_001"
    "label":                 str   — user-facing name (max 60 chars)
    "prompt":                str   — full analysis prompt
    "scope_dirs":            list  — directory paths to focus on (empty = all)
    "schedule":              str   — one of SCHEDULES keys
    "schedule_day_of_week":  int|null — 0=Mon…6=Sun pin for weekly/biweekly/
                                        monthly; null = unpinned (default)
    "first_due":             str   — YYYY-MM-DD user-chosen first run date
    "next_due":              str   — YYYY-MM-DD next scheduled run (or null)
    "last_run":              str   — YYYY-MM-DD last completed date (or null)
    "last_status":           str   — "completed" | "skipped" | null
    "output_learnings":      bool  — record key insights as learnings
    "output_report":         bool  — save full analysis as .docx report
    "report_folder":         str   — absolute path for report output
    "created_at":            str   — ISO 8601 creation timestamp
    "updated_at":            str   — ISO 8601 last-modified timestamp
  }
"""

import json
import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CUSTOM_TASKS_PATH = Path.home() / ".ai-prowler" / "custom_analysis_tasks.json"
DEFAULT_REPORT_FOLDER = str(Path.home() / "Documents" / "AI-Prowler_tasks_reports")
MAX_CUSTOM_TASKS = 25

# v8.1.11: practical ceiling for Daily's times-per-day option. 24 already
# means "up to hourly" (e.g. 00:00-23:00, 24 times/day = exactly every
# hour) — there's no real use case past that, and it keeps the generated
# per-day slot list, and the cost of running the checker that often (see
# task_queue_automation.py's active-window design notes), bounded.
MAX_DAILY_TIMES_PER_DAY = 24

# v8.1.6: settings for the 5 fixed Common Business AI Analysis buttons
# (scope dirs, output options, report folder, schedule) — previously only
# lived transiently inside the Configure popup's widgets each time it was
# opened, with no persistence between sessions or between Queue/NOW clicks
# and the popup. Mirrors the custom-task pattern (a saved definition you
# can Queue/NOW directly from, or Edit to change) rather than re-asking
# every time.
BUILTIN_ANALYSIS_CONFIG_PATH = Path.home() / ".ai-prowler" / "builtin_analysis_config.json"

# Module-level counter for guaranteed unique task IDs within the same process
# (timestamps alone can collide at microsecond resolution on fast machines)
_task_id_counter = 0


def _next_task_id() -> str:
    """Return a guaranteed-unique task ID using timestamp + counter."""
    global _task_id_counter
    _task_id_counter += 1
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    return f"custom_{ts}_{_task_id_counter:04d}"

SCHEDULES = {
    "none":      None,
    "daily":     1,
    "weekly":    7,
    "biweekly":  14,
    "monthly":   30,   # approximate — see _advance_date for exact month math
    # quarterly and yearly removed in v9.0.2 — use monthly for longer cadences
}

SCHEDULE_LABELS = {
    "none":      "Manual only",
    "daily":     "Daily",
    "weekly":    "Weekly",
    "biweekly":  "Every 2 weeks",
    "monthly":   "Monthly",
}

# v9.0.2: day-of-week pinning for weekly / biweekly / monthly schedules.
# Stored as int 0–6 (Monday=0 … Sunday=6), matching Python's weekday().
# None means "unpinned" — behaves identically to the pre-v9.0.2 +N-day math.
DOW_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday",
             "Friday", "Saturday", "Sunday"]
DOW_LABELS = ["Any day"] + DOW_NAMES   # index 0 → None, indices 1-7 → 0-6
# Schedules that support day-of-week pinning:
DOW_ELIGIBLE_SCHEDULES = {"weekly", "biweekly", "monthly"}


# ---------------------------------------------------------------------------
# Date helpers
# ---------------------------------------------------------------------------

def _today() -> str:
    """Return today's date as YYYY-MM-DD."""
    return datetime.date.today().isoformat()


def _now_iso() -> str:
    """Return current UTC time as ISO 8601."""
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_date(date_str: str) -> datetime.date:
    """Parse YYYY-MM-DD string to date object."""
    return datetime.date.fromisoformat(date_str)


def _parse_due_datetime(value: str) -> datetime.datetime:
    """v8.1.11: parse a next_due value that may be either a plain date
    (YYYY-MM-DD, used by weekly/biweekly/monthly/quarterly/yearly — those
    schedules remain date-granularity only, unchanged) or a full datetime
    (YYYY-MM-DDTHH:MM:SS, used by "daily" now that it supports a start/end
    time-of-day window with N runs per day). A bare date is treated as
    midnight, so date-only comparisons against it still work correctly."""
    if "T" in value:
        return datetime.datetime.fromisoformat(value)
    return datetime.datetime.combine(_parse_date(value), datetime.time())


def _snap_to_weekday(date: datetime.date, day_of_week: int) -> datetime.date:
    """v9.0.2: advance `date` to the nearest occurrence of `day_of_week`
    (0=Mon … 6=Sun) that is >= `date`.  If `date` already falls on that
    weekday it is returned unchanged.

    This is the core primitive for weekly/biweekly/monthly day-of-week
    pinning — every schedule path that has a DOW constraint passes through
    here so the snap logic lives in exactly one place.

    Examples (all advance-only, never backwards):
        _snap_to_weekday(date(2026, 8, 10), 0)  # Mon → 2026-08-10 (already Mon)
        _snap_to_weekday(date(2026, 8, 10), 2)  # Mon → 2026-08-12 (Wed, +2)
        _snap_to_weekday(date(2026, 8, 10), 6)  # Mon → 2026-08-16 (Sun, +6)
    """
    delta = (day_of_week - date.weekday()) % 7
    return date + datetime.timedelta(days=delta)


def compute_daily_run_times(start_time: str, end_time: str, times_per_day: int) -> list:
    """v8.1.11: return `times_per_day` "HH:MM" strings, evenly spaced across
    [start_time, end_time] INCLUSIVE of both endpoints — e.g.
    start=08:00, end=20:00, times_per_day=3 -> ["08:00", "14:00", "20:00"].

    times_per_day <= 1 just returns [start_time]; end_time is irrelevant
    in that case (classic once-daily behavior, unchanged).

    "24 times/day between 00:00-23:59" is how Hourly ends up expressed —
    there's no separate Hourly schedule key; Daily generalizes to cover it.
    """
    times_per_day = max(1, int(times_per_day))
    if times_per_day == 1:
        return [start_time]

    sh, sm = (int(p) for p in start_time.split(":"))
    eh, em = (int(p) for p in end_time.split(":"))
    start_minutes = sh * 60 + sm
    end_minutes = eh * 60 + em
    span = end_minutes - start_minutes
    step = span / (times_per_day - 1)

    out = []
    for i in range(times_per_day):
        total = round(start_minutes + i * step)
        h, m = divmod(total, 60)
        out.append(f"{h:02d}:{m:02d}")
    return out


def format_daily_run_times_preview(start_time: str, end_time: str,
                                    times_per_day) -> str:
    """v8.1.11: a single ready-to-display string showing exactly what a
    Daily schedule's Start time / End time / Times per day settings
    actually produce — e.g. "Runs at: 08:00, 14:00, 20:00" — so the user
    sees the real computed result of their settings, not just the raw
    input fields, in both the My Custom AI Analyses editor and the Common
    Business Analysis Configure dialog (both use this exact function, so
    they can never drift out of sync with each other).

    Tolerant of invalid/partial input (e.g. while a user is mid-typing a
    time) — returns an empty string rather than raising, since this is
    purely a live preview label, not a validated field.
    """
    try:
        times_per_day = max(1, int(times_per_day))
        run_times = compute_daily_run_times(start_time, end_time, times_per_day)
    except (ValueError, TypeError, ZeroDivisionError, AttributeError):
        return ""
    return "Runs at: " + ", ".join(run_times)


def _first_daily_datetime(first_due: str, daily_start_time: str, daily_end_time: str,
                           daily_times_per_day: int) -> str:
    """v8.1.11: the first next_due for a newly-created/edited daily task —
    always the FIRST slot (daily_start_time) on first_due's date. If that
    moment has already passed by the time it's actually checked, the usual
    is_queue_entry_ready()/is_due() overdue handling takes it from there —
    same "catch up on next check" philosophy the rest of this module
    already uses, not special-cased here."""
    run_times = compute_daily_run_times(daily_start_time, daily_end_time, daily_times_per_day)
    return f"{first_due}T{run_times[0]}:00"


def _advance_daily_datetime_catchup(anchor_iso: str, daily_start_time: str,
                                     daily_end_time: str, daily_times_per_day: int,
                                     now: datetime.datetime = None) -> str:
    """v8.1.11: the daily equivalent of _advance_date_catchup() — finds the
    NEXT run-time slot strictly after `now` (defaults to the real current
    moment), among the day's N evenly-spaced slots, rolling into
    subsequent days as needed. Mirrors _advance_date_catchup()'s
    catch-up-to-present philosophy: a task overdue by many missed slots
    resyncs to the next slot after now in one completion, rather than
    needing one completion per missed slot.
    """
    now = now or datetime.datetime.now()
    run_times = compute_daily_run_times(daily_start_time, daily_end_time, daily_times_per_day)

    anchor_date = _parse_due_datetime(anchor_iso).date()
    guard = 0
    day = anchor_date
    while guard < 3660:  # ~10 years of days — sanity backstop, not a real limit
        for t in run_times:
            candidate = datetime.datetime.combine(
                day, datetime.time.fromisoformat(f"{t}:00"))
            if candidate > now:
                return candidate.strftime("%Y-%m-%dT%H:%M:%S")
        day = day + datetime.timedelta(days=1)
        guard += 1
    # Unreachable in practice — the loop above always finds a slot on the
    # very next day at the latest, since every day has at least one slot.
    return f"{day.isoformat()}T{run_times[0]}:00"


def advance_next_due_for_task(task: dict, today_str: str = None) -> str:
    """v8.1.11: unified advancement entry point — figures out which
    algorithm applies based on the task/entry's own schedule, so callers
    (complete_analysis_task) don't need to know the difference between
    "daily" (datetime-granular, N slots/day) and every other schedule
    (date-granular, single daily/weekly/etc. step). Pass the full task or
    queue-entry dict, not just the anchor string, since daily needs its
    daily_start_time/daily_end_time/daily_times_per_day fields too.
    """
    schedule = task.get("schedule", "none")
    anchor = task.get("next_due")
    if schedule == "none" or not anchor:
        return None
    if schedule == "daily":
        return _advance_daily_datetime_catchup(
            anchor,
            task.get("daily_start_time", "09:00"),
            task.get("daily_end_time", "17:00"),
            task.get("daily_times_per_day", 1),
        )
    return _advance_date_catchup(anchor, schedule, today_str)


def _advance_date(from_date_str: str, schedule: str,
                  day_of_week: int = None) -> str:
    """Advance from_date by one schedule interval.

    v9.0.2: added optional day_of_week (0=Mon…6=Sun).  When supplied for
    a weekly, biweekly, or monthly schedule the result is snapped forward
    to the nearest occurrence of that weekday on or after the raw
    interval date — so tasks can be pinned to a specific day of the week
    regardless of when they were first created.

    quarterly and yearly removed in v9.0.2; use monthly for longer cadences.

    Returns YYYY-MM-DD string, or None if schedule is "none" or unknown.
    """
    if schedule == "none" or schedule not in SCHEDULES:
        return None

    base = _parse_date(from_date_str)

    if schedule == "monthly":
        # Add exactly one month, handling month-end edge cases
        import calendar
        month = base.month + 1
        year  = base.year + (1 if month > 12 else 0)
        month = month if month <= 12 else 1
        max_day = calendar.monthrange(year, month)[1]
        day = min(base.day, max_day)
        result = datetime.date(year, month, day)
        # v9.0.2: snap to the pinned weekday on or after the computed date
        if day_of_week is not None:
            result = _snap_to_weekday(result, day_of_week)
        return result.isoformat()

    # daily / weekly / biweekly — simple day arithmetic
    days = SCHEDULES[schedule]
    result = base + datetime.timedelta(days=days)
    # v9.0.2: snap weekly/biweekly to the pinned weekday
    if day_of_week is not None and schedule in DOW_ELIGIBLE_SCHEDULES:
        result = _snap_to_weekday(result, day_of_week)
    return result.isoformat()


def _advance_date_catchup(anchor: str, schedule: str, today_str: str = None,
                          day_of_week: int = None) -> str:
    """Advance anchor by schedule intervals until the result is strictly after
    today (or a supplied reference date) — rather than only one interval.

    v8.1.5 fix: previously, completing a task only ever called _advance_date()
    once, no matter how far behind it was. A task overdue by MULTIPLE
    intervals (e.g. a daily check-in overdue 5 days) needed 5 separate
    completions to fully catch up — each completion only closed one interval
    of the gap, so it stayed partially overdue in between. A task that is
    due/overdue by exactly one interval (the common case) behaves identically
    to before: a single _advance_date() call already lands in the future, so
    the loop below exits immediately. This only changes behavior once a task
    has fallen behind by more than one interval, in which case a single
    completion now fully resyncs it to the next occurrence after today,
    instead of requiring one completion per missed interval.

    v9.0.2: day_of_week threaded through to _advance_date() so the DOW pin
    is respected during catch-up advancement as well as normal advancement.
    """
    today_str = today_str or _today()
    new_date = _advance_date(anchor, schedule, day_of_week)
    if new_date is None:
        return None
    guard = 0
    while new_date <= today_str and guard < 10000:
        new_date = _advance_date(new_date, schedule, day_of_week)
        guard += 1
    return new_date


def _is_due(task: dict) -> bool:
    """Return True if the task is due today or overdue.

    This is for task DEFINITIONS in custom_analysis_tasks.json — used to
    decide whether a recurring definition should get a fresh entry pushed
    into the run queue (pending_tasks.json). A manual-only definition
    (schedule="none") is never "due" in this sense — it only gets queued
    when the user explicitly clicks Queue/Save & Queue.

    v8.1.11: uses _parse_due_datetime() + datetime.now(), same reasoning
    as is_queue_entry_ready() above — handles daily tasks' time-of-day
    next_due correctly, without changing behavior for date-only schedules.
    """
    next_due = task.get("next_due")
    if not next_due:
        return False
    schedule = task.get("schedule", "none")
    if schedule == "none":
        return False
    try:
        return _parse_due_datetime(next_due) <= datetime.datetime.now()
    except (ValueError, TypeError):
        return False


def is_queue_entry_ready(entry: dict) -> bool:
    """Return True if a pending_tasks.json QUEUE ENTRY is ready to execute
    right now. This is deliberately a different question from _is_due()
    above, and has different semantics for schedule="none":

      - schedule == "none" (a one-shot entry, whether from a Common
        Business Analysis button or a manual-only custom task): once it's
        sitting in the queue, it's always ready — there's no recurrence
        concept, the act of queueing it IS the "due" signal.
      - schedule != "none" (a recurring entry — either a built-in button
        with its own schedule, or a materialized custom-task instance):
        ready only if next_due is today or in the past. A recurring entry
        that was queued ahead of its next_due date (e.g. queued once,
        then re-armed by complete_analysis_task for a date still in the
        future) should NOT re-execute until that date arrives.

    Used by get_pending_analysis_tasks() to filter the run queue down to
    only what should actually execute on this pass — both built-in and
    custom-derived entries are treated identically here, per the v8.1.9
    queue-unification design (see complete_analysis_task's re-arm logic).

    v8.1.11: uses _parse_due_datetime() + datetime.now() rather than
    _parse_date() + date.today(), so this correctly handles BOTH plain
    dates (weekly/monthly/etc — treated as midnight, same effective
    behavior as the old date-only comparison) AND full datetimes (daily
    tasks with a specific time-of-day) without needing two code paths.
    """
    schedule = entry.get("schedule", "none")
    if schedule == "none":
        return True
    next_due = entry.get("next_due")
    if not next_due:
        # Defensive: a recurring entry somehow missing next_due shouldn't
        # get stuck in limbo forever — treat as ready rather than dead.
        return True
    try:
        return _parse_due_datetime(next_due) <= datetime.datetime.now()
    except (ValueError, TypeError):
        return True


# ---------------------------------------------------------------------------
# Load / Save
# ---------------------------------------------------------------------------

def load_custom_tasks() -> list:
    """
    Load custom tasks from disk.
    Returns empty list if file is absent or corrupt.
    """
    try:
        if CUSTOM_TASKS_PATH.exists():
            data = json.loads(CUSTOM_TASKS_PATH.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
    except Exception:
        pass
    return []


def save_custom_tasks(tasks: list) -> bool:
    """
    Save custom tasks list to disk.
    Returns True on success, False on failure.
    """
    try:
        CUSTOM_TASKS_PATH.parent.mkdir(parents=True, exist_ok=True)
        CUSTOM_TASKS_PATH.write_text(
            json.dumps(tasks, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        return True
    except Exception as e:
        print(f"[custom_tasks_manager] save failed: {e}")
        return False


# ---------------------------------------------------------------------------
# Built-in (Common Business AI Analysis) settings — v8.1.6
# ---------------------------------------------------------------------------
# Separate storage from custom tasks: these 5 are fixed types (task_def
# comes from _ANALYSIS_TASKS in rag_gui.py, not user-created), so there's
# no task_id/label/prompt to persist — just the per-type Queue/NOW
# settings a user configures via Edit. Keyed by task_def["type"]
# (e.g. "analyze_business").

def load_builtin_analysis_config() -> dict:
    """Load all built-in analysis settings. Returns {} if absent/corrupt —
    callers get sensible defaults via get_builtin_analysis_settings()."""
    try:
        if BUILTIN_ANALYSIS_CONFIG_PATH.exists():
            data = json.loads(BUILTIN_ANALYSIS_CONFIG_PATH.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def save_builtin_analysis_config(cfg: dict) -> bool:
    """Save all built-in analysis settings. Returns True on success."""
    try:
        BUILTIN_ANALYSIS_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        BUILTIN_ANALYSIS_CONFIG_PATH.write_text(
            json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
        return True
    except Exception as e:
        print(f"[custom_tasks_manager] save_builtin_analysis_config failed: {e}")
        return False


def get_builtin_analysis_settings(task_type: str) -> dict:
    """Returns the saved settings for one built-in analysis type, filled
    in with defaults for anything never configured — safe to call before
    the user has ever clicked Edit on that analysis."""
    cfg = load_builtin_analysis_config()
    saved = cfg.get(task_type, {})
    if not isinstance(saved, dict):
        saved = {}
    return {
        "scope_dirs":            saved.get("scope_dirs") or [],
        "output_learnings":      saved.get("output_learnings", True),
        "output_report":         saved.get("output_report", False),
        "output_email":          saved.get("output_email", False),
        "report_folder":         saved.get("report_folder") or DEFAULT_REPORT_FOLDER,
        "schedule":              saved.get("schedule", "none"),
        "schedule_day_of_week":  saved.get("schedule_day_of_week"),  # v9.0.2; None = unpinned
        "first_due":             saved.get("first_due"),
        # v8.1.11: extended to Common Business Analysis tasks too, matching
        # My Custom AI Analyses — Start time, End time, and Times per day
        # only apply when schedule == "daily".
        "daily_start_time":      saved.get("daily_start_time", "09:00"),
        "daily_end_time":        saved.get("daily_end_time", "17:00"),
        "daily_times_per_day":   saved.get("daily_times_per_day", 1),
    }


def save_builtin_analysis_settings(task_type: str, settings: dict) -> bool:
    """Persists settings for ONE built-in analysis type — called from the
    Edit popup's Save button. Leaves every other type's saved settings
    untouched."""
    cfg = load_builtin_analysis_config()
    cfg[task_type] = settings
    return save_builtin_analysis_config(cfg)


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def create_task(label: str,
                prompt: str,
                scope_dirs: list = None,
                schedule: str = "none",
                schedule_day_of_week: int = None,
                first_due: str = None,
                output_learnings: bool = True,
                output_report: bool = False,
                output_email: bool = False,
                report_folder: str = None,
                daily_start_time: str = "09:00",
                daily_end_time: str = "17:00",
                daily_times_per_day: int = 1) -> dict:
    """
    Create a new custom task definition.

    Args:
        label:            User-facing name (max 60 chars).
        prompt:           Full analysis prompt text.
        scope_dirs:       List of directory paths to focus on.
        schedule:         Schedule key from SCHEDULES.
        first_due:        YYYY-MM-DD first due date (AI-Prowler sets this).
        output_learnings: Record key insights as learnings.
        output_report:    Save full analysis as .docx report.
        output_email:     Email the full analysis via AI-Prowler's own
                          configured SMTP account (send_email tool) — v8.1.10.
        report_folder:    Output folder for .docx reports.
        daily_start_time: HH:MM, first run of the day — only meaningful
                          when schedule == "daily" (v8.1.11).
        daily_end_time:   HH:MM, last run of the day — only used when
                          daily_times_per_day > 1 (v8.1.11).
        schedule_day_of_week: int 0–6 (Mon=0…Sun=6) or None. Only used when
                          schedule is weekly, biweekly, or monthly. Pins
                          next_due to that weekday via _snap_to_weekday()
                          so tasks can be staggered across the week to
                          spread credit consumption (v9.0.2).
        daily_times_per_day: how many evenly-spaced runs per day, first
                          exactly at daily_start_time and last exactly at
                          daily_end_time when > 1 (v8.1.11). 1 = classic
                          once-daily at daily_start_time; up to
                          MAX_DAILY_TIMES_PER_DAY (24 — e.g. 00:00-23:00
                          at 24/day is exactly hourly; there's no separate
                          "Hourly" schedule, Daily generalizes to cover it).

    Returns:
        Task dict ready to be appended to the task list.

    Raises:
        ValueError: if validation fails, OR if MAX_CUSTOM_TASKS is already
        reached. The cap is checked here (not by callers) so every caller —
        the GUI's Add dialog and any MCP tool alike — enforces the exact
        same limit with no way to accidentally bypass it.

        v8.1.10: also raises if NONE of output_learnings/output_report/
        output_email is set — a task with zero outputs selected produces
        results nowhere retrievable when run via the Autonomous AI Task
        Queue (no chat window exists in a headless run to "display" to;
        see the audit-trail investigation this same version fixed). At
        least one output must be selected so every task's results land
        somewhere durable.

        v8.1.11: also raises if schedule == "daily" and daily_times_per_day
        is outside [1, MAX_DAILY_TIMES_PER_DAY], or (when > 1) if
        daily_end_time is not strictly after daily_start_time.
    """
    existing_count = len(load_custom_tasks())
    if existing_count >= MAX_CUSTOM_TASKS:
        raise ValueError(
            f"Maximum {MAX_CUSTOM_TASKS} custom tasks allowed. "
            f"Delete an existing task before adding a new one."
        )

    label = (label or "").strip()
    if not label:
        raise ValueError("Task name is required.")
    if len(label) > 60:
        raise ValueError("Task name must be 60 characters or fewer.")

    prompt = (prompt or "").strip()
    if not prompt:
        raise ValueError("Task prompt is required.")
    if len(prompt) > 4000:
        raise ValueError("Task prompt must be 4000 characters or fewer.")

    if not (output_learnings or output_report or output_email):
        raise ValueError(
            "At least one output must be selected: Learnings, Document, or Email."
        )

    schedule = (schedule or "none").strip().lower()
    if schedule not in SCHEDULES:
        raise ValueError(f"Invalid schedule '{schedule}'. "
                         f"Valid options: {', '.join(SCHEDULES.keys())}")

    daily_times_per_day = int(daily_times_per_day or 1)
    if schedule == "daily":
        if not (1 <= daily_times_per_day <= MAX_DAILY_TIMES_PER_DAY):
            raise ValueError(
                f"Times per day must be between 1 and {MAX_DAILY_TIMES_PER_DAY}."
            )
        try:
            datetime.time.fromisoformat(f"{daily_start_time}:00")
        except (ValueError, TypeError):
            raise ValueError(f"Invalid start time '{daily_start_time}'. Use HH:MM.")
        if daily_times_per_day > 1:
            try:
                datetime.time.fromisoformat(f"{daily_end_time}:00")
            except (ValueError, TypeError):
                raise ValueError(f"Invalid end time '{daily_end_time}'. Use HH:MM.")
            if daily_end_time <= daily_start_time:
                raise ValueError(
                    "End time must be after start time when times per day > 1."
                )

    # v9.0.2: validate schedule_day_of_week
    if schedule_day_of_week is not None:
        if schedule not in DOW_ELIGIBLE_SCHEDULES:
            raise ValueError(
                f"schedule_day_of_week is only valid for weekly, biweekly, "
                f"or monthly schedules (got '{schedule}')."
            )
        try:
            schedule_day_of_week = int(schedule_day_of_week)
        except (TypeError, ValueError):
            raise ValueError("schedule_day_of_week must be an integer 0–6.")
        if not (0 <= schedule_day_of_week <= 6):
            raise ValueError("schedule_day_of_week must be 0 (Mon) … 6 (Sun).")

    # Validate and set first_due / next_due
    next_due = None
    if schedule != "none":
        if not first_due:
            raise ValueError("A first due date is required for scheduled tasks.")
        try:
            _parse_date(first_due)
        except ValueError:
            raise ValueError(f"Invalid first due date '{first_due}'. Use YYYY-MM-DD.")
        if schedule == "daily":
            next_due = _first_daily_datetime(
                first_due, daily_start_time, daily_end_time, daily_times_per_day)
        else:
            # v9.0.2: snap first_due itself to the pinned weekday so the very
            # first run also lands on the correct day of week.
            if schedule_day_of_week is not None:
                snapped = _snap_to_weekday(_parse_date(first_due), schedule_day_of_week)
                next_due = snapped.isoformat()
            else:
                next_due = first_due

    scope_dirs = [str(d).strip() for d in (scope_dirs or []) if str(d).strip()]

    # Generate unique task_id using counter-based helper
    task_id = _next_task_id()

    now = _now_iso()
    return {
        "task_id":               task_id,
        "label":                 label,
        "prompt":                prompt,
        "scope_dirs":            scope_dirs,
        "schedule":              schedule,
        "schedule_day_of_week":  schedule_day_of_week,  # v9.0.2; None = unpinned
        "first_due":             first_due,
        "next_due":              next_due,
        "last_run":              None,
        "last_status":           None,
        "output_learnings":      bool(output_learnings),
        "output_report":         bool(output_report),
        "output_email":          bool(output_email),
        "report_folder":         report_folder or DEFAULT_REPORT_FOLDER,
        "daily_start_time":      daily_start_time,
        "daily_end_time":        daily_end_time,
        "daily_times_per_day":   daily_times_per_day,
        "created_at":            now,
        "updated_at":            now,
    }


def update_task(tasks: list, task_id: str, **kwargs) -> bool:
    """
    Update fields on an existing task in-place.
    Recalculates next_due if schedule or first_due changes.
    Returns True if found and updated, False if not found.

    v8.1.9 fix: the previous version only ever moved next_due FORWARD
    (only updated it if the incoming first_due was later than the
    already-stored next_due). Since the edit dialog pre-fills first_due
    with the task's existing value, that comparison was almost always
    False — so editing a task's schedule (e.g. Weekly -> Daily) or its
    first_due date silently had no effect on when it would actually next
    run. The fix: explicitly detect whether the CALLER changed schedule or
    first_due (compared to what was stored before this update), and if so,
    reset next_due to the new first_due — identical to how create_task()
    seeds a brand-new task. Edits that don't touch schedule/first_due
    (prompt, scope, output options, etc.) leave next_due untouched, so a
    task that has already advanced past its original first_due isn't
    regressed just because the user tweaked something unrelated.

    v8.1.11: same reasoning extended to daily_start_time/daily_end_time/
    daily_times_per_day — changing any of those for a "daily" task is
    just as much a genuine cadence edit as changing schedule/first_due,
    and must reset next_due the same way, not leave it stuck reflecting
    the old start time / old times-per-day.
    """
    for t in tasks:
        if t.get("task_id") != task_id:
            continue

        updatable = [
            "label", "prompt", "scope_dirs", "schedule",
            "schedule_day_of_week",                          # v9.0.2
            "first_due", "output_learnings", "output_report",
            "output_email", "report_folder",
            "daily_start_time", "daily_end_time", "daily_times_per_day",
        ]

        old_schedule  = t.get("schedule", "none")
        old_first_due = t.get("first_due")
        old_dow       = t.get("schedule_day_of_week")        # v9.0.2
        old_daily_start = t.get("daily_start_time", "09:00")
        old_daily_end   = t.get("daily_end_time", "17:00")
        old_daily_times = t.get("daily_times_per_day", 1)

        schedule_changed = (
            "schedule" in kwargs and kwargs["schedule"] != old_schedule
        )
        first_due_changed = (
            "first_due" in kwargs and kwargs["first_due"] != old_first_due
        )
        # v9.0.2: changing the pinned day is a cadence edit — reset next_due
        dow_changed = (
            "schedule_day_of_week" in kwargs
            and kwargs["schedule_day_of_week"] != old_dow
        )
        daily_fields_changed = (
            ("daily_start_time" in kwargs and kwargs["daily_start_time"] != old_daily_start) or
            ("daily_end_time" in kwargs and kwargs["daily_end_time"] != old_daily_end) or
            ("daily_times_per_day" in kwargs and int(kwargs["daily_times_per_day"] or 1) != old_daily_times)
        )

        # v8.1.10: validate the RESULTING output-flag state before applying
        # anything — an edit that would leave all three outputs off is
        # rejected the same way create_task() rejects it up front, rather
        # than silently producing a task whose results go nowhere.
        _would_learnings = kwargs.get("output_learnings", t.get("output_learnings", False))
        _would_report    = kwargs.get("output_report",    t.get("output_report", False))
        _would_email     = kwargs.get("output_email",     t.get("output_email", False))
        if not (_would_learnings or _would_report or _would_email):
            raise ValueError(
                "At least one output must be selected: Learnings, Document, or Email."
            )

        # v8.1.11: validate the RESULTING daily time-of-day state too, same
        # pattern — check what schedule/daily_* WOULD be after this update,
        # before actually applying anything.
        _would_schedule = kwargs.get("schedule", old_schedule)
        _would_start = kwargs.get("daily_start_time", old_daily_start)
        _would_end   = kwargs.get("daily_end_time", old_daily_end)
        _would_times = int(kwargs.get("daily_times_per_day", old_daily_times) or 1)
        if _would_schedule == "daily":
            if not (1 <= _would_times <= MAX_DAILY_TIMES_PER_DAY):
                raise ValueError(
                    f"Times per day must be between 1 and {MAX_DAILY_TIMES_PER_DAY}."
                )
            try:
                datetime.time.fromisoformat(f"{_would_start}:00")
            except (ValueError, TypeError):
                raise ValueError(f"Invalid start time '{_would_start}'. Use HH:MM.")
            if _would_times > 1:
                try:
                    datetime.time.fromisoformat(f"{_would_end}:00")
                except (ValueError, TypeError):
                    raise ValueError(f"Invalid end time '{_would_end}'. Use HH:MM.")
                if _would_end <= _would_start:
                    raise ValueError(
                        "End time must be after start time when times per day > 1."
                    )

        for key in updatable:
            if key in kwargs:
                t[key] = kwargs[key]

        schedule  = t.get("schedule", "none")
        first_due = t.get("first_due")

        if schedule == "none":
            # Manual-only tasks never carry a next_due.
            t["next_due"] = None
        elif (schedule_changed or first_due_changed or dow_changed
              or daily_fields_changed or not t.get("next_due")):
            # Genuine cadence/anchor edit (or a task that never had a
            # next_due yet, e.g. switching from "none" to a real
            # schedule) — reset to the new anchor. This can legitimately
            # move next_due EARLIER than before (Weekly -> Daily should
            # make it due sooner), not just later.
            if first_due:
                if schedule == "daily":
                    t["next_due"] = _first_daily_datetime(
                        first_due, t.get("daily_start_time", "09:00"),
                        t.get("daily_end_time", "17:00"),
                        t.get("daily_times_per_day", 1))
                else:
                    # v9.0.2: snap first_due to the (possibly new) DOW pin.
                    new_dow = t.get("schedule_day_of_week")
                    if new_dow is not None and schedule in DOW_ELIGIBLE_SCHEDULES:
                        snapped = _snap_to_weekday(_parse_date(first_due), new_dow)
                        t["next_due"] = snapped.isoformat()
                    else:
                        t["next_due"] = first_due
        # else: no cadence fields changed — next_due left as-is.

        t["updated_at"] = _now_iso()
        return True
    return False


def delete_task(tasks: list, task_id: str) -> bool:
    """
    Remove a task by task_id from the list in-place.
    Returns True if found and removed.
    """
    for i, t in enumerate(tasks):
        if t.get("task_id") == task_id:
            tasks.pop(i)
            return True
    return False


def get_task(tasks: list, task_id: str) -> dict:
    """Return the task dict with the given task_id, or None."""
    for t in tasks:
        if t.get("task_id") == task_id:
            return t
    return None


# ---------------------------------------------------------------------------
# Scheduling
# ---------------------------------------------------------------------------

def get_due_tasks(tasks: list) -> list:
    """Return all tasks that are due today or overdue."""
    return [t for t in tasks if _is_due(t)]


def advance_next_due(tasks: list, task_id: str,
                     completed_date: str = None) -> str:
    """
    Advance next_due by one schedule interval after task completion.
    Called by the complete_analysis_task MCP tool (Claude triggers this).

    Uses the ORIGINAL due date as the anchor (schedule option B) so that
    a "monthly on the 1st" task stays on the 1st regardless of when it ran.

    Args:
        tasks:          The loaded custom tasks list (modified in-place).
        task_id:        The task to advance.
        completed_date: YYYY-MM-DD date Claude reports as completion date.
                        Defaults to today.

    Returns:
        The new next_due string, or None if schedule is "none".
    """
    task = get_task(tasks, task_id)
    if not task:
        return None

    schedule = task.get("schedule", "none")
    if schedule == "none":
        task["last_run"]    = completed_date or _today()
        task["last_status"] = "completed"
        task["updated_at"]  = _now_iso()
        return None

    # Anchor: advance from the CURRENT next_due (not from completed_date)
    # This keeps the schedule anchored to its original cadence. If the task
    # fell behind by more than one interval, _advance_date_catchup() (v8.1.5)
    # skips past every already-missed occurrence in one call, so a single
    # completion always makes the task current — see its docstring.
    # v9.0.2: pass through the task's day_of_week pin so the DOW constraint
    # is preserved across completions.
    anchor = task.get("next_due") or completed_date or _today()
    dow = task.get("schedule_day_of_week")  # None = unpinned
    new_next_due = _advance_date_catchup(anchor, schedule,
                                         completed_date or _today(), dow)

    task["last_run"]    = completed_date or _today()
    task["last_status"] = "completed"
    task["next_due"]    = new_next_due
    task["updated_at"]  = _now_iso()

    return new_next_due


def catch_up_all_due_tasks(tasks: list) -> int:
    """v8.1.6: called when the Autonomous Task Queue is enabled — advances
    every currently due/overdue task's next_due to its next occurrence
    after today, WITHOUT marking it as run/completed (unlike
    advance_next_due(), which is for an actual completion Claude reports).

    Rationale: enabling the daily scheduled automation shouldn't cause a
    pile of backlog to all fire on day one just because they'd accumulated
    while automation was off — that's surprising and burns API/subscription
    usage on tasks whose specific overdue occurrences the user never asked
    to run. This resyncs everyone to the schedule's normal cadence starting
    from today, exactly like advance_next_due()'s catch-up logic, but
    labeled "skipped_on_enable" (not "completed") so the history honestly
    reflects that these specific occurrences were never actually analyzed.

    Modifies tasks in-place. Returns the number of tasks advanced — caller
    is responsible for calling save_custom_tasks(tasks) afterward.
    """
    today = _today()
    advanced = 0
    for task in tasks:
        if not _is_due(task):
            continue
        schedule = task.get("schedule", "none")
        if schedule == "none":
            continue
        anchor = task.get("next_due") or today
        dow = task.get("schedule_day_of_week")  # v9.0.2
        new_next_due = _advance_date_catchup(anchor, schedule, today, dow)
        if new_next_due is None:
            continue
        task["next_due"]    = new_next_due
        task["last_status"] = "skipped_on_enable"
        task["updated_at"]  = _now_iso()
        advanced += 1
    return advanced


# ---------------------------------------------------------------------------
# Queue helpers
# ---------------------------------------------------------------------------

def build_task_prompt(task: dict) -> str:
    """
    Build the full Claude prompt for a custom task, injecting scope dirs
    and output instructions automatically.
    """
    lines = []

    # Scope injection
    scope_dirs = task.get("scope_dirs") or []
    if scope_dirs:
        lines.append("Focus your analysis ONLY on documents in these directories:")
        for d in scope_dirs:
            lines.append(f"  - {d}")
        lines.append("")

    # Core prompt
    lines.append(task.get("prompt", "").strip())
    lines.append("")

    # Output instructions
    # v8.1.10: added a third output option (Email), and rewrote this as a
    # generic action list rather than enumerating combinations by hand —
    # there are now 2^3 combinations instead of 2^2. At least one of the
    # three is guaranteed by create_task()/update_task() validation, but
    # the "no outputs" fallback is kept for defensiveness against any
    # legacy task saved before that validation existed.
    out_learnings = task.get("output_learnings", True)
    out_report    = task.get("output_report", False)
    out_email     = task.get("output_email", False)
    report_folder = task.get("report_folder", DEFAULT_REPORT_FOLDER)

    actions = []
    if out_learnings:
        actions.append(
            "record key insights as learnings via record_learning() "
            "with category 'business_insight'"
        )
    if out_report:
        actions.append(
            f"save the full analysis as a Word document via "
            f"save_analysis_report() to folder '{report_folder}'"
        )
    if out_email:
        if out_report:
            actions.append(
                "email the full analysis via send_email() — leave 'to' "
                "blank to use the configured default recipient, use a "
                "clear subject line naming the task, and attach the "
                "report saved above via attachment_path"
            )
        else:
            actions.append(
                "email the full analysis via send_email() — leave 'to' "
                "blank to use the configured default recipient, and use "
                "a clear subject line naming the task"
            )

    if actions:
        # v8.1.10 fix: NOT .capitalize() — that lowercases every character
        # after the first, which corrupted embedded mixed-case content
        # like report_folder paths (e.g. "C:\Reports" became "c:\reports").
        # Just uppercase the first letter, leave everything else alone.
        def _cap_first(s):
            return s[0].upper() + s[1:] if s else s
        numbered = " ".join(f"({i + 1}) {_cap_first(a)}."
                             for i, a in enumerate(actions))
        lines.append(f"Output: {numbered}")
        # v8.1.12 fix: this used to fire whenever out_report or out_email
        # was true, REGARDLESS of out_learnings — so unchecking "Save key
        # insights to Learnings" didn't actually stop a learning from
        # being requested, as long as a report or email was also
        # selected. Confirmed in practice: a completion learning really
        # was recorded for a task with Learnings unchecked. Gate this on
        # out_learnings too, so the checkbox is actually respected — no
        # learning of any kind gets requested when it's off, matching
        # what the built-in Common Business Analysis prompts already do
        # correctly.
        if out_learnings and (out_report or out_email):
            lines.append(
                "After completing the above, record a completion learning "
                "via record_learning() with title '[task label] — report "
                "completed' and category 'analysis_report', noting where "
                "the output went (report path and/or recipient email) and "
                "the next scheduled run date."
            )
    else:
        lines.append(
            "Output: Display the analysis in the conversation. "
            "Nothing will be saved permanently."
        )

    return "\n".join(lines)


def tasks_to_queue_entries(custom_tasks: list) -> list:
    """
    Convert custom task definitions to pending_tasks.json queue entries.
    Used when the user clicks 'Queue' or 'Save & Queue', and by
    sync_due_tasks_to_queue() (MCP tool) for chat-driven queueing.

    v8.1.7: entries now carry their own "schedule" and "next_due",
    mirroring what built-in Common Business Analysis entries have always
    carried directly. This makes queue entries self-describing — the
    is_queue_entry_ready() / re-arm logic in complete_analysis_task() no
    longer needs to special-case "custom vs built-in"; both look the same
    once they're in the queue. source_id is kept as a back-reference so
    completion can also write the advanced next_due back to the
    definition in custom_analysis_tasks.json, keeping the GUI's task list
    display in sync with the queue.
    """
    import datetime as _dt
    entries = []
    for i, t in enumerate(custom_tasks):
        ts = _dt.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        # Add microseconds + index to guarantee uniqueness even within same second
        us = _dt.datetime.utcnow().strftime("%f")
        entries.append({
            "task_id":    f"{t['task_id']}_{ts}_{us}_{i}",
            "source_id":  t["task_id"],   # links back to custom task
            "type":       "custom",
            "label":      t["label"],
            "prompt":     build_task_prompt(t),
            "created_at": _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status":     "pending",
            "output_learnings": t.get("output_learnings", True),
            "output_report":    t.get("output_report", False),
            "output_email":     t.get("output_email", False),
            "report_folder":    t.get("report_folder", DEFAULT_REPORT_FOLDER),
            "scope_dirs":       t.get("scope_dirs", []),
            "schedule":         t.get("schedule", "none"),
            "next_due":         t.get("next_due"),
            "daily_start_time": t.get("daily_start_time", "09:00"),
            "daily_end_time":   t.get("daily_end_time", "17:00"),
            "daily_times_per_day": t.get("daily_times_per_day", 1),
        })
    return entries


# ---------------------------------------------------------------------------
# Status helpers
# ---------------------------------------------------------------------------

def due_status_label(task: dict) -> str:
    """
    Return a human-readable due status string for display in the GUI.
    Examples: 'Due today', 'Overdue 3 days', 'Due Jun 30', 'Manual only'

    v8.1.11 fix: this used _parse_date() (bare YYYY-MM-DD only), which
    raises on the full datetime next_due values ("daily" schedule now
    produces, e.g. "2026-07-26T14:00:00") — silently falling back to
    'Unknown' for every daily task, including ones genuinely due right
    now. Switched to _parse_due_datetime() (handles both formats), with a
    time-aware branch specifically for "daily" schedule entries that
    actually carry a time component, so those get a proper "Due now" /
    "Due today at 2:00 PM" / "Due tomorrow at 8:00 AM" label instead.
    Weekly/biweekly/monthly/quarterly/yearly behavior is unchanged — they
    never carry a time component, so they fall straight through to the
    existing day-granularity logic below.
    """
    schedule = task.get("schedule", "none")
    if schedule == "none":
        return "Manual only"

    next_due = task.get("next_due")
    if not next_due:
        return "Not scheduled"

    try:
        due_dt = _parse_due_datetime(next_due)

        if schedule == "daily" and "T" in next_due:
            now = datetime.datetime.now()
            time_str = due_dt.strftime("%I:%M %p").lstrip("0")
            if due_dt <= now:
                return "⚡ Due now"
            elif due_dt.date() == now.date():
                return f"Due today at {time_str}"
            elif due_dt.date() == now.date() + datetime.timedelta(days=1):
                return f"Due tomorrow at {time_str}"
            else:
                return f"Due {due_dt.strftime('%b %d')} at {time_str}"

        due_date = due_dt.date()
        today    = datetime.date.today()
        delta    = (due_date - today).days

        if delta < 0:
            return f"⚠ Overdue {abs(delta)} day{'s' if abs(delta) != 1 else ''}"
        elif delta == 0:
            return "⚡ Due today"
        elif delta == 1:
            return "Due tomorrow"
        elif delta <= 7:
            return f"Due in {delta} days"
        else:
            return f"Due {due_date.strftime('%b %d')}"
    except (ValueError, TypeError):
        return "Unknown"
