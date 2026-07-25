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
  none, daily, weekly, biweekly, monthly, quarterly, yearly

File schema (list of task objects):
  {
    "task_id":          str   — unique, e.g. "custom_001"
    "label":            str   — user-facing name (max 60 chars)
    "prompt":           str   — full analysis prompt
    "scope_dirs":       list  — directory paths to focus on (empty = all)
    "schedule":         str   — one of SCHEDULES keys
    "first_due":        str   — YYYY-MM-DD user-chosen first run date
    "next_due":         str   — YYYY-MM-DD next scheduled run (or null)
    "last_run":         str   — YYYY-MM-DD last completed date (or null)
    "last_status":      str   — "completed" | "skipped" | null
    "output_learnings": bool  — record key insights as learnings
    "output_report":    bool  — save full analysis as .docx report
    "report_folder":    str   — absolute path for report output
    "created_at":       str   — ISO 8601 creation timestamp
    "updated_at":       str   — ISO 8601 last-modified timestamp
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
    "quarterly": 91,
    "yearly":    365,
}

SCHEDULE_LABELS = {
    "none":      "Manual only",
    "daily":     "Daily",
    "weekly":    "Weekly",
    "biweekly":  "Every 2 weeks",
    "monthly":   "Monthly",
    "quarterly": "Quarterly",
    "yearly":    "Yearly",
}


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


def _advance_date(from_date_str: str, schedule: str) -> str:
    """
    Advance from_date by one schedule interval.
    Uses exact month/year arithmetic for monthly/quarterly/yearly.
    Returns YYYY-MM-DD string.
    """
    if schedule == "none" or schedule not in SCHEDULES:
        return None

    base = _parse_date(from_date_str)

    if schedule == "monthly":
        # Add exactly one month, handling month-end edge cases
        month = base.month + 1
        year  = base.year + (1 if month > 12 else 0)
        month = month if month <= 12 else 1
        # Clamp day to last day of target month
        import calendar
        max_day = calendar.monthrange(year, month)[1]
        day = min(base.day, max_day)
        return datetime.date(year, month, day).isoformat()

    if schedule == "quarterly":
        # Add 3 months
        month = base.month + 3
        year  = base.year + (month - 1) // 12
        month = ((month - 1) % 12) + 1
        import calendar
        max_day = calendar.monthrange(year, month)[1]
        day = min(base.day, max_day)
        return datetime.date(year, month, day).isoformat()

    if schedule == "yearly":
        try:
            return datetime.date(base.year + 1, base.month, base.day).isoformat()
        except ValueError:
            # Feb 29 in non-leap year → Feb 28
            return datetime.date(base.year + 1, base.month, 28).isoformat()

    # daily / weekly / biweekly — simple day arithmetic
    days = SCHEDULES[schedule]
    return (base + datetime.timedelta(days=days)).isoformat()


def _advance_date_catchup(anchor: str, schedule: str, today_str: str = None) -> str:
    """
    Advance anchor by schedule intervals until the result is strictly after
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
    """
    today_str = today_str or _today()
    new_date = _advance_date(anchor, schedule)
    if new_date is None:
        return None
    guard = 0
    while new_date <= today_str and guard < 10000:
        new_date = _advance_date(new_date, schedule)
        guard += 1
    return new_date


def _is_due(task: dict) -> bool:
    """Return True if the task is due today or overdue.

    This is for task DEFINITIONS in custom_analysis_tasks.json — used to
    decide whether a recurring definition should get a fresh entry pushed
    into the run queue (pending_tasks.json). A manual-only definition
    (schedule="none") is never "due" in this sense — it only gets queued
    when the user explicitly clicks Queue/Save & Queue.
    """
    next_due = task.get("next_due")
    if not next_due:
        return False
    schedule = task.get("schedule", "none")
    if schedule == "none":
        return False
    try:
        return _parse_date(next_due) <= datetime.date.today()
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
        return _parse_date(next_due) <= datetime.date.today()
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
        "scope_dirs":       saved.get("scope_dirs") or [],
        "output_learnings": saved.get("output_learnings", True),
        "output_report":    saved.get("output_report", False),
        "output_email":     saved.get("output_email", False),
        "report_folder":    saved.get("report_folder") or DEFAULT_REPORT_FOLDER,
        "schedule":         saved.get("schedule", "none"),
        "first_due":        saved.get("first_due"),
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
                first_due: str = None,
                output_learnings: bool = True,
                output_report: bool = False,
                output_email: bool = False,
                report_folder: str = None) -> dict:
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

    # Validate and set first_due / next_due
    next_due = None
    if schedule != "none":
        if not first_due:
            raise ValueError("A first due date is required for scheduled tasks.")
        try:
            _parse_date(first_due)
            next_due = first_due
        except ValueError:
            raise ValueError(f"Invalid first due date '{first_due}'. Use YYYY-MM-DD.")

    scope_dirs = [str(d).strip() for d in (scope_dirs or []) if str(d).strip()]

    # Generate unique task_id using counter-based helper
    task_id = _next_task_id()

    now = _now_iso()
    return {
        "task_id":          task_id,
        "label":            label,
        "prompt":           prompt,
        "scope_dirs":       scope_dirs,
        "schedule":         schedule,
        "first_due":        first_due,
        "next_due":         next_due,
        "last_run":         None,
        "last_status":      None,
        "output_learnings": bool(output_learnings),
        "output_report":    bool(output_report),
        "output_email":     bool(output_email),
        "report_folder":    report_folder or DEFAULT_REPORT_FOLDER,
        "created_at":       now,
        "updated_at":       now,
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
    """
    for t in tasks:
        if t.get("task_id") != task_id:
            continue

        updatable = [
            "label", "prompt", "scope_dirs", "schedule",
            "first_due", "output_learnings", "output_report",
            "output_email", "report_folder"
        ]

        old_schedule  = t.get("schedule", "none")
        old_first_due = t.get("first_due")
        schedule_changed = (
            "schedule" in kwargs and kwargs["schedule"] != old_schedule
        )
        first_due_changed = (
            "first_due" in kwargs and kwargs["first_due"] != old_first_due
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

        for key in updatable:
            if key in kwargs:
                t[key] = kwargs[key]

        schedule  = t.get("schedule", "none")
        first_due = t.get("first_due")

        if schedule == "none":
            # Manual-only tasks never carry a next_due.
            t["next_due"] = None
        elif schedule_changed or first_due_changed or not t.get("next_due"):
            # Genuine cadence/anchor edit (or a task that never had a
            # next_due yet, e.g. switching from "none" to a real
            # schedule) — reset to the new anchor. This can legitimately
            # move next_due EARLIER than before (Weekly -> Daily should
            # make it due sooner), not just later.
            if first_due:
                t["next_due"] = first_due
        # else: neither schedule nor first_due changed — next_due is left
        # exactly as it was.

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
    anchor = task.get("next_due") or completed_date or _today()
    new_next_due = _advance_date_catchup(anchor, schedule, completed_date or _today())

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
        new_next_due = _advance_date_catchup(anchor, schedule, today)
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
        if out_report or out_email:
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
        })
    return entries


# ---------------------------------------------------------------------------
# Status helpers
# ---------------------------------------------------------------------------

def due_status_label(task: dict) -> str:
    """
    Return a human-readable due status string for display in the GUI.
    Examples: 'Due today', 'Overdue 3 days', 'Due Jun 30', 'Manual only'
    """
    schedule = task.get("schedule", "none")
    if schedule == "none":
        return "Manual only"

    next_due = task.get("next_due")
    if not next_due:
        return "Not scheduled"

    try:
        due_date = _parse_date(next_due)
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
