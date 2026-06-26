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
MAX_CUSTOM_TASKS = 10

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


def _is_due(task: dict) -> bool:
    """Return True if the task is due today or overdue."""
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
# CRUD
# ---------------------------------------------------------------------------

def create_task(label: str,
                prompt: str,
                scope_dirs: list = None,
                schedule: str = "none",
                first_due: str = None,
                output_learnings: bool = True,
                output_report: bool = False,
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
        report_folder:    Output folder for .docx reports.

    Returns:
        Task dict ready to be appended to the task list.

    Raises:
        ValueError: if validation fails.
    """
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
        "report_folder":    report_folder or DEFAULT_REPORT_FOLDER,
        "created_at":       now,
        "updated_at":       now,
    }


def update_task(tasks: list, task_id: str, **kwargs) -> bool:
    """
    Update fields on an existing task in-place.
    Recalculates next_due if schedule or first_due changes.
    Returns True if found and updated, False if not found.
    """
    for t in tasks:
        if t.get("task_id") != task_id:
            continue

        updatable = [
            "label", "prompt", "scope_dirs", "schedule",
            "first_due", "output_learnings", "output_report", "report_folder"
        ]
        for key in updatable:
            if key in kwargs:
                t[key] = kwargs[key]

        # Recompute next_due if schedule or first_due changed
        schedule  = t.get("schedule", "none")
        first_due = t.get("first_due")
        if schedule != "none" and first_due:
            # Keep next_due as whichever is later: original first_due or
            # already-stored next_due (don't regress a future due date)
            existing_next = t.get("next_due")
            if not existing_next:
                t["next_due"] = first_due
            else:
                try:
                    if _parse_date(first_due) > _parse_date(existing_next):
                        t["next_due"] = first_due
                except (ValueError, TypeError):
                    t["next_due"] = first_due
        elif schedule == "none":
            t["next_due"] = None

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
    # This keeps the schedule anchored to its original cadence.
    anchor = task.get("next_due") or completed_date or _today()
    new_next_due = _advance_date(anchor, schedule)

    task["last_run"]    = completed_date or _today()
    task["last_status"] = "completed"
    task["next_due"]    = new_next_due
    task["updated_at"]  = _now_iso()

    return new_next_due


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
    out_learnings = task.get("output_learnings", True)
    out_report    = task.get("output_report", False)
    report_folder = task.get("report_folder", DEFAULT_REPORT_FOLDER)

    if out_learnings and out_report:
        lines.append(
            f"Output: (1) Record key insights as learnings via record_learning() "
            f"with category 'business_insight'. "
            f"(2) Save the full analysis as a Word document via save_analysis_report() "
            f"to folder '{report_folder}'. "
            f"(3) Record a completion learning via record_learning() with title "
            f"'[task label] — report completed' and category 'analysis_report' "
            f"noting the report path and next scheduled run date."
        )
    elif out_report:
        lines.append(
            f"Output: Save the full analysis as a Word document via "
            f"save_analysis_report() to folder '{report_folder}'. "
            f"Then record a completion learning via record_learning() with title "
            f"'[task label] — report completed' and category 'analysis_report'."
        )
    elif out_learnings:
        lines.append(
            "Output: Record key insights as learnings via record_learning() "
            "with category 'business_insight'. Keep each learning concise "
            "(1-3 sentences)."
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
    Used when the user clicks 'Queue' or 'Run Due Tasks'.
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
            "report_folder":    t.get("report_folder", DEFAULT_REPORT_FOLDER),
            "scope_dirs":       t.get("scope_dirs", []),
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
