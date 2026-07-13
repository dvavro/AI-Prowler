"""
scheduler_engine.py
====================
Background scheduler engine for AI-Prowler proactive alerts.
Personal mode only — not available in server mode.

Design:
  - Runs as a daemon thread inside the AI-Prowler process
  - Checks every 60 seconds whether any job is due
  - Sends output via send_alert() (email) — no API cost, no SMS required
  - All config lives in ~/.ai-prowler/scheduler_config.json
  - Never crashes the host process — all exceptions logged and swallowed

Config schema:
  {
    "enabled": true,
    "email_to": "david.vavro1@gmail.com",
    "location": "New Smyrna Beach, Florida",
    "name": "David",
    "jobs": {
      "morning_briefing":      {"enabled": true,  "time": "07:00", "days": "weekdays"},
      "overdue_invoice_alert": {"enabled": true,  "time": "08:00", "days": "daily"},
      "due_analysis_tasks":    {"enabled": true,  "time": "08:05", "days": "daily"},
      "sms_reply_monitor":     {"enabled": false, "time": "every_2h", "days": "daily"},
      "weather_watch":         {"enabled": true,  "time": "19:00", "days": "sunday"},
      "end_of_day_summary":    {"enabled": false, "time": "18:00", "days": "daily"}
    }
  }
"""
from __future__ import annotations
import datetime, json, threading, time, traceback
from pathlib import Path
from typing import Callable

CONFIG_PATH = Path.home() / ".ai-prowler" / "scheduler_config.json"
LOG_PATH    = Path.home() / ".ai-prowler" / "scheduler_log.txt"
_LOCK       = threading.Lock()
_last_run: dict[str, str] = {}   # job_id -> "YYYY-MM-DD HH:MM" of last run


# ── Config ────────────────────────────────────────────────────────────────────

def load_config() -> dict:
    """Load scheduler config, returning defaults if missing."""
    defaults = {
        "enabled":  False,
        "email_to": "",
        "location": "New Smyrna Beach, Florida",
        "name":     "David",
        "jobs": {}
    }
    try:
        if CONFIG_PATH.exists():
            saved = json.loads(CONFIG_PATH.read_text(encoding="utf-8")) or {}
            defaults.update(saved)
    except Exception:
        pass
    return defaults


def save_config(cfg: dict) -> None:
    """Persist scheduler config to disk."""
    try:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(
            json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def default_job_config(job_id: str) -> dict:
    """Return default config for a job from the registry."""
    try:
        from scheduler_jobs import JOB_REGISTRY
        meta = JOB_REGISTRY.get(job_id, {})
        return {
            "enabled": False,
            "time":    meta.get("default_time", "08:00"),
            "days":    meta.get("default_days", "daily"),
        }
    except Exception:
        return {"enabled": False, "time": "08:00", "days": "daily"}


# ── Scheduling logic ──────────────────────────────────────────────────────────

def _is_day_match(days: str, now: datetime.datetime) -> bool:
    """Return True if the current day matches the 'days' setting."""
    d = days.strip().lower()
    wd = now.weekday()  # 0=Mon … 6=Sun
    if d == "daily":
        return True
    if d == "weekdays":
        return wd < 5
    if d == "weekends":
        return wd >= 5
    if d == "monday":
        return wd == 0
    if d == "tuesday":
        return wd == 1
    if d == "wednesday":
        return wd == 2
    if d == "thursday":
        return wd == 3
    if d == "friday":
        return wd == 4
    if d == "saturday":
        return wd == 5
    if d == "sunday":
        return wd == 6
    return True  # unknown → always match


def _is_time_due(job_id: str, time_str: str, now: datetime.datetime) -> bool:
    """Return True if this job should fire right now."""
    t = time_str.strip().lower()

    if t.startswith("every_"):
        # Interval: every_2h, every_30m, etc.
        try:
            val  = int("".join(c for c in t if c.isdigit()))
            unit = "h" if "h" in t else "m"
            mins = val * 60 if unit == "h" else val
            last = _last_run.get(job_id)
            if not last:
                return True  # never run
            last_dt = datetime.datetime.strptime(last, "%Y-%m-%d %H:%M")
            return (now - last_dt).total_seconds() >= mins * 60
        except Exception:
            return False

    # Fixed time: HH:MM
    try:
        hh, mm = map(int, t.split(":"))
        # Fire if within the current minute
        return now.hour == hh and now.minute == mm
    except Exception:
        return False


def _already_ran_today(job_id: str) -> bool:
    """True if this job already ran today (prevents double-fire on fixed times)."""
    last = _last_run.get(job_id, "")
    if not last:
        return False
    today = datetime.date.today().isoformat()
    return last.startswith(today)


# ── Email delivery ────────────────────────────────────────────────────────────

def _send_email(to: str, subject: str, body_html: str) -> bool:
    """Send alert via AI-Prowler's existing send_alert / send_email tools."""
    try:
        from ai_prowler_mcp import send_email as _send
        # send_email(to, subject, body, attachment_path="") — no 'html' kwarg.
        result = _send(to=to, subject=subject, body=body_html)
        return "✅" in str(result) or "sent" in str(result).lower()
    except Exception:
        try:
            from ai_prowler_mcp import send_alert as _alert
            # send_alert(message, to="") — no 'subject' kwarg. Fold subject
            # into the message body since send_alert has nowhere else to put it.
            import re
            plain = re.sub(r"<[^>]+>", " ", body_html).strip()
            _alert(message=f"{subject}\n\n{plain[:450]}", to=to)
            return True
        except Exception:
            return False


# ── Logging ───────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    try:
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{ts}] {msg}\n"
        with _LOCK:
            # Keep log to last 500 lines
            existing = []
            if LOG_PATH.exists():
                existing = LOG_PATH.read_text(encoding="utf-8").splitlines()
            existing.append(entry.rstrip())
            LOG_PATH.write_text(
                "\n".join(existing[-500:]) + "\n", encoding="utf-8")
    except Exception:
        pass


def get_log_tail(n: int = 100) -> str:
    """Return the last n lines of the scheduler log."""
    try:
        if not LOG_PATH.exists():
            return "(no log yet)"
        lines = LOG_PATH.read_text(encoding="utf-8").splitlines()
        return "\n".join(lines[-n:])
    except Exception:
        return "(error reading log)"


# ── Last-run tracking ─────────────────────────────────────────────────────────

_LAST_RUN_PATH = Path.home() / ".ai-prowler" / "scheduler_last_run.json"

def _load_last_run() -> None:
    global _last_run
    try:
        if _LAST_RUN_PATH.exists():
            _last_run = json.loads(_LAST_RUN_PATH.read_text(encoding="utf-8")) or {}
    except Exception:
        _last_run = {}


def _save_last_run() -> None:
    try:
        _LAST_RUN_PATH.write_text(
            json.dumps(_last_run, indent=2), encoding="utf-8")
    except Exception:
        pass


def get_last_run(job_id: str) -> str:
    """Return human-readable last-run string for a job."""
    return _last_run.get(job_id, "Never")


# ── Main scheduler loop ───────────────────────────────────────────────────────

_running = False
_thread: threading.Thread | None = None
# Per-generation stop signal. Created fresh in start(), owned exclusively by
# the thread it was created for. Fixes a real bug where the old shared
# boolean flag let an orphaned thread from a PRIOR start()/stop() cycle
# "resurrect" itself: stop() only flipped _running and returned immediately
# (no join()), so the old thread could still be mid-sleep when a new
# start() flipped _running back to True — at which point the orphan woke
# up, saw _running == True, and kept ticking concurrently with the new
# thread, both writing to the same LOG_PATH file with no coordination.
_stop_event: threading.Event | None = None


def _tick() -> None:
    """Called every 60 seconds. Checks which jobs are due and runs them."""
    global _last_run
    try:
        from scheduler_jobs import JOB_REGISTRY
    except Exception as e:
        _log(f"ERROR importing scheduler_jobs: {e}")
        return

    cfg = load_config()
    if not cfg.get("enabled"):
        return

    email_to = cfg.get("email_to", "").strip()
    if not email_to:
        _log("WARNING: email_to not configured — alerts have nowhere to go")
        return

    now = datetime.datetime.now()

    for job_id, meta in JOB_REGISTRY.items():
        job_cfg = cfg.get("jobs", {}).get(job_id, default_job_config(job_id))
        if not job_cfg.get("enabled"):
            continue

        time_str = job_cfg.get("time", meta.get("default_time", "08:00"))
        days_str = job_cfg.get("days", meta.get("default_days", "daily"))

        # Skip if wrong day
        if not _is_day_match(days_str, now):
            continue

        # Skip interval jobs that haven't elapsed; skip fixed-time jobs already run today
        is_interval = time_str.lower().startswith("every_")
        if not is_interval and _already_ran_today(job_id):
            continue
        if not _is_time_due(job_id, time_str, now):
            continue

        # Run the job
        _log(f"Running job: {job_id}")
        try:
            result = meta["fn"](cfg)
        except Exception:
            _log(f"ERROR in job {job_id}: {traceback.format_exc()}")
            result = None

        now_str = now.strftime("%Y-%m-%d %H:%M")
        _last_run[job_id] = now_str
        _save_last_run()

        if result is None:
            _log(f"Job {job_id}: no output (silent — nothing to report)")
            continue

        subject, body = result
        ok = _send_email(email_to, subject, body)
        _log(f"Job {job_id}: sent '{subject}' to {email_to} — {'OK' if ok else 'FAILED'}")


def _loop(stop_event: threading.Event) -> None:
    """Background thread: tick every 60 seconds.

    stop_event belongs exclusively to this thread's generation (created by
    the start() call that spawned this thread). It is never shared across
    generations, so an orphaned thread from an earlier stop() can never be
    mistaken for the current one — even if a new start()/stop() cycle
    happens while this thread is still winding down.
    """
    _load_last_run()
    _log("Scheduler started")
    while not stop_event.is_set():
        try:
            _tick()
        except Exception:
            _log(f"ERROR in _tick: {traceback.format_exc()}")
        # Wait up to 60s, but wake immediately (no polling delay) as soon as
        # stop_event is set — more responsive than the old 12×5s poll loop
        # and, more importantly, race-free.
        stop_event.wait(60)
    _log("Scheduler stopped")


def start() -> None:
    """Start the background scheduler thread."""
    global _running, _thread, _stop_event
    if _running:
        return
    _running = True
    _stop_event = threading.Event()
    _thread = threading.Thread(
        target=_loop, args=(_stop_event,),
        daemon=True, name="AI-Prowler-Scheduler")
    _thread.start()


def stop() -> None:
    """Stop the background scheduler thread and wait for it to actually exit.

    Callers (including tests) can rely on the thread being fully terminated
    — not just a flag being flipped — by the time this returns. Uses a
    bounded join() rather than blocking forever in case the thread is stuck
    mid-tick; 65s covers the worst case (a tick already in progress plus one
    full 60s wait cycle) with margin.
    """
    global _running
    _running = False
    if _stop_event is not None:
        _stop_event.set()
    if _thread is not None and _thread.is_alive():
        _thread.join(timeout=65)


def is_running() -> bool:
    return _running and _thread is not None and _thread.is_alive()


def run_job_now(job_id: str) -> str:
    """Manually trigger a specific job immediately. Returns result summary."""
    try:
        from scheduler_jobs import JOB_REGISTRY
        if job_id not in JOB_REGISTRY:
            return f"❌ Unknown job: {job_id}"
        cfg = load_config()
        result = JOB_REGISTRY[job_id]["fn"](cfg)
        if result is None:
            return "ℹ️ Job ran but had nothing to report."
        subject, body = result
        email_to = cfg.get("email_to", "").strip()
        if email_to:
            ok = _send_email(email_to, subject, body)
            _last_run[job_id] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            _save_last_run()
            return f"✅ Sent: {subject}" if ok else f"⚠️ Generated but email failed: {subject}"
        else:
            return f"⚠️ No email configured. Would have sent: {subject}"
    except Exception:
        return f"❌ Error: {traceback.format_exc()}"
