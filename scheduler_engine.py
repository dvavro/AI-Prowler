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

v8.1.3: email_to/location/name are no longer read from this config at
all. The send recipient now comes live from Settings -> Email
Configuration (~/.ai-prowler/email_config.json's default_to — see
_read_default_to_email()). The owner's name/address for job body text
now comes live from Settings -> Owner Name (~/.ai-prowler/config.json's
owner_name/owner_city/owner_state/owner_zip — see ai_prowler_mcp.py's
_get_personal_owner_name()/_get_personal_owner_location_string()).
These three keys may still be PRESENT in an existing config file for
backward compatibility, but are dead weight — nothing reads them anymore.

Config schema:
  {
    "enabled": true,
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

# Safe-save: write to a temp file then swap it in, so a reader (or a crash)
# never sees a half-written / empty scheduler file. Falls back to a plain
# write if safe_save.py is missing (partial update).
try:
    from safe_save import atomic_write_text as _ss_write_text, read_json_retry as _ss_read_json
except Exception:  # pragma: no cover
    def _ss_write_text(path, text, encoding="utf-8", **_k):
        Path(path).write_text(text, encoding=encoding)

    def _ss_read_json(path, default=None, **_k):
        try:
            return json.loads(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError:
            return default


# ── Config ────────────────────────────────────────────────────────────────────

def load_config() -> dict:
    """Load scheduler config, returning defaults if missing.

    v8.1.3: no longer defaults email_to/location/name to anything — those
    keys are dead weight now (see module docstring). An existing config
    file with those keys still present is left untouched (harmless), but
    nothing reads them anymore.
    """
    defaults = {
        "enabled":  False,
        "jobs": {}
    }
    try:
        if CONFIG_PATH.exists():
            saved = _ss_read_json(CONFIG_PATH) or {}   # retries a mid-save read
            defaults.update(saved)
    except Exception:
        pass
    return defaults


def save_config(cfg: dict) -> None:
    """Persist scheduler config to disk."""
    try:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        _ss_write_text(CONFIG_PATH,                        # atomic (safe_save)
                       json.dumps(cfg, indent=2, ensure_ascii=False))
    except Exception:
        pass


def default_job_config(job_id: str) -> dict:
    """Return default config for a job from the registry."""
    try:
        from scheduler_jobs import JOB_REGISTRY
        meta = JOB_REGISTRY.get(job_id, {})
        return {
            "enabled":  False,
            "time":     meta.get("default_time", "08:00"),
            "days":     meta.get("default_days", "daily"),
            "audience": meta.get("default_audience", "owner"),     # server: who gets it (2026-11-02)
            "email":    True,                                      # ✉ send it by email
            "sms":      False,                                     # 📱 also send it as a text
        }
    except Exception:
        return {"enabled": False, "time": "08:00", "days": "daily", "audience": "owner",
                "email": True, "sms": False}


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


# ── Time choices for the Proactive Alerts dropdowns (2026-11-02, David: "make the time boxes a drop down
# selection for time and every N hours") ───────────────────────────────────────────────────────────────
# Repeating alerts only run in the daytime — the descriptions always promised 8am–8pm, but nothing
# enforced it, so a 2-hour alert could email at 2 AM.
INTERVAL_START_HOUR = 8     # first run no earlier than 8:00 AM
INTERVAL_END_HOUR   = 20    # nothing at or after 8:00 PM
INTERVAL_HOURS = (1, 2, 3, 4, 6, 8, 12)


def time_label(value: str) -> str:
    """'07:30' → '7:30 AM', 'every_2h' → 'Every 2 hours', 'every_30m' → 'Every 30 minutes'.
    Anything it can't read comes back as typed."""
    t = (value or "").strip().lower()
    try:
        if t.startswith("every_"):
            n = int("".join(c for c in t if c.isdigit()))
            if t.endswith("h"):
                return "Every hour" if n == 1 else f"Every {n} hours"
            return f"Every {n} minutes"
        hh, mm = map(int, t.split(":"))
        if not (0 <= hh < 24 and 0 <= mm < 60):
            return value
        return f"{(hh % 12) or 12}:{mm:02d} {'AM' if hh < 12 else 'PM'}"
    except Exception:
        return value


def time_choices(current: str = "") -> list:
    """The dropdown's choices as [(label, stored value)]: every half hour of the day, then the
    'Every N hours' options. A saved value that isn't in the list (say '07:15' or 'every_45m' typed
    in by hand earlier) is added so opening the screen never changes someone's setting."""
    out = [(time_label(f"{h:02d}:{m:02d}"), f"{h:02d}:{m:02d}") for h in range(24) for m in (0, 30)]
    out += [(time_label(f"every_{n}h"), f"every_{n}h") for n in INTERVAL_HOURS]
    cur = (current or "").strip()
    if cur and time_label(cur) not in {lab for lab, _ in out}:    # '7:00' and '07:00' are the same choice
        out.append((time_label(cur), cur))
    return out


def time_value(label: str, current: str = "") -> str:
    """The stored value for a dropdown label (the reverse of time_label)."""
    for lab, val in time_choices(current):
        if lab == label:
            return val
    return (label or "").strip()


def _in_interval_hours(now: datetime.datetime) -> bool:
    return INTERVAL_START_HOUR <= now.hour < INTERVAL_END_HOUR


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
    """Send alert via AI-Prowler's existing send_alert / send_email tools.

    body_html is real HTML (see scheduler_jobs.py job functions). send_email()
    now accepts an explicit body_html kwarg (v8.2+) and sends a proper
    multipart/alternative message so mail clients render the formatting
    instead of showing raw tags — 'body' still carries a tag-stripped
    plain-text fallback for clients that don't render HTML.
    """
    import re
    plain = re.sub(r"<[^>]+>", " ", body_html).strip()
    try:
        from ai_prowler_mcp import send_email as _send
        # send_email(to, subject, body, attachment_path="", body_html="")
        result = _send(to=to, subject=subject, body=plain, body_html=body_html)
        return "✅" in str(result) or "sent" in str(result).lower()
    except Exception:
        try:
            from ai_prowler_mcp import send_alert as _alert
            # send_alert(message, to="") — no 'subject' kwarg. Fold subject
            # into the message body since send_alert has nowhere else to put it.
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


def clear_log() -> bool:
    """Empty the log (2026-11-02, David: a Clear Log button). Leaves one line saying when it was
    cleared, so an empty log never looks like the alerts simply never ran."""
    try:
        with _LOCK:
            LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            LOG_PATH.write_text(f"[{ts}] Log cleared\n", encoding="utf-8")
        return True
    except Exception:
        return False


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
            _last_run = _ss_read_json(_LAST_RUN_PATH) or {}   # retries a mid-save read
    except Exception:
        _last_run = {}


def _save_last_run() -> None:
    try:
        _ss_write_text(_LAST_RUN_PATH, json.dumps(_last_run, indent=2))   # atomic (safe_save)
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


def _read_default_to_email() -> str:
    """Read the recipient address from Settings -> Email Configuration
    (~/.ai-prowler/email_config.json's default_to — the same file
    configure_email() writes). Added v8.1.3, replacing scheduler_config.
    json's own separate email_to field, which had its own hardcoded
    default and no relationship to the actual SMTP setup — a real bug
    where the "sent" recipient and the configured SMTP default_to could
    silently be two different addresses. Never raises; "" means not
    configured, which the caller must treat as "nowhere to send this,
    skip the tick" rather than guessing an address.

    v8.1.5 fix: default_to was only ever WRITTEN by _save_smtp_cfg() when
    the user clicks Save Config — so upgrades and fresh installs that
    already had SMTP configured (username/password saved from a prior
    version, before default_to existed) still read "" here forever unless
    the user happened to re-open Settings and click Save again with no
    changes. That's a confusing trap on upgrade. Fall back to username —
    for personal-mode use, the SMTP login IS the recipient inbox in the
    overwhelming majority of cases — so this resolves correctly the
    moment SMTP is configured, with no extra click required."""
    try:
        p = Path.home() / ".ai-prowler" / "email_config.json"
        if not p.exists():
            return ""
        cfg = json.loads(p.read_text(encoding="utf-8-sig")) or {}
        to_addr = (cfg.get("default_to") or "").strip()
        if to_addr:
            return to_addr
        return (cfg.get("username") or "").strip()
    except Exception:
        return ""


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

    server = _is_server()
    email_to = _read_default_to_email()
    if not _has_recipient(cfg, email_to, server):
        _log("WARNING: no default recipient configured — go to Settings -> "
             "Email Configuration and set a default recipient (or a 'Texts go to' "
             "number in Proactive Alerts). Alerts have nowhere to go.")
        return

    now = datetime.datetime.now()
    mode = "server" if server else "personal"

    for job_id, meta in JOB_REGISTRY.items():
        if mode not in meta.get("modes", ("personal", "server")):
            continue                                        # e.g. SMS monitor on a server
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
        if is_interval and not _in_interval_hours(now):     # repeating alerts: 8 AM – 8 PM only
            continue
        if not _is_time_due(job_id, time_str, now):
            continue

        # Run the job
        _log(f"Running job: {job_id}")
        sent = _deliver(job_id, meta, cfg, job_cfg, email_to, server)

        now_str = now.strftime("%Y-%m-%d %H:%M")
        _last_run[job_id] = now_str
        _save_last_run()

        if not sent:
            _log(f"Job {job_id}: no output (silent — nothing to report)")
            continue
        for to, subject, ok in sent:
            _log(f"Job {job_id}: sent '{subject}' to {to} — {'OK' if ok else 'FAILED'}")


# ── Recipients (2026-11-02, server alerts) ───────────────────────────────────────────────────────────
# Personal: everything goes to the Email Configuration recipient, as before. Server: each alert has an
# audience (Owner only by default — David: "server alerts go only to the owner (Configurable)"); the
# alert runs once per recipient AS that person, so a manager, staff member or crew member only ever
# gets what they can see in the apps (crew: their own jobs).
_AUDIENCE_ROLES = {
    "owner":    ("owner",),
    "managers": ("owner", "manager"),
    "team":     ("owner", "manager", "staff", "field_crew"),
    "crew":     ("owner", "manager", "staff", "field_crew"),   # my-day: only people with jobs get one
    "senders":  ("owner",),
    "customers": ("owner",),
}


def _is_server() -> bool:
    try:
        from scheduler_jobs import _server_mode
        return bool(_server_mode())
    except Exception:
        return False


def _team() -> list:
    """The server's active users with their role and email (users.json, via the running server)."""
    try:
        import sys as _sys
        m = _sys.modules.get("ai_prowler_mcp")
        if m is None:
            import ai_prowler_mcp as m
        return [dict(p) for p in m._desk_team()]
    except Exception:
        return []


def _owner_people() -> list:
    return [p for p in _team() if str(p.get("role", "")).lower() == "owner" and (p.get("email") or p.get("phone"))]


def _has_recipient(cfg: dict, email_to: str, server: bool) -> bool:
    """Somewhere for alerts to go: the default email, the "Texts go to" number, or (server) an owner."""
    return bool(email_to or str((cfg or {}).get("sms_to") or "").strip() or (server and _owner_people()))


def audience_for(job_id: str, meta: dict, job_cfg: dict) -> str:
    allowed = tuple(meta.get("audiences") or ("owner",))
    a = str((job_cfg or {}).get("audience") or "").strip().lower()
    return a if a in allowed else allowed[0]


def recipients(audience: str, email_to: str = "", owner_phone: str = "", need: str = "email") -> list:
    """The people an alert goes to on a server: {"id", "name", "role", "email", "phone"}, one each. With
    need="email" only people with an email count; "phone" → only people with a cell phone; "either" → both.
    The owner always gets it; when no owner can be reached, Settings → Email Configuration (and the
    alerts panel's "Texts go to" number) stand in. Phones come from each user's cell phone in the Admin tab."""
    roles = _AUDIENCE_ROLES.get(audience, ("owner",))

    def reachable(p):
        e, ph = bool(p.get("email")), bool(p.get("phone"))
        return {"email": e, "phone": ph}.get(need, e or ph)
    people = [dict(p) for p in _team() if reachable(p) and str(p.get("role", "")).lower() in roles]
    for p in people:                              # an owner with no cell phone: the panel's number
        if str(p.get("role", "")).lower() == "owner" and not p.get("phone") and owner_phone:
            p["phone"] = owner_phone
    if not any(str(p.get("role", "")).lower() == "owner" for p in people) and (email_to or owner_phone):
        people.insert(0, {"id": "owner", "name": "", "role": "owner", "email": email_to, "phone": owner_phone})
    seen, out = set(), []
    for p in people:
        key = (str(p.get("email") or "").strip().lower(), str(p.get("phone") or "").strip())
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


# ── Text messages (2026-11-02, David: "send individual alerts to SMS when enabled ... per Alert along with
# email") ─────────────────────────────────────────────────────────────────────────────────────────────
SMS_LIMIT = 320                                   # two text segments


def channels(job_cfg: dict) -> tuple:
    """(email on, text on) for one alert. Email stays on unless switched off; texts are off until on."""
    jc = job_cfg or {}
    return jc.get("email", True) is not False, bool(jc.get("sms", False))


def texting_ready() -> bool:
    """Texting is switched on (Settings → MCP Tool Configuration) and an SMS provider is set up."""
    try:
        from scheduler_jobs import _app_on
        if not _app_on("sms_whatsapp"):
            return False
        from sms_backends import get_sms_backend, load_sms_config
        ok, _msg = get_sms_backend(load_sms_config()).validate_config()
        return bool(ok)
    except Exception:
        return False


def sms_text(subject: str, body_html: str, limit: int = SMS_LIMIT) -> str:
    """A short text version of an alert: the subject and its first few list lines."""
    import html as _html
    import re as _re
    items = []
    for m in _re.findall(r"<li[^>]*>(.*?)</li>", body_html or "", _re.S | _re.I):
        t = " ".join(_html.unescape(_re.sub(r"<[^>]+>", " ", m)).split())
        if t:
            items.append(t)
    text = " ".join(str(subject or "").split())
    if items:
        text += ": " + "; ".join(items[:6]) + (f" (+{len(items) - 6} more)" if len(items) > 6 else "")
    return text if len(text) <= limit else text[:limit - 1].rstrip() + "…"


def _send_sms(to: str, text: str) -> bool:
    try:
        from ai_prowler_mcp import send_sms as _sms
        return str(_sms(to=to, message=text)).lstrip().startswith("✅")
    except Exception:
        return False


def _items(res, default_to: str) -> list:
    """A job's result as [(email, subject, html, extra)] — extra may carry {"phone", "sms"}."""
    if not res:
        return []
    raw = res if isinstance(res, list) else [(default_to,) + tuple(res)]
    out = []
    for it in raw:
        it = tuple(it)
        out.append((it[0], it[1], it[2], dict(it[3]) if len(it) > 3 and isinstance(it[3], dict) else {}))
    return out


def _deliver(job_id: str, meta: dict, cfg: dict, job_cfg: dict, email_to: str, server: bool) -> list:
    """Run one alert and send what it produces — by email and/or text, as the alert's switches say.
    Returns [(to, subject, ok)] (to = an email address or a phone number); [] when it had nothing."""
    fn = meta["fn"]
    use_email, use_sms = channels(job_cfg)
    use_sms = use_sms and texting_ready()
    owner_phone = str((cfg or {}).get("sms_to") or "").strip()

    def call(c):
        try:
            return fn(c)
        except Exception:
            _log(f"ERROR in job {job_id}: {traceback.format_exc()}")
            return None

    sent = []

    def send(email, phone, subject, body, text=""):
        if use_email and email:
            sent.append((email, subject, _send_email(email, subject, body)))
        if use_sms and phone:
            sent.append((phone, subject, _send_sms(phone, text or sms_text(subject, body))))

    flags = {"_email_on": use_email, "_sms_on": use_sms}
    if not server:
        res = call({**cfg, **flags, "_owners": [email_to], "_audience": "owner"}
                   if meta.get("delivery") == "self" else cfg)
        for to, subject, body, extra in _items(res, email_to):
            if not to and not extra.get("phone"):              # "for the owner" — that's you
                send(email_to, owner_phone, subject, body, extra.get("sms", ""))
                continue
            phone = extra.get("phone") or (owner_phone if to == email_to else "")
            send(to if "@" in str(to) else "", phone, subject, body, extra.get("sms", ""))
        return sent

    need = "either" if (use_email and use_sms) else ("phone" if use_sms else "email")
    audience = audience_for(job_id, meta, job_cfg)
    if meta.get("delivery") == "self":
        team = _team()
        owners = recipients("owner", email_to, owner_phone, need)
        phone_of = {str(p.get("email") or "").lower(): p.get("phone", "") for p in team if p.get("email")}
        phone_of.update({str(p.get("email") or "").lower(): p.get("phone", "") for p in owners})
        res = call({**cfg, **flags, "_audience": audience, "_owners": [p.get("email", "") for p in owners],
                    "_team": team})
        for to, subject, body, extra in _items(res, ""):
            if not to and not extra.get("phone"):          # a summary for "the owner(s)"
                for o in owners:
                    send(o.get("email", ""), o.get("phone", ""), subject, body, extra.get("sms", ""))
                continue
            send(to if "@" in str(to) else "", extra.get("phone") or phone_of.get(str(to).lower(), ""),
                 subject, body, extra.get("sms", ""))
        return sent
    for person in recipients(audience, email_to, owner_phone, need):
        res = call({**cfg, "_viewer": person})
        if res:
            subject, body = res
            send(person.get("email", ""), person.get("phone", ""), subject, body)
    return sent


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
        meta = JOB_REGISTRY[job_id]
        job_cfg = cfg.get("jobs", {}).get(job_id, default_job_config(job_id))
        # v8.1.3: recipient comes from Settings -> Email Configuration's
        # default_to, same as _tick() — see _read_default_to_email().
        email_to = _read_default_to_email()
        server = _is_server()
        if not _has_recipient(cfg, email_to, server):
            if meta.get("delivery") == "self":       # customer reminders etc.: don't run it just to look
                return "⚠️ No default recipient configured (Settings -> Email Configuration)."
            res = meta["fn"](cfg)
            if res is None:
                return "ℹ️ Job ran but had nothing to report."
            subject = res[0][1] if isinstance(res, list) else res[0]
            return f"⚠️ No default recipient configured (Settings -> Email " \
                   f"Configuration). Would have sent: {subject}"
        sent = _deliver(job_id, meta, cfg, job_cfg, email_to, server)
        if not sent:
            return "ℹ️ Job ran but had nothing to report."
        _last_run[job_id] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        _save_last_run()
        for to, subject, ok in sent:
            _log(f"Job {job_id} (▶ Now): sent '{subject}' to {to} — {'OK' if ok else 'FAILED'}")
        ok_n = sum(1 for _, _, ok in sent if ok)
        if len(sent) == 1:
            subject, ok = sent[0][1], sent[0][2]
            return f"✅ Sent: {subject}" if ok else f"⚠️ Generated but sending failed: {subject}"
        return f"✅ Sent {ok_n} of {len(sent)} message(s)" if ok_n else f"⚠️ {len(sent)} message(s) failed"
    except Exception:
        return f"❌ Error: {traceback.format_exc()}"
