"""Write guard for the Jobs-app E2E suite (spec §4.2) — the safety core.

EVERY call to the Jobs app's API, whether the browser makes it (Playwright
route handler) or test setup/cleanup makes it (ApiClient), is classified here
before it is allowed to reach the live server.

  read       -> allowed
  create     -> allowed; the new ID is added to the registry
  scoped     -> allowed ONLY if it targets something this run created (or the
                sandbox date / a ZTEST- price code); otherwise BLOCKED
  outbound   -> email/SMS/etc.: blocked and recorded (tier "email" lets exactly
                ONE email_route_now through, to the owner)
  credits    -> start_ai_routing: blocked unless tier "full"
  never      -> always blocked
  unknown    -> blocked: every new tool must be classified here on purpose
"""
from __future__ import annotations

import datetime as _dt
import re
import threading

# SANDBOX DATE = TODAY (David's decision, 2026-09-25, replacing the original
# 2030-01-07): several views hide or never load dates outside a window around
# today (the Calendar loads a rolling 12-month range; job lists hide older
# items), so far-future test data can't exercise them. This suite runs
# against a VALIDATION database with no real work in it.
#
# Because the guard allows route changes on this date and the cleanup sweep
# deletes every job dated on it, the pre-flight (conftest.py) STOPS the run if
# any non-ZTEST job exists on the sandbox date — so pointed at a database with
# real work, the suite refuses instead of deleting it. Override the date with
# E2E_SANDBOX_DATE=YYYY-MM-DD if ever needed.
#
# Note: the Route date picker missing the sandbox date (the run of 2026-09-25
# 19:40) was NOT a date-window issue: the picker is rebuilt only by the app's
# _populateRouteDateOptions(), which the test helper never called after
# refreshing the job list — fixed in app.py RouteScreen.pick_date().
import os as _os
SANDBOX_DATE = _os.environ.get("E2E_SANDBOX_DATE", "").strip() or _dt.date.today().isoformat()

# Sandbox WINDOW: tests that need other days (overdue / upcoming / "changing
# the date clears the old route") use sandbox_day(offset) within
# -3 .. +7 days of SANDBOX_DATE. The guard, the cleanup sweep and the
# pre-flight "no real jobs here" check all cover the whole window.
SANDBOX_DAYS_BEFORE = 3
SANDBOX_DAYS_AFTER = 7
_SB = _dt.date.fromisoformat(SANDBOX_DATE)
SANDBOX_DATES = frozenset((_SB + _dt.timedelta(days=d)).isoformat()
                          for d in range(-SANDBOX_DAYS_BEFORE, SANDBOX_DAYS_AFTER + 1))


def sandbox_day(offset: int = 0) -> str:
    """ISO date `offset` days from the sandbox date (0 = today). Only offsets
    inside the window are allowed, so test data never lands outside what the
    guard and cleanup cover."""
    if not -SANDBOX_DAYS_BEFORE <= offset <= SANDBOX_DAYS_AFTER:
        raise ValueError(f"sandbox_day({offset}) is outside the sandbox window "
                         f"(-{SANDBOX_DAYS_BEFORE}..+{SANDBOX_DAYS_AFTER})")
    return (_SB + _dt.timedelta(days=offset)).isoformat()


ZTEST_PREFIX = "ZTEST E2E"
ZTEST_CODE_PREFIX = "ZTEST-"

READ = {
    "read_job_spreadsheet", "get_board_updates", "get_sheet_columns", "prescreen_route_jobs",
    "get_route_start_options", "get_working_days", "list_team_members", "check_ai_prowler_status", "check_sms_configured",
    "check_email_configured", "check_sms_inbox", "search_learnings", "poll_ai_routing",
    "find_stale_customers", "get_ar_aging_report", "get_home_address", "get_route_drive_matrix",
    "get_daily_mileage", "get_file_download_url", "get_file_upload_url", "list_sms_consents",
    "list_sms_contacts_with_replies", "get_sms_thread", "whoami", "geocode_address",
}
CREATE = {"create_job", "create_customer", "create_quote", "create_service_pricing", "create_setting",
          "create_invoice"}
SCOPED = {
    "update_job_spreadsheet", "delete_job", "delete_customer", "delete_quote", "delete_route_stop",
    "delete_route", "delete_service_pricing", "reorder_route_stop", "replan_route_day",
    "suggest_route_schedule", "build_daily_route", "approve_route_schedule",
    "unapprove_route_schedule", "apply_route_order", "log_time_entry", "backup_job_database",
}
OUTBOUND = {
    "email_route_now", "send_email", "send_alert", "send_sms", "send_whatsapp", "email_invoice",
    "text_invoice", "email_receipt", "text_receipt", "send_customer_reminders", "send_file",
    "send_learnings_report",
}
CREDITS = {"start_ai_routing"}
# Route builds that email the route automatically when Settings → "Email Route
# On Build" is Enabled, and the argument that switches that off for one call
# (R-059). The server reports a sent one with ROUTE_EMAILED_MARK.
ROUTE_EMAIL_ARG = {"suggest_route_schedule": "email_route", "build_daily_route": "email_link"}
ROUTE_EMAILED_MARK = "Route link and results emailed to"
# Reads that also change state: check_sms_replies / check_whatsapp_replies mark
# every message they return as READ for the calling user (mark_read defaults to
# True and the Jobs app doesn't override it). Server mode's Messages → "Check
# replies" uses check_sms_replies, so a sweep on the real users' accounts would
# silently mark David's / Vicki's / Samual's texts as read. Recorded, not sent:
# the page gets the labeled stand-in reply and nothing changes. (Found
# 2026-09-27 by SRV-SCR-08.)
MARKS_READ = {"check_sms_replies", "check_whatsapp_replies"}
NEVER = {"restore_job_database", "record_learning", "update_learning", "delete_learning",
         "schedule_next_recurring_job", "delete_sms_consent", "configure_email"}

# create_quote says NEW_QTE_ID=… (found 2026-09-26, DB-08: a quote the test
# made through the UI wasn't registered, so its Delete was — correctly — blocked).
_ID_RE = re.compile(r"NEW_(?:JOB|CUST|QUOTE|QTE|INVOICE|INV)_ID=([A-Z]+-\d+)")


class GuardViolation(Exception):
    pass


class Guard:
    """One per run. Thread-safe: Playwright route handlers and test code both use it."""

    def __init__(self, tier: str = "safe", log=None):
        self.tier = tier
        self.log = log or (lambda *a: None)
        self._lock = threading.Lock()
        self.created: set[str] = set()          # JOB-/CUST-/QTE-/INV- ids this run created
        self.stop_ids: set[str] = set()         # route stop ids seen on the sandbox date
        self.recorded: list[dict] = []          # blocked-and-recorded outbound/credit calls
        self.violations: list[dict] = []        # blocked scoped/never/unknown calls
        self.real_emails_sent = 0
        self.real_comms_sent = {"email": 0, "sms": 0}   # comms tier (server mode) — see _comms_decision
        # stop_id -> its route date (ISO) or None; set by conftest.py (reads
        # Route_Planner through the guarded API client). Lets the guard
        # recognise server-created stops on sandbox routes.
        self.stop_resolver = None
        # cust_id -> {"name", "email", "phone"} or None; set by conftest.py.
        # Lets the guard check who a customer reminder would really reach.
        self.customer_resolver = None
        self.real_reminders_sent = 0
        # Settings → "Email Route On Build" (R-059, David 2026-09-29: "we need to
        # test this, it's a test gap"). Set by conftest.py's pre-flight. When on,
        # every route build would email the route automatically — see
        # route_email_args(). route_email_to = where that email goes (personal
        # mode: the SMTP config's default_to/username; '' = unknown -> never real).
        self.route_email_to = ""
        # R-060: the Settings toggles the suite may flip (settings_switch.py).
        # settings_saved = the originals (only these keys may be written);
        # settings_current = what the guard knows each one is now.
        self.settings_saved: dict | None = None
        self.settings_current: dict[str, str] = {}
        self.real_route_emails = 0          # auto route emails the guard let through
        self.route_emails_seen = 0          # "📧 Route link and results emailed to" replies
        self.route_emails_suppressed = 0    # builds whose auto-email the guard switched off

    # ── Settings toggles (R-060) ──────────────────────────────────────────────
    @property
    def route_email_on(self) -> bool:
        """Is "Email Route On Build" (possibly) Enabled? Unknown counts as yes:
        switching a build's email off when the setting is off costs nothing."""
        v = self.settings_current.get("Email Route On Build")
        return True if v is None else v.strip().lower() == "enabled"

    @route_email_on.setter
    def route_email_on(self, on: bool):
        self.settings_current["Email Route On Build"] = "Enabled" if on else "Disabled"

    def observe_setting(self, key: str, value: str, pending: bool = False):
        """Record a toggle's value. pending=True (a write about to be made):
        only a change towards Enabled is taken at once — the safe direction —
        a change to Disabled counts once it has been read back."""
        v = str(value or "").strip()
        with self._lock:
            if not pending or v.lower() == "enabled":
                self.settings_current[key] = v

    def _setting_write_ok(self, a: dict) -> tuple[bool, str]:
        key = str(a.get("job_identifier", "") or "").strip()
        saved = (self.settings_saved or {}).get(key)
        if saved is None:
            return False, f"setting={key or '(none)'} (not a saved test toggle)"
        ups = a.get("updates") or {}
        if isinstance(ups, str):
            try:
                import json as _j
                ups = _j.loads(ups)
            except ValueError:
                return False, f"setting={key} (unreadable updates)"
        val = str(ups.get("Value", ups.get("value", ""))).strip()
        # "Allowed" missing = an older snapshot of an on/off toggle; [] = a row
        # that may only be written back unchanged (R-061: Start/End Address)
        allowed = saved["Allowed"] if "Allowed" in saved else ["Enabled", "Disabled"]
        original = str(saved.get("Value", "")).strip()
        allowed_vals = {str(x).strip().lower() for x in allowed} | {original.lower()}
        if val.lower() not in allowed_vals or (not val and original):
            return False, (f"setting={key} value {val!r} (only {' / '.join(allowed)})" if allowed
                           else f"setting={key} value {val!r} (may only be re-saved unchanged: {original!r})")
        for col, v in ups.items():
            c = str(col).strip().lower()
            if c in ("value",):
                continue
            if c in ("setting", "key") and str(v).strip() == key:
                continue
            if c == "notes" and str(v).strip() == str(saved.get("Notes", "")).strip():
                continue
            return False, f"setting={key} also changes {col!r}"
        if str(a.get("id_column", "Setting") or "Setting").strip().lower() not in ("setting", "key"):
            return False, f"setting={key} (id_column {a.get('id_column')!r})"
        return True, f"test toggle {key} -> {val} (original {saved.get('Value')!r} saved, put back after)"

    # ── registry ──────────────────────────────────────────────────────────────
    def note_result(self, tool: str, result_text: str):
        if tool in ROUTE_EMAIL_ARG and ROUTE_EMAILED_MARK in str(result_text or ""):
            with self._lock:
                self.route_emails_seen += 1
                over = self.route_emails_seen > self.real_route_emails
                if over:
                    self.violations.append({"source": "server", "tool": tool, "args": {},
                                            "decision": "block",
                                            "reason": "server sent a route email the guard had switched off"})
            self.log(f"guard: route email reported by {tool}"
                     + (" — NOT one the guard allowed!" if over else " (the allowed one)"))
        if tool in CREATE and result_text:
            for i in _ID_RE.findall(result_text):
                with self._lock:
                    self.created.add(i)
                self.log(f"guard: registered {i} (from {tool})")

    def add_stop_ids(self, ids):
        with self._lock:
            self.stop_ids.update(str(i) for i in ids)

    def adopt(self, record_id: str, name: str = "", date: str = "", reason: str = ""):
        """Take a leftover from an earlier (interrupted) run into this run's
        registry so cleanup may delete it. Only provably-test records are
        accepted: named ZTEST E2E…, or on the sandbox date. Anything else
        raises — the sweep must never widen to real data."""
        if not (str(name).startswith(ZTEST_PREFIX) or str(date) in SANDBOX_DATES):
            raise GuardViolation(f"refusing to adopt {record_id} ('{name}', {date}) — not test data")
        with self._lock:
            self.created.add(str(record_id))
        self.log(f"guard: adopted leftover {record_id} ('{name}', {date or 'no date'}) — {reason}")

    # ── the decision ──────────────────────────────────────────────────────────
    def _owned(self, tool: str, a: dict) -> tuple[bool, str]:
        """Is this scoped write aimed only at test data?"""
        rd = str(a.get("route_date", "") or "").strip()
        if rd:
            # The Database tab's "Delete Route" sends the date as the table
            # shows it (MM/DD/YYYY) — compare in ISO either way.
            if len(rd) == 10 and rd[2] == "/" and rd[5] == "/":
                rd = f"{rd[6:]}-{rd[:2]}-{rd[3:5]}"
            return (rd in SANDBOX_DATES, f"route_date={rd}")
        if "stop_id" in a:
            sid = str(a["stop_id"])
            if sid in self.stop_ids:
                return (True, f"stop_id={sid}")
            # Route stops are created by the SERVER when a route is built, so
            # their ids are never in the registry. Look the stop up: allowed
            # only if its route date is inside the sandbox window. (Found
            # 2026-09-26: once the guard really saw every request — see the
            # service-worker fix — ▲▼🗑️ on a sandbox route were blocked.)
            rd = self.stop_resolver(sid) if self.stop_resolver else None
            if rd in SANDBOX_DATES:
                with self._lock:
                    self.stop_ids.add(sid)
                return (True, f"stop_id={sid} (route {rd})")
            return (False, f"stop_id={sid} (route {rd or 'unknown'})")
        sheet = str(a.get("sheet_name", "") or "")
        ident = str(a.get("job_identifier", a.get("customer_identifier", a.get("quote_identifier",
                    a.get("service_code", "")))) or "")
        if sheet.lower() == "settings":
            if tool != "update_job_spreadsheet":
                return False, "Settings"
            ok, why = self._setting_write_ok(a)
            if ok:
                val = str((a.get("updates") or {}).get("Value", "")).strip() if isinstance(a.get("updates"), dict) else ""
                self.observe_setting(str(a.get("job_identifier", "")).strip(), val, pending=True)
            return ok, why
        if tool == "delete_service_pricing" or sheet.lower() in ("services_pricing", "service_pricing"):
            return (ident.upper().startswith(ZTEST_CODE_PREFIX), f"service_code={ident}")
        if sheet.lower() == "route_planner":
            if ident in self.stop_ids:
                return (True, f"route stop={ident}")
            rd = self.stop_resolver(ident) if self.stop_resolver else None
            if rd in SANDBOX_DATES:
                with self._lock:
                    self.stop_ids.add(ident)
                return (True, f"route stop={ident} (route {rd})")
            return (False, f"route stop={ident} (route {rd or 'unknown'})")
        if tool == "backup_job_database":
            return (True, "backup")
        if tool == "log_time_entry":
            j = str(a.get("job_id", a.get("job_identifier", "")) or "")
            return (j in self.created, f"job={j}")
        return (ident in self.created, f"id={ident or '(none)'}")

    def check(self, tool: str, args: dict | None) -> tuple[str, str]:
        """Returns (decision, reason). decision: 'allow' | 'record' | 'block'."""
        a = args or {}
        if tool in READ:
            return "allow", "read"
        if tool in CREATE:
            return "allow", "create"
        if tool in SCOPED:
            ok, why = self._owned(tool, a)
            return ("allow", f"test data ({why})") if ok else ("block", f"NOT test data ({why})")
        if tool in OUTBOUND:
            if tool == "send_customer_reminders":
                d = self._reminder_decision(a)
                if d:
                    return d
            if (self.tier in ("email", "full") and tool == "email_route_now"
                    and str(a.get("route_date", "")) in SANDBOX_DATES and self.real_emails_sent == 0):
                return "allow", "the ONE real email this run (tier email/full)"
            if self.tier == "comms":
                return self._comms_decision(tool, a)
            return "record", f"outbound, not sent in tier '{self.tier}'"
        if tool in CREDITS:
            if self.tier == "full" and str(a.get("route_date", "")) in SANDBOX_DATES:
                if self.route_email_on and not self._route_email_ok(a):
                    # the AI worker emails the finished route itself and has no
                    # per-call switch — with the auto-email on, run it only when
                    # that email may really go (the ONE route email, to David)
                    return "record", ("AI routing would auto-email the route (Email Route On Build is "
                                      "Enabled) and the one allowed route email is used/not allowed")
                return "allow", "AI credits allowed (tier full)"
            return "record", f"spends AI credits, not run in tier '{self.tier}'"
        if tool in MARKS_READ:
            return "record", "would mark real messages as read — not sent"
        if tool in NEVER:
            return "block", f"{tool} is never allowed in E2E"
        return "block", f"UNCLASSIFIED tool '{tool}' — add it to tests/gui_jobs_e2e/safety.py"

    # ── comms tier (server mode, spec §4.3 — David's decision 2026-09-27) ─────
    COMMS_NAMES = {"david vavro", "vicki vavro"}      # the ONLY people real sends may reach
    COMMS_MAX = {"email": 2, "sms": 2}                 # per run
    # send_email isn't on the Jobs app's server allow-list ("Unknown tool") — the app
    # emails only through its features, so email_receipt / email_invoice count too,
    # but ONLY with an explicit `to` that is David's or Vicki's address (without
    # `to` the server looks the customer's email up — never allowed here).
    COMMS_TOOLS = {"send_email": "email", "send_alert": "email", "send_sms": "sms",
                   "email_receipt": "email", "email_invoice": "email"}

    def _comms_targets(self) -> set[str]:
        """Allowed recipients: David's / Vicki's names + the emails / phone
        numbers in the Windows user env var AIPROWLER_E2E_COMMS_TO."""
        import os
        raw = os.environ.get("AIPROWLER_E2E_COMMS_TO", "")
        if not raw:
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as k:
                    raw = str(winreg.QueryValueEx(k, "AIPROWLER_E2E_COMMS_TO")[0])
            except Exception:
                raw = ""
        return {self._norm_recipient(x) for x in raw.split(",") if x.strip()} | set(self.COMMS_NAMES)

    @staticmethod
    def _norm_recipient(v) -> str:
        s = str(v or "").strip().lower()
        digits = re.sub(r"\D", "", s)
        if "@" not in s and len(digits) >= 10:        # a phone number in any format
            return digits[-10:]
        return " ".join(s.split())

    def _comms_decision(self, tool: str, a: dict) -> tuple[str, str]:
        kind = self.COMMS_TOOLS.get(tool)
        if not kind:
            return "record", (f"comms tier sends only send_email / send_alert / send_sms — {tool} "
                              "looks its recipient up server-side, so it stays recorded")
        to = self._norm_recipient(a.get("to", ""))
        if not to or to not in self._comms_targets():
            return "record", f"comms tier: recipient {a.get('to', '')!r} is not David or Vicki — not sent"
        sent = self.real_comms_sent[kind]
        if sent >= self.COMMS_MAX[kind]:
            return "block", f"comms tier: already sent {sent} real {kind}(s) this run (max {self.COMMS_MAX[kind]})"
        return "allow", f"REAL {kind} #{sent + 1} to {a.get('to')!r} (comms tier)"

    # ── customer reminders (personal six-week schedule, David 2026-09-28) ────
    # send_customer_reminders looks each customer's email/phone up SERVER-side,
    # so the guard resolves them first (customer_resolver, set by conftest.py):
    #   • every id must be a ZTEST customer THIS run created, else -> recorded
    #   • none of them has a contact for the channel -> allowed: the server can
    #     only answer "skipped — no email on file", nothing can be sent
    #   • tier email/full/comms, ONE customer whose contact is David's or Vicki's
    #     (AIPROWLER_E2E_COMMS_TO) -> the ONE real reminder this run
    #   • anything else -> recorded, not sent
    REMINDERS_MAX = 1

    def _reminder_decision(self, a: dict):
        if not self.customer_resolver:
            return None
        ids = [c.strip() for c in str(a.get("customer_ids", "") or "").split(",") if c.strip()]
        if not ids:
            return None
        field = "phone" if str(a.get("channel", "email") or "email").strip().lower() == "sms" else "email"
        contacts = []
        for cid in ids:
            if cid not in self.created:
                return None
            rec = self.customer_resolver(cid) or {}
            if not str(rec.get("name", "")).startswith(ZTEST_PREFIX):
                return None
            contacts.append(self._norm_recipient(rec.get(field, "")))
        if not any(contacts):
            return "allow", f"reminder to test customer(s) with no {field} on file — nothing can be sent"
        if (self.tier in ("email", "full", "comms") and len(ids) == 1
                and self.real_reminders_sent < self.REMINDERS_MAX
                and contacts[0] in self._comms_targets()):
            return "allow", f"REAL reminder {field} to {contacts[0]} (David/Vicki only, tier {self.tier})"
        return None

    # ── Email Route On Build (R-059, David 2026-09-29) ────────────────────────
    # With the setting Enabled every route build emails the route. Builds are
    # still allowed (they're scoped writes to sandbox routes), but the guard
    # rewrites each call's own switch to "don't email" — EXCEPT the ONE real
    # route email per run: tier email/full/comms, sandbox route date, and the
    # recipient is David or Vicki (AIPROWLER_E2E_COMMS_TO). The server's reply
    # is checked too (note_result): a route email the guard switched off that
    # still went out is a violation.
    ROUTE_EMAILS_MAX = 1

    def _route_email_ok(self, a: dict) -> bool:
        to = self._norm_recipient(self.route_email_to)
        return (self.tier in ("email", "full", "comms")
                and self.real_route_emails < self.ROUTE_EMAILS_MAX
                and str(a.get("route_date", "")) in SANDBOX_DATES
                and bool(to) and to in self._comms_targets())

    def route_email_args(self, tool: str, args: dict | None) -> tuple[dict, str]:
        """Call AFTER enforce() allowed a call. Returns the args to really send
        (a copy with the auto-email switched off when needed) and a note."""
        a = dict(args or {})
        key = ROUTE_EMAIL_ARG.get(tool)
        if not key or not self.route_email_on:
            return a, ""
        v = a.get(key)
        if v is False or str(v).strip().lower() in ("false", "0", "no"):
            return a, "route email: off for this call already"
        with self._lock:
            if self._route_email_ok(a):
                self.real_route_emails += 1
                note = f"route email: the ONE real route email this run -> {self.route_email_to}"
            else:
                a[key] = False
                self.route_emails_suppressed += 1
                note = (f"route email: switched off for this call ({key}=False) — "
                        f"tier '{self.tier}', {self.real_route_emails} already sent, "
                        f"recipient {self.route_email_to or 'unknown'}")
        self.log(f"guard: {tool} — {note}")
        return a, note

    def enforce(self, tool: str, args: dict | None, source: str) -> tuple[str, str]:
        decision, why = self.check(tool, args)
        entry = {"source": source, "tool": tool, "args": args or {}, "decision": decision, "reason": why}
        with self._lock:
            if decision == "record":
                self.recorded.append(entry)
            elif decision == "block":
                self.violations.append(entry)
            elif tool == "email_route_now":
                self.real_emails_sent += 1
            elif tool == "send_customer_reminders" and why.startswith("REAL"):
                self.real_reminders_sent += 1
            elif tool in CREDITS and self.route_email_on:
                self.real_route_emails += 1      # the AI worker will email the route
            elif tool in self.COMMS_TOOLS and self.tier == "comms":
                self.real_comms_sent[self.COMMS_TOOLS[tool]] += 1
        self.log(f"guard[{source}]: {decision.upper():6} {tool} — {why}")
        return decision, why

    def recorded_calls(self, tool: str) -> list[dict]:
        with self._lock:
            return [e for e in self.recorded if e["tool"] == tool]

    def take_violations(self) -> list[dict]:
        with self._lock:
            v, self.violations = self.violations, []
        return v


def canned_reply(tool: str, why: str) -> dict:
    """What the browser gets for a recorded (not sent) call: a success-shaped
    reply so the UI carries on, clearly labeled."""
    return {"ok": True, "result": f"✅ [E2E guard — not sent] {tool}: {why}"}
