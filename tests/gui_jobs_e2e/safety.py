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
  credits    -> (none since 2026-10-22: the Claude CLI AI Route was removed)
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
    "get_working_days", "list_team_members", "check_ai_prowler_status", "check_sms_configured",
    "check_email_configured", "check_sms_inbox", "search_learnings",
    "find_stale_customers", "get_ar_aging_report", "get_home_address", "get_route_drive_matrix",
    "get_daily_mileage", "get_file_download_url", "get_file_upload_url", "list_sms_consents",
    "list_sms_contacts_with_replies", "get_sms_thread", "whoami", "geocode_address",
    # 2026-10-06: Jobs/Board cards read the approved schedule (read-only tool)
    "get_approved_route_stops",
    # 2026-10-22: "📋 Copy AI Route" — builds a prompt (saves only its route code)
    "get_ai_route_prompt", "confirm_route_code",
    # 2026-10-22: 🗓️ Plan Week — these only read, or save/close a SUGGESTION
    # (no job changes); apply_week_moves (which moves dates) is SCOPED below.
    "get_week_plan_prompt", "get_week_plan_data", "propose_week_moves",
    "get_week_proposal", "dismiss_week_proposal",
}
CREATE = {"create_job", "create_customer", "create_quote", "create_service_pricing", "create_setting",
          "create_invoice"}
SCOPED = {
    "update_job_spreadsheet", "delete_job", "delete_customer", "delete_quote", "delete_route_stop",
    "delete_route", "delete_service_pricing", "reorder_route_stop", "replan_route_day",
    "suggest_route_schedule", "build_daily_route", "approve_route_schedule",
    "unapprove_route_schedule", "apply_route_order", "log_time_entry", "backup_job_database",
    # 2026-10-08: tools added to the Jobs app after the guard was last updated —
    # pause_job (⏸️, job_id), pin_route_stop (route_date), rename_customer
    # (CUST-YEAR-N number editor, customer_id). Each is allowed only on test data.
    "pause_job", "pin_route_stop", "rename_customer",
    # 2026-10-09 (David: tests must NOT avoid recurring jobs): "schedule next
    # visit" on a test job (job_identifier) creates the follow-up for the same
    # ZTEST customer — cleanup removes it with the customer.
    "schedule_next_recurring_job",
    # 2026-10-22: 🗓️ Plan Week "Approve selected" — allowed only when EVERY
    # job it would move was created by this test run.
    "apply_week_moves",
}
OUTBOUND = {
    "email_route_now", "send_email", "send_alert", "send_sms", "send_whatsapp", "email_invoice",
    "text_invoice", "email_receipt", "text_receipt", "send_customer_reminders", "send_file",
    "send_learnings_report",
}
CREDITS: frozenset = frozenset()   # start_ai_routing removed 2026-10-22
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
NEVER = {"restore_job_database", "record_learning", "update_learning",
         "delete_sms_consent", "configure_email",
         # 2026-10-25: on the Jobs app's allow-list but never classified here —
         # stopping a real indexing run is never a test's business.
         "cancel_indexing"}
READ |= {"indexing_status",
         # 2026-10-25: the server suite's SRV-API-12 lists the owner's ztest learnings
         "list_learnings"}

# ── Mileage tracker (2026-10-25) ──────────────────────────────────────────────
# Found while writing test_mileage_e2e.py: the Jobs app calls mileage_settings
# on EVERY page load (mileageInit) and get_mileage_log for the Clock screen's
# vehicle picker, and none of the 13 mileage tools was classified — so every
# E2E test ended with "GUARD BLOCKED … UNCLASSIFIED tool 'mileage_settings'".
# Rules (Guard._mileage_decision):
#   reads                      get_mileage_log / get_mileage_report / review_mileage_log,
#                              history, status/list, downloads (deliver=download)
#   add_mileage_trip           a new trip dated inside the sandbox window; a crew
#                              member only if ZTEST-named; a vehicle only if ours
#   update_mileage_trip /      a trip this run created, or one on a sandbox day that
#   apply_mileage_review_fix   belongs to a test job or a ZTEST driver
#   build_mileage_log          one sandbox day (never a backfill range)
#   fix_mileage_gap            a time entry on a test job
#   job_cancelled_on_arrival   a test job
#   manage_vehicles            add a ZTEST-nicknamed vehicle; odometer/update/
#                              retire/set_day only on our vehicles; set_default never
#                              (it would steer every future real trip)
#   mileage_reimbursement      submit for a ZTEST driver; approve/return/paid only
#                              on a reimbursement this run submitted
#   mileage_settings           get/reminders; set_period/set_reminder only after the
#                              originals were saved (put back after); the rest never
#   export / statement         download only; file -> recorded, email -> outbound
MILEAGE_READ = {"get_mileage_log", "get_mileage_report", "review_mileage_log"}
MILEAGE_TOOLS = MILEAGE_READ | {
    "add_mileage_trip", "update_mileage_trip", "build_mileage_log", "fix_mileage_gap",
    "manage_vehicles", "mileage_settings", "export_mileage_log", "mileage_reimbursement",
    "apply_mileage_review_fix", "job_cancelled_on_arrival",
}
_MILEAGE_ID_RE = re.compile(r"\b((?:TRIP|VEH|REIM)-\d+)\b")

# create_quote says NEW_QTE_ID=… (found 2026-09-26, DB-08: a quote the test
# made through the UI wasn't registered, so its Delete was — correctly — blocked).
#
# 2026-10-08: customer ids are now CUST-<year>-<n> (CUST-YEAR-N scheme,
# 2026-10-04). The old pattern [A-Z]+-\d+ stopped at the second hyphen and
# registered "CUST-2026" for EVERY new customer — the wrong id, so writes to
# the test's own customers were blocked. The optional -\d+ group takes the
# number too; legacy JOB-#### / CUST-#### still match. NEW_CUSTOMER_ID is
# what rename_customer reports for the renumbered customer.
_ID_RE = re.compile(r"NEW_(?:JOB|CUST|CUSTOMER|QUOTE|QTE|INVOICE|INV)_ID=([A-Z]+-\d+(?:-\d+)?)")


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
        # Mileage (2026-10-25), set by conftest.py — read-only lookups:
        # trip_resolver(trip_id) -> {"trip_date", "job_id", "crew"} or None;
        # entry_resolver(entry_id) -> job_id of that time entry, or None.
        self.trip_resolver = None
        self.entry_resolver = None
        self.reimb_resolver = None      # rid -> driver name, or {"crew", "all_test"}; None = unknown
        # Server suite: names whose OWN pay period a test checked holds only
        # test trips — their plain "submit" (no crew) is then allowed.
        self.mileage_submit_ok: set[str] = set()
        # learning id -> its title, or None (server suite: the owner deletes
        # only "ZTEST E2E …" learnings — SRV-API-12 set-up / clean-up)
        self.learning_resolver = None
        # Original mileage pay period + reminder switches; set_period /
        # set_reminder are allowed only once these were saved (a test puts them back).
        self.mileage_settings_saved: dict | None = None

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
        # rename_customer (2026-10-08): the guard only lets it run on a customer
        # this run created, so the renumbered id (NEW_CUSTOMER_ID=…) is test data
        # too — register it so later writes/cleanup on the new id are allowed.
        if tool == "rename_customer" and result_text and str(result_text).startswith("✅"):
            for i in _ID_RE.findall(result_text):
                with self._lock:
                    self.created.add(i)
                self.log(f"guard: registered {i} (renamed by rename_customer)")
        # Mileage (2026-10-25): trips / vehicles / reimbursements a call the
        # guard allowed has just created ("✅ Saved TRIP-0012, TRIP-0013",
        # "✅ Added VEH-0003", "✅ Split … TRIP-…"). The guard only lets these
        # run on test data, so whatever they made is ours. (Reimbursements are
        # recognised by their ZTEST driver instead — reimb_resolver — because
        # a status/list reply names other people's too.)
        if (tool in ("add_mileage_trip", "update_mileage_trip", "manage_vehicles",
                     "job_cancelled_on_arrival", "apply_mileage_review_fix")
                and str(result_text or "").lstrip().startswith("✅")):
            ids = set(_MILEAGE_ID_RE.findall(str(result_text)))
            if ids:
                with self._lock:
                    new = ids - self.created
                    self.created |= ids
                if new:
                    self.log(f"guard: registered {', '.join(sorted(new))} (from {tool})")
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
                    a.get("service_code", a.get("job_id", a.get("customer_id", "")))))) or "")
        # job_id: pause_job; customer_id: rename_customer (2026-10-08)
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
        if tool == "apply_week_moves":
            ids = [x.strip().upper() for x in str(a.get("job_ids", "") or "").split(",") if x.strip()]
            bad = [j for j in ids if j not in self.created]
            return (bool(ids) and not bad, f"jobs={','.join(ids) or '(none)'}"
                    + (f" (not test data: {','.join(bad)})" if bad else ""))
        if tool == "log_time_entry":
            j = str(a.get("job_id", a.get("job_identifier", "")) or "")
            return (j in self.created, f"job={j}")
        return (ident in self.created, f"id={ident or '(none)'}")

    # ── mileage tracker (2026-10-25) — see MILEAGE_TOOLS above ───────────────
    def _mileage_trip_owned(self, trip_id: str) -> tuple[bool, str]:
        tid = str(trip_id or "").strip().upper()
        if not tid:
            return False, "trip=(none)"
        if tid in self.created:
            return True, f"trip={tid} (made by this run)"
        t = self.trip_resolver(tid) if self.trip_resolver else None
        if not t:
            return False, f"trip={tid} (not found in the sandbox window)"
        d, job, crew = str(t.get("trip_date") or ""), str(t.get("job_id") or ""), str(t.get("crew") or "")
        if d in SANDBOX_DATES and (job in self.created or crew.startswith(ZTEST_PREFIX)):
            with self._lock:
                self.created.add(tid)
            return True, f"trip={tid} ({d}, {'job ' + job if job in self.created else 'driver ' + crew})"
        return False, f"trip={tid} ({d or 'no date'}, job {job or '-'}, driver {crew or 'owner'})"

    def _mileage_vehicle_ok(self, vid) -> bool:
        v = str(vid or "").strip().upper()
        return (not v) or v in self.created

    def _mileage_decision(self, tool: str, a: dict) -> tuple[str, str]:
        act = str(a.get("action", "") or "").strip().lower()
        deliver = str(a.get("deliver", "file") or "file").strip().lower()
        if tool in MILEAGE_READ:
            return "allow", "read (mileage)"
        if tool == "export_mileage_log" or (tool == "mileage_reimbursement" and act == "statement"):
            if deliver == "download":
                return "allow", "read (download to the browser)"
            if deliver == "email":
                return "record", "outbound: emails the mileage file"
            return "record", "would save a file next to the real job database"
        if tool == "mileage_settings":
            if act in ("", "get", "reminders"):
                return "allow", "read (mileage settings)"
            if act in ("set_period", "set_reminder"):
                if self.mileage_settings_saved is None:
                    return "block", f"mileage_settings {act} before the originals were saved"
                return "allow", f"test toggle mileage {act} (originals saved, put back after)"
            return "block", f"mileage_settings {act} is never changed by E2E (tracking on/off, rates, locks)"
        if tool == "add_mileage_trip":
            d = str(a.get("date", "") or "").strip() or SANDBOX_DATE
            fc = str(a.get("for_crew", "") or "").strip()
            if d not in SANDBOX_DATES:
                return "block", f"new trip dated {d} — outside the sandbox window"
            # A real crew member (server suite: Samual / Vicki) only on a trip
            # marked as test data in its notes — the cleanup finds it by that.
            if fc and not fc.startswith(ZTEST_PREFIX) and ZTEST_PREFIX not in str(a.get("notes", "") or ""):
                return "block", f"new trip for {fc!r} — not a ZTEST driver and not marked {ZTEST_PREFIX!r}"
            if not self._mileage_vehicle_ok(a.get("vehicle_id")):
                return "block", f"new trip in vehicle {a.get('vehicle_id')} — not a test vehicle"
            return "allow", f"new trip on {d}" + (f" for {fc}" if fc else "")
        if tool == "update_mileage_trip":
            if act == "history":
                return "allow", "read (trip history)"
            ok, why = self._mileage_trip_owned(a.get("trip_id"))
            if ok and not self._mileage_vehicle_ok(a.get("vehicle_id")):
                return "block", f"{why} -> vehicle {a.get('vehicle_id')} is not a test vehicle"
            d = str(a.get("date", "") or "").strip()
            if ok and d and d not in SANDBOX_DATES:
                return "block", f"{why} -> date {d} is outside the sandbox window"
            return ("allow" if ok else "block"), (f"test data ({why})" if ok else f"NOT test data ({why})")
        if tool == "apply_mileage_review_fix":
            m = re.search(r"TRIP-\d+", str(a.get("finding_id", "") or "").upper())
            ok, why = self._mileage_trip_owned(m.group(0) if m else "")
            return ("allow" if ok else "block"), f"review finding {a.get('finding_id')!r}: {why}"
        if tool == "build_mileage_log":
            if a.get("start_date") or a.get("end_date"):
                return "block", "backfill ranges are never run by E2E"
            d = str(a.get("date", "") or "").strip() or SANDBOX_DATE
            return (("allow", f"rebuild sandbox day {d}") if d in SANDBOX_DATES
                    else ("block", f"rebuild {d} — outside the sandbox window"))
        if tool == "fix_mileage_gap":
            eid = str(a.get("entry_id", "") or "").strip()
            job = self.entry_resolver(eid) if self.entry_resolver else None
            return (("allow", f"time entry {eid} on test job {job}") if job and job in self.created
                    else ("block", f"time entry {eid} (job {job or 'unknown'}) — not test data"))
        if tool == "job_cancelled_on_arrival":
            j = str(a.get("job_id", "") or "").strip().upper()
            return (("allow", f"test job {j}") if j in self.created else ("block", f"job {j} — not test data"))
        if tool == "manage_vehicles":
            if act in ("", "list"):
                return "allow", "read (vehicles)"
            if act == "add":
                nick = str(a.get("nickname", "") or "")
                return (("allow", f"new test vehicle {nick!r}") if nick.startswith(ZTEST_PREFIX)
                        else ("block", f"new vehicle {nick!r} — test vehicles are nicknamed '{ZTEST_PREFIX} …'"))
            if act == "set_default":
                return "block", "set_default changes the default vehicle for every future real trip"
            vid = str(a.get("vehicle_id", "") or "").strip().upper()
            if act == "set_day":
                d = str(a.get("date", "") or "").strip() or SANDBOX_DATE
                ok = vid in self.created and d in SANDBOX_DATES
                return ("allow" if ok else "block"), f"day vehicle {vid} on {d}"
            return (("allow", f"test vehicle {vid} ({act})") if vid in self.created
                    else ("block", f"vehicle {vid or '(none)'} ({act}) — not a test vehicle"))
        if tool == "mileage_reimbursement":
            if act in ("", "status", "list"):
                return "allow", "read (reimbursements)"
            if act == "submit":
                crew = str(a.get("crew", "") or "").strip()
                if crew.startswith(ZTEST_PREFIX):
                    return "allow", f"submit for test driver {crew}"
                # Server suite: a real user submits their OWN period only after
                # the test confirmed (as the owner) it holds nothing but test trips.
                ok = self.mileage_submit_ok
                if ok and (not crew or crew in ok):
                    return "allow", f"submit {crew or 'own'} period — checked: only test trips in it"
                return "block", f"submit for {crew or 'the caller'} — not a ZTEST driver, period not checked"
            rid = str(a.get("reimbursement_id", "") or "").strip().upper()
            if rid and rid in self.created:                # submitted by this run after the period check
                return "allow", f"{rid} ({act}) — submitted by this run"
            who = self.reimb_resolver(rid) if (self.reimb_resolver and rid) else None
            if isinstance(who, dict):                     # {"crew": …, "all_test": bool}
                all_test, who = bool(who.get("all_test")), who.get("crew")
            else:
                all_test = False
            return (("allow", f"{rid} of {who} ({act}) — test data") if (str(who or "").startswith(ZTEST_PREFIX)
                                                                         or all_test)
                    else ("block", f"{rid or '(none)'} ({act}) — not a test driver's reimbursement"))
        return "block", f"mileage tool {tool} has no rule"

    def check(self, tool: str, args: dict | None) -> tuple[str, str]:
        """Returns (decision, reason). decision: 'allow' | 'record' | 'block'."""
        a = args or {}
        if tool in MILEAGE_TOOLS:
            return self._mileage_decision(tool, a)
        if tool == "delete_learning":
            # 2026-10-25: SRV-API-12's learnings are removed by the owner over
            # /mcp — only ones titled "ZTEST E2E …" (looked up, never guessed).
            lid = str(a.get("learning_id", "") or "").strip()
            title = self.learning_resolver(lid) if (self.learning_resolver and lid) else None
            return (("allow", f"test learning {lid} {title!r}") if str(title or "").upper().startswith(ZTEST_PREFIX)
                    else ("block", f"learning {lid or '(none)'} ({title!r}) — not a ZTEST learning"))
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
