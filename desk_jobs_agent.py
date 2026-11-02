"""
desk_jobs_agent.py — the Jobs agent (jobs-agent-spec.md, J1 + J2): the shared agent engine
(desk_agent.py) working the Jobs app, with two kinds of item, both kept in the agent's own
database (desk_agent_store.py):

    kind 'job'    the Jobs flow:  Quotes · Schedule · Prep the day · On site · Close out ·
                                  Get paid · Repeat & win back · Learn
    kind 'route'  the Route flow: Sort the week · Schedule the week · Route · Send routes ·
                                  Re-plan the day

The timer (scan) reads the Jobs database and queues an item when something needs doing —
each once per version of the job / invoice / quote / day. The AI gets a context pack and
submits actions; desk_agent's policy decides (Off → rejected, practice → shown, a hard rule →
a person, high risk → a person, Suggest → a person, Auto → applied). Applying goes through the
Jobs app's own write functions (db_write_ops, week_plan) and, for messages and routes, the
same tools a chat uses (`ops`, set by ai_prowler_mcp.py; tests put fakes in).

David's decisions (2026-10-31): 1 the agent may send invoices — behind "Let the agent send
invoices" (off by default) with an amount and a daily limit; 2 payment reminders at 7 / 14 / 30
days, the 3rd firmer, then "call them"; 3 dates are only SUGGESTED at first, and a fixed-time
(Hard) job or anything today is never moved; 4 its own database; 5 settings and diagrams first.

Never, whatever the settings: take or record a payment, change an amount or a price or a
setting, delete or cancel anything, edit time or mileage entries, message a customer who
opted out, add a job to today.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import secrets

import desk_agent as engine
import desk_agent_settings as das
from db_access import get_connection, utcnow_iso

JOB, ROUTE = "job", "route"
ACTOR = "assistant"
PAID = ("paid", "cash", "check", "zelle", "venmo", "other")
OPEN_PAY = ("unpaid", "partial", "")
CLOSED = ("complete", "completed", "cancelled", "canceled")
SCHEDULE_DAYS = 21                 # how far ahead Schedule looks for a date
REMIND_GAP_DAYS = 3                # never two payment reminders closer than this
FLAGS = ("running_long", "still_clocked_in", "no_time_logged", "missing_address", "overfull_day",
         "bad_weather", "not_ready_to_bill", "other")
OUTDOOR_WORDS = ("window", "pressure", "wash", "gutter", "roof", "lawn", "exterior", "deck", "fence", "paint",
                 "landscap", "solar", "siding", "driveway")

ops: dict = {}                      # set by ai_prowler_mcp.py (see install_ops); tests use fakes
clock = None                        # tests: fn() -> naive local datetime
opted_out_fn = None                 # tests: fn(phone) -> bool


class JobsAgentError(engine.AgentError):
    pass


# ── actions, risk, which stage may use them ──────────────────────────────────

RISK = {
    "jb_note": "low", "jb_flag": "low", "jb_call_customer": "low", "jb_prep_note": "low",
    "jb_quote_followup": "medium", "jb_job_from_quote": "medium", "jb_schedule": "medium",
    "jb_draft_invoice": "medium", "jb_send_receipt": "medium", "jb_payment_reminder": "medium",
    "jb_next_visit": "medium", "jb_winback": "medium", "jb_customer_note": "medium",
    "jb_send_invoice": "high", "jb_set_estimate": "high",
    "rt_propose_week": "low", "rt_apply_week": "medium", "rt_route_day": "medium", "rt_send": "medium",
    "rt_replan": "medium",
}
ALLOWED = {
    (JOB, "quotes"): ("jb_quote_followup", "jb_job_from_quote", "jb_note", "no_action"),
    (JOB, "schedule"): ("jb_schedule", "jb_note", "no_action"),
    (JOB, "prep"): ("jb_prep_note", "jb_flag", "jb_schedule", "jb_note", "no_action"),
    (JOB, "onsite"): ("jb_flag", "jb_note", "no_action"),
    (JOB, "closeout"): ("jb_draft_invoice", "jb_send_invoice", "jb_send_receipt", "jb_flag", "jb_note", "no_action"),
    (JOB, "collect"): ("jb_payment_reminder", "jb_call_customer", "jb_note", "no_action"),
    (JOB, "repeat"): ("jb_next_visit", "jb_winback", "jb_note", "no_action"),
    (JOB, "learn"): ("jb_set_estimate", "jb_customer_note", "jb_note", "no_action"),
    (ROUTE, "sort"): ("rt_propose_week", "no_action"),
    (ROUTE, "plan"): ("rt_apply_week", "no_action"),
    (ROUTE, "route"): ("rt_route_day", "no_action"),
    (ROUTE, "send"): ("rt_send", "no_action"),
    (ROUTE, "replan"): ("rt_replan", "no_action"),
}
# Change nothing in the Jobs app — they're recorded for the 🤖 tab (a week plan is only saved
# as a suggestion). Applied even on Suggest; practice still only shows them.
FREE = ("jb_note", "jb_flag", "jb_call_customer", "rt_propose_week")
MESSAGES = ("jb_quote_followup", "jb_payment_reminder", "jb_winback")
GUARDED = ("jb_send_invoice",)
ACTION_FIELDS = {
    "jb_note": "{body} — a note for you in the 🤖 tab (changes nothing)",
    "jb_flag": "{flag: " + "|".join(FLAGS) + ", detail}",
    "jb_prep_note": "{body} — added to the job's notes for the crew",
    "jb_call_customer": "{body} — tells you to phone the customer",
    "jb_quote_followup": "{body} — a short follow-up to the customer (no amounts; the quote number is added)",
    "jb_job_from_quote": "{notes} — makes the job from the approved quote (price comes from the quote)",
    "jb_schedule": "{date} — one of the dates in \"dates\"",
    "jb_draft_invoice": "{} — the invoice is made from the job's own price",
    "jb_send_invoice": "{channel: email|text}",
    "jb_send_receipt": "{channel: email|text}",
    "jb_payment_reminder": "{body} — the reminder text (no amounts; the invoice number and balance are added)",
    "jb_next_visit": "{} — sets up the next recurring visit",
    "jb_winback": "{body} — a friendly 'time for your next service?' message (no prices)",
    "jb_set_estimate": "{minutes} — the customer's usual job time, from \"time_on_site\"",
    "jb_customer_note": "{body} — saved on the customer (e.g. 'call on arrival')",
    "rt_propose_week": "{moves: [{job_id, to, reason}]} — only jobs with movable true, only to their may_move_to "
                       "dates (never today); [] when nothing is worth moving",
    "rt_apply_week": "{job_ids: [..]} — which of the plan's moves to make",
    "rt_route_day": "{} — orders the day's stops (Route Advisor)",
    "rt_send": "{} — approves the day's route and sends it to the crew",
    "rt_replan": "{} — re-orders the rest of today's route",
    "no_action": "{}",
}
RULES = [
    "Amounts always come from the job, quote or invoice — never write a price, amount or discount; it's added for you.",
    "Never take, record or mark a payment. Never change prices, settings, time or mileage entries. Never delete or "
    "cancel anything.",
    "Dates: only dates listed in the pack. Never today, never a fixed-time (Hard) job.",
    "Customer messages: plain, friendly, short, signed. If \"opted_out\" is true or there's no way to reach them, "
    "leave a note for the owner instead.",
    "When unsure, leave a note (jb_note) instead of acting.",
]


def rt_stage_mode(settings: dict, stage: str) -> str:
    """The Route flow's steps follow its own switches (agent_jb_rt_enabled / agent_jb_rt_shadow)."""
    return das.rt_stage_mode(settings, stage)


# ── the engine's hooks (desk_agent.KINDS) ────────────────────────────────────

def mode(kind: str, s: dict, stage: str) -> str:
    return das.jb_stage_mode(s, stage) if kind == JOB else rt_stage_mode(s, stage)


def stages(kind: str) -> tuple:
    return tuple(k for k, _ in (das.JB_STAGES if kind == JOB else das.RT_STAGES))


def enabled(s: dict) -> bool:
    """The Jobs section runs when the Jobs agent or the Route flow is on (each step still checks its own switch)."""
    return das.jb_any_on(s)


# ── time, small helpers ──────────────────────────────────────────────────────

def _now_local(now: dt.datetime | None = None) -> dt.datetime:
    if now is None:
        now = clock() if clock else dt.datetime.now()
    return now.astimezone().replace(tzinfo=None) if now.tzinfo else now


def _d(s) -> dt.date | None:
    s = str(s or "").strip()
    if len(s) == 10 and s[2] == "/" and s[5] == "/":
        s = f"{s[6:]}-{s[:2]}-{s[3:5]}"
    try:
        return dt.date.fromisoformat(s[:10])
    except ValueError:
        return None


def _low(v) -> str:
    return str(v or "").strip().lower()


def _minutes_of(value, unit) -> float:
    try:
        v = float(value or 0)
    except (TypeError, ValueError):
        return 0.0
    u = _low(unit) or "min"
    return v * 60 if u.startswith("h") else v * 480 if u.startswith("d") else v


def _hhmm(s, fallback: int) -> int:
    try:
        h, m = str(s).strip().split(":")[:2]
        return int(h) * 60 + int(m[:2])
    except Exception:  # noqa: BLE001
        return fallback


def _sig(*parts) -> str:
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:12]


def _cust_name(c) -> str:
    if not c:
        return ""
    return (str(c["company_name"] or "").strip()
            or " ".join(x for x in (c["first_name"], c["last_name"]) if x).strip())


def _opted_out(phone: str) -> bool:
    if not phone:
        return False
    if opted_out_fn:
        return bool(opted_out_fn(phone))
    try:
        import sms_consent as sc
        p = sc._norm_e164(phone)
        return any(r.get("phone") == p and not r.get("consented") for r in sc.consent_list())
    except Exception:  # noqa: BLE001
        return False


def _outdoor(jobs_db, service_type: str) -> bool:
    st = _low(service_type)
    if not st:
        return False
    try:
        conn = get_connection(jobs_db)
        try:
            r = conn.execute("SELECT outdoor FROM booking_services WHERE LOWER(name) = ? OR LOWER(service_code) = ?",
                             (st, st)).fetchone()
        finally:
            conn.close()
        if r is not None:
            return bool(r["outdoor"])
    except Exception:  # noqa: BLE001 — no booking tables
        pass
    return any(w in st for w in OUTDOOR_WORDS)


# ── the agent's own records (sent messages, for spacing and the daily limit) ─

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jb_messages (
  ref TEXT NOT NULL, kind TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 1, sent_at TEXT NOT NULL,
  PRIMARY KEY (ref, kind, n)
);
"""


def _adb(adb):
    conn = get_connection(adb)
    conn.executescript(_SCHEMA)
    return conn


def _sent(adb, ref: str, kind: str) -> list:
    conn = _adb(adb)
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM jb_messages WHERE ref = ? AND kind = ? ORDER BY n",
                                              (ref, kind))]
    finally:
        conn.close()


def _mark(adb, ref: str, kind: str, n: int = 1) -> None:
    conn = _adb(adb)
    try:
        conn.execute("INSERT OR REPLACE INTO jb_messages (ref, kind, n, sent_at) VALUES (?, ?, ?, ?)",
                     (ref, kind, int(n), _now_local().isoformat(timespec="seconds")))
    finally:
        conn.close()


def _sent_today(adb, kind: str) -> int:
    conn = _adb(adb)
    try:
        return conn.execute("SELECT COUNT(*) FROM jb_messages WHERE kind = ? AND substr(sent_at, 1, 10) = ?",
                            (kind, _now_local().date().isoformat())).fetchone()[0]
    finally:
        conn.close()


# ── J2: the timer's scan of the Jobs database ────────────────────────────────

def scan(adb: str, jobs_db: str, *, settings: dict | None = None, edition: str = "solo",
         now: dt.datetime | None = None) -> int:
    """Queue what needs doing. Never raises; returns how many items were newly queued."""
    s = settings if settings is not None else engine.desk_db.get_settings(adb)
    if not enabled(s) or not jobs_db:
        return 0
    now = _now_local(now)
    n = 0
    for fn in (_scan_quotes, _scan_schedule, _scan_prep, _scan_onsite, _scan_closeout, _scan_collect,
               _scan_repeat, _scan_learn, _scan_route):
        try:
            n += fn(adb, jobs_db, s, now, edition)
        except Exception:  # noqa: BLE001 — one bad check never stops the others
            pass
    return n


def _q(adb, kind, ref, stage, reason, version, s) -> int:
    return 1 if engine.enqueue(adb, kind, ref, stage, reason, version=version, settings=s) else 0


def _rows(jobs_db, sql, args=()):
    conn = get_connection(jobs_db)
    try:
        return [dict(r) for r in conn.execute(sql, args).fetchall()]
    finally:
        conn.close()


def _scan_quotes(adb, jobs_db, s, now, edition) -> int:
    today, n = now.date(), 0
    cut = (today - dt.timedelta(days=int(s.get("agent_jb_quote_days", 5)))).isoformat()
    for q in _rows(jobs_db, "SELECT quote_id, quote_date, valid_until, customer_id, service_type, status FROM quotes "
                            "WHERE LOWER(COALESCE(status, 'open')) IN ('open', 'approved')"):
        if _low(q["status"]) in ("", "open"):
            if (q["quote_date"] or "") and q["quote_date"][:10] <= cut and not (
                    q["valid_until"] and _d(q["valid_until"]) and _d(q["valid_until"]) < today):
                n += _q(adb, JOB, q["quote_id"], "quotes", "quote still open", f"open|{q['quote_id']}", s)
        elif not _rows(jobs_db, "SELECT 1 FROM jobs WHERE customer_id = ? AND LOWER(COALESCE(service_type, '')) = ? "
                                "AND LOWER(COALESCE(job_status, '')) NOT IN ('cancelled', 'canceled') "
                                "AND (service_date IS NULL OR service_date = '' OR service_date >= ?)",
                       (q["customer_id"], _low(q["service_type"]), (q["quote_date"] or "")[:10])):
            n += _q(adb, JOB, q["quote_id"], "quotes", "quote approved — no job yet", f"approved|{q['quote_id']}", s)
    return n


def _scan_schedule(adb, jobs_db, s, now, edition) -> int:
    n = 0
    for j in _rows(jobs_db, "SELECT job_id, version FROM jobs WHERE LOWER(COALESCE(job_status, '')) = 'unscheduled' "
                            "OR ((service_date IS NULL OR service_date = '') AND LOWER(COALESCE(job_status, '')) NOT IN "
                            "('complete', 'completed', 'cancelled', 'canceled', 'declined')) ORDER BY job_id LIMIT 20"):
        n += _q(adb, JOB, j["job_id"], "schedule", "unscheduled", f"unsched|{j['version']}", s)
    return n


def _workday(jobs_db) -> tuple:
    try:
        import week_plan as wp
        ws, we = wp.db_read_settings_workday_start(jobs_db), wp.db_read_settings_workday_end(jobs_db)
        lunch = int(wp.db_read_settings_lunch_break_duration_min(jobs_db) or 0)
    except Exception:  # noqa: BLE001
        ws, we, lunch = "07:00", "17:00", 0
    return _hhmm(ws, 420), _hhmm(we, 1020), lunch


def _scan_prep(adb, jobs_db, s, now, edition) -> int:
    if now.hour < int(s.get("agent_jb_prep_hour", 16)):
        return 0
    day = (now.date() + dt.timedelta(days=1)).isoformat()
    jobs = _rows(jobs_db, "SELECT * FROM jobs WHERE service_date = ? AND LOWER(COALESCE(job_status, '')) = 'scheduled' "
                          "ORDER BY start_time, job_id", (day,))
    n = 0
    for j in jobs:
        why = []
        if not str(j["street_address"] or "").strip() or j["latitude"] in (None, ""):
            why.append("missing_address")
        if s.get("agent_jb_weather", True) and _outdoor(jobs_db, j["service_type"]) and j["latitude"] not in (None, ""):
            wx = _weather(j, day)
            if wx.get("bad"):
                why.append("bad_weather")
        if why:
            n += _q(adb, JOB, j["job_id"], "prep", ",".join(why), f"prep|{day}|{','.join(why)}", s)
    ws, we, lunch = _workday(jobs_db)
    crews = {}
    for j in jobs:
        crews.setdefault(str(j["crew"] or "").strip(), []).append(j)
    for crew, js in crews.items():
        if sum(_minutes_of(j["est_duration"], j["est_duration_unit"]) for j in js) > max(0, we - ws - lunch):
            soft = [j for j in js if _low(j["schedule_type"]) != "hard"]
            if soft:
                n += _q(adb, JOB, soft[-1]["job_id"], "prep", "overfull_day", f"prep|{day}|overfull", s)
    return n


def _weather(j, day) -> dict:
    try:
        import desk_agent_evidence as ev
        return ev.weather(float(j["latitude"]), float(j["longitude"]), day, j.get("start_time") or "",
                          j.get("end_time") or "") or {}
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


def _scan_onsite(adb, jobs_db, s, now, edition) -> int:
    n = 0
    ws, we, _ = _workday(jobs_db)
    for t in _rows(jobs_db, "SELECT t.entry_id, t.job_id, t.clock_in, j.est_duration, j.est_duration_unit FROM time_entries t "
                            "JOIN jobs j ON j.job_id = t.job_id WHERE t.clock_in IS NOT NULL AND t.clock_out IS NULL"):
        try:
            started = dt.datetime.fromisoformat(str(t["clock_in"])[:19])
        except ValueError:
            continue
        mins = (now - started).total_seconds() / 60
        est = _minutes_of(t["est_duration"], t["est_duration_unit"])
        if est and mins > est * 1.5:
            n += _q(adb, JOB, t["job_id"], "onsite", "running_long", f"long|{t['entry_id']}", s)
        if now.hour * 60 + now.minute > we + 60 or now.date() > started.date():
            n += _q(adb, JOB, t["job_id"], "onsite", "still_clocked_in", f"late|{t['entry_id']}", s)
    days = ((now.date() - dt.timedelta(days=1)).isoformat(), now.date().isoformat())
    for j in _rows(jobs_db, "SELECT job_id FROM jobs j WHERE LOWER(COALESCE(job_status, '')) IN ('complete', 'completed') "
                            "AND service_date IN (?, ?) AND NOT EXISTS (SELECT 1 FROM time_entries t WHERE "
                            "t.job_id = j.job_id) AND (actual_duration IS NULL OR actual_duration = 0)", days):
        n += _q(adb, JOB, j["job_id"], "onsite", "no_time_logged", f"notime|{j['job_id']}", s)
    return n


def _scan_closeout(adb, jobs_db, s, now, edition) -> int:
    n = 0
    since = (now.date() - dt.timedelta(days=14)).isoformat()
    for j in _rows(jobs_db, "SELECT job_id, version FROM jobs WHERE LOWER(COALESCE(job_status, '')) IN "
                            "('complete', 'completed') AND service_date >= ? AND (invoice_id IS NULL OR invoice_id = '')",
                   (since,)):
        n += _q(adb, JOB, j["job_id"], "closeout", "done — no invoice", f"close|{j['version']}", s)
    if das.can_send_invoices(s):     # the agent's own drafts, not sent yet (decision 1)
        for r in _rows(jobs_db, "SELECT j.job_id, i.invoice_id FROM jobs j JOIN invoices i ON i.invoice_id = j.invoice_id "
                                "WHERE COALESCE(j.invoice_sent_date, '') = '' AND i.created_by = ? AND "
                                "COALESCE(i.invoice_date, '') >= ?", (ACTOR, since)):
            n += _q(adb, JOB, r["job_id"], "closeout", "invoice drafted — not sent", f"send|{r['invoice_id']}", s)
    for r in _rows(jobs_db, "SELECT i.invoice_id, i.job_id FROM invoices i JOIN jobs j ON j.job_id = i.job_id WHERE "
                            "LOWER(COALESCE(i.payment_status, '')) IN (%s) AND COALESCE(i.payment_date, '') >= ? "
                            "AND (j.receipt_sent_date IS NULL OR j.receipt_sent_date = '')"
                            % ",".join("?" * len(PAID)), (*PAID, since)):
        n += _q(adb, JOB, r["job_id"], "closeout", "paid — send the receipt", f"receipt|{r['invoice_id']}", s)
    return n


def _scan_collect(adb, jobs_db, s, now, edition) -> int:
    days = list(s.get("agent_jb_remind_days") or [7, 14, 30])
    today, n = now.date(), 0
    for i in _rows(jobs_db, "SELECT i.invoice_id, i.invoice_date FROM invoices i JOIN jobs j ON j.job_id = i.job_id "
                            "WHERE LOWER(COALESCE(i.payment_status, '')) IN ('unpaid', 'partial', '') AND "
                            "COALESCE(i.balance_due, 0) > 0 AND COALESCE(j.invoice_sent_date, '') != ''"):
        d0 = _d(i["invoice_date"])
        if not d0:
            continue
        age = (today - d0).days
        done = len(_sent(adb, i["invoice_id"], "reminder"))
        if done < len(days) and age >= days[done]:
            n += _q(adb, JOB, i["invoice_id"], "collect", f"reminder {done + 1}", f"remind|{done + 1}", s)
        elif done >= len(days) and age >= days[-1] + 7:
            n += _q(adb, JOB, i["invoice_id"], "collect", "call them", "call", s)
    return n


def _scan_repeat(adb, jobs_db, s, now, edition) -> int:
    n = 0
    since = (now.date() - dt.timedelta(days=30)).isoformat()
    once = "('', 'none', 'one-time', 'one time', 'onetime', 'once', 'ot')"
    for j in _rows(jobs_db, "SELECT j.job_id, j.customer_id, j.service_type, j.service_date FROM jobs j LEFT JOIN "
                            "customers c ON c.customer_id = j.customer_id WHERE LOWER(COALESCE(j.job_status, '')) IN "
                            "('complete', 'completed') AND j.service_date >= ? AND "
                            f"(LOWER(COALESCE(c.frequency, '')) NOT IN {once} OR "
                            f"LOWER(COALESCE(j.recurrence, '')) NOT IN {once})", (since,)):
        later = _rows(jobs_db, "SELECT 1 FROM jobs WHERE customer_id = ? AND job_id != ? AND "
                               "LOWER(COALESCE(service_type, '')) = ? AND LOWER(COALESCE(job_status, '')) NOT IN "
                               "('cancelled', 'canceled') AND (service_date IS NULL OR service_date = '' OR "
                               "service_date > ?)", (j["customer_id"], j["job_id"], _low(j["service_type"]),
                                                     j["service_date"]))
        if not later:
            n += _q(adb, JOB, j["job_id"], "repeat", "recurring — next visit", f"next|{j['job_id']}", s)
    try:
        import db_write_ops as dwo
        stale = dwo.db_find_stale_customers(jobs_db) or []
    except Exception:  # noqa: BLE001
        stale = []
    quarter = f"{now.year}Q{(now.month - 1) // 3 + 1}"
    for c in stale[:5]:
        cid = c.get("customer_id") if isinstance(c, dict) else None
        if cid:
            n += _q(adb, JOB, cid, "repeat", "quiet customer", f"winback|{quarter}", s)
    return n


def time_on_site(jobs_db, customer_id: str) -> dict:
    """The customer's real job minutes (timer first, else Actual Duration) against their usual
    time: a pattern needs 5+ timed jobs and 20 %+ off."""
    rows = _rows(jobs_db, "SELECT j.job_id, j.est_duration, j.est_duration_unit, j.actual_duration, j.actual_duration_unit, "
                          "(SELECT SUM(elapsed_min) FROM time_entries t WHERE t.job_id = j.job_id) AS timed "
                          "FROM jobs j WHERE j.customer_id = ? AND LOWER(COALESCE(j.job_status, '')) IN "
                          "('complete', 'completed') ORDER BY j.service_date DESC LIMIT 20", (customer_id,))
    real = [float(r["timed"]) if r["timed"] else _minutes_of(r["actual_duration"], r["actual_duration_unit"]) for r in rows]
    real = sorted(m for m in real if m and m > 0)
    c = _rows(jobs_db, "SELECT avg_job_duration_min FROM customers WHERE customer_id = ?", (customer_id,))
    est = float(c[0]["avg_job_duration_min"] or 0) if c else 0.0
    if not est:
        ests = sorted(_minutes_of(r["est_duration"], r["est_duration_unit"]) for r in rows)
        ests = [e for e in ests if e > 0]
        est = ests[len(ests) // 2] if ests else 0.0
    out = {"n": len(real), "min_jobs": 5, "off_by_pct": 20, "usual_minutes": round(est), "pattern": False}
    if real:
        med = real[len(real) // 2] if len(real) % 2 else (real[len(real) // 2 - 1] + real[len(real) // 2]) / 2
        out["median_minutes"] = round(med)
        out["propose_minutes"] = int(5 * round(med / 5))
        out["pattern"] = len(real) >= 5 and bool(est) and abs(med - est) / est >= 0.2
    return out


def _scan_learn(adb, jobs_db, s, now, edition) -> int:
    n = 0
    since = (now.date() - dt.timedelta(days=30)).isoformat()
    for c in _rows(jobs_db, "SELECT DISTINCT customer_id FROM jobs WHERE LOWER(COALESCE(job_status, '')) IN "
                            "('complete', 'completed') AND service_date >= ? AND customer_id IS NOT NULL", (since,)):
        tos = time_on_site(jobs_db, c["customer_id"])
        if tos["pattern"]:
            n += _q(adb, JOB, c["customer_id"], "learn", "job times differ from the estimate",
                    f"learn|{tos['propose_minutes']}", s)
    return n


# ── the Route flow's scan ────────────────────────────────────────────────────

def _crews(jobs, edition) -> list:
    if edition != "business":
        return [""]
    return sorted({str(j["crew"] or "").strip() for j in jobs}) or [""]


def _day_jobs(jobs_db, day: str, crew: str, edition: str, statuses=("scheduled",)) -> list:
    rows = _rows(jobs_db, "SELECT * FROM jobs WHERE service_date = ? ORDER BY start_time, job_id", (day,))
    rows = [r for r in rows if _low(r["job_status"]) in statuses]
    if edition == "business":
        rows = [r for r in rows if str(r["crew"] or "").strip().casefold() == crew.casefold()]
    return rows


def _route_state(jobs_db, day: str, job_ids: list) -> dict:
    """{'stops': n, 'crew_ids': [...], 'approved': bool} for the day's routed jobs."""
    if not job_ids:
        return {"stops": 0, "crew_ids": [], "approved": False}
    marks = ",".join("?" * len(job_ids))
    stops = _rows(jobs_db, f"SELECT DISTINCT crew_id FROM route_stops WHERE route_date = ? AND job_id IN ({marks})",
                  (day, *job_ids))
    crew_ids = [r["crew_id"] for r in stops]
    approved = bool(crew_ids) and all(_rows(jobs_db, "SELECT 1 FROM route_approvals WHERE route_date = ? AND crew_id = ?",
                                            (day, c)) for c in crew_ids)
    n = _rows(jobs_db, f"SELECT COUNT(*) AS n FROM route_stops WHERE route_date = ? AND job_id IN ({marks})",
              (day, *job_ids))[0]["n"]
    return {"stops": n, "crew_ids": crew_ids, "approved": approved}


def proposals_path():
    fn = ops.get("week_proposals_path")
    if fn:
        return fn()
    from pathlib import Path
    import desk_agent_store
    return Path(desk_agent_store.path()).parent / "week_proposals.json"


def _scan_route(adb, jobs_db, s, now, edition) -> int:
    today, n = now.date(), 0
    import week_plan as wp
    if today.weekday() == int(s.get("agent_jb_sort_weekday", 4)) and now.hour >= 7:
        monday = wp.monday_of(today) + dt.timedelta(days=7)
        week = wp.load_week(jobs_db, monday)
        for crew in _crews([{"crew": j["crew"]} for j in week], edition):
            n += _q(adb, ROUTE, f"W:{monday.isoformat()}|{crew}", "sort", "the coming week",
                    f"sort|{monday.isoformat()}", s)
    try:
        props = wp._load(proposals_path())
    except Exception:  # noqa: BLE001
        props = {}
    for code, p in props.items():
        if str(code).startswith("WK-AG") and p.get("status") == "pending":
            n += _q(adb, ROUTE, f"W:{p['week_start']}|{p.get('crew') or ''}", "plan", "the agent's week plan",
                    f"plan|{code}", s)
    span = 7 if s.get("agent_jb_route_scope") == "week" else 1
    for k in range(1, span + 1):
        day = (today + dt.timedelta(days=k)).isoformat()
        alljobs = _rows(jobs_db, "SELECT crew FROM jobs WHERE service_date = ? AND LOWER(COALESCE(job_status, '')) = "
                                 "'scheduled'", (day,))
        for crew in _crews(alljobs, edition) if alljobs else []:
            js = _day_jobs(jobs_db, day, crew, edition)
            ids = [j["job_id"] for j in js]
            if ids and not _route_state(jobs_db, day, ids)["stops"]:
                n += _q(adb, ROUTE, f"{day}|{crew}", "route", "not routed yet", f"route|{_sig(*ids)}", s)
    hour = int(s.get("agent_jb_route_send_hour", 18))
    if now.hour >= hour:
        day = (today + dt.timedelta(days=1 if hour >= 12 else 0)).isoformat()
        alljobs = _rows(jobs_db, "SELECT crew FROM jobs WHERE service_date = ? AND LOWER(COALESCE(job_status, '')) = "
                                 "'scheduled'", (day,))
        for crew in _crews(alljobs, edition) if alljobs else []:
            ids = [j["job_id"] for j in _day_jobs(jobs_db, day, crew, edition)]
            st = _route_state(jobs_db, day, ids)
            if st["stops"] and not st["approved"]:
                n += _q(adb, ROUTE, f"{day}|{crew}", "send", "route ready to send", f"send|{_sig(*ids)}", s)
    day = today.isoformat()
    cancelled = _rows(jobs_db, "SELECT j.job_id, j.crew FROM jobs j WHERE j.service_date = ? AND "
                               "LOWER(COALESCE(j.job_status, '')) IN ('cancelled', 'canceled') AND EXISTS (SELECT 1 FROM "
                               "route_stops r WHERE r.route_date = ? AND r.job_id = j.job_id)", (day, day))
    for crew in _crews(cancelled, edition) if cancelled else []:
        ids = [c["job_id"] for c in cancelled if edition != "business" or str(c["crew"] or "").strip() == crew]
        if ids:
            n += _q(adb, ROUTE, f"{day}|{crew}", "replan", "a job was cancelled", f"replan|{_sig(*ids)}", s)
    return n


# ── facts: what the pack shows and the policy checks (read fresh, never from the AI) ──

def _one(conn, sql, args):
    r = conn.execute(sql, args).fetchone()
    return dict(r) if r else None


def _customer_view(c) -> dict:
    if not c:
        return {"name": "", "can_email": False, "can_text": False, "opted_out": False}
    phone = str(c.get("phone") or "").strip()
    out = {"customer_id": c["customer_id"], "name": _cust_name(c), "type": c.get("customer_type") or "",
           "can_email": bool(str(c.get("email") or "").strip()), "can_text": bool(phone),
           "opted_out": _opted_out(phone), "active": _low(c.get("status")) in ("", "active"),
           "preferred_days": c.get("preferred_days") or "", "notes": (c.get("gate_code_notes") or "")[:300]}
    return out


def _job_view(j) -> dict:
    return {k: j.get(k) for k in ("job_id", "customer_name", "service_type", "service_date", "start_time", "end_time",
                                  "job_status", "schedule_type", "crew", "est_duration", "est_duration_unit",
                                  "quote_amount", "recurrence", "invoice_id", "payment_status", "city")} | {
        "notes": (j.get("service_details") or "")[:500], "has_address": bool(str(j.get("street_address") or "").strip())}


def facts(adb, jobs_db, item, s, edition) -> dict | None:
    ref, stage, kind = item["ref"], item["stage"], item["kind"]
    now = _now_local()
    today = now.date()
    f = {"ref": ref, "today": today.isoformat()}
    if kind == ROUTE:
        return _route_facts(jobs_db, ref, stage, s, edition, today, f)
    conn = get_connection(jobs_db)
    try:
        if ref.startswith("QTE-"):
            q = _one(conn, "SELECT * FROM quotes WHERE quote_id = ?", (ref,))
            if not q:
                return None
            c = _one(conn, "SELECT * FROM customers WHERE customer_id = ?", (q["customer_id"],))
            f["quote"] = {k: q.get(k) for k in ("quote_id", "quote_date", "valid_until", "service_type",
                                                "service_description", "status")}
            f["_quote"], f["_customer"] = q, c
            f["customer"] = _customer_view(c)
            f["version"] = f"{q['version']}|{q['status']}"
            f["followups_sent"] = len(_sent(adb, ref, "quote_followup"))
        elif ref.startswith("INV-"):
            i = _one(conn, "SELECT * FROM invoices WHERE invoice_id = ?", (ref,))
            if not i:
                return None
            c = _one(conn, "SELECT * FROM customers WHERE customer_id = ?", (i["customer_id"],))
            j = _one(conn, "SELECT * FROM jobs WHERE job_id = ?", (i["job_id"],)) or {}
            sent = _sent(adb, ref, "reminder")
            days = list(s.get("agent_jb_remind_days") or [7, 14, 30])
            d0 = _d(i["invoice_date"])
            f["invoice"] = {"invoice_id": ref, "invoice_date": i["invoice_date"], "due_date": i["due_date"],
                            "days_since_invoice": (today - d0).days if d0 else None,
                            "payment_status": i["payment_status"] or "Unpaid", "service_type": i["service_type"],
                            "reminders_sent": len(sent), "reminder_days": days,
                            "next_reminder": len(sent) + 1 if len(sent) < len(days) else None,
                            "last_reminder_at": sent[-1]["sent_at"] if sent else ""}
            f["_invoice"], f["_customer"], f["_job"], f["_sent"] = i, c, j, sent
            f["customer"] = _customer_view(c)
            f["version"] = f"{i['version']}|{i['payment_status']}|{len(sent)}"
            if f["invoice"]["next_reminder"] == len(days):
                f["hint"] = "This is the last reminder — firmer (still polite): ask them to pay or call."
            elif f["invoice"]["next_reminder"] is None:
                f["hint"] = "All reminders were sent — tell the owner to call them (jb_call_customer)."
        elif ref.startswith("CUST-"):
            c = _one(conn, "SELECT * FROM customers WHERE customer_id = ?", (ref,))
            if not c:
                return None
            f["_customer"] = c
            f["customer"] = _customer_view(c)
            f["recent_jobs"] = [_job_view(dict(r)) for r in conn.execute(
                "SELECT * FROM jobs WHERE customer_id = ? ORDER BY service_date DESC LIMIT 5", (ref,))]
            f["version"] = str(c["version"])
            if stage == "learn":
                f["time_on_site"] = time_on_site(jobs_db, ref)
            f["winbacks_sent"] = len(_sent(adb, ref, "winback"))
        else:
            j = _one(conn, "SELECT * FROM jobs WHERE job_id = ?", (ref,))
            if not j:
                return None
            c = _one(conn, "SELECT * FROM customers WHERE customer_id = ?", (j["customer_id"],))
            f["job"], f["_job"], f["_customer"] = _job_view(j), j, c
            f["customer"] = _customer_view(c)
            f["version"] = f"{j['version']}|{j['job_status']}|{j['invoice_id'] or ''}"
            f["timed_minutes"] = round(conn.execute("SELECT COALESCE(SUM(elapsed_min), 0) FROM time_entries WHERE "
                                                    "job_id = ?", (ref,)).fetchone()[0] or 0)
            f["open_clock"] = bool(conn.execute("SELECT 1 FROM time_entries WHERE job_id = ? AND clock_in IS NOT NULL "
                                                "AND clock_out IS NULL", (ref,)).fetchone())
            if j.get("invoice_id"):
                inv = _one(conn, "SELECT * FROM invoices WHERE invoice_id = ?", (j["invoice_id"],))
                f["_invoice"] = inv
                if inv:
                    f["invoice"] = {"invoice_id": inv["invoice_id"], "payment_status": inv["payment_status"],
                                    "sent": bool(j.get("invoice_sent_date")),
                                    "receipt_sent": bool(j.get("receipt_sent_date"))}
            if stage in ("schedule", "prep"):
                f["dates"] = schedule_dates(jobs_db, j, c, today)
            if stage == "prep" and _outdoor(jobs_db, j.get("service_type")) and j.get("latitude") not in (None, ""):
                f["weather"] = _weather(j, j.get("service_date") or "")
    finally:
        conn.close()
    return f


def schedule_dates(jobs_db, j: dict, c: dict | None, today: dt.date, limit: int = 8) -> list:
    """Dates the job may go on: working days from tomorrow, its (or the customer's) Preferred
    Day(s), never today — best first: closest to other jobs that day, then the lightest day."""
    import week_plan as wp
    if _low(j.get("schedule_type")) == "hard" and j.get("service_date"):
        return []
    wdays = wp.working_days(jobs_db)
    pref = wp.parse_preferred_days(j.get("preferred_days") or (c or {}).get("preferred_days") or "")
    out = []
    for k in range(1, SCHEDULE_DAYS + 1):
        d = today + dt.timedelta(days=k)
        if d.weekday() not in wdays or (pref and d.weekday() not in pref) or d.isoformat() == j.get("service_date"):
            continue
        others = _rows(jobs_db, "SELECT job_id, latitude, longitude, est_duration, est_duration_unit FROM jobs WHERE "
                                "service_date = ? AND job_id != ? AND LOWER(COALESCE(job_status, '')) NOT IN "
                                "('cancelled', 'canceled')", (d.isoformat(), j["job_id"]))
        near = None
        if j.get("latitude") not in (None, ""):
            dist = [wp.miles_between(float(j["latitude"]), float(j["longitude"]), float(o["latitude"]),
                                     float(o["longitude"])) for o in others if o["latitude"] not in (None, "")]
            near = round(min(dist), 1) if dist else None
        out.append({"date": d.isoformat(), "weekday": wp._DAY[d.weekday()], "jobs_that_day": len(others),
                    "booked_minutes": round(sum(_minutes_of(o["est_duration"], o["est_duration_unit"]) for o in others)),
                    "nearest_job_miles": near})
    out.sort(key=lambda x: (x["nearest_job_miles"] if x["nearest_job_miles"] is not None else 999, x["booked_minutes"],
                            x["date"]))
    return out[:limit]


def _route_facts(jobs_db, ref, stage, s, edition, today, f) -> dict | None:
    import week_plan as wp
    key, _, crew = ref.partition("|")
    f["crew"] = crew
    if key.startswith("W:"):
        monday = wp.parse_iso(key[2:])
        if monday is None:
            return None
        f["week_start"] = monday.isoformat()
        if stage == "plan":
            p = next((p for c, p in wp._load(proposals_path()).items() if str(c).startswith("WK-AG")
                      and p.get("status") == "pending" and p.get("week_start") == monday.isoformat()
                      and (p.get("crew") or "") == crew), None)
            if not p:
                return None
            f["plan"] = {"code": p["code"], "moves": p.get("moves", []), "warnings": p.get("warnings", [])}
            f["_plan"] = p
            f["version"] = f"{p['code']}|{p['status']}"
            return f
        data = wp.week_data(jobs_db, monday, crew if edition == "business" else "", today)
        for jj in data["jobs"]:                       # decision 3: never anything today
            jj["may_move_to"] = [d for d in jj.get("may_move_to", []) if d != today.isoformat()]
            if jj["date"] == today.isoformat() and jj.get("movable"):
                jj["movable"], jj["not_movable_because"], jj["may_move_to"] = False, "today", []
        if not any(jj.get("movable") for jj in data["jobs"]):
            return None
        f["week"] = data
        f["version"] = _sig(*[(jj["job_id"], jj["date"]) for jj in data["jobs"]])
        return f
    day = wp.parse_iso(key)
    if day is None:
        return None
    f["day"] = day.isoformat()
    js = _day_jobs(jobs_db, day.isoformat(), crew, edition,
                   statuses=("scheduled", "in progress", "complete", "completed", "cancelled", "canceled"))
    f["jobs"] = [{k: j[k] for k in ("job_id", "customer_name", "start_time", "end_time", "schedule_type", "job_status",
                                    "city")} for j in js]
    open_ids = [j["job_id"] for j in js if _low(j["job_status"]) == "scheduled"]
    f["route"] = _route_state(jobs_db, day.isoformat(), [j["job_id"] for j in js])
    f["version"] = _sig(*[(j["job_id"], j["version"], j["job_status"]) for j in js], f["route"]["approved"])
    if stage in ("route", "send") and not open_ids:
        return None
    return f


def pack(adb, jobs_db, item, s, edition, business) -> dict | None:
    f = facts(adb, jobs_db, item, s, edition)
    if f is None:
        return None
    if item["kind"] == JOB and item["stage"] == "prep" and "missing_address" not in (item.get("reason") or "") \
            and "overfull" not in (item.get("reason") or "") and not (f.get("weather") or {}).get("bad"):
        f["hint"] = "The forecast has improved — nothing to move. no_action is fine."
    out = {k: v for k, v in f.items() if not k.startswith("_")}
    out["why_queued"] = item.get("reason") or ""
    out["rules"] = RULES
    out["action_fields"] = {a: ACTION_FIELDS[a] for a in ALLOWED[(item["kind"], item["stage"])]}
    return out


def context(adb, jobs_db, item, s, edition, business) -> dict:
    f = facts(adb, jobs_db, item, s, edition)
    if f is None:
        return {"gone": True, "stale": False}
    f["stale"] = bool(item.get("read_version")) and str(f.get("version")) != str(item["read_version"])
    f["invoices_sent_today"] = _sent_today(adb, "invoice")
    return f


# ── the policy's Jobs rules ──────────────────────────────────────────────────

def holds(kind, stage, act, s, ctx, conf, mode_) -> tuple:
    """(holds, guarded): extra reasons a person must decide, and for a guarded high-risk
    action (jb_send_invoice) whether every guardrail holds."""
    name = act.get("action")
    out = []
    if ctx.get("gone"):
        out.append("it's no longer in the Jobs app")
    if name in MESSAGES:
        out += engine._text_problems(str(act.get("body") or ""))
        cust = ctx.get("customer") or {}
        if cust.get("opted_out"):
            out.append("the customer opted out of messages")
        if not (cust.get("can_email") or cust.get("can_text")):
            out.append("no email or phone for the customer")
        if cust and not cust.get("active", True):
            out.append("the customer is inactive")
    if name == "jb_payment_reminder":
        last = (ctx.get("invoice") or {}).get("last_reminder_at")
        if last:
            try:
                gap = (_now_local() - dt.datetime.fromisoformat(last)).days
                if gap < REMIND_GAP_DAYS:
                    out.append(f"the last reminder went {gap} day(s) ago — at least {REMIND_GAP_DAYS} days apart")
            except ValueError:
                pass
    if name == "jb_quote_followup" and ctx.get("followups_sent"):
        out.append("a follow-up was already sent for this quote")
    if name == "jb_winback" and ctx.get("winbacks_sent"):
        out.append("a win-back message was already sent")
    if name == "jb_set_estimate" and not (ctx.get("time_on_site") or {}).get("pattern"):
        tos = ctx.get("time_on_site") or {}
        out.append(f"not enough evidence yet ({tos.get('n', 0)} timed job(s), need 5 and 20 %+ off)")
    guarded = _invoice_guardrails(s, ctx, act, conf) if name in GUARDED else None
    return out, guarded


def _invoice_guardrails(s, ctx, act, conf) -> tuple:
    """Decision 1 — every one must hold for the agent to send an invoice itself."""
    if not das.can_send_invoices(s):
        return False, "the agent isn't allowed to send invoices (or Close out isn't on Auto)"
    inv, job = ctx.get("_invoice") or {}, ctx.get("_job") or {}
    if not inv:
        return False, "no invoice yet"
    if str(inv.get("created_by") or "") != ACTOR:
        return False, "the invoice wasn't drafted by the agent"
    if str(inv.get("last_edited_by") or ACTOR) not in (ACTOR, "", "system"):
        return False, "the invoice was changed after the agent drafted it"
    if abs(float(inv.get("subtotal") or 0) - float(job.get("quote_amount") or 0)) > 0.005:
        return False, "the invoice amount doesn't match the job's price"
    cust = ctx.get("customer") or {}
    if cust.get("opted_out") or not cust.get("active", True):
        return False, "the customer opted out or is inactive"
    channel = act.get("channel") or "email"
    if not (cust.get("can_email") if channel == "email" else cust.get("can_text")):
        return False, f"no {'email' if channel == 'email' else 'phone'} for the customer"
    if not (ctx.get("timed_minutes") or float(job.get("actual_duration") or 0)):
        return False, "no time was logged on the job"
    if float(inv.get("total_due") or 0) > float(s.get("agent_jb_invoice_max", 1000)):
        return False, f"over the ${s.get('agent_jb_invoice_max', 1000):,} limit"
    if ctx.get("invoices_sent_today", 0) >= int(s.get("agent_jb_invoices_per_day", 10)):
        return False, "the agent's daily invoice limit is reached"
    if conf < engine.CONFIRM_CONFIDENCE:
        return False, f"confidence {conf:.2f} < {engine.CONFIRM_CONFIDENCE}"
    return True, ""


def validate(item, act, ctx) -> None:
    name = act["action"]
    if ctx.get("gone"):
        raise JobsAgentError("it's no longer in the Jobs app")
    if name in ("jb_note", "jb_prep_note", "jb_call_customer", "jb_customer_note", *MESSAGES) and \
            not str(act.get("body") or "").strip():
        raise JobsAgentError(f"{name} needs a body")
    if name == "jb_flag" and act.get("flag") not in FLAGS:
        raise JobsAgentError(f"flag must be one of {', '.join(FLAGS)}")
    job = ctx.get("_job") or {}
    today = ctx.get("today")
    if name == "jb_schedule":
        if _low(job.get("schedule_type")) == "hard" and job.get("service_date"):
            raise JobsAgentError("a fixed-time (Hard) job is never moved")
        if job.get("service_date") and job["service_date"][:10] <= today:
            raise JobsAgentError("a job today (or in the past) is never moved")
        if act.get("date") not in {d["date"] for d in ctx.get("dates") or []}:
            raise JobsAgentError("that date isn't one of the dates in the pack")
    if name == "jb_draft_invoice":
        if _low(job.get("job_status")) not in ("complete", "completed"):
            raise JobsAgentError("the job isn't Complete")
        if job.get("invoice_id"):
            raise JobsAgentError("the job already has an invoice")
        if not float(job.get("quote_amount") or 0):
            raise JobsAgentError("the job has no price to invoice")
    if name == "jb_send_invoice":
        if not ctx.get("_invoice"):
            raise JobsAgentError("draft the invoice first")
        if (ctx.get("invoice") or {}).get("sent"):
            raise JobsAgentError("the invoice was already sent")
    if name in ("jb_send_invoice", "jb_send_receipt") and (act.get("channel") or "email") not in ("email", "text"):
        raise JobsAgentError("channel must be email or text")
    if name == "jb_send_receipt":
        inv = ctx.get("_invoice") or {}
        if _low(inv.get("payment_status")) not in PAID:
            raise JobsAgentError("the invoice isn't marked paid")
        if (ctx.get("invoice") or {}).get("receipt_sent"):
            raise JobsAgentError("the receipt was already sent")
    if name == "jb_payment_reminder":
        inv = ctx.get("_invoice") or {}
        if _low(inv.get("payment_status")) not in OPEN_PAY or float(inv.get("balance_due") or 0) <= 0:
            raise JobsAgentError("nothing is owed on this invoice")
        if not (ctx.get("invoice") or {}).get("next_reminder"):
            raise JobsAgentError("all the reminders were sent — tell the owner to call (jb_call_customer)")
    if name in ("jb_quote_followup", "jb_job_from_quote"):
        st = _low((ctx.get("_quote") or {}).get("status")) or "open"
        if name == "jb_quote_followup" and st != "open":
            raise JobsAgentError("the quote isn't open")
        if name == "jb_job_from_quote" and st != "approved":
            raise JobsAgentError("the quote isn't approved")
    if name == "jb_next_visit" and _low(job.get("job_status")) not in ("complete", "completed"):
        raise JobsAgentError("the job isn't Complete")
    if name == "jb_set_estimate":
        try:
            m = int(act.get("minutes"))
        except (TypeError, ValueError):
            raise JobsAgentError("jb_set_estimate needs whole minutes") from None
        if not 15 <= m <= 600:
            raise JobsAgentError("jb_set_estimate must be 15-600 minutes")
    if name == "rt_propose_week":
        moves = act.get("moves")
        if isinstance(moves, str):
            try:
                moves = json.loads(moves or "[]")
            except ValueError:
                raise JobsAgentError("moves must be a JSON list") from None
        if not isinstance(moves, list):
            raise JobsAgentError("moves must be a list of {job_id, to, reason}")
        ok = {jj["job_id"]: set(jj.get("may_move_to") or []) for jj in (ctx.get("week") or {}).get("jobs", [])
              if jj.get("movable")}
        clean = []
        for m in moves[:40]:
            jid = str((m or {}).get("job_id") or "").strip().upper()
            if jid not in ok or str(m.get("to") or "") not in ok[jid]:
                raise JobsAgentError(f"{jid or '(blank)'} can't move to {m.get('to')} — only movable jobs, only to "
                                     "their may_move_to dates")
            clean.append({"job_id": jid, "to": m["to"], "reason": str(m.get("reason") or "")[:300]})
        act["moves"] = clean
    if name == "rt_apply_week":
        moves = {m["job_id"] for m in (ctx.get("plan") or {}).get("moves", [])}
        ids = [str(x).strip().upper() for x in (act.get("job_ids") or list(moves)) if str(x).strip()]
        if not ids or any(x not in moves for x in ids):
            raise JobsAgentError("job_ids must be moves from the plan")
        act["job_ids"] = ids
    if name in ("rt_route_day", "rt_send") and ctx.get("day", "") < (today or ""):
        raise JobsAgentError("that day is over")
    if name == "rt_route_day" and ctx.get("day") == today:
        raise JobsAgentError("today's route is changed only by Re-plan the day")
    if name == "rt_send" and not (ctx.get("route") or {}).get("stops"):
        raise JobsAgentError("the day isn't routed yet")
    if name == "rt_replan" and ctx.get("day") != today:
        raise JobsAgentError("Re-plan the day is for today only")


# ── applying (only ever through here) ────────────────────────────────────────

def _op(name, *args, **kw) -> str:
    fn = ops.get(name)
    if not fn:
        raise JobsAgentError(f"the Jobs app tool '{name}' isn't available here")
    r = str(fn(*args, **kw) or "")
    if r.lstrip().startswith("❌"):
        raise JobsAgentError(r.strip().splitlines()[0][:300])
    return r


def _ok(r) -> str:
    r = str(r or "")
    if r.lstrip().startswith("❌"):
        raise JobsAgentError(r.strip().splitlines()[0][:300])
    return r


def _say(ctx, subject: str, body: str) -> str:
    c = ctx.get("_customer") or {}
    cust = ctx.get("customer") or {}
    if cust.get("opted_out") or not cust.get("active", True):
        raise JobsAgentError("the customer opted out of messages (or is inactive) — not sent")
    email, phone = str(c.get("email") or "").strip(), str(c.get("phone") or "").strip()
    if email:
        _op("send_email", email, subject, body)
        return "emailed"
    if phone:
        _op("send_sms", phone, body)
        return "texted"
    raise JobsAgentError("no email or phone for the customer")


def _append(jobs_db, table, key_col, key, col, text) -> None:
    conn = get_connection(jobs_db)
    try:
        conn.execute(f"UPDATE {table} SET {col} = TRIM(COALESCE({col}, '') || char(10) || ?), version = version + 1, "
                     f"last_edited_by = ?, last_edited_at = ? WHERE {key_col} = ?",
                     (text, ACTOR, utcnow_iso(), key))
    finally:
        conn.close()


def apply(adb, jobs_db, item, act, s, edition, business, *, approved_by: str) -> str:
    name = act["action"]
    ctx = context(adb, jobs_db, item, s, edition, business)
    if ctx.get("gone"):
        raise JobsAgentError("it's no longer in the Jobs app")
    body = str(act.get("body") or "").strip()
    sig = engine._signature(s, business)
    signed = body if not body or sig in body else f"{body}\n\n{sig}"
    ref = item["ref"]
    if name in ("jb_note", "jb_flag", "jb_call_customer"):
        return "noted in the 🤖 tab"
    if name == "jb_prep_note":
        _append(jobs_db, "jobs", "job_id", ref, "service_details", f"🤖 {body}")
        return "note added to the job for the crew"
    if name == "jb_customer_note":
        cid = (ctx.get("_customer") or {}).get("customer_id")
        _append(jobs_db, "customers", "customer_id", cid, "gate_code_notes", f"{body} (assistant)")
        return "note saved on the customer"
    if name == "jb_quote_followup":
        how = _say(ctx, f"Your quote {ref}", f"{signed}\n\n(Quote {ref})")
        _mark(adb, ref, "quote_followup")
        return f"follow-up {how}"
    if name == "jb_job_from_quote":
        q = ctx["_quote"]
        price = round(float(q.get("subtotal") or 0) - float(q.get("discount_amt") or 0), 2)
        import db_write_ops as dwo
        r = _ok(dwo.db_create_job(jobs_db, {"CustomerID": q["customer_id"], "Service Type": q.get("service_type") or "",
                                            "Service Details / Notes": (q.get("service_description") or "")
                                            + (f"\nFrom quote {ref}." if ref else ""),
                                            "Quote Amount ($)": price, "Job Status": "Unscheduled"}, ACTOR))
        jid = r.split("NEW_JOB_ID=")[1].splitlines()[0].strip() if "NEW_JOB_ID=" in r else ""
        return f"job {jid or ''} made from {ref} (Unscheduled)".replace("  ", " ")
    if name == "jb_schedule":
        import db_write_ops as dwo
        upd = {"Service Date": act["date"]}
        if _low((ctx.get("_job") or {}).get("job_status")) in ("unscheduled", ""):
            upd["Job Status"] = "Scheduled"
        _ok(dwo.db_update_job(jobs_db, ref, upd, ACTOR))
        return f"scheduled for {act['date']}"
    if name == "jb_draft_invoice":
        import db_write_ops as dwo
        r = _ok(dwo.db_create_invoice(jobs_db, ref, ACTOR))
        return r.strip().splitlines()[0][:200]
    if name == "jb_send_invoice":
        inv = ctx["_invoice"]["invoice_id"]
        _op("email_invoice" if (act.get("channel") or "email") == "email" else "text_invoice", inv)
        _mark(adb, inv, "invoice")
        return f"{inv} sent to the customer"
    if name == "jb_send_receipt":
        inv = ctx["_invoice"]
        method = inv.get("payment_method") or inv.get("payment_status") or "Other"
        _op("email_receipt" if (act.get("channel") or "email") == "email" else "text_receipt", inv["invoice_id"],
            method)
        return f"receipt for {inv['invoice_id']} sent"
    if name == "jb_payment_reminder":
        inv, info = ctx["_invoice"], ctx["invoice"]
        n = info["next_reminder"]
        line = (f"Invoice {inv['invoice_id']} — balance due ${float(inv.get('balance_due') or 0):,.2f}"
                + (f" (due {inv['due_date']})" if inv.get("due_date") else "") + ".")
        how = _say(ctx, f"Reminder: invoice {inv['invoice_id']}", f"{signed}\n\n{line}")
        _mark(adb, inv["invoice_id"], "reminder", n)
        return f"reminder {n} {how}"
    if name == "jb_next_visit":
        import db_write_ops as dwo
        r = _ok(dwo.db_schedule_next_recurring_job(jobs_db, ref, ACTOR))
        if not r.lstrip().startswith("✅"):          # e.g. "ℹ️ … a one-time customer"
            raise JobsAgentError(r.strip().splitlines()[0][:300])
        nid = r.split("New Job ID:")[1].split()[0] if "New Job ID:" in r else ""
        return f"next visit set up{' — ' + nid if nid else ''} (on the customer's usual frequency)"
    if name == "jb_winback":
        how = _say(ctx, "Time for your next service?", signed)
        _mark(adb, ref, "winback")
        return f"message {how}"
    if name == "jb_set_estimate":
        conn = get_connection(jobs_db)
        try:
            conn.execute("UPDATE customers SET avg_job_duration_min = ?, version = version + 1, last_edited_by = ?, "
                         "last_edited_at = ? WHERE customer_id = ?", (int(act["minutes"]), ACTOR, utcnow_iso(), ref))
        finally:
            conn.close()
        return f"usual job time set to {int(act['minutes'])} min"
    if name == "rt_propose_week":
        import week_plan as wp
        monday = wp.parse_iso(ctx["week_start"])
        accepted, rejected, warnings = wp.validate_moves(jobs_db, monday, ctx.get("crew") or "", act["moves"],
                                                         _now_local().date())
        accepted = [a for a in accepted if ctx["today"] not in (a["from"], a["to"])]
        if not accepted:
            return "nothing worth moving" + (f" ({len(rejected)} not allowed)" if rejected else "")
        code = "WK-AG" + secrets.token_hex(2).upper()
        wp.save_proposal(proposals_path(), code, monday.isoformat(), ctx.get("crew") or "", accepted, warnings,
                         "🤖 " + "; ".join(f"{a['job_id']} {a['from']} → {a['to']}" for a in accepted))
        return f"week plan {code}: {len(accepted)} move(s) — see 🗓️ Plan Week"
    if name == "rt_apply_week":
        import week_plan as wp
        p = dict(ctx["_plan"])
        p["moves"] = [m for m in p.get("moves", []) if ctx["today"] not in (m.get("from"), m.get("to"))]
        res = wp.apply_moves(jobs_db, p, act["job_ids"], ACTOR, _now_local().date())
        wp.set_status(proposals_path(), p["code"], "approved", applied=[j for j, ok, _ in res if ok])
        return f"moved {sum(1 for _, ok, _ in res if ok)} of {len(res)} job(s)"
    if name == "rt_route_day":
        _op("suggest_route", ctx["day"], ctx.get("crew") or "")
        return f"{ctx['day']} routed — waiting to be approved"
    if name == "rt_send":
        _op("approve_route", ctx["day"], ctx.get("crew") or "")
        _op("email_route", ctx["day"], ctx.get("crew") or "")
        return f"route for {ctx['day']} approved and sent to the crew"
    if name == "rt_replan":
        _op("replan_route", ctx["day"], ctx.get("crew") or "")
        return "the rest of today's route was re-ordered"
    raise JobsAgentError(f"can't apply {name}")


# ── wiring ───────────────────────────────────────────────────────────────────

def install_ops(**fns) -> None:
    """ai_prowler_mcp.py hands over the tools a chat would use (ctx=None = the owner)."""
    ops.update({k: v for k, v in fns.items() if v})


def queue_counts(adb: str) -> dict:
    """For the Jobs app chips: what waits for a person, by stage."""
    conn = engine._conn(adb)
    try:
        rows = conn.execute("SELECT kind, stage, COUNT(*) n FROM agent_proposals WHERE status = 'pending' "
                            "GROUP BY kind, stage").fetchall()
    finally:
        conn.close()
    return {f"{r['kind']}:{r['stage']}": r["n"] for r in rows}


def _register() -> None:
    engine.RISK.update(RISK)
    engine.ALLOWED.update(ALLOWED)
    import sys
    me = sys.modules[__name__]
    engine.KINDS[JOB] = me
    engine.KINDS[ROUTE] = me
    if scan not in engine.SCANNERS:
        engine.SCANNERS.append(scan)


_register()
