"""
live_lib.py — helpers for the PAID live agent cost tests (tests/live_api_cost, 2026-11-03).

David: "create a test that checks a typical workflow for each of the 4 agents and also the AI task to get
real token cost and also check that the AI Agents perform correctly as well as the code ... only run these
tests once and make a special enable switch ... Make sure the test data is removed after each test because
you will be using the real install AI-Prowlers both local and server."

How a test stays safe on a REAL install
  * Nothing is changed in the saved settings. The settings the agents read are overlaid IN THIS PROCESS only
    (runner = Claude API key, the section on, PRACTICE MODE on), so the running AI-Prowler never starts a
    run of its own and nothing the agent suggests is applied, sent or booked.
  * Real queue items are parked (held) while the test's run works and put back afterwards; the timer's
    scans are off in this process, so the run only ever works the test's own items.
  * Test records use their own ids (JOB-LCT-1, QTE-LCT-1, INV-LCT-1, CUST-LCT-1, T-#### for the ticket) and
    are deleted afterwards; the cleanup is checked. HR test data is never written to the HR folders — the
    HR agent is handed an in-memory copy that holds the test employee.
  * The money spent is real and stays in the agents' run records, tagged "[live cost test]", so the
    monthly budget stays honest.

Cost is measured from the API's own usage block on every call (input, cache writes, cache reads, output,
web searches) at the published prices — that is the API credit charge. Claude Pro / Max subscription usage
is never involved: every call here goes through the Agent API Key.
"""
from __future__ import annotations

import contextlib
import datetime as dt
import json
import os
import shutil
import socket
import sqlite3
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
TAG = "[live cost test]"
HOLD = "live-cost-test-hold"
RESULTS_DIR = Path(os.environ.get("AIPROWLER_LIVE_RESULTS_DIR") or (HERE / "results"))

# ── exact API prices (checked 2026-11-03 against Anthropic's published price list) ──────────────────────────
# Sonnet 5.5 $2 / $10, cache reads $0.10 per 1M (halved on 2026-10-07 → 0.05x input); Haiku 5.5 $0.10 / $0.50
# with cache reads $0.01 (0.1x) — and a prompt over 100,000 tokens (counting cache reads and writes) pays 5x
# on everything; Opus 5.5 $4 / $20. Cache writes (5-minute) are 1.25x input. Web search $10 per 1,000.
PRICES = {"claude-haiku-5-5": (0.10, 0.50), "claude-sonnet-5-5": (2.0, 10.0), "claude-opus-5-5": (4.0, 20.0),
          "grok-4.3": (1.25, 2.50)}
CACHE_READ_X = {"claude-sonnet-5-5": 0.05}
LONG_PROMPT_X = {"claude-haiku-5-5": (100_000, 5.0)}


def exact_cost(model: str, u: dict) -> float:
    pin, pout = PRICES.get(model) or (PRICES["grok-4.3"] if str(model).startswith("grok") else (0.0, 0.0))
    inp, cw, cr, out = (int(u.get(k, 0) or 0) for k in ("input", "cache_write", "cache_read", "output"))
    lim = LONG_PROMPT_X.get(model)
    if lim and inp + cw + cr > lim[0]:
        pin, pout = pin * lim[1], pout * lim[1]
    c = (inp * pin + cw * pin * 1.25 + cr * pin * CACHE_READ_X.get(model, 0.10) + out * pout) / 1_000_000
    return round(c + 0.01 * int(u.get("web_searches", 0) or 0), 6)


# ── the meter: every API call's real usage ─────────────────────────────────────────────────────────────────
class Meter:
    def __init__(self):
        self.calls: list = []
        self.tools: list = []

    def wrap(self, fn, via: str):
        def wrapped(url, body, headers, *a, **k):
            t0 = time.time()
            data = fn(url, body, headers, *a, **k)
            u = (data or {}).get("usage") or {}
            if "anthropic" in str(url):
                rec = {"input": int(u.get("input_tokens") or 0),
                       "cache_write": int(u.get("cache_creation_input_tokens") or 0),
                       "cache_read": int(u.get("cache_read_input_tokens") or 0),
                       "output": int(u.get("output_tokens") or 0),
                       "web_searches": int((u.get("server_tool_use") or {}).get("web_search_requests") or 0)}
            else:
                cached = int((u.get("prompt_tokens_details") or {}).get("cached_tokens") or 0)
                rec = {"input": int(u.get("prompt_tokens") or 0) - cached, "cache_write": 0, "cache_read": cached,
                       "output": int(u.get("completion_tokens") or 0), "web_searches": 0}
            rec.update(model=str((body or {}).get("model") or ""), secs=round(time.time() - t0, 1), via=via)
            rec["cost"] = exact_cost(rec["model"], rec)
            self.calls.append(rec)
            return data
        return wrapped

    @staticmethod
    def _dry_post(url, body, headers, *a, **k):
        """--dry: no API call (costs nothing) — a safe note for whatever item it's given, so the whole path
        (test data, queue, run, policy, checks, cleanup) can be tried first."""
        try:
            pack = json.loads(body["messages"][0]["content"])
            allowed = pack.get("allowed_actions") or ["no_action"]
        except Exception:  # noqa: BLE001
            allowed = ["no_action"]
        act = next((a for a in ("note", "bk_note", "jb_note", "hr_note") if a in allowed), "no_action")
        text = json.dumps({"actions": [{"action": act, "body": "Dry run — no AI was called.", "why": "dry run",
                                        "confidence": 1}], "summary": "dry run"})
        return {"content": [{"type": "text", "text": text}], "usage": {"input_tokens": 0, "output_tokens": 0}}

    def install(self, mp, dry: bool = False):
        import desk_agent_providers as prov
        import task_queue_automation as tqa
        mp.setattr(prov, "_post", self.wrap(self._dry_post if dry else prov._post, "agent"))
        mp.setattr(tqa, "_post_json", self.wrap(tqa._post_json, "task"))
        orig_call = tqa._HttpMCPClient.call_tool
        meter = self

        def call_tool(self_, name, arguments=None, timeout=300):
            meter.tools.append(name)
            return orig_call(self_, name, arguments, timeout)
        mp.setattr(tqa._HttpMCPClient, "call_tool", call_tool)
        return self

    def totals(self) -> dict:
        t = {"calls": len(self.calls), "input": 0, "cache_write": 0, "cache_read": 0, "output": 0,
             "web_searches": 0, "cost": 0.0}
        for c in self.calls:
            for k in ("input", "cache_write", "cache_read", "output", "web_searches"):
                t[k] += c[k]
            t["cost"] += c["cost"]
        t["cost"] = round(t["cost"], 6)
        t["by_model"] = {}
        for c in self.calls:
            m = t["by_model"].setdefault(c["model"], {"calls": 0, "cost": 0.0, "input_all": 0, "output": 0})
            m["calls"] += 1
            m["cost"] = round(m["cost"] + c["cost"], 6)
            m["input_all"] += c["input"] + c["cache_write"] + c["cache_read"]
            m["output"] += c["output"]
        return t


# ── the settings the agents see in THIS process (nothing is saved) ─────────────────────────────────────────
SHARED = {"agent_provider": "claude_api", "agent_hours": [0, 24], "agent_batch_seconds": 0, "agent_max_items": 10}
OVERLAY_DESK = {**SHARED, "agent_enabled": True, "agent_shadow": True,
                "agent_stage_intake": "suggest", "agent_stage_first_reply": "suggest",
                "agent_stage_resolution": "suggest",
                "agent_bk_enabled": True, "agent_bk_shadow": True, "agent_bk_can_confirm": False,
                "agent_bk_stage_check": "suggest", "agent_bk_stage_decide": "suggest"}
OVERLAY_JOBS = {**SHARED, "agent_jb_enabled": True, "agent_jb_shadow": True, "agent_jb_can_send_invoices": False,
                "agent_jb_rt_enabled": True, "agent_jb_rt_shadow": True,
                **{f"agent_jb_stage_{k}": "suggest" for k in ("quotes", "schedule", "closeout", "collect")},
                "agent_jb_rt_stage_route": "suggest"}
OVERLAY_HR = {**SHARED, "agent_hr_enabled": True, "agent_hr_shadow": True, "agent_hr_can_approve_timeoff": False,
              **{f"agent_hr_stage_{k}": "suggest" for k in ("onboard", "timeoff", "answer")}}


def _key(p) -> str:
    try:
        return str(Path(p).resolve()).lower()
    except OSError:
        return str(p).lower()


def overlay_settings(mp, overlays: dict) -> None:
    import desk_db
    orig = desk_db.get_settings
    by = {_key(p): v for p, v in overlays.items()}

    def patched(db, *a, **k):
        s = orig(db, *a, **k)
        o = by.get(_key(db))
        if o:
            s = dict(s)
            s.update(o)
        return s
    mp.setattr(desk_db, "get_settings", patched)


# ── park the real queue, run only the test's items ─────────────────────────────────────────────────────────
def _db(path):
    con = sqlite3.connect(str(path), timeout=30)
    con.row_factory = sqlite3.Row
    return con


def park(db, keep: set, parked: dict) -> None:
    con = _db(db)
    try:
        rows = con.execute("SELECT item_id, status, claimed_by, claimed_until FROM agent_queue WHERE status IN "
                           "('waiting', 'claimed') AND COALESCE(claimed_by, '') != ?", (HOLD,)).fetchall()
        for r in rows:
            if r["item_id"] in keep:
                continue
            parked.setdefault(r["item_id"], (r["status"], r["claimed_by"], r["claimed_until"]))
            con.execute("UPDATE agent_queue SET status = 'claimed', claimed_by = ?, "
                        "claimed_until = '9999-12-31T00:00:00+00:00' WHERE item_id = ?", (HOLD, r["item_id"]))
        con.commit()
    finally:
        con.close()


def unpark(db, parked: dict) -> int:
    con = _db(db)
    n = 0
    try:
        for iid, (st, cb, cu) in parked.items():
            n += con.execute("UPDATE agent_queue SET status = ?, claimed_by = ?, claimed_until = ? "
                             "WHERE item_id = ? AND claimed_by = ?", (st, cb, cu, iid, HOLD)).rowcount
        con.commit()
    finally:
        con.close()
    return n


@contextlib.contextmanager
def only_these_items(mp, db, keep: set):
    """The run sees only `keep`: real waiting items are held (and put back), the timer's scans are off in this
    process, and every submit is recorded so the checks can read what the AI sent and what the policy did."""
    import desk_agent
    parked, subs = {}, {}
    mp.setattr(desk_agent, "SCANNERS", [])
    mp.setattr(desk_agent, "scan_bookings", lambda *a, **k: 0)
    orig_next, orig_submit = desk_agent.next_items, desk_agent.submit

    def nxt(d, **kw):
        park(d, keep, parked)                  # anything the app queued since is held too
        return orig_next(d, **kw)

    def sub(d, item_id, actions, **kw):
        r = orig_submit(d, item_id, actions, **kw)
        subs[int(item_id)] = {"actions": actions, "summary": kw.get("summary", ""), "result": r}
        return r
    mp.setattr(desk_agent, "next_items", nxt)
    mp.setattr(desk_agent, "submit", sub)
    park(db, keep, parked)
    try:
        yield subs
    finally:
        back = unpark(db, parked)
        if parked and back != len(parked):
            print(f"   NOTE: {len(parked) - back} held item(s) changed while held and were left as they are")


def tag_run(db, run_id) -> None:
    if not run_id:
        return
    con = _db(db)
    try:
        con.execute("UPDATE agent_runs SET summary = ? || ' ' || COALESCE(summary, '') WHERE run_id = ? "
                    "AND COALESCE(summary, '') NOT LIKE ?", (TAG, run_id, TAG + "%"))
        con.commit()
    finally:
        con.close()


def drop_run(db, run_id) -> None:
    """A dry run's record ($0, no AI call) — removed so it never counts as agent volume."""
    if not run_id:
        return
    con = _db(db)
    try:
        con.execute("DELETE FROM agent_runs WHERE run_id = ? AND COALESCE(cost_usd, 0) = 0 "
                    "AND COALESCE(input_tokens, 0) = 0", (run_id,))
        con.commit()
    finally:
        con.close()


def remove_agent_items(db, item_ids) -> None:
    ids = [int(i) for i in item_ids if i]
    if not ids:
        return
    marks = ",".join("?" * len(ids))
    con = _db(db)
    try:
        con.execute(f"DELETE FROM agent_proposals WHERE item_id IN ({marks})", ids)
        con.execute(f"DELETE FROM agent_queue WHERE item_id IN ({marks})", ids)
        con.commit()
    finally:
        con.close()


def proposals(db, item_ids) -> list:
    ids = [int(i) for i in item_ids if i]
    if not ids:
        return []
    con = _db(db)
    try:
        return [dict(r) for r in con.execute(
            f"SELECT * FROM agent_proposals WHERE item_id IN ({','.join('?' * len(ids))}) ORDER BY proposal_id", ids)]
    finally:
        con.close()


def queue_rows(db, item_ids) -> list:
    ids = [int(i) for i in item_ids if i]
    con = _db(db)
    try:
        return [dict(r) for r in con.execute(
            f"SELECT * FROM agent_queue WHERE item_id IN ({','.join('?' * len(ids))})", ids)] if ids else []
    finally:
        con.close()


# ── generic row insert (only columns the table has; NOT NULL columns without a default get a blank) ───────
def insert(con, table: str, row: dict) -> None:
    cols = {r[1]: r for r in con.execute(f"PRAGMA table_info('{table}')")}
    data = {k: v for k, v in row.items() if k in cols}
    for name, r in cols.items():                 # r = (cid, name, type, notnull, dflt, pk)
        if r[3] and r[4] is None and not r[5] and name not in data:
            t = (r[2] or "").upper()
            data[name] = 0 if ("INT" in t or "REAL" in t or "NUM" in t) else ""
    con.execute(f"INSERT INTO {table} ({', '.join(data)}) VALUES ({', '.join('?' * len(data))})", list(data.values()))


def count(db, sql, args=()) -> int:
    con = _db(db)
    try:
        return int(con.execute(sql, args).fetchone()[0] or 0)
    except sqlite3.Error:
        return 0
    finally:
        con.close()


# ── test data: the Jobs app ────────────────────────────────────────────────────────────────────────────────
CUSTOMERS = ("CUST-LCT-1", "CUST-LCT-2")
JOBS = ("JOB-LCT-1", "JOB-LCT-2", "JOB-LCT-3", "JOB-LCT-4", "JOB-LCT-5", "JOB-LCT-B1")
QUOTES = ("QTE-LCT-1",)
INVOICES = ("INV-LCT-1",)


def _workday_after(d: dt.date, days: int) -> dt.date:
    x = d + dt.timedelta(days=days)
    while x.weekday() >= 5:
        x += dt.timedelta(days=1)
    return x


def make_jobs_data(jobs_db: str, today: dt.date | None = None) -> dict:
    """Two test customers and a typical week's paperwork: an open quote 8 days old, an unscheduled job, two jobs
    on one day next week (not routed yet), a job finished yesterday with no invoice, and an invoice sent 8 days
    ago that's still unpaid. Returns the facts the test uses."""
    today = today or dt.date.today()
    day = _workday_after(today, 9)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    who = {"created_by": "live-cost-test", "last_edited_by": "live-cost-test", "last_edited_at": stamp, "version": 1}
    c1 = {"customer_id": "CUST-LCT-1", "customer_type": "Residential", "first_name": "Zz", "last_name": "LiveCost Test",
          "company_name": "", "phone": "", "email": "livecost-test@example.com",
          "street_address": "100 Flagler Ave", "city": "New Smyrna Beach", "state": "FL", "zip": "32169",
          "latitude": 29.0262, "longitude": -80.9248, "service_types": "Window Cleaning", "frequency": "One-time",
          "preferred_days": "", "avg_job_duration_min": 90, "status": "Active",
          "gate_code_notes": "Test customer for the live cost test — gate is unlocked.", **who}
    c2 = dict(c1, customer_id="CUST-LCT-2", last_name="LiveCost Test Two", email="livecost-test2@example.com",
              street_address="3600 S Atlantic Ave", latitude=28.9930, longitude=-80.8865,
              gate_code_notes="Test customer — call on arrival.")

    def job(jid, cust, **kw):
        base = {"job_id": jid, "customer_id": cust["customer_id"],
                "customer_name": f"{cust['first_name']} {cust['last_name']}", "customer_type": "Residential",
                "street_address": cust["street_address"], "city": cust["city"], "state": "FL", "zip": cust["zip"],
                "latitude": cust["latitude"], "longitude": cust["longitude"], "service_type": "Window Cleaning",
                "service_details": "Inside and outside windows, 2-storey house. (live cost test)", "crew": "",
                "est_duration": 90, "est_duration_unit": "min", "schedule_type": "Soft", "quote_amount": 285,
                **who}
        base.update(kw)
        return base
    jobs = [
        job("JOB-LCT-1", c1, job_status="Unscheduled", service_date=None),
        job("JOB-LCT-2", c1, job_status="Scheduled", service_date=day.isoformat(), start_time="09:00",
            end_time="10:30", day_of_week=day.strftime("%A")),
        job("JOB-LCT-3", c2, job_status="Scheduled", service_date=day.isoformat(), start_time="11:00",
            end_time="12:30", day_of_week=day.strftime("%A"), service_type="Pressure Washing",
            service_details="Driveway and pool deck. (live cost test)"),
        job("JOB-LCT-4", c2, job_status="Complete", service_date=(today - dt.timedelta(days=1)).isoformat(),
            start_time="09:00", end_time="10:30", actual_duration=95, actual_duration_unit="min"),
        job("JOB-LCT-5", c1, job_status="Complete", service_date=(today - dt.timedelta(days=10)).isoformat(),
            start_time="13:00", end_time="14:30", invoice_id="INV-LCT-1",
            invoice_sent_date=(today - dt.timedelta(days=8)).isoformat(), payment_status="Unpaid"),
    ]
    quote = {"quote_id": "QTE-LCT-1", "customer_id": "CUST-LCT-2", "customer_name": "Zz LiveCost Test Two",
             "customer_type": "Residential", "address": c2["street_address"], "city": c2["city"],
             "quote_date": (today - dt.timedelta(days=8)).isoformat(),
             "valid_until": (today + dt.timedelta(days=22)).isoformat(), "service_type": "Window Cleaning",
             "service_description": "Exterior windows and screens, 24 panes.", "subtotal": 320, "quote_total": 320,
             "status": "Open", **who}
    inv = {"invoice_id": "INV-LCT-1", "job_id": "JOB-LCT-5", "customer_id": "CUST-LCT-1",
           "customer_name": "Zz LiveCost Test", "customer_type": "Residential",
           "invoice_date": (today - dt.timedelta(days=8)).isoformat(),
           "due_date": (today - dt.timedelta(days=1)).isoformat(),
           "service_date": (today - dt.timedelta(days=10)).isoformat(), "service_type": "Window Cleaning",
           "description": "Window cleaning (live cost test)", "subtotal": 250, "total_due": 250, "amount_paid": 0,
           "balance_due": 250, "payment_status": "Unpaid", **who}
    con = _db(jobs_db)
    try:
        con.execute("BEGIN IMMEDIATE")
        insert(con, "customers", c1)
        insert(con, "customers", c2)
        for j in jobs:
            insert(con, "jobs", j)
        insert(con, "quotes", quote)
        insert(con, "invoices", inv)
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()
    return {"route_day": day.isoformat(), "customers": list(CUSTOMERS)}


def remove_jobs_data(jobs_db: str) -> dict:
    gone = {}
    con = _db(jobs_db)
    try:
        con.execute("BEGIN IMMEDIATE")
        jm = ",".join("?" * len(JOBS))
        for t, col in (("booking_holds", "job_id"), ("booking_requests", "job_id"), ("booking_reminders", "job_id"),
                       ("calendar_sync_queue", "job_id"), ("calendar_clashes", "job_id"), ("route_stops", "job_id"),
                       ("time_entries", "job_id")):
            try:
                gone[t] = con.execute(f"DELETE FROM {t} WHERE {col} IN ({jm})", JOBS).rowcount
            except sqlite3.Error:
                pass
        for t, col, vals in (("invoices", "invoice_id", INVOICES), ("quotes", "quote_id", QUOTES),
                             ("jobs", "job_id", JOBS), ("customers", "customer_id", CUSTOMERS)):
            gone[t] = con.execute(f"DELETE FROM {t} WHERE {col} IN ({','.join('?' * len(vals))})", vals).rowcount
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()
    gone.update(remove_scanned(JOBS + QUOTES + INVOICES + CUSTOMERS))
    return {k: v for k, v in gone.items() if v}


def remove_scanned(refs) -> dict:
    """Queue items the RUNNING AI-Prowler's own timer queued for the test's records while they existed (its scans
    run every few minutes in the app's own process, which this test can't switch off — found 2026-11-03: the
    Jobs scan queued QTE-LCT-1, JOB-LCT-1, JOB-LCT-4 and INV-LCT-1 30 s after the Jobs test). Removed with them."""
    refs = [r for r in refs if r]
    out = {}
    if not refs:
        return out
    try:
        import desk_agent_store
        import desk_db
        paths = [desk_db.default_db_path(), desk_agent_store.path()]
    except Exception:  # noqa: BLE001
        return out
    marks = ",".join("?" * len(refs))
    for p in paths:
        if not Path(p).exists():
            continue
        con = _db(p)
        try:
            n = con.execute(f"DELETE FROM agent_proposals WHERE ref IN ({marks})", refs).rowcount
            n += con.execute(f"DELETE FROM agent_queue WHERE ref IN ({marks})", refs).rowcount
            con.commit()
            if n:
                out[f"items the app's scan queued ({Path(p).stem})"] = n
        except sqlite3.Error:
            pass
        finally:
            con.close()
    return out


def scanned_leftovers(refs) -> list:
    out = []
    try:
        import desk_agent_store
        import desk_db
        paths = [desk_db.default_db_path(), desk_agent_store.path()]
    except Exception:  # noqa: BLE001
        return out
    refs = [r for r in refs if r]
    for p in paths:
        if refs and Path(p).exists():
            n = count(p, f"SELECT COUNT(*) FROM agent_queue WHERE ref IN ({','.join('?' * len(refs))})", refs)
            if n:
                out.append(f"{n} agent queue item(s) for test records left in {Path(p).stem}")
    return out


def jobs_leftovers(jobs_db: str) -> list:
    out = scanned_leftovers(JOBS + QUOTES + INVOICES + CUSTOMERS)
    for t, col, vals in (("jobs", "job_id", JOBS), ("customers", "customer_id", CUSTOMERS),
                         ("quotes", "quote_id", QUOTES), ("invoices", "invoice_id", INVOICES),
                         ("booking_requests", "job_id", JOBS), ("booking_holds", "job_id", JOBS)):
        n = count(jobs_db, f"SELECT COUNT(*) FROM {t} WHERE {col} IN ({','.join('?' * len(vals))})", vals)
        if n:
            out.append(f"{n} row(s) left in {t}")
    return out


# ── test data: a Service Desk ticket ───────────────────────────────────────────────────────────────────────
def make_ticket(tdb: str, edition: str) -> dict:
    """A customer's ticket as it arrives from the support page: a contact, the ticket, and the customer's
    first message. Nothing is sent to anyone (the customer's own message is never queued for delivery)."""
    import desk_db
    stamp = dt.datetime.now().strftime("%Y%m%d%H%M%S")
    con = _db(tdb)
    try:
        seq = con.execute("SELECT seq FROM sqlite_sequence WHERE name = 'tickets'").fetchone()
        seq_before = int(seq[0]) if seq else None
    except sqlite3.Error:
        seq_before = None
    finally:
        con.close()
    c = desk_db.upsert_contact(tdb, name="Zz LiveCost Test", email=f"livecost-{stamp}@example.com",
                               contact_type="customer")
    t = desk_db.create_ticket(tdb, title="LIVE COST TEST - streaks left on the back windows",
                              actor=None, edition=edition, source="test", contact_id=c["contact_id"],
                              description=("You cleaned our windows on Friday. The back sliding doors and the two "
                                           "big windows facing the pool have streaks all over them in the "
                                           "afternoon sun. Can someone come back and fix it?"))
    desk_db.add_message(tdb, t["ticket_id"], "Hi, it's the windows at the back by the pool. The front looks great. "
                                             "We're home most afternoons this week if you can come by. Thanks!",
                        actor=None, edition=edition, visibility="public", author_kind="customer", channel="web")
    return {"ticket_id": t["ticket_id"], "contact_id": c["contact_id"], "folder": t.get("folder") or "",
            "seq_before": seq_before}


def remove_ticket(tdb: str, info: dict) -> dict:
    import desk_db
    tid, cid = info.get("ticket_id"), info.get("contact_id")
    gone = {}
    row = None
    con = _db(tdb)
    try:
        con.execute("BEGIN IMMEDIATE")
        row = con.execute("SELECT row_id, folder FROM tickets WHERE ticket_id = ?", (tid,)).fetchone() if tid else None
        for t in ("ticket_messages", "ticket_events", "ticket_links", "ticket_relations", "ticket_watchers",
                  "ticket_attachments"):
            try:
                gone[t] = con.execute(f"DELETE FROM {t} WHERE ticket_id = ?", (tid,)).rowcount
            except sqlite3.Error:
                pass
        if tid:
            gone["tickets"] = con.execute("DELETE FROM tickets WHERE ticket_id = ?", (tid,)).rowcount
        if cid:
            gone["customer_contacts"] = con.execute("DELETE FROM customer_contacts WHERE contact_id = ?", (cid,)).rowcount
        if row and info.get("seq_before") is not None:       # the next real ticket keeps the next number
            con.execute("UPDATE sqlite_sequence SET seq = ? WHERE name = 'tickets' AND seq = ?",
                        (info["seq_before"], row["row_id"]))
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()
    folder = info.get("folder") or (row["folder"] if row else "")
    if folder and tid and tid in folder:
        p = desk_db.root_for(tdb) / folder
        if p.exists():
            shutil.rmtree(p, ignore_errors=True)
            gone["folder"] = 1
    gone.update(remove_scanned([tid]))
    return {k: v for k, v in gone.items() if v}


def ticket_leftovers(tdb: str, info: dict) -> list:
    import desk_db
    out = scanned_leftovers([info.get("ticket_id")])
    if info.get("ticket_id") and count(tdb, "SELECT COUNT(*) FROM tickets WHERE ticket_id = ?", (info["ticket_id"],)):
        out.append("the test ticket is still there")
    if info.get("contact_id") and count(tdb, "SELECT COUNT(*) FROM customer_contacts WHERE contact_id = ?",
                                        (info["contact_id"],)):
        out.append("the test contact is still there")
    if info.get("folder") and (desk_db.root_for(tdb) / info["folder"]).exists():
        out.append("the ticket folder is still there")
    return out


# ── test data: a booking waiting for approval ──────────────────────────────────────────────────────────────
def make_booking(jobs_db: str, settings: dict, edition: str) -> dict | None:
    """A customer booked online: a Pending Approval job with their chosen window held and one backup — the same
    records booking_flow.create_pending makes, with the test's own job id. None when booking isn't set up."""
    import booking_db
    import booking_flow as bf
    svcs = booking_db.list_services(jobs_db)
    if not svcs:
        return None
    code = svcs[0]["code"]
    ws = bf.windows(jobs_db, settings, code, edition, online_only=False)
    if not ws:
        return None
    first = ws[min(3, len(ws) - 1)]["key"]
    backup = ws[min(8, len(ws) - 1)]["key"]
    jid = "JOB-LCT-B1"
    h = bf._hold(jobs_db, settings, code, first, kind="pending", minutes=72 * 60, edition=edition, now=None,
                 job_id=jid, online_only=False)
    choices = {"first": first, "first_label": bf.label_of(first),
               "backups": [{"key": backup, "label": bf.label_of(backup)}] if backup != first else []}
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    con = _db(jobs_db)
    try:
        con.execute("BEGIN IMMEDIATE")
        insert(con, "jobs", {"job_id": jid, "customer_id": "CUST-LCT-1", "customer_name": "Zz LiveCost Test",
                             "customer_type": "Residential", "street_address": "100 Flagler Ave",
                             "city": "New Smyrna Beach", "state": "FL", "zip": "32169", "latitude": 29.0262,
                             "longitude": -80.9248, "service_type": svcs[0].get("name") or svcs[0].get("label") or code,
                             "service_details": f"Gate code 4411, dog in the back yard.\nWants: {choices['first_label']}"
                                                + (f"\nOr: {choices['backups'][0]['label']}" if choices["backups"] else "")
                                                + "\nBooked on the website — waiting for approval. (live cost test)",
                             "est_duration": svcs[0].get("minutes") or 90, "est_duration_unit": "min",
                             "job_status": "Pending Approval", "schedule_type": "Soft",
                             "created_by": getattr(booking_db, "WEB_BOOKING", "web"),
                             "last_edited_by": "live-cost-test", "last_edited_at": stamp, "version": 1})
        insert(con, "booking_requests", {"job_id": jid, "path": "book", "service_code": code,
                                         "choices_json": json.dumps(choices), "status": "pending", "created_at": stamp})
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()
    return {"job_id": jid, "service_code": code, "held": bool(h), "first": first,
            "windows": [w["key"] for w in ws[:60]]}


# ── test data: HR (in memory only — the HR folders are never written) ──────────────────────────────────────
def hr_data(adb: str, today: dt.date | None = None) -> dict:
    today = today or dt.date.today()
    cfg = {}
    try:                                             # the company's real policies, read only
        p = Path(adb).resolve().parent.parent / "company" / "settings.json"
        cfg = json.loads(p.read_text(encoding="utf-8-sig")) if p.exists() else {}
    except Exception:  # noqa: BLE001
        cfg = {}
    cfg.setdefault("pto_days_per_year", 10)
    cfg.setdefault("sick_days_per_year", 5)
    emp = {"id": "EMP-LCT1", "first_name": "Zz", "last_name": "LiveCostTest", "title": "Window Technician",
           "department": "Field", "status": "onboarding", "start_date": (today + dt.timedelta(days=3)).isoformat(),
           "work_state": "FL", "employment_type": "full_time", "pay_type": "hourly",
           "flsa_classification": "non-exempt", "pay_frequency": "biweekly"}
    off = _workday_after(today, 20)
    return {"config": cfg, "employees": [emp],
            "tasks": [{"id": "TSK-LCT-1", "employee_id": "EMP-LCT1", "name": "Form I-9 Section 1", "phase": "pre-start",
                       "due_date": (today + dt.timedelta(days=1)).isoformat(), "status": "Pending",
                       "priority": "HIGH", "assigned_to_role": "employee", "federal_required": True},
                      {"id": "TSK-LCT-2", "employee_id": "EMP-LCT1", "name": "Form W-4", "phase": "pre-start",
                       "due_date": (today + dt.timedelta(days=2)).isoformat(), "status": "Pending",
                       "priority": "MEDIUM", "assigned_to_role": "employee", "federal_required": True}],
            "pto_requests": [{"id": "PTO-LCT-1", "employee_id": "EMP-LCT1", "type": "PTO",
                              "start_date": off.isoformat(), "end_date": off.isoformat(), "half_day": False,
                              "status": "pending",
                              "created_at": (dt.datetime.now() - dt.timedelta(hours=26)).isoformat(timespec="seconds")}],
            "messages": [{"id": "MSG-LCT-1", "employee_id": "EMP-LCT1", "subject": "Paid holidays",
                          "body": "Hi, which days are paid holidays this year, and how many PTO days do I get in my "
                                  "first year?", "message_type": "help_question",
                          "sent_at": dt.datetime.now().isoformat(timespec="seconds")}],
            "documents": [], "training": [], "time_entries": [], "incidents": [],
            "schedule_change_requests": [], "recruiting": {"candidates": []}}


# ── the checks ─────────────────────────────────────────────────────────────────────────────────────────────
EXPECT = {("ticket", "intake"): {"set_type", "set_priority", "route", "note"},
          ("ticket", "first_reply"): {"reply", "ask_customer"},
          ("ticket", "resolution"): {"note", "reply", "ask_customer", "propose_learning", "nudge_team"},
          ("booking", "check"): {"bk_note", "bk_flag", "bk_customer_note", "bk_job_note"},
          ("booking", "decide"): {"bk_recommend", "bk_approve", "bk_suggest_time", "bk_decline"},
          ("job", "quotes"): {"jb_quote_followup"},
          ("job", "schedule"): {"jb_schedule"},
          ("job", "closeout"): {"jb_draft_invoice"},
          ("job", "collect"): {"jb_payment_reminder"},
          ("route", "route"): {"rt_route_day"},
          ("hr", "onboard"): {"hr_remind_employee", "hr_task", "hr_flag", "hr_note"},
          ("hr", "timeoff"): {"hr_recommend"},
          ("hr", "answer"): {"hr_reply", "hr_note", "hr_ack_sensitive"}}
MESSAGE_ACTIONS = {"reply", "ask_customer", "bk_reply", "bk_decline", "bk_offer_times", "jb_quote_followup",
                   "jb_payment_reminder", "jb_winback", "hr_reply", "hr_remind_employee"}


def check_run(res: dict, item_ids: list, subs: dict, props: list, qrows: list) -> tuple:
    """(problems, warnings, lines): problems fail the test, warnings are reported."""
    import desk_agent
    problems, warnings, lines = [], [], []
    n = len(item_ids)
    if not res.get("ran"):
        return [f"the agent didn't run: {res.get('why')}"], [], []
    if res.get("items") != n:
        problems.append(f"the run worked {res.get('items')} item(s), expected exactly the test's {n}")
    if res.get("ok") != n:
        problems.append(f"only {res.get('ok')} of {n} item(s) got a usable answer: {res.get('notes')}")
    byitem = {q["item_id"]: q for q in qrows}
    for iid in item_ids:
        q = byitem.get(iid) or {}
        key = (q.get("kind"), q.get("stage"))
        s = subs.get(iid)
        if not s:
            problems.append(f"{key}: nothing was submitted ({q.get('note') or 'no answer'})")
            continue
        results = (s["result"] or {}).get("results", [])
        acts = [a.get("action") for a in s["actions"] if isinstance(a, dict)]
        lines.append(f"   {q.get('kind')}/{q.get('stage')}: {', '.join(map(str, acts)) or 'no actions'}"
                     + (f" — {s['summary'][:110]}" if s.get("summary") else ""))
        for a in s["actions"]:
            if not isinstance(a, dict):
                continue
            body = str(a.get("body") or a.get("note") or "").strip()
            extra = {k: v for k, v in a.items() if k not in ("action", "why", "confidence", "body", "note")}
            lines.append(f"      • {a.get('action')} (confidence {a.get('confidence')}): {str(a.get('why') or '')[:140]}"
                         + (f" | {json.dumps(extra, ensure_ascii=False)[:160]}" if extra else ""))
            if body:
                lines.append(f"        \"{body[:300]}{'…' if len(body) > 300 else ''}\"")
            if a.get("action") in MESSAGE_ACTIONS:
                if not body:
                    problems.append(f"{key}: {a.get('action')} has no text")
                for p in desk_agent._text_problems(body):
                    problems.append(f"{key}: {a.get('action')} text {p}")
        for r in results:
            st = r.get("status")
            if st == "applied":
                problems.append(f"{key}: {r.get('action')} was APPLIED — practice mode must never apply anything")
            elif st == "failed":
                problems.append(f"{key}: {r.get('action')} failed: {r.get('why')}")
            elif st == "rejected":
                problems.append(f"{key}: the policy rejected {r.get('action')}: {r.get('why')}")
        want = EXPECT.get(key)
        if want and not (set(acts) & want):
            warnings.append(f"{key}: expected one of {sorted(want)}, the AI chose {acts or 'nothing'}")
        if q.get("status") != "done":
            problems.append(f"{key}: the queue item ended '{q.get('status')}' ({q.get('note')})")
    for p in props:
        if p["status"] not in ("practice",):
            problems.append(f"proposal {p['proposal_id']} ({p['action']}) is '{p['status']}' — expected 'practice'")
    return problems, warnings, lines


# ── the ledger: what each test cost, running totals, files the owner can open ─────────────────────────────
class Ledger:
    def __init__(self, edition: str):
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        self.host = socket.gethostname()
        self.edition = edition
        self.started = dt.datetime.now()
        stem = f"live_cost_{self.host}_{self.started:%Y%m%d_%H%M%S}"
        self.json_path = RESULTS_DIR / f"{stem}.json"
        self.md_path = RESULTS_DIR / f"{stem}.md"
        self.rows: list = []
        self.predicted = {}

    @property
    def total(self) -> float:
        return round(sum(r["exact_cost"] for r in self.rows), 6)

    def add(self, row: dict) -> None:
        self.rows.append(row)
        self.save()

    def save(self) -> None:
        doc = {"host": self.host, "edition": self.edition, "started": self.started.isoformat(timespec="seconds"),
               "prices_per_1M": PRICES, "rows": self.rows, "total_exact_cost": self.total,
               "popup_prediction_at_start": self.predicted}
        self.json_path.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
        md = [f"# Live API cost test — {self.host} ({self.edition}), {self.started:%Y-%m-%d %H:%M}", "",
              "| Test | Result | API calls | Tokens in (new / cache write / cache read) | Tokens out | "
              "Exact cost | AI-Prowler recorded | Per call |", "|---|---|---|---|---|---|---|---|"]
        for r in self.rows:
            t = r["tokens"]
            md.append(f"| {r['test']} | {r['outcome']} | {t['calls']} | {t['input']:,} / {t['cache_write']:,} / "
                      f"{t['cache_read']:,} | {t['output']:,} | ${r['exact_cost']:.4f} | "
                      f"${r.get('recorded_cost', 0):.4f} | ${r.get('per_item', 0):.4f} per {r.get('unit', 'item')} |")
        md += ["", f"**Running total (API credits): ${self.total:.4f}**", ""]
        for r in self.rows:
            md += [f"## {r['test']}", ""] + [f"    {x}" for x in r.get("lines", [])]
            md += [f"- PROBLEM: {p}" for p in r.get("problems", [])] + [f"- warning: {w}" for w in r.get("warnings", [])]
            md += [f"- cleanup: {r.get('cleanup')}", f"- shown: {r.get('shown', '')}", ""]
        self.md_path.write_text("\n".join(md), encoding="utf-8")

    def print_block(self, row: dict) -> None:
        t = row["tokens"]
        bar = "=" * 96
        print(f"\n{bar}\n  {row['test']} — {row['outcome']}")
        print(f"  API calls {t['calls']} · tokens in {t['input']:,} new + {t['cache_write']:,} cache-write + "
              f"{t['cache_read']:,} cache-read · out {t['output']:,}" +
              (f" · web searches {t['web_searches']}" if t.get("web_searches") else ""))
        for m, v in t.get("by_model", {}).items():
            print(f"     {m}: {v['calls']} call(s), {v['input_all']:,} in / {v['output']:,} out, ${v['cost']:.5f}")
        print(f"  THIS TEST: ${row['exact_cost']:.5f} in API credits  (AI-Prowler recorded ${row.get('recorded_cost', 0):.5f})"
              f"  ·  ${row.get('per_item', 0):.5f} per {row.get('unit', 'item')}")
        if row.get("predicted"):
            print(f"  Cost Analysis popup predicted: {row['predicted']}")
        print(f"  RUNNING TOTAL this session: ${self.total:.5f}   ·   month so far (all agents): "
              f"${row.get('month_spent', 0):.2f}")
        for x in row.get("lines", []):
            print(x)
        for p in row.get("problems", []):
            print(f"  PROBLEM: {p}")
        for w in row.get("warnings", []):
            print(f"  warning: {w}")
        print(f"  cleanup: {row.get('cleanup')}\n  shown: {row.get('shown', '')}\n  results: {self.md_path}\n{bar}\n")


def month_spent() -> float:
    try:
        import desk_agent_budget as ab
        return float(ab.month_totals(ab.agent_db_paths(), dt.datetime.now().strftime("%Y-%m"))["cost"])
    except Exception:  # noqa: BLE001
        return 0.0


# ── human mode: show the results in the real apps before they're cleaned up ───────────────────────────────
class Viewer:
    """Opens the real app pages in a visible, slowed-down browser (human mode) and shows the agent's practice
    results for the test's records. Never fails a test — when it can't show something it says why."""

    def __init__(self, human: bool, edition: str, seconds: int = 12):
        self.human, self.edition, self.seconds = human, edition, seconds
        self.base = os.environ.get("AIPROWLER_LOCAL_API_ORIGIN", "http://127.0.0.1:8000").rstrip("/")

    def _login(self):
        """(name, token) for the apps' sign-in: personal → the Bearer Token; server → the first owner."""
        home = Path.home() / ".ai-prowler"
        if self.edition != "business":
            try:
                cfg = json.loads((home / "config.json").read_text(encoding="utf-8-sig"))
                return "", str(cfg.get("remote_token") or "").strip()
            except Exception:  # noqa: BLE001
                return "", ""
        try:
            data = json.loads((home / "users.json").read_text(encoding="utf-8-sig")) or {}
            for tok, rec in (data.get("users") or {}).items():
                if isinstance(rec, dict) and str(rec.get("role", "")).lower() == "owner" and \
                        str(rec.get("status", "active") or "active").lower() == "active":
                    return str(rec.get("name") or ""), tok
        except Exception:  # noqa: BLE001
            pass
        return "", ""

    @contextlib.contextmanager
    def _page(self):
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            b = p.chromium.launch(headless=False, slow_mo=int(os.environ.get("E2E_SLOWMO", "350")))
            ctx = b.new_context(viewport={"width": 1280, "height": 900})
            page = ctx.new_page()
            try:
                yield page
            finally:
                ctx.close()
                b.close()

    @staticmethod
    def _banner(page, text):
        page.evaluate("""t => { let d = document.getElementById('lct_banner'); if (!d) { d = document.createElement('div');
            d.id = 'lct_banner'; d.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:99999;background:#7c3aed;'
            + 'color:#fff;font:600 15px system-ui;padding:8px 14px;box-shadow:0 2px 8px #0004';
            document.body.appendChild(d); } d.textContent = t; }""", text)

    @staticmethod
    def _type(page, sel, text):
        page.click(sel)
        page.locator(sel).press_sequentially(text, delay=int(os.environ.get("E2E_TYPE_DELAY", "45")))

    def _highlight(self, page, needles):
        found = 0
        for n in needles:
            loc = page.get_by_text(n, exact=False)
            try:
                if loc.count():
                    el = loc.first
                    el.scroll_into_view_if_needed(timeout=3000)
                    el.evaluate("e => { e.style.outline = '3px solid #f59e0b'; e.style.background = '#fef3c7'; }")
                    found += 1
                    page.wait_for_timeout(1500)
            except Exception:  # noqa: BLE001
                pass
        return found

    def show_desk(self, title: str, needles: list) -> str:
        if not self.human:
            return "not shown (human mode off)"
        name, tok = self._login()
        if not tok:
            return "not shown — no sign-in found for this install"
        try:
            with self._page() as page:
                page.goto(self.base + "/desk/", wait_until="domcontentloaded")
                page.wait_for_timeout(1500)
                if page.locator("#lgTok").count():
                    if self.edition == "business" and page.locator("#lgName").count():
                        self._type(page, "#lgName", name)
                    self._type(page, "#lgTok", tok)
                    page.click("#lgGo")
                page.wait_for_timeout(2500)
                tab = page.locator("#tabAgent")
                if not tab.count() or not tab.is_visible():
                    self._banner(page, f"LIVE COST TEST — {title}: the 🤖 Agent tab is hidden because Service Desk → "
                                       "Agent is off in your saved settings (the test ran it in practice mode only).")
                    page.wait_for_timeout(self.seconds * 1000)
                    return "Agent tab hidden (agent off in saved settings) — results are in the report"
                tab.click()
                page.wait_for_timeout(2500)
                self._banner(page, f"LIVE COST TEST — {title} (practice mode: nothing was sent or changed)")
                n = self._highlight(page, needles)
                page.wait_for_timeout(self.seconds * 1000)
                return f"shown in Service Desk → 🤖 Agent ({n} highlighted)"
        except Exception as e:  # noqa: BLE001
            return f"not shown ({type(e).__name__}: {str(e)[:160]})"

    def show_jobs(self, title: str, needles: list) -> str:
        if not self.human:
            return "not shown (human mode off)"
        name, tok = self._login()
        if not tok:
            return "not shown — no sign-in found for this install"
        try:
            with self._page() as page:
                page.goto(self.base + "/jobs/", wait_until="domcontentloaded")
                page.wait_for_timeout(2000)
                if page.locator("#authScreen").is_visible():
                    if self.edition == "business" and page.locator("#authName").count():
                        self._type(page, "#authName", name)
                    self._type(page, "#authCode", tok)
                    page.get_by_test_id("auth-unlock").click()
                    page.wait_for_timeout(3000)
                nav = page.get_by_test_id("nav-agent")
                if not nav.count() or not nav.is_visible():
                    self._banner(page, f"LIVE COST TEST — {title}: the 🤖 Agent tab is hidden because the Jobs agent "
                                       "is off in your saved settings (the test ran it in practice mode only).")
                    page.wait_for_timeout(self.seconds * 1000)
                    return "Agent tab hidden (Jobs agent off in saved settings) — results are in the report"
                nav.click()
                page.wait_for_timeout(3000)
                self._banner(page, f"LIVE COST TEST — {title} (practice mode: nothing was sent or changed)")
                n = self._highlight(page, needles)
                page.wait_for_timeout(self.seconds * 1000)
                return f"shown in Jobs app → 🤖 Agent ({n} highlighted)"
        except Exception as e:  # noqa: BLE001
            return f"not shown ({type(e).__name__}: {str(e)[:160]})"

    def show_text(self, title: str, text: str) -> str:
        """For results with no app screen (the Task Queue run): a simple page with the result."""
        if not self.human:
            return "not shown (human mode off)"
        try:
            import html
            with self._page() as page:
                page.set_content(f"<html><body style='font:15px system-ui;padding:50px 30px;white-space:pre-wrap'>"
                                 f"<h2>{html.escape(title)}</h2>{html.escape(text)}</body></html>")
                self._banner(page, f"LIVE COST TEST — {title}")
                page.wait_for_timeout(self.seconds * 1000)
            return "shown"
        except Exception as e:  # noqa: BLE001
            return f"not shown ({type(e).__name__}: {str(e)[:160]})"
