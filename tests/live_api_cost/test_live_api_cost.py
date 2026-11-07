"""
PAID live tests (2026-11-03): a typical workflow for each agent on the real install, on the Agent API Key,
with the real token cost of each one. See conftest.py for how to run them and live_lib.py for how they stay
safe (practice mode, real queue held aside, test records removed and checked).

    1 Service Desk tickets   a new customer ticket: intake, first reply, resolution help        (3 AI calls)
    2 Service Desk bookings  a web booking waiting for approval: check, decide                  (2 AI calls)
    3 Jobs app agent         quote follow-up, schedule, close out, payment reminder, route a day (5 AI calls)
    4 HR agent (server)      onboarding checklist, a time-off request, an employee question     (3 AI calls)
    5 AI task (Task Queue)   a typical daily business check run on its own, saved as a report  (a tool run)
"""
from __future__ import annotations

import datetime as dt
import json
from pathlib import Path

import pytest

import live_lib as L

pytestmark = pytest.mark.live_api_cost


def _predicted(live, models_used: dict) -> str:
    est = {e["model"]: e for e in (live["ledger"].predicted.get("estimates") or [])}
    parts = []
    for m in models_used:
        if m in est:
            parts.append(f"{m} ${est[m]['per_call']:.4f}/call")
    smart = next((e for k, e in est.items() if "+" in k), None)
    if smart:
        parts.append(f"smart mix ${smart['per_call']:.4f}/call, ${smart['per_month']:.2f}/month")
    return " · ".join(parts)


def _run_agent(live, mp, *, test: str, db: str, overlays: dict, items: list, show) -> dict:
    """Queue the test's items, run the agent once on the Agent API Key (practice mode), check what it did,
    record the cost. Returns the ledger row. `items` = [(kind, ref, stage, reason)]."""
    import desk_agent
    import desk_db
    meter = L.Meter().install(mp, dry=live["dry"])
    if live["dry"]:
        test += " (DRY — no AI call)"
    L.overlay_settings(mp, overlays)
    s = desk_db.get_settings(db)
    ids = []
    for kind, ref, stage, reason in items:
        iid = desk_agent.enqueue(db, kind, ref, stage, f"{L.TAG} {reason}", settings=s)
        assert iid, f"couldn't queue {kind}/{stage} for {ref} (stage off, or already queued?)"
        ids.append(iid)
    res, subs = {}, {}
    try:
        with L.only_these_items(mp, db, set(ids)) as subs:
            res = desk_agent.run(db, edition=live["edition"], business=live["business"], jobs_db=live["jobs_db"],
                                 force=True)
        if live["dry"]:
            L.drop_run(db, res.get("run_id"))      # nothing was spent — don't let it count as volume
        else:
            L.tag_run(db, res.get("run_id"))
        problems, warnings, lines = L.check_run(res, ids, subs, L.proposals(db, ids), L.queue_rows(db, ids))
        shown = show() if show else ""
    finally:
        L.remove_agent_items(db, ids)
    t = meter.totals()
    row = {"test": test, "tokens": t, "exact_cost": t["cost"], "recorded_cost": float(res.get("cost_usd") or 0),
           "per_item": round(t["cost"] / max(1, len(ids)), 6), "unit": "item (one AI call)", "items": len(ids),
           "calls": meter.calls, "problems": problems, "warnings": warnings, "lines": lines, "shown": shown,
           "predicted": _predicted(live, t["by_model"]), "run_id": res.get("run_id")}
    if t["calls"] != len(ids):
        row["problems"].append(f"{t['calls']} API call(s) for {len(ids)} item(s) — expected one call per item")
    if abs(row["recorded_cost"] - row["exact_cost"]) > max(0.0005, 0.05 * row["exact_cost"]):
        row["warnings"].append(f"AI-Prowler recorded ${row['recorded_cost']:.5f} but the API charged "
                               f"${row['exact_cost']:.5f} (cache pricing in desk_agent_providers.cost)")
    return row


def _finish(live, row: dict, cleanup: dict, leftovers: list) -> None:
    row["cleanup"] = ("removed " + ", ".join(f"{k} {v}" for k, v in cleanup.items()) if cleanup else "nothing to remove")
    if leftovers:
        row["problems"].append("test data left behind: " + "; ".join(leftovers))
        row["cleanup"] += " — LEFT BEHIND: " + "; ".join(leftovers)
    row["outcome"] = "FAILED" if row["problems"] else "passed"
    row["month_spent"] = L.month_spent()
    live["ledger"].add(row)
    live["ledger"].print_block(row)
    assert not row["problems"], "\n".join(row["problems"])


# ── 1 ────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_1_service_desk_tickets(live, monkeypatch):
    """Service Desk agent — a customer's new ticket ("streaks left on the back windows").
    The agent sorts it (intake), drafts the first reply and suggests how to fix it: 3 AI calls.
    Practice mode: nothing is sent to anyone. The test ticket and contact are deleted afterwards."""
    tdb = live["tdb"]
    L.overlay_settings(monkeypatch, {tdb: L.OVERLAY_DESK})
    info, row = {}, None
    try:
        info = L.make_ticket(tdb, live["edition"])
        tid = info["ticket_id"]
        row = _run_agent(live, monkeypatch, test="1 Service Desk — tickets", db=tdb,
                         overlays={tdb: L.OVERLAY_DESK},
                         items=[("ticket", tid, "intake", "new ticket"), ("ticket", tid, "first_reply", "new customer ticket"),
                                ("ticket", tid, "resolution", "customer replied")],
                         show=lambda: live["viewer"].show_desk("Service Desk ticket agent", ["LIVE COST TEST", tid]))
    finally:
        gone = L.remove_ticket(tdb, info) if info else {}
    _finish(live, row, gone, L.ticket_leftovers(tdb, info))


# ── 2 ────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_2_service_desk_bookings(live, monkeypatch):
    """Service Desk agent — a booking made on the website, waiting for approval.
    The agent checks it (address, area, history) and recommends approve / another time / decline: 2 AI calls.
    Practice mode: nothing is booked or sent. The test job, booking and customer are deleted afterwards."""
    tdb, jdb = live["tdb"], live["jobs_db"]
    import desk_db
    L.overlay_settings(monkeypatch, {tdb: L.OVERLAY_DESK})
    row, b = None, None
    try:
        L.make_jobs_data(jdb)                     # the booking's customer (and the Jobs test's records)
        b = L.make_booking(jdb, desk_db.get_settings(tdb), live["edition"])
        if not b:
            pytest.skip("online booking isn't set up on this install (no services or no open times)")
        row = _run_agent(live, monkeypatch, test="2 Service Desk — bookings", db=tdb, overlays={tdb: L.OVERLAY_DESK},
                         items=[("booking", b["job_id"], "check", "new booking"),
                                ("booking", b["job_id"], "decide", "waiting for approval")],
                         show=lambda: live["viewer"].show_desk("Service Desk booking agent", ["Zz LiveCost", "JOB-LCT-B1"]))
    finally:
        gone = L.remove_jobs_data(jdb)
    _finish(live, row, gone, L.jobs_leftovers(jdb))


# ── 3 ────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_3_jobs_agent(live, monkeypatch):
    """Jobs app agent — a typical week's paperwork for two test customers.
    Quote follow-up (customer message), pick a date for an unscheduled job, draft the invoice for a finished
    job, a payment reminder for an unpaid invoice, and route next week's day (Route flow): 5 AI calls.
    Practice mode: nothing is scheduled, invoiced or sent. All test jobs/customers are deleted afterwards."""
    import desk_agent_store
    jdb = live["jobs_db"]
    adb = desk_agent_store.init()
    desk_agent_store.sync_shared(live["tdb"], adb)
    row = None
    try:
        facts = L.make_jobs_data(jdb)
        row = _run_agent(live, monkeypatch, test="3 Jobs app agent", db=adb, overlays={adb: L.OVERLAY_JOBS},
                         items=[("job", "QTE-LCT-1", "quotes", "quote still open"),
                                ("job", "JOB-LCT-1", "schedule", "unscheduled"),
                                ("job", "JOB-LCT-4", "closeout", "done — no invoice"),
                                ("job", "INV-LCT-1", "collect", "reminder 1"),
                                ("route", f"{facts['route_day']}|", "route", "not routed yet")],
                         show=lambda: live["viewer"].show_jobs("Jobs app agent", ["LCT", "Zz LiveCost"]))
    finally:
        gone = L.remove_jobs_data(jdb)
    _finish(live, row, gone, L.jobs_leftovers(jdb))


# ── 4 ────────────────────────────────────────────────────────────────────────────────────────────────────────
def test_4_hr_agent(live, monkeypatch):
    """HR agent (server only) — a new hire's onboarding checklist, their time-off request and a question
    ("which days are paid holidays?"): 3 AI calls. The test employee exists only in this test's memory —
    nothing is written to the HR folders. Practice mode: nothing is approved or sent."""
    if live["edition"] != "business":
        pytest.skip("the HR agent runs on the AI-Prowler Server (business edition) only")
    import desk_agent_hr_store
    import desk_hr_agent
    adb = desk_agent_hr_store.path()
    if not Path(adb).exists():
        pytest.skip(f"no HR agent database at {adb} (HR agent never turned on)")
    desk_agent_hr_store.sync_shared(live["tdb"], adb)
    data = L.hr_data(adb)
    monkeypatch.setattr(desk_hr_agent, "hr", {"load": lambda: data})
    row = _run_agent(live, monkeypatch, test="4 HR agent", db=adb, overlays={adb: L.OVERLAY_HR},
                     items=[("hr", "emp:EMP-LCT1", "onboard", "onboarding checklist"),
                            ("hr", "pto:PTO-LCT-1", "timeoff", "time-off request"),
                            ("hr", "msg:MSG-LCT-1", "answer", "employee message")],
                     show=None)
    row["shown"] = "HR results stay out of the shared screens; they are in this report"
    _finish(live, row, {"HR folders": "never written (test employee was in memory only)"}, [])


# ── 5 ────────────────────────────────────────────────────────────────────────────────────────────────────────
TASK_LABEL = "LIVE COST TEST daily check"
TASK_PROMPT = ("Morning business check for today. (1) List the jobs scheduled in the next 7 days (date, customer, "
               "service). (2) List unpaid invoices older than 14 days with the customer and amount. (3) Get tomorrow's "
               "weather for New Smyrna Beach, FL and say whether it affects outdoor window cleaning or pressure "
               "washing. Keep it short. Save the result with save_analysis_report. Do not send any email or message.")


def test_5_ai_task_queue(live, monkeypatch):
    """AI task (Autonomous Task Queue) — a typical daily business check: upcoming jobs, old unpaid invoices and
    tomorrow's weather, saved as a report. Runs exactly like a scheduled task (AI-Prowler's own tools over the
    local connection, read-only, web search allowed): one tool run of several AI rounds.
    The task and its report are deleted afterwards."""
    import custom_tasks_manager as ctm
    import task_queue_automation as tqa
    if live["dry"]:
        pytest.skip("--dry: a task run can't be tried without the AI")
    meter = L.Meter().install(monkeypatch)
    why = tqa.why_not_ready(tqa.load_config(), None)
    if why:
        pytest.fail(f"the Task Queue can't run here: {why}")
    rep_dir = Path(ctm.DEFAULT_REPORT_FOLDER)
    before = set(rep_dir.glob("*")) if rep_dir.exists() else set()
    client = tqa._HttpMCPClient(tqa._bearer_token(None))
    client.initialize()
    task_id, ok, detail, row = "", False, "", None
    try:
        out = client.call_tool("create_analysis_task", {"label": TASK_LABEL, "prompt": TASK_PROMPT, "schedule": "none",
                                                        "auto_run": False, "output_learnings": False,
                                                        "output_report": True, "output_email": False})
        task = next((t for t in ctm.load_custom_tasks() if t.get("label") == TASK_LABEL), None)
        assert task, f"the task wasn't created: {out[:300]}"
        task_id = task["task_id"]
        meter.tools.clear()
        ok, detail = tqa.run_task(task_id, trigger="manual", timeout_sec=900)
        t = meter.totals()
        con = L._db(tqa.runs_db_path())
        try:
            rec = con.execute("SELECT * FROM agent_runs WHERE summary LIKE ? ORDER BY run_id DESC LIMIT 1",
                              (TASK_LABEL + "%",)).fetchone()
        finally:
            con.close()
        recorded = float(rec["cost_usd"]) if rec else 0.0
        tools = [n for n in meter.tools if n not in ("initialize",)]
        problems, warnings = [], []
        if not ok:
            problems.append(f"the run didn't finish: {detail[:300]}")
        if "save_analysis_report" not in tools:
            problems.append("the report wasn't saved (save_analysis_report was never called)")
        bad = [n for n in tools if n in ("send_email", "send_sms", "send_whatsapp") or n.startswith(
            ("create_", "update_", "delete_", "apply_", "approve_", "email_", "text_"))]
        if bad:
            problems.append(f"an unattended read-only run called tools that change or send things: {sorted(set(bad))}")
        if abs(recorded - t["cost"]) > max(0.001, 0.03 * t["cost"]):
            warnings.append(f"AI-Prowler recorded ${recorded:.5f} for this run, the API charged ${t['cost']:.5f} "
                            "(task_queue_automation.run_cost cache-read price)")
        rounds = len([c for c in meter.calls if c["via"] == "task"])
        row = {"test": "5 AI task (Task Queue)", "tokens": t, "exact_cost": t["cost"], "recorded_cost": recorded,
               "per_item": t["cost"], "unit": "task run", "items": 1, "calls": meter.calls, "rounds": rounds,
               "problems": problems, "warnings": warnings,
               "lines": [f"   {rounds} AI round(s); tools used: {', '.join(tools) or 'none'}",
                         f"   summary: {detail[:600]}"],
               "predicted": _predicted(live, t["by_model"]) + " (the popup treats a whole task run as one 'call')"}
        row["shown"] = live["viewer"].show_text("AI task result", detail[:3000])
    finally:
        gone = {}
        if task_id:
            fresh = ctm.load_custom_tasks()
            if ctm.delete_task(fresh, task_id):
                ctm.save_custom_tasks(fresh)
                gone["task"] = 1
        after = set(rep_dir.glob("*")) if rep_dir.exists() else set()
        for p in sorted(after - before):
            try:
                if p.is_file():
                    p.unlink()
                    gone["report files"] = gone.get("report files", 0) + 1
            except OSError:
                pass
        client.close()
    left = []
    if any(t.get("label") == TASK_LABEL for t in ctm.load_custom_tasks()):
        left.append("the test task is still in the task list")
    _finish(live, row, gone, left)
