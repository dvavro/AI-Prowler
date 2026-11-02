"""The Jobs agent (jobs-agent-spec.md J1 + J2): the shared engine working the Jobs app — kinds
'job' (Jobs flow) and 'route' (Route flow) in the agent's own database. David's decisions:
1 the agent may send invoices behind a switch (off by default) with limits; 2 reminders at
7 / 14 / 30 days then "call them"; 3 dates are only suggested at first, never a Hard job or
anything today; 4 a separate database. No network: the Jobs tools are fakes (ja.ops).
The clock is the next Friday after the real today, 09:00 (invoices are dated by the real clock).
Run: run_tests.bat tests\\unit\\test_jobs_agent_engine.py
"""
import datetime as dt
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
import desk_agent as ag  # noqa: E402
import desk_agent_providers as prov  # noqa: E402
import desk_agent_store as store  # noqa: E402
import desk_db  # noqa: E402
import desk_jobs_agent as ja  # noqa: E402
import desk_rules as r  # noqa: E402
from db_access import get_connection, init_db  # noqa: E402

S = r.SOLO
OWNER = {"id": "owner", "role": r.OWNER, "name": "Dave"}
REAL = dt.date.today()
FRI = REAL + dt.timedelta(days=((4 - REAL.weekday()) % 7) or 7)
d = lambda n: (FRI + dt.timedelta(days=n)).isoformat()  # noqa: E731


@pytest.fixture
def e(tmp_path):
    store.PATH_OVERRIDE = tmp_path / "agent_database" / "agent.db"
    adb = store.init()
    jobs = str(tmp_path / "jobs.db")
    init_db(jobs)
    clock = {"now": dt.datetime.combine(FRI, dt.time(9, 0))}
    calls, opted = [], set()

    def fake(name):
        def fn(*a, **kw):
            calls.append((name, a))
            if name in ("email_invoice", "text_invoice"):
                conn = get_connection(jobs)
                conn.execute("UPDATE jobs SET invoice_sent_date = ? WHERE invoice_id = ?", (d(0), a[0]))
                conn.close()
            return f"✅ {name} ok"
        return fn
    ja.ops.clear()
    ja.install_ops(**{n: fake(n) for n in ("send_email", "send_sms", "email_invoice", "text_invoice", "email_receipt",
                                           "text_receipt", "suggest_route", "approve_route", "email_route",
                                           "replan_route")},
                   week_proposals_path=lambda: tmp_path / "week_proposals.json")
    ja.clock = lambda: clock["now"]
    ja.opted_out_fn = lambda p: p in opted
    for k, v in (("agent_jb_enabled", True), ("agent_jb_shadow", False), ("agent_jb_weather", False),
                 ("agent_jb_rt_enabled", True), ("agent_jb_rt_shadow", False)):     # the Route flow's own switches
        store.set_setting(k, v, actor=OWNER, edition=S)
    ins(jobs, "customers", customer_id="CUST-0001", first_name="Ann", last_name="Lee", email="ann@example.com",
        phone="386-555-0100", street_address="1 Main St", city="DeLand", state="FL", zip="32720", latitude=29.03,
        longitude=-81.30, status="Active")
    yield {"a": adb, "j": jobs, "clock": clock, "calls": calls, "opted": opted, "tmp": tmp_path}
    store.PATH_OVERRIDE = None
    ja.ops.clear()
    ja.clock = ja.opted_out_fn = None
    ag.transport = None


def ins(db, table, **cols):
    conn = get_connection(db)
    try:
        conn.execute(f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", tuple(cols.values()))
    finally:
        conn.close()


def sql(db, q, args=()):
    conn = get_connection(db)
    try:
        return [dict(x) for x in conn.execute(q, args).fetchall()]
    finally:
        conn.close()


def job(e, jid, **kw):
    cols = dict(job_id=jid, customer_id="CUST-0001", customer_name="Ann Lee", street_address="1 Main St", city="DeLand",
                latitude=29.03, longitude=-81.30, service_type="Window cleaning", job_status="Scheduled",
                service_date=d(3), schedule_type="soft", est_duration=60, est_duration_unit="min", quote_amount=200,
                crew="")
    cols.update(kw)
    ins(e["j"], "jobs", **cols)


def setj(**kw):
    for k, v in kw.items():
        store.set_setting(k, v, actor=OWNER, edition=S)


def items(e, stage=None, ref=None):
    release(e)                       # items handed out earlier but not worked go back (a claim lasts 10 min)
    out = ag.next_items(e["a"], edition=S, jobs_db=e["j"], limit=10)["items"]
    return [i for i in out if (stage is None or i["stage"] == stage) and (ref is None or i["ref"] == ref)]


def submit(e, item, *actions):
    return ag.submit(e["a"], item["item_id"], list(actions), edition=S, jobs_db=e["j"])["results"]


def act(name, conf=0.9, **kw):
    return {"action": name, "why": "test", "confidence": conf, **kw}


def release(e):
    """Put every claimed item back (the next call sees them again)."""
    conn = get_connection(e["a"])
    conn.execute("UPDATE agent_queue SET status = 'waiting', claimed_by = NULL WHERE status = 'claimed'")
    conn.close()


# ── the registry and the policy table ────────────────────────────────────────

def test_registered_and_the_policy_table(e):
    assert ag.KINDS["job"] is ja and ag.KINDS["route"] is ja and ja.scan in ag.SCANNERS
    s = desk_db.get_settings(e["a"])
    ctx = {"customer": {"can_email": True, "active": True}}
    note = act("jb_note", body="x")
    assert ag.decide("job", "schedule", note, s, ctx) == ("apply", "")                 # records only — even on Suggest
    assert ag.decide("job", "schedule", act("jb_schedule", date=d(3)), s, ctx)[0] == "pending"   # Suggest
    assert ag.decide("job", "schedule", act("jb_draft_invoice"), s, ctx)[0] == "rejected"     # not this stage
    assert ag.decide("job", "onsite", act("jb_flag", flag="running_long"), s, ctx) == ("apply", "")  # onsite = Auto
    setj(agent_jb_stage_learn="auto")
    s = desk_db.get_settings(e["a"])
    st, why = ag.decide("job", "learn", act("jb_set_estimate", minutes=90), s, ctx)
    assert st == "pending" and "evidence" in why                                          # high risk, no pattern
    setj(agent_jb_stage_schedule="off")
    assert ag.decide("job", "schedule", note, desk_db.get_settings(e["a"]), ctx)[0] == "rejected"
    setj(agent_jb_shadow=True)
    assert ag.decide("job", "onsite", note, desk_db.get_settings(e["a"]), ctx)[0] == "practice"
    setj(agent_jb_enabled=False)
    assert ag.enqueue(e["a"], "job", "JOB-0001", "onsite", "x") is None                   # the agent is off


# ── Quotes ───────────────────────────────────────────────────────────────────

def test_quote_follow_up_then_the_job_from_the_approved_quote(e):
    ins(e["j"], "quotes", quote_id="QTE-0001", customer_id="CUST-0001", customer_name="Ann Lee", quote_date=d(-6),
        service_type="Pressure washing", service_description="Driveway", subtotal=300, discount_amt=20, tax=0,
        quote_total=280, status="Open")
    setj(agent_jb_stage_quotes="auto")
    it = items(e, "quotes", "QTE-0001")[0]
    assert "quote_total" not in json.dumps(it) and it["customer"]["can_email"] and "rules" in it
    res = submit(e, it, act("jb_quote_followup", body="Hi Ann, any questions about the driveway quote? $280 is a deal"))
    assert res[0]["status"] == "pending" and "price" in res[0]["why"]                     # no amounts from the AI
    ag.retry_errors(e["a"])
    conn = get_connection(e["a"])
    conn.execute("UPDATE agent_queue SET status = 'waiting' WHERE ref = 'QTE-0001'")
    conn.close()
    it = items(e, "quotes", "QTE-0001")[0]
    res = submit(e, it, act("jb_quote_followup", body="Hi Ann, any questions about the driveway quote?"))
    assert res[0]["status"] == "applied"
    (name, (to, subj, body)), = [c for c in e["calls"] if c[0] == "send_email"]
    assert to == "ann@example.com" and "(Quote QTE-0001)" in body and "Virtual assistant" in body
    assert not items(e, "quotes", "QTE-0001")                                              # once only
    conn = get_connection(e["j"])
    conn.execute("UPDATE quotes SET status = 'Approved', version = version + 1 WHERE quote_id = 'QTE-0001'")
    conn.close()
    it = items(e, "quotes", "QTE-0001")[0]
    assert it["why_queued"].startswith("quote approved")
    res = submit(e, it, act("jb_job_from_quote"))
    assert res[0]["status"] == "applied", res
    j = sql(e["j"], "SELECT * FROM jobs WHERE customer_id = 'CUST-0001' AND service_type = 'Pressure washing'")[0]
    assert j["quote_amount"] == 280 and j["job_status"] == "Unscheduled"                   # the quote's price
    assert not items(e, "quotes", "QTE-0001")


# ── Schedule (decision 3) ───────────────────────────────────────────────────

def test_schedule_only_suggests_never_today_never_a_hard_job(e):
    job(e, "JOB-0001", job_status="Unscheduled", service_date="")
    job(e, "JOB-0002", service_date=d(3), latitude=29.031, longitude=-81.301)            # a neighbour on Monday
    it = items(e, "schedule", "JOB-0001")[0]
    dates = [x["date"] for x in it["dates"]]
    assert d(0) not in dates and dates[0] == d(3)                                         # next to JOB-0002 first
    assert all(dt.date.fromisoformat(x).weekday() < 5 for x in dates)                     # working days only
    res = submit(e, it, act("jb_schedule", date=d(0)))
    assert res[0]["status"] == "rejected" and "dates in the pack" in res[0]["why"]
    release(e)
    conn = get_connection(e["a"])
    conn.execute("UPDATE agent_queue SET status = 'waiting' WHERE ref = 'JOB-0001'")
    conn.close()
    it = items(e, "schedule", "JOB-0001")[0]
    res = submit(e, it, act("jb_schedule", date=d(3)))
    assert res[0]["status"] == "pending" and "Suggest" in res[0]["why"]                   # only suggested
    assert sql(e["j"], "SELECT service_date FROM jobs WHERE job_id = 'JOB-0001'")[0]["service_date"] == ""
    out = ag.review(e["a"], res[0]["proposal_id"], "approve", actor_=OWNER, edition=S, jobs_db=e["j"])
    assert out["status"] == "applied"
    j = sql(e["j"], "SELECT service_date, job_status FROM jobs WHERE job_id = 'JOB-0001'")[0]
    assert j == {"service_date": d(3), "job_status": "Scheduled"}
    # Prep can suggest a better day — but never for a Hard job or today's job
    job(e, "JOB-0003", service_date=d(3), schedule_type="hard", start_time="09:00", end_time="10:00")
    item = {"kind": "job", "ref": "JOB-0003", "stage": "prep", "item_id": 0}
    ctx = ja.context(e["a"], e["j"], item, desk_db.get_settings(e["a"]), S, "")
    with pytest.raises(ja.JobsAgentError, match="Hard"):
        ja.validate(item, act("jb_schedule", date=d(4)), ctx)
    job(e, "JOB-0004", service_date=d(0))
    item = {"kind": "job", "ref": "JOB-0004", "stage": "prep", "item_id": 0}
    ctx = ja.context(e["a"], e["j"], item, desk_db.get_settings(e["a"]), S, "")
    with pytest.raises(ja.JobsAgentError, match="today"):
        ja.validate(item, act("jb_schedule", date=d(4)), ctx)


# ── Close out & invoice (decision 1) ────────────────────────────────────────

def _done_job(e, jid="JOB-0010", **kw):
    job(e, jid, job_status="Complete", service_date=d(0), **kw)
    ins(e["j"], "time_entries", entry_id=f"TE-{jid}", job_id=jid, entry_date=d(0), clock_in=f"{d(0)} 08:00:00",
        clock_out=f"{d(0)} 09:10:00")


def test_draft_then_send_the_invoice_only_when_every_check_holds(e):
    _done_job(e)
    setj(agent_jb_stage_closeout="auto")
    it = items(e, "closeout", "JOB-0010")[0]
    res = submit(e, it, act("jb_draft_invoice"), act("jb_send_invoice", channel="email"))
    assert res[0]["status"] == "applied" and "Invoice created" in res[0]["result"]
    assert res[1]["status"] == "pending" and "isn't allowed to send invoices" in res[1]["why"]   # switch off
    inv = sql(e["j"], "SELECT * FROM invoices WHERE job_id = 'JOB-0010'")[0]
    assert inv["subtotal"] == 200 and inv["created_by"] == "assistant"
    assert not [c for c in e["calls"] if c[0] == "email_invoice"]
    setj(agent_jb_can_send_invoices=True)
    it = items(e, "closeout", "JOB-0010")[0]                                               # drafted — not sent
    assert it["why_queued"].startswith("invoice drafted")
    res = submit(e, it, act("jb_send_invoice", conf=0.7, channel="email"))
    assert res[0]["status"] == "pending" and "confidence" in res[0]["why"]
    ok = ja._invoice_guardrails(desk_db.get_settings(e["a"]),
                                ja.context(e["a"], e["j"], {"kind": "job", "ref": "JOB-0010", "stage": "closeout"},
                                           desk_db.get_settings(e["a"]), S, ""), {"channel": "email"}, 0.9)
    assert ok == (True, "")
    setj(agent_jb_invoice_max=100)
    ok = ja._invoice_guardrails(desk_db.get_settings(e["a"]),
                                ja.context(e["a"], e["j"], {"kind": "job", "ref": "JOB-0010", "stage": "closeout"},
                                           desk_db.get_settings(e["a"]), S, ""), {"channel": "email"}, 0.9)
    assert ok[0] is False and "limit" in ok[1]
    setj(agent_jb_invoice_max=1000)
    # the person approves the held send → sent through the Jobs app's own email_invoice
    p = [x for x in ag.inbox(e["a"]) if x["action"] == "jb_send_invoice"][0]
    out = ag.review(e["a"], p["proposal_id"], "approve", actor_=OWNER, edition=S, jobs_db=e["j"])
    assert out["status"] == "applied" and ("email_invoice", (inv["invoice_id"],)) in e["calls"]
    # an invoice someone changed is never sent by the agent
    _done_job(e, "JOB-0011")
    it = items(e, "closeout", "JOB-0011")[0]
    submit(e, it, act("jb_draft_invoice"))
    conn = get_connection(e["j"])
    conn.execute("UPDATE invoices SET last_edited_by = 'owner' WHERE job_id = 'JOB-0011'")
    conn.close()
    it = items(e, "closeout", "JOB-0011")[0]
    res = submit(e, it, act("jb_send_invoice", channel="email"))
    assert res[0]["status"] == "pending" and "changed" in res[0]["why"]


def test_receipt_after_paid_and_the_daily_limit(e):
    _done_job(e)
    setj(agent_jb_stage_closeout="auto", agent_jb_can_send_invoices=True, agent_jb_invoices_per_day=1)
    it = items(e, "closeout", "JOB-0010")[0]
    res = submit(e, it, act("jb_draft_invoice"), act("jb_send_invoice", channel="email"))
    assert [x["status"] for x in res] == ["applied", "applied"]
    _done_job(e, "JOB-0012")
    it = items(e, "closeout", "JOB-0012")[0]
    res = submit(e, it, act("jb_draft_invoice"), act("jb_send_invoice", channel="email"))
    assert res[1]["status"] == "pending" and "daily invoice limit" in res[1]["why"]
    inv = sql(e["j"], "SELECT invoice_id FROM invoices WHERE job_id = 'JOB-0010'")[0]["invoice_id"]
    conn = get_connection(e["j"])                     # the OWNER records the payment — never the agent
    conn.execute("UPDATE invoices SET payment_status = 'Zelle', payment_method = 'Zelle', amount_paid = total_due, "
                 "payment_date = ? WHERE invoice_id = ?", (d(0), inv))
    conn.close()
    it = items(e, "closeout", "JOB-0010")[0]
    assert it["why_queued"].startswith("paid")
    res = submit(e, it, act("jb_send_receipt", channel="email"))
    assert res[0]["status"] == "applied" and ("email_receipt", (inv, "Zelle")) in e["calls"]
    assert "jb_mark_paid" not in ja.RISK and all("paid" not in a for a in ja.RISK if a.startswith("jb_"))


# ── Get paid (decision 2) ───────────────────────────────────────────────────

def _unpaid(e, inv="INV-0100", age=8, jid="JOB-0100"):
    job(e, jid, job_status="Complete", service_date=d(-age), invoice_id=None, invoice_sent_date=d(-age))
    ins(e["j"], "invoices", invoice_id=inv, job_id=jid, customer_id="CUST-0001", customer_name="Ann Lee",
        invoice_date=d(-age), due_date=d(30 - age), subtotal=200, discount=0, taxable_amt=200, tax=14, total_due=214,
        amount_paid=0, payment_status="Unpaid", created_by="owner")
    conn = get_connection(e["j"])
    conn.execute("UPDATE jobs SET invoice_id = ? WHERE job_id = ?", (inv, jid))
    conn.close()


def test_reminders_at_7_14_30_the_last_firmer_then_call(e):
    _unpaid(e)
    setj(agent_jb_stage_collect="auto")
    it = items(e, "collect", "INV-0100")[0]
    assert it["invoice"]["next_reminder"] == 1 and "214" not in json.dumps(it["invoice"])
    res = submit(e, it, act("jb_payment_reminder", body="Hi Ann, a friendly reminder about your invoice."))
    assert res[0]["status"] == "applied"
    body = [c for c in e["calls"] if c[0] == "send_email"][-1][1][2]
    assert "Invoice INV-0100 — balance due $214.00" in body                             # the amount is the invoice's
    assert not items(e, "collect")                                                       # not again today
    e["clock"]["now"] += dt.timedelta(days=1)
    item = {"kind": "job", "ref": "INV-0100", "stage": "collect", "item_id": 0}
    ctx = ja.context(e["a"], e["j"], item, desk_db.get_settings(e["a"]), S, "")
    assert any("days apart" in h for h in ja.holds("job", "collect", act("jb_payment_reminder", body="x"),
                                                   desk_db.get_settings(e["a"]), ctx, 0.9, "auto")[0])
    e["clock"]["now"] += dt.timedelta(days=6)                                            # day 15
    it = items(e, "collect", "INV-0100")[0]
    assert it["invoice"]["next_reminder"] == 2
    submit(e, it, act("jb_payment_reminder", body="Hi Ann, your invoice is now two weeks old."))
    e["clock"]["now"] += dt.timedelta(days=16)                                           # day 31
    it = items(e, "collect", "INV-0100")[0]
    assert it["invoice"]["next_reminder"] == 3 and "firmer" in it["hint"]
    submit(e, it, act("jb_payment_reminder", body="Hi Ann, please pay this week or give us a call."))
    e["clock"]["now"] += dt.timedelta(days=7)
    it = items(e, "collect", "INV-0100")[0]
    assert it["why_queued"] == "call them" and it["invoice"]["next_reminder"] is None
    res = submit(e, it, act("jb_payment_reminder", body="x"))
    assert res[0]["status"] == "rejected" and "call" in res[0]["why"]
    release(e)
    conn = get_connection(e["a"])
    conn.execute("UPDATE agent_queue SET status = 'waiting' WHERE ref = 'INV-0100' AND stage = 'collect'")
    conn.close()
    it = items(e, "collect", "INV-0100")[0]
    res = submit(e, it, act("jb_call_customer", body="Call Ann about INV-0100 — 3 reminders, no payment."))
    assert res[0]["status"] == "applied"
    assert len([c for c in e["calls"] if c[0] == "send_email"]) == 3
    assert sql(e["j"], "SELECT payment_status FROM invoices WHERE invoice_id = 'INV-0100'")[0]["payment_status"] == "Unpaid"


def test_a_customer_who_opted_out_is_never_messaged(e):
    _unpaid(e)
    e["opted"].add("386-555-0100")
    setj(agent_jb_stage_collect="auto")
    it = items(e, "collect", "INV-0100")[0]
    assert it["customer"]["opted_out"] is True
    res = submit(e, it, act("jb_payment_reminder", body="Friendly reminder."))
    assert res[0]["status"] == "pending" and "opted out" in res[0]["why"]
    with pytest.raises(ag.AgentError, match="opted out"):
        ag.review(e["a"], res[0]["proposal_id"], "approve", actor_=OWNER, edition=S, jobs_db=e["j"])
    assert not [c for c in e["calls"] if c[0] in ("send_email", "send_sms")]


# ── On site · Learn ─────────────────────────────────────────────────────────

def test_on_site_flags_a_job_running_long_and_never_touches_the_time(e):
    job(e, "JOB-0020", job_status="In Progress", service_date=d(0))
    ins(e["j"], "time_entries", entry_id="TE-1", job_id="JOB-0020", entry_date=d(0), clock_in=f"{d(0)} 07:00:00")
    it = items(e, "onsite", "JOB-0020")[0]
    assert it["why_queued"] == "running_long" and it["open_clock"] is True
    res = submit(e, it, act("jb_flag", flag="running_long", detail="2 h on a 1 h job"))
    assert res[0]["status"] == "applied"                                                  # On site is Auto
    assert sql(e["j"], "SELECT clock_out FROM time_entries")[0]["clock_out"] is None
    assert not any(a.startswith("jb_") and ("time" in a or "mileage" in a) for a in ja.RISK)


def test_learn_proposes_a_new_usual_time_and_a_person_decides(e):
    for k in range(6):
        jid = f"JOB-03{k:02d}"
        job(e, jid, job_status="Complete", service_date=d(-3 - k))
        ins(e["j"], "time_entries", entry_id=f"TE-L{k}", job_id=jid, entry_date=d(-3 - k),
            clock_in=f"{d(-3 - k)} 08:00:00", clock_out=f"{d(-3 - k)} 09:30:00")
    setj(agent_jb_stage_learn="auto")
    it = [i for i in items(e, "learn") if i["ref"] == "CUST-0001"][0]
    tos = it["time_on_site"]
    assert tos["pattern"] and tos["median_minutes"] == 90 and tos["usual_minutes"] == 60
    res = submit(e, it, act("jb_set_estimate", minutes=90))
    assert res[0]["status"] == "pending" and "high risk" in res[0]["why"]
    ag.review(e["a"], res[0]["proposal_id"], "approve", actor_=OWNER, edition=S, jobs_db=e["j"])
    assert sql(e["j"], "SELECT avg_job_duration_min FROM customers")[0]["avg_job_duration_min"] == 90


# ── the Route flow ──────────────────────────────────────────────────────────

def test_sort_the_week_then_schedule_it(e):
    # next week: two soft jobs 0.1 mi apart on Monday and Wednesday (today is Friday = the sort day)
    job(e, "JOB-0401", service_date=d(3))
    job(e, "JOB-0402", service_date=d(5), latitude=29.031, longitude=-81.301)
    job(e, "JOB-0403", service_date=d(4), schedule_type="hard", start_time="09:00", end_time="10:00",
        latitude=29.2, longitude=-81.0)
    it = items(e, "sort")[0]
    assert it["ref"] == f"W:{d(3)}|" and {j["job_id"]: j["movable"] for j in it["week"]["jobs"]}["JOB-0403"] is False
    res = submit(e, it, act("rt_propose_week", moves=[{"job_id": "JOB-0403", "to": d(3)}]))
    assert res[0]["status"] == "rejected" and "movable" in res[0]["why"]                  # never a Hard job
    release(e)
    conn = get_connection(e["a"])
    conn.execute("UPDATE agent_queue SET status = 'waiting' WHERE stage = 'sort'")
    conn.close()
    it = items(e, "sort")[0]
    res = submit(e, it, act("rt_propose_week", moves=[{"job_id": "JOB-0402", "to": d(3), "reason": "0.1 mi from JOB-0401"}]))
    assert res[0]["status"] == "applied" and "WK-AG" in res[0]["result"]                  # saved, nothing moved
    assert sql(e["j"], "SELECT service_date FROM jobs WHERE job_id = 'JOB-0402'")[0]["service_date"] == d(5)
    import week_plan as wp
    p = wp.latest_pending(e["tmp"] / "week_proposals.json", d(3), "")
    assert p and p["moves"][0]["job_id"] == "JOB-0402"                                     # 🗓️ Plan Week shows it
    it = items(e, "plan")[0]
    res = submit(e, it, act("rt_apply_week", job_ids=["JOB-0402"]))
    assert res[0]["status"] == "pending"                                                   # Suggest
    ag.review(e["a"], res[0]["proposal_id"], "approve", actor_=OWNER, edition=S, jobs_db=e["j"])
    assert sql(e["j"], "SELECT service_date FROM jobs WHERE job_id = 'JOB-0402'")[0]["service_date"] == d(3)
    assert wp.get_proposal(e["tmp"] / "week_proposals.json", p["code"])["status"] == "approved"


def test_route_tomorrow_send_it_and_replan_today(e):
    e["clock"]["now"] = dt.datetime.combine(FRI - dt.timedelta(days=1), dt.time(9, 0))    # Thursday
    job(e, "JOB-0501", service_date=d(0))
    job(e, "JOB-0502", service_date=d(0), latitude=29.1, longitude=-81.2)
    setj(agent_jb_rt_stage_route="auto", agent_jb_rt_stage_send="auto", agent_jb_rt_stage_replan="auto")
    it = items(e, "route")[0]
    assert it["ref"] == f"{d(0)}|" and it["route"]["stops"] == 0
    assert submit(e, it, act("rt_route_day"))[0]["status"] == "applied"
    assert ("suggest_route", (d(0), "")) in e["calls"]
    for n, jid in enumerate(("JOB-0501", "JOB-0502"), 1):           # what suggest_route would have written
        ins(e["j"], "route_stops", route_date=d(0), crew_id="owner", stop_number=n, job_id=jid)
    assert not items(e, "route") and not items(e, "send")                                  # not before 18:00
    e["clock"]["now"] = e["clock"]["now"].replace(hour=18)
    it = items(e, "send")[0]
    assert submit(e, it, act("rt_send"))[0]["status"] == "applied"
    assert [c[0] for c in e["calls"][-2:]] == ["approve_route", "email_route"]
    # Friday: a job is cancelled → re-plan the rest of today
    e["clock"]["now"] = dt.datetime.combine(FRI, dt.time(10, 0))
    conn = get_connection(e["j"])
    conn.execute("UPDATE jobs SET job_status = 'Cancelled', version = version + 1 WHERE job_id = 'JOB-0501'")
    conn.close()
    it = items(e, "replan")[0]
    assert submit(e, it, act("rt_replan"))[0]["status"] == "applied"
    assert ("replan_route", (d(0), "")) in e["calls"]
    item = {"kind": "route", "ref": f"{d(3)}|", "stage": "replan", "item_id": 0}
    ctx = ja.context(e["a"], e["j"], item, desk_db.get_settings(e["a"]), S, "")
    with pytest.raises(ja.JobsAgentError, match="today only"):
        ja.validate(item, act("rt_replan"), ctx)


# ── practice, the runner, who reviews ───────────────────────────────────────

def test_practice_mode_changes_nothing(e):
    job(e, "JOB-0001", job_status="Unscheduled", service_date="")
    setj(agent_jb_shadow=True, agent_jb_stage_schedule="auto")
    it = items(e, "schedule", "JOB-0001")[0]
    assert it["mode"] == "practice"
    res = submit(e, it, act("jb_schedule", date=it["dates"][0]["date"]))
    assert res[0]["status"] == "practice"
    assert sql(e["j"], "SELECT service_date FROM jobs WHERE job_id = 'JOB-0001'")[0]["service_date"] == ""


def test_the_runner_works_the_jobs_queue_on_its_own(e, monkeypatch):
    job(e, "JOB-0020", job_status="In Progress", service_date=d(0))
    ins(e["j"], "time_entries", entry_id="TE-1", job_id="JOB-0020", entry_date=d(0), clock_in=f"{d(0)} 07:00:00")
    tickets = str(e["tmp"] / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(tickets)
    for k, v in (("agent_provider", "claude_api"), ("agent_name", "Sam"), ("agent_batch_seconds", 0)):
        desk_db.set_setting(tickets, k, v, edition=S)
    s = store.sync_shared(tickets)
    assert s["agent_provider"] == "claude_api" and s["agent_name"] == "Sam" and not s["agent_enabled"]
    monkeypatch.setattr(prov, "_key", lambda p: "test-key")
    monkeypatch.setattr(prov, "_cfg", lambda: {})
    seen = []

    def fake(provider, system, user):
        pack = json.loads(user)
        seen.append(pack)
        return json.dumps({"actions": [{"action": "jb_flag", "flag": "running_long", "detail": "2 h",
                                        "why": "over", "confidence": 0.9}], "summary": "flagged"}), \
            {"input": 100, "output": 20}
    ag.transport = fake
    out = ag.run(e["a"], edition=S, jobs_db=e["j"], force=True)
    assert out["ran"] and out["ok"] >= 1
    assert any(p["kind"] == "job" and p["stage"] == "onsite" and "action_fields" in p for p in seen)
    assert [x for x in sql(e["a"], "SELECT action, status FROM agent_proposals") if x["action"] == "jb_flag"][0][
        "status"] == "applied"
    assert ag.spend(tickets)["spent_usd"] == ag.spend(e["a"])["spent_usd"]                 # one budget for both


def test_chat_tools_run_both_queues_with_j_ids(e):
    import desk_tools
    tickets = str(e["tmp"] / "tickets_database" / desk_db.DEFAULT_DB_FILENAME)
    desk_db.init_db(tickets)
    job(e, "JOB-0001", job_status="Unscheduled", service_date="")
    out = json.loads(desk_tools.desk_agent_next(tickets, OWNER, S, limit=5, jobs_db=e["j"]))
    it = [i for i in out["items"] if i["stage"] == "schedule"][0]
    assert str(it["item_id"]).startswith("J") and "action_fields" in it
    res = json.loads(desk_tools.desk_agent_submit(tickets, OWNER, S, item_id=it["item_id"], jobs_db=e["j"],
                                                  actions=json.dumps([act("jb_schedule", date=it["dates"][0]["date"])])))
    pid = res["results"][0]["proposal_id"]
    assert pid.startswith("J") and res["results"][0]["status"] == "pending"
    assert f"#{pid} job JOB-0001" in desk_tools.desk_agent_review(tickets, OWNER, S, action="list")
    assert "Jobs agent on" in desk_tools.desk_agent_status(tickets, OWNER, S)
    assert desk_tools.desk_agent_review(tickets, OWNER, S, action="approve", proposal_id=pid,
                                        jobs_db=e["j"]).startswith(f"✅ #{pid}: applied")


def test_the_jobs_app_tool(e):
    import desk_tools
    job(e, "JOB-0001", job_status="Unscheduled", service_date="")
    st = json.loads(desk_tools.jobs_agent(OWNER, S, action="status", jobs_db=e["j"]))
    assert st["ok"] and st["enabled"] and st["can_change_settings"]
    it = items(e, "schedule", "JOB-0001")[0]
    submit(e, it, act("jb_schedule", date=it["dates"][0]["date"]))
    st = json.loads(desk_tools.jobs_agent(OWNER, S, action="status"))
    assert st["by_stage"] == {"job:schedule": 1}
    lst = json.loads(desk_tools.jobs_agent(OWNER, S, action="list"))["items"]
    assert lst[0]["proposal_id"].startswith("J")
    out = json.loads(desk_tools.jobs_agent({"id": "u-m", "role": r.MANAGER}, r.BUSINESS, action="reject",
                                           proposal_id=lst[0]["proposal_id"]))
    assert out["ok"] and out["status"] == "rejected"
    no = json.loads(desk_tools.jobs_agent({"id": "u-1", "role": r.FIELD_CREW}, r.BUSINESS, action="list"))
    assert no["ok"] is False
    no = json.loads(desk_tools.jobs_agent({"id": "u-m", "role": r.MANAGER}, r.BUSINESS, action="set",
                                          settings='{"agent_jb_enabled": false}'))
    assert no["ok"] is False and "owner" in no["error"]
    cfg = json.loads(desk_tools.jobs_agent(OWNER, S, action="settings"))
    assert cfg["jb_flow"]["steps"] and cfg["rt_flow"]["steps"] and "route_stages" in cfg["options"]
    out = json.loads(desk_tools.jobs_agent(OWNER, S, action="set", settings='{"agent_jb_stage_quotes": "auto"}'))
    assert out["settings"]["agent_jb_stage_quotes"] == "auto"


def test_the_scheduler_tick_works_without_service_desk(e, monkeypatch):
    import desk_portal
    import desk_scheduler
    job(e, "JOB-0001", job_status="Unscheduled", service_date="")
    monkeypatch.setattr(desk_portal, "jobs_db_fn", lambda: e["j"])
    desk_scheduler._jobs_last["scan"] = None
    did = desk_scheduler.jobs_agent_tick(None, edition=S)
    assert did.get("jobs_agent_queued", 0) >= 1 and "jobs_agent_run" not in did     # runs in a chat
    assert not desk_scheduler.jobs_agent_tick(None, edition=S).get("jobs_agent_queued")   # every 5 minutes
    it = items(e, "schedule", "JOB-0001")[0]
    submit(e, it, act("jb_schedule", date=it["dates"][0]["date"]))
    assert "1 suggestion(s) waiting" in desk_scheduler.jobs_agent_digest_line()


def test_a_job_from_quote_to_paid_time_machine(e):
    """One job's life with the agent: quote → job → date → done → invoice → reminder → paid →
    receipt → next visit. The owner approves what's on Suggest; the clock moves forward."""
    clock = e["clock"]
    setj(agent_jb_stage_quotes="auto", agent_jb_stage_closeout="auto", agent_jb_stage_collect="auto",
         agent_jb_stage_repeat="auto", agent_jb_can_send_invoices=True)
    ins(e["j"], "quotes", quote_id="QTE-0007", customer_id="CUST-0001", customer_name="Ann Lee", quote_date=d(-5),
        service_type="Window cleaning", service_description="All windows", subtotal=240, discount_amt=0, tax=0,
        quote_total=240, status="Approved")
    # Friday: the approved quote becomes a job (Auto)
    it = items(e, "quotes", "QTE-0007")[0]
    assert submit(e, it, act("jb_job_from_quote"))[0]["status"] == "applied"
    jid = sql(e["j"], "SELECT job_id FROM jobs WHERE service_type = 'Window cleaning'")[0]["job_id"]
    conn = get_connection(e["j"])
    conn.execute("UPDATE customers SET frequency = 'Monthly' WHERE customer_id = 'CUST-0001'")
    conn.close()
    # … and gets a date — only suggested; the owner approves it
    it = items(e, "schedule", jid)[0]
    p = submit(e, it, act("jb_schedule", date=it["dates"][0]["date"]))[0]
    day = it["dates"][0]["date"]
    ag.review(e["a"], p["proposal_id"], "approve", actor_=OWNER, edition=S, jobs_db=e["j"])
    # the visit day: the crew does the job (the timer logs time; the owner marks it Complete)
    clock["now"] = dt.datetime.combine(dt.date.fromisoformat(day), dt.time(15, 0))
    ins(e["j"], "time_entries", entry_id="TE-S1", job_id=jid, entry_date=day, clock_in=f"{day} 09:00:00",
        clock_out=f"{day} 10:00:00")
    conn = get_connection(e["j"])
    conn.execute("UPDATE jobs SET job_status = 'Complete', version = version + 1 WHERE job_id = ?", (jid,))
    conn.close()
    it = items(e, "closeout", jid)[0]
    res = submit(e, it, act("jb_draft_invoice"), act("jb_send_invoice", channel="email"))
    assert [x["status"] for x in res] == ["applied", "applied"]                      # every check held
    inv = sql(e["j"], "SELECT * FROM invoices WHERE job_id = ?", (jid,))[0]
    assert inv["subtotal"] == 240
    conn = get_connection(e["j"])                                                 # (invoices are dated today)
    conn.execute("UPDATE invoices SET invoice_date = ? WHERE invoice_id = ?", (day, inv["invoice_id"]))
    conn.close()
    # a week later, still unpaid: reminder 1
    clock["now"] += dt.timedelta(days=7)
    it = items(e, "collect", inv["invoice_id"])[0]
    assert submit(e, it, act("jb_payment_reminder", body="Hi Ann, a friendly reminder."))[0]["status"] == "applied"
    # the owner records the payment; the agent sends the receipt and sets up the next visit
    conn = get_connection(e["j"])
    conn.execute("UPDATE invoices SET payment_status = 'Check', payment_method = 'Check', amount_paid = total_due, "
                 "payment_date = ? WHERE invoice_id = ?", (clock["now"].date().isoformat(), inv["invoice_id"]))
    conn.close()
    it = items(e, "closeout", jid)[0]
    assert submit(e, it, act("jb_send_receipt", channel="email"))[0]["status"] == "applied"
    assert not items(e, "collect")                                                 # paid — no more reminders
    it = items(e, "repeat", jid)[0]
    res = submit(e, it, act("jb_next_visit"))
    assert res[0]["status"] == "applied", res
    nxt = sql(e["j"], "SELECT job_id FROM jobs WHERE customer_id = 'CUST-0001' AND job_id != ? AND "
                      "service_type = 'Window cleaning'", (jid,))
    assert nxt
    names = [c[0] for c in e["calls"]]
    assert names.count("email_invoice") == 1 and names.count("email_receipt") == 1 and names.count("send_email") == 1


def test_only_the_owner_or_a_manager_reviews(e):
    job(e, "JOB-0001", job_status="Unscheduled", service_date="")
    it = items(e, "schedule", "JOB-0001")[0]
    res = submit(e, it, act("jb_schedule", date=it["dates"][0]["date"]))
    with pytest.raises(ag.AgentError, match="owner or a manager"):
        ag.review(e["a"], res[0]["proposal_id"], "approve", actor_={"id": "u-1", "role": r.FIELD_CREW},
                  edition=r.BUSINESS, jobs_db=e["j"])
    out = ag.review(e["a"], res[0]["proposal_id"], "approve", actor_={"id": "u-m", "role": r.MANAGER, "name": "Mo"},
                    edition=r.BUSINESS, jobs_db=e["j"])
    assert out["status"] == "applied"
